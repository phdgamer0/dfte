//! Multi-stream TCP backend (manual §15, Windows default). Each logical
//! connection is 1 control + N data sockets; a short preamble on every socket
//! groups them back together on the accepting side.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use uuid::Uuid;

use crate::framed::FramedStream;
use crate::{Connection, Listener, MAX_DATA_STREAMS, Result, Transport, TransportError, TransportKind};

const PREAMBLE_MAGIC: &[u8; 8] = b"DFTE/tcp";
const PREAMBLE_LEN: usize = 8 + 16 + 2;
/// Half-formed groups kept at once; bounds memory under a connection flood (manual §34).
const MAX_PENDING_GROUPS: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct TcpConfig {
    /// `None` keeps OS buffer autotuning (on Linux, setting a size disables it).
    pub send_buffer: Option<u32>,
    pub recv_buffer: Option<u32>,
    /// How long a peer gets to open every socket of a connection.
    pub group_timeout: Duration,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self { send_buffer: None, recv_buffer: None, group_timeout: Duration::from_secs(10) }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpTransport {
    pub config: TcpConfig,
}

impl TcpTransport {
    pub fn new(config: TcpConfig) -> Self {
        Self { config }
    }

    fn socket(&self, addr: SocketAddr) -> Result<TcpSocket> {
        let s = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        if let Some(n) = self.config.send_buffer {
            s.set_send_buffer_size(n)?;
        }
        if let Some(n) = self.config.recv_buffer {
            s.set_recv_buffer_size(n)?;
        }
        Ok(s)
    }
}

impl Transport for TcpTransport {
    type Listener = TcpListener;

    fn kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    async fn listen(&self, addr: SocketAddr) -> Result<TcpListener> {
        let s = self.socket(addr)?;
        s.set_reuseaddr(true)?;
        s.bind(addr)?;
        Ok(TcpListener { inner: s.listen(128)?, config: self.config, pending: HashMap::new() })
    }

    async fn connect(&self, addr: SocketAddr, data_streams: usize) -> Result<Connection> {
        if data_streams == 0 || data_streams > MAX_DATA_STREAMS {
            return Err(TransportError::InvalidStreamCount(data_streams));
        }
        let token = *Uuid::new_v4().as_bytes();
        let total = data_streams + 1;
        let mut streams = Vec::with_capacity(total);
        for index in 0..total {
            let mut s = self.socket(addr)?.connect(addr).await?;
            s.set_nodelay(true)?;
            s.write_all(&preamble(&token, index as u8, total as u8)).await?;
            streams.push(s);
        }
        let mut streams = streams.into_iter().map(framed);
        let control = streams.next().ok_or(TransportError::InvalidStreamCount(0))?;
        Ok(Connection { kind: TransportKind::Tcp, peer: addr, control, data: streams.collect() })
    }
}

pub struct TcpListener {
    inner: tokio::net::TcpListener,
    config: TcpConfig,
    pending: HashMap<[u8; 16], Group>,
}

struct Group {
    started: Instant,
    peer: SocketAddr,
    slots: Vec<Option<TcpStream>>,
}

impl Listener for TcpListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }

    /// Accepts sockets until one connection's full set has arrived. Sockets
    /// with a bad preamble are dropped without failing the listener.
    async fn accept(&mut self) -> Result<Connection> {
        loop {
            let (mut s, peer) = self.inner.accept().await?;
            let timeout = self.config.group_timeout;
            let mut p = [0u8; PREAMBLE_LEN];
            // Rejected sockets are dropped on purpose so one bad peer can't take
            // the listener down (manual §34); each drop is logged, not silent.
            match tokio::time::timeout(timeout, s.read_exact(&mut p)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "dropping socket: preamble read failed");
                    continue;
                }
                Err(_) => {
                    tracing::debug!(%peer, "dropping socket: preamble timed out");
                    continue;
                }
            }
            let Some((token, index, total)) = parse_preamble(&p) else {
                tracing::debug!(%peer, "dropping socket: bad preamble");
                continue;
            };
            s.set_nodelay(true)?;

            let now = Instant::now();
            self.pending.retain(|_, g| now.duration_since(g.started) < timeout);
            if !self.pending.contains_key(&token) && self.pending.len() >= MAX_PENDING_GROUPS {
                tracing::warn!(%peer, "dropping socket: too many half-open connections");
                continue;
            }
            let group = self.pending.entry(token).or_insert_with(|| Group { started: now, peer, slots: (0..total).map(|_| None).collect() });
            // A token is only valid from one peer IP and one declared size.
            if group.peer.ip() != peer.ip() || group.slots.len() != total as usize || group.slots[index as usize].is_some() {
                tracing::debug!(%peer, "dropping socket: preamble conflicts with its group");
                continue;
            }
            group.slots[index as usize] = Some(s);
            if group.slots.iter().all(Option::is_some) {
                let g = self.pending.remove(&token).ok_or(TransportError::BadPreamble)?;
                let mut streams = g.slots.into_iter().flatten().map(framed);
                let control = streams.next().ok_or(TransportError::BadPreamble)?;
                return Ok(Connection { kind: TransportKind::Tcp, peer: g.peer, control, data: streams.collect() });
            }
        }
    }
}

fn framed(s: TcpStream) -> FramedStream {
    let (r, w) = s.into_split();
    FramedStream::new(Box::new(r), Box::new(w))
}

fn preamble(token: &[u8; 16], index: u8, total: u8) -> [u8; PREAMBLE_LEN] {
    let mut p = [0u8; PREAMBLE_LEN];
    p[..8].copy_from_slice(PREAMBLE_MAGIC);
    p[8..24].copy_from_slice(token);
    p[24] = index;
    p[25] = total;
    p
}

fn parse_preamble(p: &[u8; PREAMBLE_LEN]) -> Option<([u8; 16], u8, u8)> {
    if &p[..8] != PREAMBLE_MAGIC {
        return None;
    }
    let (index, total) = (p[24], p[25]);
    if total < 2 || total as usize > MAX_DATA_STREAMS + 1 || index >= total {
        return None;
    }
    Some((p[8..24].try_into().ok()?, index, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_roundtrip_and_rejects() {
        let t = [3u8; 16];
        assert_eq!(parse_preamble(&preamble(&t, 1, 3)), Some((t, 1, 3)));
        assert_eq!(parse_preamble(&preamble(&t, 3, 3)), None);
        assert_eq!(parse_preamble(&preamble(&t, 0, 1)), None);
        assert_eq!(parse_preamble(&preamble(&t, 0, 200)), None);
        let mut bad = preamble(&t, 0, 2);
        bad[0] = b'X';
        assert_eq!(parse_preamble(&bad), None);
    }
}
