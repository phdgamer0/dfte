// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Receiving on both backends at once, and the per-device sending default.
//!
//! The sender picks the backend (manual §15), and that choice now depends on
//! the sender's own kernel (see [`TransportKind::platform_default`]), so a
//! receiver can't know it in advance: it listens with TCP and QUIC on the same
//! port number (one is a TCP socket, the other a UDP socket, so they don't clash).

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::quic::ListenerDrain;
use crate::{Connection, Listener, QuicListener, QuicTransport, Result, TcpListener, TcpTransport, Transport, TransportError, TransportKind};

/// Port-0 binds retried when the OS-picked UDP port is already taken for TCP.
const PAIR_BIND_ATTEMPTS: usize = 8;
/// Pause after a failed accept so a persistent error can't spin a task.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

impl TransportKind {
    /// The backend this device should *send* with (manual §15): TCP on Windows
    /// (USO/URO instability), and TCP on Linux/Android kernels without UDP GSO.
    ///
    /// Measured on a Galaxy A30 (Linux 4.4, no GSO; manual §30 #6): QUIC sends
    /// topped out at ~7 MiB/s on every path, even unencrypted, while TCP reached
    /// 25–32 MiB/s on the same link — without GSO, quinn pays a syscall and a
    /// packet seal per ~1.4 KB. Everything else keeps QUIC. The probe runs once.
    pub fn platform_default() -> Self {
        static KIND: OnceLock<TransportKind> = OnceLock::new();
        *KIND.get_or_init(|| {
            if cfg!(windows) {
                return Self::Tcp;
            }
            if cfg!(any(target_os = "linux", target_os = "android")) && !udp_gso_available() {
                tracing::info!("kernel has no UDP GSO; sending over TCP (manual §15)");
                return Self::Tcp;
            }
            Self::Quic
        })
    }
}

/// Whether the kernel segments UDP sends for us (Linux 4.18+). A probe that
/// can't even open a socket counts as "no": TCP is the safe fallback.
fn udp_gso_available() -> bool {
    let probe = std::net::UdpSocket::bind(("127.0.0.1", 0)).and_then(|s| quinn::udp::UdpSocketState::new((&s).into()));
    match probe {
        Ok(state) => state.max_gso_segments() > 1,
        Err(e) => {
            tracing::warn!(error = %e, "UDP GSO probe failed; assuming no GSO");
            false
        }
    }
}

/// Binds TCP and QUIC on the same port. With port 0 the OS picks a free UDP
/// port, which may already be taken for TCP; that case is retried.
pub async fn listen_pair(tcp: &TcpTransport, quic: &QuicTransport, addr: SocketAddr) -> Result<(TcpListener, QuicListener)> {
    let mut last = None;
    for _ in 0..PAIR_BIND_ATTEMPTS {
        let q = quic.listen(addr).await?;
        let mut at = addr;
        at.set_port(q.local_addr()?.port());
        match tcp.listen(at).await {
            Ok(t) => return Ok((t, q)),
            Err(TransportError::Io(e)) if addr.port() == 0 && e.kind() == std::io::ErrorKind::AddrInUse => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.map_or(TransportError::InvalidConfig("listen_pair: no attempts"), TransportError::Io))
}

/// Accepts from a TCP and a QUIC listener on one port. Each runs its own accept
/// loop in a task (TCP's accept isn't cancel-safe, so the two can't simply be
/// raced in a `select!`); [`accept`](Listener::accept) is cancel-safe.
/// Dropping it stops both.
pub struct DualListener {
    rx: mpsc::Receiver<Result<Connection>>,
    addr: SocketAddr,
    quic_drain: ListenerDrain,
    tasks: [JoinHandle<()>; 2],
}

impl DualListener {
    /// Binds both backends (see [`listen_pair`]). Must run inside a tokio runtime.
    pub async fn bind(tcp: &TcpTransport, quic: &QuicTransport, addr: SocketAddr) -> Result<Self> {
        let (t, q) = listen_pair(tcp, quic, addr).await?;
        let addr = t.local_addr()?;
        let quic_drain = q.drain_handle();
        let (tx, rx) = mpsc::channel(4);
        let tasks = [tokio::spawn(accept_loop(t, tx.clone())), tokio::spawn(accept_loop(q, tx))];
        Ok(Self { rx, addr, quic_drain, tasks })
    }
}

async fn accept_loop<L: Listener>(mut l: L, tx: mpsc::Sender<Result<Connection>>) {
    loop {
        let r = l.accept().await;
        let (closed, failed) = (matches!(r, Err(TransportError::Closed)), r.is_err());
        if tx.send(r).await.is_err() || closed {
            return;
        }
        if failed {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
        }
    }
}

impl Drop for DualListener {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Listener for DualListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.addr)
    }

    async fn accept(&mut self) -> Result<Connection> {
        self.rx.recv().await.unwrap_or(Err(TransportError::Closed))
    }

    /// TCP needs no drain (the kernel delivers after close); QUIC does.
    async fn drain(&self) -> Result<()> {
        self.quic_drain.drain().await
    }
}
