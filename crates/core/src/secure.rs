//! Session establishment on the control stream (manual §9.1/§12.1) and the sealed
//! control channel used afterwards.
//!
//! Flow: `Hello` → `HelloAck` (plaintext; versions, caps, stream count, cipher
//! preferences) → three `Handshake` frames carrying Noise_XX, with the exact
//! Hello/HelloAck frame bytes bound in as the Noise prologue → the caller's
//! [`PeerVerifier`] decides on the SAS/fingerprint → established. From then on
//! every frame body is AEAD-sealed with a per-stream session (stream 0 = control,
//! 1..=N = data); the frame's sequence number is the nonce input and the 24-byte
//! header (whose `payload_length` already counts the tag) is the AAD.
//!
//! This is the low-level layer under [`crate::send_files`]/[`crate::receive`];
//! it is public so other front ends (and adversarial tests) can drive a session
//! message by message.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crypto::{CipherSuite, Handshake, Opener, Sealer, TAG_LEN, negotiate};
use protocol::header::{HEADER_LEN, Header, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use protocol::manifest::Manifest;
use protocol::message::{ChunkAck, CloseReason, Hello, ManifestAccept, Message, SelectiveNack, caps};
use protocol::state::Role;
use protocol::state::connection::{ConnEvent, Connection as ConnMachine};
use protocol::{MsgType, ProtocolError};
use transport::{Connection, FrameReader, FrameWriter, FramedStream, TransportKind};

use crate::error::{EngineError, Result};
use crate::options::{CommonOptions, PeerAuth};

/// Largest frame accepted before the peer is authenticated. Hello/HelloAck and
/// Noise messages are tiny; this stops an unauthenticated peer from making us
/// allocate the 16 MiB `MAX_PAYLOAD`.
const MAX_PREAUTH_FRAME: u32 = 64 * 1024;

/// A decoded, authenticated control-stream message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Control {
    ManifestOffer(Manifest),
    ManifestAccept(ManifestAccept),
    ChunkAck(ChunkAck),
    SelectiveNack(SelectiveNack),
    Cancel,
    Close(CloseReason),
    Ping(u64),
    Pong(u64),
}

/// Sending half of the sealed control stream.
pub struct ControlTx {
    writer: FrameWriter,
    sealer: Sealer,
    seq: u64,
    scratch: Vec<u8>,
}

impl ControlTx {
    /// Seal and buffer `msg`; it is not sent until [`flush`](Self::flush).
    pub async fn queue(&mut self, msg: &Message<'_>) -> Result<()> {
        self.scratch.clear();
        msg.encode_body(&mut self.scratch)?;
        self.seq += 1;
        let len = u32::try_from(self.scratch.len() + TAG_LEN).map_err(|_| EngineError::Internal("control message too large".into()))?;
        let header = Header::new(msg.msg_type(), 0, 0, self.seq, len);
        self.sealer.seal_in_place(self.seq, &header.to_bytes(), &mut self.scratch)?;
        self.writer.queue_frame(&header, &[&self.scratch]).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        Ok(self.writer.flush().await?)
    }

    /// Seal and send `msg` now.
    pub async fn send(&mut self, msg: &Message<'_>) -> Result<()> {
        self.queue(msg).await?;
        self.flush().await
    }

    /// Best-effort `Close(reason)` and half-close; errors are ignored because this
    /// runs on paths that are already failing.
    pub async fn close(&mut self, reason: CloseReason) {
        let _ = self.send(&Message::Close(reason)).await;
        let _ = self.writer.shutdown().await;
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        Ok(self.writer.shutdown().await?)
    }
}

/// Receiving half of the sealed control stream.
pub struct ControlRx {
    reader: FrameReader,
    opener: Opener,
}

impl ControlRx {
    /// Next authenticated control message; `Ok(None)` on a clean EOF. A forged,
    /// replayed or malformed frame is an error and ends the session (manual §34).
    pub async fn recv(&mut self) -> Result<Option<Control>> {
        let Some(h) = self.reader.read_header().await? else { return Ok(None) };
        if h.stream_id != 0 {
            return Err(EngineError::violation("control frame with non-zero stream id"));
        }
        if (h.payload_length as usize) < TAG_LEN {
            return Err(EngineError::violation("sealed frame shorter than its tag"));
        }
        let aad = h.to_bytes();
        let body = self.reader.read_body(&h).await?;
        let plain = self.opener.open_in_place(h.sequence_number, &aad, body)?;
        let msg = Message::decode(h.msg_type, plain)?;
        Ok(Some(match msg {
            Message::ManifestOffer(m) => Control::ManifestOffer(m),
            Message::ManifestAccept(m) => Control::ManifestAccept(m),
            Message::ChunkAck(m) => Control::ChunkAck(m),
            Message::SelectiveNack(m) => Control::SelectiveNack(m),
            Message::Cancel => Control::Cancel,
            Message::Close(r) => Control::Close(r),
            Message::Ping(n) => Control::Ping(n),
            Message::Pong(n) => Control::Pong(n),
            Message::Hello(_) | Message::HelloAck(_) | Message::Handshake(_) | Message::ChunkData { .. } => {
                return Err(EngineError::violation(format!("{:?} on the established control stream", h.msg_type)));
            }
        }))
    }
}

/// One data stream after establishment. `sealer`/`opener` are `None` only when
/// the bench-only plaintext capability was negotiated.
pub struct DataStream {
    pub stream_id: u32,
    pub reader: FrameReader,
    pub writer: FrameWriter,
    pub sealer: Option<Sealer>,
    pub opener: Option<Opener>,
}

/// An authenticated, verified session (manual §9.1 ESTABLISHED).
pub struct SecureConnection {
    pub control_tx: ControlTx,
    pub control_rx: ControlRx,
    /// The negotiated number of data streams (≤ the transport's).
    pub data: Vec<DataStream>,
    pub peer: PeerAuth,
    /// `None` = data streams are unencrypted (bench-only).
    pub data_cipher: Option<CipherSuite>,
    pub kind: TransportKind,
    pub remote: SocketAddr,
    pub handshake_time: Duration,
    machine: ConnMachine,
}

impl SecureConnection {
    pub fn cipher_name(&self) -> String {
        match self.data_cipher {
            Some(CipherSuite::Aes256Gcm) => "AES-256-GCM".into(),
            Some(CipherSuite::ChaCha20Poly1305) => "ChaCha20-Poly1305".into(),
            None => "plaintext".into(),
        }
    }

    pub fn is_established(&self) -> bool {
        self.machine.is_established()
    }
}

fn transport_cap(kind: TransportKind) -> u64 {
    match kind {
        TransportKind::Tcp => caps::TRANSPORT_TCP,
        TransportKind::Quic => caps::TRANSPORT_QUIC,
    }
}

fn plaintext_cap(requested: bool) -> u64 {
    if cfg!(feature = "bench-insecure-plaintext") && requested { caps::BENCH_INSECURE_PLAINTEXT } else { 0 }
}

/// Writes one plaintext pre-auth frame and returns its exact wire bytes (for the prologue).
async fn send_plain(w: &mut FrameWriter, msg: &Message<'_>, seq: u64) -> Result<Vec<u8>> {
    let mut frame = vec![0u8; HEADER_LEN];
    msg.encode_body(&mut frame)?;
    let len = u32::try_from(frame.len() - HEADER_LEN).map_err(|_| EngineError::Internal("handshake frame too large".into()))?;
    let header = Header::new(msg.msg_type(), 0, 0, seq, len);
    frame[..HEADER_LEN].copy_from_slice(&header.to_bytes());
    w.write_frame(&header, &[&frame[HEADER_LEN..]]).await?;
    Ok(frame)
}

/// Reads one plaintext pre-auth frame: header and body, plus the frame's bytes.
async fn recv_plain(r: &mut FrameReader, machine: &mut ConnMachine, limit: Duration) -> Result<(MsgType, Vec<u8>)> {
    let read = async {
        let h = r.read_header().await?.ok_or(EngineError::PeerLost)?;
        if h.stream_id != 0 || h.payload_length > MAX_PREAUTH_FRAME {
            return Err(EngineError::violation("bad pre-authentication frame"));
        }
        if h.msg_type != MsgType::Close
            && let Err(e) = machine.check_incoming(h.msg_type)
        {
            let _ = machine.on_event(ConnEvent::Malformed(e.clone()));
            return Err(EngineError::violation(format!("unexpected {:?} during handshake", h.msg_type)));
        }
        let mut frame = h.to_bytes().to_vec();
        frame.extend_from_slice(r.read_body(&h).await?);
        Ok((h.msg_type, frame))
    };
    let (t, frame) = tokio::time::timeout(limit, read).await.map_err(|_| EngineError::Timeout)??;
    if t == MsgType::Close {
        // Pre-auth Close only carries a reason; it can't be trusted, but it explains
        // the hang-up (e.g. version mismatch) better than a bare EOF.
        let reason = match Message::decode(t, &frame[HEADER_LEN..]) {
            Ok(Message::Close(r)) => r,
            _ => CloseReason::ProtocolViolation,
        };
        return Err(EngineError::from_peer_close(reason));
    }
    Ok((t, frame))
}

fn suites_from_ids(ids: &[u8]) -> Vec<CipherSuite> {
    ids.iter().filter_map(|&id| CipherSuite::from_id(id)).collect()
}

fn suite_ids(suites: &[CipherSuite]) -> Vec<u8> {
    suites.iter().map(|s| s.id()).collect()
}

/// Initiator side (the file sender, manual §9.1). `want_plaintext` only has an
/// effect in builds with the `bench-insecure-plaintext` feature.
pub async fn establish_initiator(conn: Connection, opts: &CommonOptions, want_plaintext: bool) -> Result<SecureConnection> {
    let started = Instant::now();
    let Connection { kind, peer: remote, control, data } = conn;
    let FramedStream { reader: mut cr, writer: mut cw } = control;
    let mut machine = ConnMachine::new(Role::Initiator);
    let local_caps = transport_cap(kind) | plaintext_cap(want_plaintext);
    let prefs = CipherSuite::local_preferences();
    let streams = u8::try_from(data.len()).map_err(|_| EngineError::InvalidInput("too many data streams".into()))?;

    let hello = Hello::new(local_caps, streams, opts.device_name.clone()).with_ciphers(suite_ids(&prefs));
    let hello_frame = send_plain(&mut cw, &Message::Hello(hello), 0).await?;
    machine.on_event(ConnEvent::HelloSent)?;

    let (_, ack_frame) = recv_plain(&mut cr, &mut machine, opts.handshake_timeout).await?;
    let Message::HelloAck(ack) = Message::decode(MsgType::HelloAck, &ack_frame[HEADER_LEN..])? else {
        return Err(EngineError::violation("expected HelloAck"));
    };
    if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&ack.version) {
        return Err(EngineError::UnsupportedVersion);
    }
    if ack.streams == 0 || ack.streams > streams || ack.capabilities & !local_caps != 0 {
        return Err(EngineError::violation("HelloAck grants more than was offered"));
    }
    machine.on_event(ConnEvent::HelloAckReceived)?;

    let mut prologue = hello_frame;
    prologue.extend_from_slice(&ack_frame);
    let mut hs = Handshake::initiator_with_prologue(&opts.identity, &prologue)?;
    send_plain(&mut cw, &Message::Handshake(&hs.write_message(&[])?), 1).await?;
    let (_, m2) = recv_plain(&mut cr, &mut machine, opts.handshake_timeout).await?;
    hs.read_message(&m2[HEADER_LEN..])?;
    send_plain(&mut cw, &Message::Handshake(&hs.write_message(&[])?), 2).await?;

    let parts = Parts { kind, remote, cr, cw, data, machine, started };
    finish(parts, hs, opts, &prefs, &suites_from_ids(&ack.ciphers), ack.capabilities, usize::from(ack.streams), ack.device_name).await
}

/// Responder side (the file receiver). `max_streams` clamps the sender's request.
pub async fn establish_responder(conn: Connection, opts: &CommonOptions, max_streams: u8, allow_plaintext: bool) -> Result<SecureConnection> {
    let started = Instant::now();
    let Connection { kind, peer: remote, control, data } = conn;
    let FramedStream { reader: mut cr, writer: mut cw } = control;
    let mut machine = ConnMachine::new(Role::Responder);
    let local_caps = transport_cap(kind) | plaintext_cap(allow_plaintext);
    let prefs = CipherSuite::local_preferences();

    let (_, hello_frame) = recv_plain(&mut cr, &mut machine, opts.handshake_timeout).await?;
    let Message::Hello(hello) = Message::decode(MsgType::Hello, &hello_frame[HEADER_LEN..])? else {
        return Err(EngineError::violation("expected Hello"));
    };
    if usize::from(hello.streams) != data.len() {
        return Err(EngineError::violation("Hello stream count does not match the connection"));
    }
    let mut ack = match hello.accept(local_caps, max_streams, &opts.device_name) {
        Ok(ack) => ack,
        Err(ProtocolError::NoCommonVersion) => {
            // Manual §37: say why, then close; never guess at an unknown version.
            let _ = send_plain(&mut cw, &Message::Close(CloseReason::UnsupportedVersion), 0).await;
            return Err(EngineError::UnsupportedVersion);
        }
        Err(e) => return Err(e.into()),
    };
    ack.ciphers = suite_ids(&prefs);
    let ack_frame = send_plain(&mut cw, &Message::HelloAck(ack.clone()), 0).await?;
    machine.on_event(ConnEvent::HelloReceived)?;

    let mut prologue = hello_frame;
    prologue.extend_from_slice(&ack_frame);
    let mut hs = Handshake::responder_with_prologue(&opts.identity, &prologue)?;
    let (_, m1) = recv_plain(&mut cr, &mut machine, opts.handshake_timeout).await?;
    hs.read_message(&m1[HEADER_LEN..])?;
    send_plain(&mut cw, &Message::Handshake(&hs.write_message(&[])?), 1).await?;
    let (_, m3) = recv_plain(&mut cr, &mut machine, opts.handshake_timeout).await?;
    hs.read_message(&m3[HEADER_LEN..])?;

    let parts = Parts { kind, remote, cr, cw, data, machine, started };
    finish(parts, hs, opts, &prefs, &suites_from_ids(&hello.ciphers), ack.capabilities, usize::from(ack.streams), hello.device_name).await
}

struct Parts {
    kind: TransportKind,
    remote: SocketAddr,
    cr: FrameReader,
    cw: FrameWriter,
    data: Vec<FramedStream>,
    machine: ConnMachine,
    started: Instant,
}

#[allow(clippy::too_many_arguments)]
async fn finish(parts: Parts, hs: Handshake, opts: &CommonOptions, local: &[CipherSuite], remote: &[CipherSuite], agreed_caps: u64, streams: usize, peer_name: String) -> Result<SecureConnection> {
    let Parts { kind, remote: remote_addr, cr, cw, data, mut machine, started } = parts;
    let (mut secrets, outcome) = hs.into_parts()?;
    machine.on_event(ConnEvent::HandshakeComplete)?;

    let suite = negotiate(local, remote)?;
    let plaintext = cfg!(feature = "bench-insecure-plaintext") && agreed_caps & caps::BENCH_INSECURE_PLAINTEXT != 0;
    let (sealer, opener) = secrets.session(suite, 0)?.split();
    let mut control_tx = ControlTx { writer: cw, sealer, seq: 0, scratch: Vec::with_capacity(256) };
    let control_rx = ControlRx { reader: cr, opener };

    let mut streams_out = Vec::with_capacity(streams);
    for (i, s) in data.into_iter().take(streams).enumerate() {
        let stream_id = u32::try_from(i + 1).map_err(|_| EngineError::Internal("stream id overflow".into()))?;
        let (sealer, opener) = secrets.session(suite, stream_id)?.split();
        let (sealer, opener) = if plaintext { (None, None) } else { (Some(sealer), Some(opener)) };
        streams_out.push(DataStream { stream_id, reader: s.reader, writer: s.writer, sealer, opener });
    }
    drop(secrets);

    let peer = PeerAuth { fingerprint: outcome.remote_fingerprint, sas: outcome.sas, device_name: peer_name };
    let verifier = opts.verifier.clone();
    let shown = peer.clone();
    let accepted = tokio::task::spawn_blocking(move || verifier.verify(&shown)).await?;
    if !accepted {
        let _ = machine.on_event(ConnEvent::PeerRejected);
        control_tx.close(CloseReason::AuthenticationFailed).await;
        return Err(EngineError::AuthenticationFailed);
    }
    machine.on_event(ConnEvent::PeerVerified)?;
    tracing::info!(peer = %peer.fingerprint, cipher = ?suite, plaintext, streams, "session established");

    Ok(SecureConnection { control_tx, control_rx, data: streams_out, peer, data_cipher: (!plaintext).then_some(suite), kind, remote: remote_addr, handshake_time: started.elapsed(), machine })
}
