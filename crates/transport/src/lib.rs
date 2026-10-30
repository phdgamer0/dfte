// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Transport trait plus TCP and QUIC backends (manual §15).
//!
//! A [`Connection`] is one control stream plus N data streams (manual §11:
//! 2–4 parallel streams). Both backends hand back the same shape, so `core`
//! and the shared conformance tests never care which one is underneath.
//!
//! # Peer identity
//! [`Connection::peer_key`] is the peer's Ed25519 identity key *as authenticated
//! by the transport*: `Some` on QUIC, where TLS 1.3 with self-signed identity
//! certificates proves possession of the key (manual §12.1), and `None` on TCP,
//! where the Noise_XX handshake runs above the transport and binds identity
//! itself. The transport never decides whether the key is the *right* peer —
//! `core` compares it against the SAS-confirmed / QR-scanned / pinned fingerprint
//! (see [`Connection::peer_fingerprint`]).

use std::future::Future;
use std::net::SocketAddr;

pub mod dual;
pub mod framed;
pub mod quic;
pub mod tcp;

pub use dual::{DualListener, listen_pair};
pub use framed::{FrameReader, FrameWriter, FramedStream};
pub use quic::{CongestionControl, MAX_SAFE_STREAM_WINDOW, QuicConfig, QuicListener, QuicTransport};
pub use tcp::{TcpConfig, TcpListener, TcpTransport};

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("peer closed mid-frame")]
    UnexpectedEof,
    #[error("frame body of {actual} bytes does not match header length {header}")]
    LengthMismatch { header: u32, actual: usize },
    #[error("{0} body parts exceeds the per-frame maximum")]
    TooManyParts(usize),
    #[error("buffer too small for {needed}-byte body")]
    BufferTooSmall { needed: usize },
    #[error("bad stream preamble")]
    BadPreamble,
    #[error("invalid stream count {0} (1..=16)")]
    InvalidStreamCount(usize),
    #[error("timed out")]
    Timeout,
    #[error("listener closed")]
    Closed,
    #[error("invalid transport config: {0}")]
    InvalidConfig(&'static str),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate generation: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("quic connect: {0}")]
    QuicConnect(#[from] quinn::ConnectError),
    #[error("quic connection: {0}")]
    QuicConnection(#[from] quinn::ConnectionError),
    #[error("peer presented no usable Ed25519 identity")]
    PeerIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    Quic,
}

pub const MAX_DATA_STREAMS: usize = 16;

pub struct Connection {
    pub kind: TransportKind,
    pub peer: SocketAddr,
    /// Peer's Ed25519 public key, authenticated by the transport (QUIC/TLS);
    /// `None` on TCP, whose identity check is the Noise handshake above it.
    pub peer_key: Option<[u8; 32]>,
    /// Handshake, manifest and acks.
    pub control: FramedStream,
    /// Bulk chunk streams.
    pub data: Vec<FramedStream>,
}

impl Connection {
    /// Fingerprint of [`peer_key`](Self::peer_key), in the format users compare (manual §6).
    pub fn peer_fingerprint(&self) -> Option<String> {
        self.peer_key.as_ref().map(crypto::fingerprint_of)
    }
}

pub trait Transport: Send + Sync {
    type Listener: Listener;

    fn kind(&self) -> TransportKind;
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Self::Listener>> + Send;
    fn connect(&self, addr: SocketAddr, data_streams: usize) -> impl Future<Output = Result<Connection>> + Send;

    /// Waits until data still owed to peers on connections the caller already
    /// dropped has been delivered. Call it before the process exits. TCP needs
    /// nothing (the kernel keeps delivering after close). QUIC retransmits in
    /// userspace, so exiting first loses an unacknowledged final message under
    /// packet loss (found by the netem harness). `Err(Timeout)` means something
    /// was still undelivered after the configured linger.
    fn drain(&self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}

pub trait Listener: Send {
    fn local_addr(&self) -> Result<SocketAddr>;
    fn accept(&mut self) -> impl Future<Output = Result<Connection>> + Send;

    /// Same contract as [`Transport::drain`], for connections this listener accepted.
    fn drain(&self) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}
