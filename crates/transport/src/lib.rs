//! Transport trait plus TCP and QUIC backends (manual §15).
//!
//! A [`Connection`] is one control stream plus N data streams (manual §11:
//! 2–4 parallel streams). Both backends hand back the same shape, so `core`
//! and the shared conformance tests never care which one is underneath.

use std::future::Future;
use std::net::SocketAddr;

pub mod framed;
pub mod tcp;

pub use framed::{FrameReader, FrameWriter, FramedStream};
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
    /// Handshake, manifest and acks.
    pub control: FramedStream,
    /// Bulk chunk streams.
    pub data: Vec<FramedStream>,
}

pub trait Transport: Send + Sync {
    type Listener: Listener;

    fn kind(&self) -> TransportKind;
    fn listen(&self, addr: SocketAddr) -> impl Future<Output = Result<Self::Listener>> + Send;
    fn connect(&self, addr: SocketAddr, data_streams: usize) -> impl Future<Output = Result<Connection>> + Send;
}

pub trait Listener: Send {
    fn local_addr(&self) -> Result<SocketAddr>;
    fn accept(&mut self) -> impl Future<Output = Result<Connection>> + Send;
}
