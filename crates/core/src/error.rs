//! The single error type that crosses the engine boundary (manual §36).
//!
//! Lower crates keep their own error types; they are mapped here into variants a
//! platform UI can turn into specific copy without matching on strings.

use std::io;
use std::path::PathBuf;

use crypto::CryptoError;
use discovery::{DiscoveryError, Permission};
use protocol::ProtocolError;
use protocol::message::CloseReason;
use storage::StorageError;
use transport::TransportError;

pub type Result<T, E = EngineError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// The link or peer process went away mid-handshake/transfer. The receiver
    /// keeps its resume state (manual §19).
    #[error("lost connection to peer")]
    PeerLost,
    /// The peer declined the pairing (SAS/fingerprint rejected on its side).
    #[error("peer declined the connection")]
    ConnectionRejected,
    /// The local SAS/fingerprint check failed. Never retried silently (manual §36).
    #[error("security check failed: peer could not be verified")]
    AuthenticationFailed,
    #[error("not enough free space: need {needed} bytes, {available} available")]
    DiskFull { needed: u64, available: u64 },
    /// The receiver reported it lacks space for the offered files.
    #[error("receiver does not have enough free space")]
    PeerDiskFull,
    #[error("source file changed while sending: {path}")]
    SourceFileChanged { path: PathBuf },
    #[error("source file not found: {path}")]
    SourceFileMissing { path: PathBuf },
    /// AEAD failure, replayed frame, BLAKE3 mismatch, or a chunk that kept failing
    /// its integrity check (manual §20/§34).
    #[error("transfer failed an integrity check")]
    CorruptedData,
    #[error("peer's protocol version is not compatible")]
    UnsupportedVersion,
    #[error("transfer cancelled")]
    Cancelled,
    /// A peer-supplied path was rejected (traversal, symlink escape, …, manual §35).
    #[error("rejected unsafe path from peer: {0}")]
    UnsafePath(String),
    /// Malformed or out-of-order traffic from the peer (manual §33/§35).
    #[error("peer violated the protocol: {0}")]
    ProtocolViolation(String),
    #[error("timed out waiting for peer")]
    Timeout,
    /// Bad local input (unreadable source path, non-UTF-8 name, bad option).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("i/o error: {0}")]
    Io(io::Error),
    #[error("internal error: {0}")]
    Internal(String),
    /// This side declined an incoming offer, or nobody answered it in time
    /// ([`TransferManager::accept_incoming`](crate::TransferManager::accept_incoming)).
    /// The sender sees [`ConnectionRejected`](Self::ConnectionRejected).
    #[error("incoming transfer declined")]
    Declined,
    /// Wi-Fi is off or the platform radio API hard-failed (manual §36).
    #[error("radio unavailable: {0}")]
    RadioUnavailable(String),
    /// An OS permission is missing (manual §26); the UI deep-links to settings.
    #[error("permission denied: {0:?}")]
    PermissionDenied(Permission),
    /// Discovery failed in a way with no better mapping (backend detail for logs).
    #[error("discovery: {0}")]
    Discovery(String),
    /// No transfer with this id is known to the manager.
    #[error("unknown transfer: {0}")]
    UnknownTransfer(String),
    /// The manager is shutting down and takes no new work.
    #[error("transfer manager is shutting down")]
    ShuttingDown,
}

/// Field-less mirror of [`EngineError`]'s variants: `Copy`, so it can sit in
/// snapshots ([`TransferState::Failed`](crate::TransferState::Failed)) and cross
/// the FFI boundary (manual §36: platforms never match on strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    PeerLost,
    ConnectionRejected,
    AuthenticationFailed,
    DiskFull,
    PeerDiskFull,
    SourceFileChanged,
    SourceFileMissing,
    CorruptedData,
    UnsupportedVersion,
    Cancelled,
    UnsafePath,
    ProtocolViolation,
    Timeout,
    InvalidInput,
    Io,
    Internal,
    Declined,
    RadioUnavailable,
    PermissionDenied,
    Discovery,
    UnknownTransfer,
    ShuttingDown,
}

impl EngineError {
    pub fn code(&self) -> ErrorCode {
        match self {
            EngineError::PeerLost => ErrorCode::PeerLost,
            EngineError::ConnectionRejected => ErrorCode::ConnectionRejected,
            EngineError::AuthenticationFailed => ErrorCode::AuthenticationFailed,
            EngineError::DiskFull { .. } => ErrorCode::DiskFull,
            EngineError::PeerDiskFull => ErrorCode::PeerDiskFull,
            EngineError::SourceFileChanged { .. } => ErrorCode::SourceFileChanged,
            EngineError::SourceFileMissing { .. } => ErrorCode::SourceFileMissing,
            EngineError::CorruptedData => ErrorCode::CorruptedData,
            EngineError::UnsupportedVersion => ErrorCode::UnsupportedVersion,
            EngineError::Cancelled => ErrorCode::Cancelled,
            EngineError::UnsafePath(_) => ErrorCode::UnsafePath,
            EngineError::ProtocolViolation(_) => ErrorCode::ProtocolViolation,
            EngineError::Timeout => ErrorCode::Timeout,
            EngineError::InvalidInput(_) => ErrorCode::InvalidInput,
            EngineError::Io(_) => ErrorCode::Io,
            EngineError::Internal(_) => ErrorCode::Internal,
            EngineError::Declined => ErrorCode::Declined,
            EngineError::RadioUnavailable(_) => ErrorCode::RadioUnavailable,
            EngineError::PermissionDenied(_) => ErrorCode::PermissionDenied,
            EngineError::Discovery(_) => ErrorCode::Discovery,
            EngineError::UnknownTransfer(_) => ErrorCode::UnknownTransfer,
            EngineError::ShuttingDown => ErrorCode::ShuttingDown,
        }
    }

    /// Close reason to send the peer before tearing down because of `self`.
    pub(crate) fn close_reason(&self) -> CloseReason {
        match self {
            EngineError::Cancelled => CloseReason::Cancelled,
            EngineError::AuthenticationFailed => CloseReason::AuthenticationFailed,
            // There is no dedicated wire reason; AuthenticationFailed makes the
            // sender report "peer declined the connection" (manual §36), which is
            // exactly what happened.
            EngineError::Declined => CloseReason::AuthenticationFailed,
            EngineError::CorruptedData => CloseReason::IntegrityFailure,
            EngineError::UnsupportedVersion => CloseReason::UnsupportedVersion,
            EngineError::DiskFull { .. } => CloseReason::InsufficientSpace,
            EngineError::SourceFileChanged { .. } | EngineError::SourceFileMissing { .. } | EngineError::Io(_) | EngineError::Internal(_) => CloseReason::Cancelled,
            _ => CloseReason::ProtocolViolation,
        }
    }

    /// Error to report locally when the peer closes with `reason` before we were done.
    pub(crate) fn from_peer_close(reason: CloseReason) -> Self {
        match reason {
            CloseReason::Done => EngineError::ProtocolViolation("peer closed before the transfer finished".into()),
            CloseReason::Cancelled => EngineError::Cancelled,
            CloseReason::UnsupportedVersion => EngineError::UnsupportedVersion,
            CloseReason::ProtocolViolation => EngineError::ProtocolViolation("peer reported a protocol violation".into()),
            CloseReason::AuthenticationFailed => EngineError::ConnectionRejected,
            CloseReason::IntegrityFailure => EngineError::CorruptedData,
            CloseReason::InsufficientSpace => EngineError::PeerDiskFull,
        }
    }

    pub(crate) fn violation(what: impl Into<String>) -> Self {
        EngineError::ProtocolViolation(what.into())
    }
}

fn is_disconnect(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected)
}

impl From<io::Error> for EngineError {
    fn from(e: io::Error) -> Self {
        if is_disconnect(&e) { EngineError::PeerLost } else { EngineError::Io(e) }
    }
}

impl From<ProtocolError> for EngineError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::UnsupportedVersion(_) | ProtocolError::NoCommonVersion => EngineError::UnsupportedVersion,
            ProtocolError::InvalidPath | ProtocolError::PathTooLong => EngineError::UnsafePath(e.to_string()),
            ProtocolError::TooManyRetries => EngineError::CorruptedData,
            ProtocolError::Timeout => EngineError::Timeout,
            other => EngineError::ProtocolViolation(other.to_string()),
        }
    }
}

impl From<TransportError> for EngineError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Io(e) => e.into(),
            TransportError::UnexpectedEof => EngineError::PeerLost,
            TransportError::Protocol(p) => p.into(),
            TransportError::Timeout => EngineError::Timeout,
            other => EngineError::ProtocolViolation(other.to_string()),
        }
    }
}

impl From<CryptoError> for EngineError {
    fn from(e: CryptoError) -> Self {
        match e {
            // Manual §34: replay and tampering both tear the connection down.
            CryptoError::Replay { .. } | CryptoError::Tampered => EngineError::CorruptedData,
            CryptoError::IdentityMismatch | CryptoError::FingerprintMismatch | CryptoError::Noise(_) | CryptoError::MalformedHandshake => EngineError::AuthenticationFailed,
            CryptoError::NoCommonCipherSuite => EngineError::UnsupportedVersion,
            other => EngineError::Internal(other.to_string()),
        }
    }
}

impl From<StorageError> for EngineError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Io(e) => EngineError::Io(e),
            StorageError::DiskFull { needed, available } => EngineError::DiskFull { needed, available },
            StorageError::SourceFileChanged { path } => EngineError::SourceFileChanged { path },
            StorageError::SourceFileMissing { path } => EngineError::SourceFileMissing { path },
            StorageError::HashMismatch { .. } | StorageError::PieceCountMismatch { .. } => EngineError::CorruptedData,
            StorageError::InvalidPath { path, reason } => EngineError::UnsafePath(format!("{path:?}: {reason}")),
            StorageError::SymlinkEscape { path } => EngineError::UnsafePath(format!("symlink at {}", path.display())),
            other => EngineError::Internal(other.to_string()),
        }
    }
}

impl From<DiscoveryError> for EngineError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::RadioUnavailable(m) => EngineError::RadioUnavailable(m),
            DiscoveryError::PermissionDenied(p) => EngineError::PermissionDenied(p),
            DiscoveryError::PeerLost => EngineError::PeerLost,
            DiscoveryError::ConnectionRejected => EngineError::ConnectionRejected,
            DiscoveryError::AuthenticationFailed => EngineError::AuthenticationFailed,
            DiscoveryError::Timeout => EngineError::Timeout,
            DiscoveryError::Io(e) => e.into(),
            other => EngineError::Discovery(other.to_string()),
        }
    }
}

impl From<tokio::task::JoinError> for EngineError {
    fn from(e: tokio::task::JoinError) -> Self {
        if e.is_cancelled() { EngineError::Cancelled } else { EngineError::Internal(format!("task panicked: {e}")) }
    }
}
