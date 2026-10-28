use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    // Header / decode
    #[error("buffer shorter than needed")]
    Truncated,
    #[error("bad magic number")]
    BadMagic,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("no protocol version in common with peer")]
    NoCommonVersion,
    #[error("unknown message type")]
    UnknownMsgType,
    #[error("reserved field non-zero")]
    ReservedBitsSet,
    #[error("payload of {len} bytes exceeds cap of {max}")]
    PayloadTooLarge { len: u32, max: u32 },
    #[error("trailing bytes after message body")]
    TrailingBytes,
    #[error("control message decode error")]
    MessageDecode,
    #[error("control message encode error")]
    MessageEncode,

    // Manifest
    #[error("too many manifest entries")]
    TooManyEntries,
    #[error("manifest too large")]
    ManifestTooLarge,
    #[error("path too long")]
    PathTooLong,
    #[error("invalid path")]
    InvalidPath,
    #[error("duplicate path")]
    DuplicatePath,
    #[error("chunk count mismatch")]
    ChunkCountMismatch,
    #[error("file too large")]
    FileTooLarge,
    #[error("manifest decode error")]
    ManifestDecode,

    // State machine
    #[error("unexpected message in current state")]
    UnexpectedMessage,
    #[error("too many retries")]
    TooManyRetries,
    #[error("timed out")]
    Timeout,
    #[error("index out of range")]
    OutOfRange,

    // Math
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}
