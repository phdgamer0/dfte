use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ProtocolError {
    //Header / decode
    #[error("Buffer shorter than needed")]
    Truncated, //(buffer shorter than needed)
    #[error("Bad magic number")]
    BadMagic,
    #[error("Unsupported version")]
    UnsupportedVersion,
    #[error("Unknown message type")]
    UnknownMsgType,
    #[error("Reserved bits set")]
    ReservedBitsSet, //(flags or reserved field non-zero)
    #[error("Payload too large")]
    PayloadTooLarge, //(carries the length and the cap)
    //Manifest
    #[error("Too many entries")]
    TooManyEntries,
    #[error("Manifest too large")]
    ManifestTooLarge, //(serialized size cap, from the last message)
    #[error("Path too long")]
    PathTooLong,
    #[error("Invalid path")]
    InvalidPath, //(traversal, absolute, NUL, empty)
    #[error("Duplicate path")]
    DuplicatePath,
    #[error("Chunk count mismatch")]
    ChunkCountMismatch,
    #[error("File too large")]
    FileTooLarge, //(chunk count doesn't fit the u32 field)
    #[error("Manifest decode error")]
    ManifestDecode, //(wraps the MessagePack error)
    //State machine
    #[error("Unexpected message")]
    UnexpectedMessage, //(right message, wrong time, e.g. chunk data before manifest accept)
    #[error("Too many retries")]
    TooManyRetries, //(the 8-retry limit from §9.3)
    //Math
    #[error("Arithmetic overflow")]
    ArithmeticOverflow, //(offset calculations)
}
