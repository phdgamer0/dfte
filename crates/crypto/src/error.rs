use thiserror::Error;

/// Errors produced by the crypto layer (manual §12, §36).
///
/// `Replay` and `Tampered` are deliberately distinct variants: manual §34 requires the
/// receiver to tell an already-seen sequence number apart from a forged/corrupted frame.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("noise handshake error: {0}")]
    Noise(#[from] snow::Error),
    #[error("system random number generator failed")]
    Rng,
    #[error("invalid public key bytes")]
    InvalidKey,
    #[error("handshake message is malformed")]
    MalformedHandshake,
    #[error("peer's Noise static key does not match its claimed Ed25519 identity")]
    IdentityMismatch,
    #[error("handshake has not finished")]
    HandshakeNotFinished,
    #[error("peer fingerprint does not match the expected fingerprint")]
    FingerprintMismatch,
    #[error("no cipher suite supported by both peers")]
    NoCommonCipherSuite,
    #[error("session for stream {0} was already derived")]
    StreamAlreadyDerived(u32),
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("replayed frame: sequence {seq} is not above last accepted {last}")]
    Replay { seq: u64, last: u64 },
    #[error("refusing to reuse send sequence {seq}: last sent was {last}")]
    SequenceReuse { seq: u64, last: u64 },
    #[error("frame failed authentication")]
    Tampered,
}
