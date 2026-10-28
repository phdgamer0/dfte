//! Handshake, AEAD session and device identity (manual §12).
//!
//! Everything here is sans-I/O: callers feed bytes in and get bytes out, so the
//! `transport` crate owns sockets and this crate stays deterministic and fuzzable.

mod error;
pub mod handshake;
pub mod identity;
pub mod session;

pub use error::CryptoError;
pub use handshake::{Handshake, HandshakeOutcome, NOISE_PARAMS, SessionSecrets};
pub use identity::{DeviceIdentity, fingerprint_of};
pub use session::{CipherSuite, Opener, Sealer, Session, TAG_LEN, negotiate};

pub type Result<T> = core::result::Result<T, CryptoError>;
