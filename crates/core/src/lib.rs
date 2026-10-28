//! Transfer engine (manual §9, §10, §12, §14, §17–§20, §22).
//!
//! Minimal public surface for now: [`send_files`] and [`receive`], generic over
//! any [`transport::Transport`]/[`transport::Listener`], plus the options,
//! progress/cancel hooks and the [`TransferReport`]. [`secure`] exposes the
//! session layer underneath for other front ends and adversarial tests.

pub mod error;
pub mod options;
mod receiver;
pub mod report;
pub mod secure;
mod sender;
mod source;
mod tasks;

pub use crypto::DeviceIdentity;
pub use error::{EngineError, Result};
pub use options::{CancelHandle, CommonOptions, ExpectFingerprint, PeerAuth, PeerVerifier, Progress, ProgressFn, ReceiveOptions, SendOptions, TrustAny};
pub use receiver::receive;
pub use report::{Direction, PhaseTimings, TransferReport};
pub use sender::send_files;
