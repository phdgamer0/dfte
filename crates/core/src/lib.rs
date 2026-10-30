// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Transfer engine (manual §9, §10, §12, §14, §17–§20, §22).
//!
//! Two layers of public surface:
//!
//! * [`TransferManager`] (manual §22): the app-facing, job-oriented API. One
//!   long-lived object per process owning the tokio runtime, the job map,
//!   listeners and discovery; platform UIs observe it through a
//!   [`TransferObserver`] and only ever see immutable snapshots.
//! * [`send_files`] and [`receive`]: one transfer each, generic over any
//!   [`transport::Transport`]/[`transport::Listener`], plus the options,
//!   progress/cancel hooks and the [`TransferReport`]. CLI tools and the bench
//!   use these directly. [`secure`] exposes the session layer underneath for
//!   other front ends and adversarial tests.

pub mod error;
mod hooks;
pub mod manager;
pub mod notice;
pub mod options;
mod receiver;
pub mod report;
pub mod secure;
mod sender;
mod source;
mod tasks;

pub use crypto::DeviceIdentity;
pub use error::{EngineError, Result};
pub use options::{CancelHandle, CommonOptions, ExpectFingerprint, ManifestHook, PeerAuth, PeerVerifier, Progress, ProgressFn, ReceiveOptions, SendOptions, TrustAny};
pub use protocol::{FileEntry, Manifest};
pub use receiver::receive;
pub use report::{Direction, PhaseTimings, TransferReport};
pub use sender::send_files;

// The app-facing TransferManager surface (manual §22).
pub use error::ErrorCode;
pub use manager::{IncomingOffer, ManagerConfig, OfferedFile, SendTarget, Transfer, TransferId, TransferManager, TransferObserver, TransferState, VerifyRequest};
