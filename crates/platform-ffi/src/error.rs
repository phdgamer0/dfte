// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! The error crossing the FFI boundary (manual §36): typed variants so
//! platform code never matches on strings.

use dfte_core as engine;

use crate::types::Permission;

/// Field-less error kind, for snapshots (`TransferState.Failed`) and `on_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
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

impl From<engine::ErrorCode> for ErrorCode {
    fn from(c: engine::ErrorCode) -> Self {
        use engine::ErrorCode as C;
        match c {
            C::PeerLost => Self::PeerLost,
            C::ConnectionRejected => Self::ConnectionRejected,
            C::AuthenticationFailed => Self::AuthenticationFailed,
            C::DiskFull => Self::DiskFull,
            C::PeerDiskFull => Self::PeerDiskFull,
            C::SourceFileChanged => Self::SourceFileChanged,
            C::SourceFileMissing => Self::SourceFileMissing,
            C::CorruptedData => Self::CorruptedData,
            C::UnsupportedVersion => Self::UnsupportedVersion,
            C::Cancelled => Self::Cancelled,
            C::UnsafePath => Self::UnsafePath,
            C::ProtocolViolation => Self::ProtocolViolation,
            C::Timeout => Self::Timeout,
            C::InvalidInput => Self::InvalidInput,
            C::Io => Self::Io,
            C::Internal => Self::Internal,
            C::Declined => Self::Declined,
            C::RadioUnavailable => Self::RadioUnavailable,
            C::PermissionDenied => Self::PermissionDenied,
            C::Discovery => Self::Discovery,
            C::UnknownTransfer => Self::UnknownTransfer,
            C::ShuttingDown => Self::ShuttingDown,
            // `ErrorCode` is non_exhaustive; a code added in core before this
            // mirror is updated still reaches the UI as a generic failure.
            _ => Self::Internal,
        }
    }
}

/// Error passed to `TransferObserver.onError`: the kind plus log-level detail
/// (never shown verbatim to users, manual §36).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: String,
}

impl From<&engine::EngineError> for ErrorInfo {
    fn from(e: &engine::EngineError) -> Self {
        Self { code: e.code().into(), message: e.to_string() }
    }
}

/// Returned by every fallible FFI call (Kotlin `EngineException`, Swift `EngineError`).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EngineError {
    #[error("lost connection to peer")]
    PeerLost,
    #[error("peer declined the connection")]
    ConnectionRejected,
    #[error("security check failed: peer could not be verified")]
    AuthenticationFailed,
    #[error("not enough free space: need {needed} bytes, {available} available")]
    DiskFull { needed: u64, available: u64 },
    #[error("receiver does not have enough free space")]
    PeerDiskFull,
    #[error("source file changed while sending: {path}")]
    SourceFileChanged { path: String },
    #[error("source file not found: {path}")]
    SourceFileMissing { path: String },
    #[error("transfer failed an integrity check")]
    CorruptedData,
    #[error("peer's protocol version is not compatible")]
    UnsupportedVersion,
    #[error("transfer cancelled")]
    Cancelled,
    #[error("rejected unsafe path from peer: {detail}")]
    UnsafePath { detail: String },
    #[error("peer violated the protocol: {detail}")]
    ProtocolViolation { detail: String },
    #[error("timed out")]
    Timeout,
    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },
    #[error("i/o error: {detail}")]
    Io { detail: String },
    #[error("internal error: {detail}")]
    Internal { detail: String },
    #[error("incoming transfer declined")]
    Declined,
    #[error("radio unavailable: {detail}")]
    RadioUnavailable { detail: String },
    #[error("permission denied: {permission:?}")]
    PermissionDenied { permission: Permission },
    #[error("discovery: {detail}")]
    Discovery { detail: String },
    #[error("unknown transfer: {id}")]
    UnknownTransfer { id: String },
    #[error("transfer manager is shutting down")]
    ShuttingDown,
}

impl From<engine::EngineError> for EngineError {
    fn from(e: engine::EngineError) -> Self {
        use engine::EngineError as E;
        match e {
            E::PeerLost => Self::PeerLost,
            E::ConnectionRejected => Self::ConnectionRejected,
            E::AuthenticationFailed => Self::AuthenticationFailed,
            E::DiskFull { needed, available } => Self::DiskFull { needed, available },
            E::PeerDiskFull => Self::PeerDiskFull,
            E::SourceFileChanged { path } => Self::SourceFileChanged { path: path.display().to_string() },
            E::SourceFileMissing { path } => Self::SourceFileMissing { path: path.display().to_string() },
            E::CorruptedData => Self::CorruptedData,
            E::UnsupportedVersion => Self::UnsupportedVersion,
            E::Cancelled => Self::Cancelled,
            E::UnsafePath(detail) => Self::UnsafePath { detail },
            E::ProtocolViolation(detail) => Self::ProtocolViolation { detail },
            E::Timeout => Self::Timeout,
            E::InvalidInput(detail) => Self::InvalidInput { detail },
            E::Io(e) => Self::Io { detail: e.to_string() },
            E::Internal(detail) => Self::Internal { detail },
            E::Declined => Self::Declined,
            E::RadioUnavailable(detail) => Self::RadioUnavailable { detail },
            E::PermissionDenied(p) => Self::PermissionDenied { permission: p.into() },
            E::Discovery(detail) => Self::Discovery { detail },
            E::UnknownTransfer(id) => Self::UnknownTransfer { id },
            E::ShuttingDown => Self::ShuttingDown,
            // Non-exhaustive in core: keep the detail rather than lose it.
            other => Self::Internal { detail: other.to_string() },
        }
    }
}
