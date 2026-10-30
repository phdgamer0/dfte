// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! User-facing error copy and exit codes (manual §36).
//!
//! Every [`EngineError`] variant maps to specific copy (never a raw debug string)
//! and to an exit code per *class*, so scripts can tell "the other device said no"
//! from "the disk is full" without parsing text.

use std::path::Path;

use dfte_core::EngineError;
use discovery::DiscoveryError;

/// Process exit codes. Documented in `dfte --help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Ok = 0,
    /// Unexpected local failure (I/O, internal).
    Failure = 1,
    /// Bad command line (clap's own code).
    Usage = 2,
    /// Connection lost or timed out.
    Connection = 3,
    /// Security check failed (SAS/fingerprint) — possible MITM.
    Authentication = 4,
    /// The other device declined.
    Rejected = 5,
    /// Not enough space (here or on the receiver).
    DiskFull = 6,
    /// A source file is missing/changed, or local input is invalid.
    Source = 7,
    /// Integrity check failed.
    Integrity = 8,
    /// Incompatible app versions.
    Version = 9,
    /// The peer misbehaved (protocol violation, unsafe path).
    Protocol = 10,
    /// Local configuration/identity problem (e.g. key file permissions).
    Config = 11,
    /// No matching device found nearby.
    NotFound = 12,
    /// Interrupted (Ctrl-C) or cancelled by the other device. Resume state is kept.
    Interrupted = 130,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as u8 as i32
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("discovery: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    /// Identity/trust store/configuration problem; the message is user copy.
    #[error("{0}")]
    Config(String),
    /// Bad arguments not caught by clap; the message is user copy.
    #[error("{0}")]
    Usage(String),
    /// No device matched; the message is user copy.
    #[error("{0}")]
    NotFound(String),
    /// Local Ctrl-C during a transfer.
    #[error("interrupted")]
    Interrupted,
    /// Local Ctrl-C while idle (nothing to resume).
    #[error("stopped")]
    Stopped,
}

impl CliError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        CliError::Io { context: context.into(), source }
    }

    pub fn exit_code(&self) -> ExitCode {
        match self {
            CliError::Engine(e) => engine_exit_code(e),
            CliError::Discovery(DiscoveryError::InvalidConfig(_)) => ExitCode::Usage,
            CliError::Discovery(_) | CliError::Io { .. } => ExitCode::Failure,
            CliError::Config(_) => ExitCode::Config,
            CliError::Usage(_) => ExitCode::Usage,
            CliError::NotFound(_) => ExitCode::NotFound,
            CliError::Interrupted | CliError::Stopped => ExitCode::Interrupted,
        }
    }

    /// The text shown to the user. `peer` names the other device when known.
    pub fn user_message(&self, peer: Option<&str>) -> String {
        match self {
            CliError::Engine(e) => engine_message(e, peer),
            CliError::Discovery(e) => format!("Could not look for nearby devices: {e}."),
            CliError::Io { context, source } => format!("{context}: {source}."),
            CliError::Config(m) | CliError::Usage(m) | CliError::NotFound(m) => m.clone(),
            CliError::Interrupted => RESUME_HINT.to_owned(),
            CliError::Stopped => "Stopped.".to_owned(),
        }
    }
}

pub const RESUME_HINT: &str = "Transfer interrupted; run the same command again to resume.";

pub fn engine_exit_code(e: &EngineError) -> ExitCode {
    match e {
        EngineError::PeerLost | EngineError::Timeout => ExitCode::Connection,
        EngineError::AuthenticationFailed => ExitCode::Authentication,
        EngineError::ConnectionRejected => ExitCode::Rejected,
        EngineError::DiskFull { .. } | EngineError::PeerDiskFull => ExitCode::DiskFull,
        EngineError::SourceFileChanged { .. } | EngineError::SourceFileMissing { .. } | EngineError::InvalidInput(_) => ExitCode::Source,
        EngineError::CorruptedData => ExitCode::Integrity,
        EngineError::UnsupportedVersion => ExitCode::Version,
        EngineError::UnsafePath(_) | EngineError::ProtocolViolation(_) => ExitCode::Protocol,
        EngineError::Cancelled => ExitCode::Interrupted,
        EngineError::Io(_) | EngineError::Internal(_) => ExitCode::Failure,
        // `EngineError` is non-exhaustive: a future variant is an unclassified failure.
        _ => ExitCode::Failure,
    }
}

fn file_name(p: &Path) -> String {
    p.file_name().map_or_else(|| p.display().to_string(), |n| n.to_string_lossy().into_owned())
}

/// Manual §36 copy, adapted to a terminal.
pub fn engine_message(e: &EngineError, peer: Option<&str>) -> String {
    let who = peer.unwrap_or("the other device");
    match e {
        EngineError::PeerLost => format!("Lost connection to {who}. Move closer and try again; run the same command again to resume."),
        EngineError::Timeout => format!("{} stopped responding. Check that it is still running (and uses the same --transport), then try again.", capitalize(who)),
        EngineError::ConnectionRejected => format!("{} declined the connection.", capitalize(who)),
        EngineError::AuthenticationFailed => "Security check failed — this may not be the device you expect. Connection blocked.".to_owned(),
        EngineError::DiskFull { needed, available } => format!("Not enough free space to receive this transfer (needs {}, {} available).", crate::progress::human_bytes(*needed), crate::progress::human_bytes(*available)),
        EngineError::PeerDiskFull => format!("{} does not have enough free space for this transfer.", capitalize(who)),
        EngineError::SourceFileChanged { path } => format!("{} changed while sending and was not sent. Try again once it is no longer being modified.", file_name(path)),
        EngineError::SourceFileMissing { path } => format!("{} could not be found.", path.display()),
        EngineError::CorruptedData => "Transfer failed an integrity check and was stopped.".to_owned(),
        EngineError::UnsupportedVersion => format!("{}'s app version isn't compatible. Please update both apps.", capitalize(who)),
        EngineError::Cancelled => "The transfer was cancelled. Partial data was kept; run the same command again to resume.".to_owned(),
        EngineError::UnsafePath(_) => format!("{} offered a file with an unsafe name or location; the transfer was blocked.", capitalize(who)),
        EngineError::ProtocolViolation(_) => format!("{} sent something unexpected; the connection was closed.", capitalize(who)),
        EngineError::InvalidInput(m) => format!("Cannot send: {m}."),
        EngineError::Io(err) => format!("A file error stopped the transfer: {err}."),
        EngineError::Internal(m) => format!("Internal error: {m}. Please report this."),
        other => format!("The transfer failed: {other}."),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_copy_is_exact_and_never_retried() {
        let e = CliError::Engine(EngineError::AuthenticationFailed);
        assert_eq!(e.user_message(Some("laptop")), "Security check failed — this may not be the device you expect. Connection blocked.");
        assert_eq!(e.exit_code(), ExitCode::Authentication);
    }

    #[test]
    fn each_class_has_specific_copy_and_code() {
        let cases: Vec<(EngineError, ExitCode, &str)> = vec![(EngineError::PeerLost, ExitCode::Connection, "Lost connection to laptop"), (EngineError::Timeout, ExitCode::Connection, "Laptop stopped responding"), (EngineError::ConnectionRejected, ExitCode::Rejected, "Laptop declined the connection."), (EngineError::DiskFull { needed: 2 << 30, available: 1 << 30 }, ExitCode::DiskFull, "Not enough free space"), (EngineError::PeerDiskFull, ExitCode::DiskFull, "Laptop does not have enough free space"), (EngineError::SourceFileChanged { path: "/x/a.txt".into() }, ExitCode::Source, "a.txt changed while sending"), (EngineError::SourceFileMissing { path: "/x/b.txt".into() }, ExitCode::Source, "/x/b.txt could not be found."), (EngineError::CorruptedData, ExitCode::Integrity, "integrity check"), (EngineError::UnsupportedVersion, ExitCode::Version, "Please update both apps."), (EngineError::Cancelled, ExitCode::Interrupted, "cancelled"), (EngineError::UnsafePath("../x".into()), ExitCode::Protocol, "unsafe name"), (EngineError::ProtocolViolation("x".into()), ExitCode::Protocol, "unexpected"), (EngineError::Internal("x".into()), ExitCode::Failure, "Internal error")];
        for (e, code, needle) in cases {
            let ce = CliError::Engine(e);
            assert_eq!(ce.exit_code(), code, "{ce:?}");
            let msg = ce.user_message(Some("laptop"));
            assert!(msg.contains(needle), "{msg:?} lacks {needle:?}");
        }
        assert!(CliError::Engine(EngineError::PeerLost).user_message(None).contains("the other device"));
    }

    #[test]
    fn exit_codes_are_distinct_per_class() {
        let all = [ExitCode::Ok, ExitCode::Failure, ExitCode::Usage, ExitCode::Connection, ExitCode::Authentication, ExitCode::Rejected, ExitCode::DiskFull, ExitCode::Source, ExitCode::Integrity, ExitCode::Version, ExitCode::Protocol, ExitCode::Config, ExitCode::NotFound, ExitCode::Interrupted];
        let mut codes: Vec<i32> = all.iter().map(|c| c.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        assert_eq!(CliError::Interrupted.exit_code().code(), 130);
        assert_eq!(CliError::Interrupted.user_message(None), RESUME_HINT);
    }
}
