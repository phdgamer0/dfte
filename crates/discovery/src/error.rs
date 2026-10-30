// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Discovery error type (manual §36).

use crate::qr::QrError;

/// OS permissions discovery can be blocked on (manual §26). Platform code maps each
/// variant to its own settings deep-link and rationale copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// iOS `NSLocalNetworkUsageDescription`.
    LocalNetwork,
    /// Android 13+ `NEARBY_WIFI_DEVICES`.
    NearbyWifiDevices,
    /// Android `ACCESS_FINE_LOCATION` on older API levels (a Wi-Fi API quirk, not a location need).
    Location,
    /// QR scanning for the iOS↔non-Apple bootstrap (manual §6).
    Camera,
    /// Linux: the process may not talk to wpa_supplicant over D-Bus (polkit / bus policy).
    WifiControl,
}

/// Everything discovery can fail with. Variants mirror manual §36 so `core` can convert
/// them into `EngineError` one-to-one, without string matching.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// Wi-Fi is off, or the platform radio API hard-failed (manual §36 `RadioUnavailable`).
    #[error("radio unavailable: {0}")]
    RadioUnavailable(String),
    #[error("permission denied: {0:?}")]
    PermissionDenied(Permission),
    /// The radio link or the peer disappeared mid-discovery/negotiation.
    #[error("peer lost")]
    PeerLost,
    /// The peer declined the radio-level connection (e.g. WFD invitation rejected).
    #[error("connection rejected by peer")]
    ConnectionRejected,
    /// SAS/QR fingerprint mismatch. Never retried automatically (manual §6, §36).
    #[error("authentication failed: peer fingerprint mismatch (possible MITM)")]
    AuthenticationFailed,
    #[error("timed out")]
    Timeout,
    /// The backend was stopped; its event stream has ended.
    #[error("discovery stopped")]
    Stopped,
    /// `connect` was called with a handle this backend has never reported.
    #[error("unknown peer")]
    UnknownPeer,
    /// An iOS AWDL-only path was tried against a non-Apple peer; callers fall through to
    /// the QR bootstrap rather than surfacing this to the user (manual §36).
    #[error("link kind not available for this peer")]
    IncompatiblePlatformLink,
    #[error("invalid QR payload: {0}")]
    InvalidQr(#[from] QrError),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// A platform backend error that has no better mapping (D-Bus error name, OS code, ...).
    /// For logs/diagnostics only (manual §36: internal codes are a superset).
    #[error("backend: {0}")]
    Backend(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
}

impl DiscoveryError {
    /// Whether a caller may retry automatically after this error. Authentication failures
    /// must go back to the user, never into a silent retry loop (manual §6, §35, §36).
    pub fn is_auto_retryable(&self) -> bool {
        matches!(self, Self::PeerLost | Self::Timeout | Self::Io(_))
    }
}
