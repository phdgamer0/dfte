//! Plain data types crossing the discovery boundary (manual §5, §22).

use std::fmt;
use std::net::IpAddr;

/// Which radio mechanism produced a link (manual §22 `LinkKind`, plus `Lan` for the
/// development backend of manual §41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    WifiDirect,
    WifiAware,
    SoftApJoin,
    AwdlPeerToPeer,
    /// Ordinary shared network (router). Development/MVP only (manual §41).
    Lan,
}

/// Opaque, backend-specific peer reference. Only the backend that reported it can
/// interpret it (a D-Bus object path for wpa_supplicant, a hex public key for LAN, a
/// `WifiP2pDevice` address on Android, ...). Callers pass it back verbatim to `connect`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerHandle(String);

impl PeerHandle {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A nearby device as reported by a discovery backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Identity fingerprint (`crypto::fingerprint_of` format) when the discovery channel
    /// carries an authenticated one (LAN beacons, QR codes). `None` when the radio layer
    /// only exposes a device name and MAC (plain Wi-Fi Direct `p2p_find`): the identity is
    /// then learned and user-verified in the handshake's SAS step (manual §12.1).
    pub fingerprint: Option<String>,
    /// Untrusted, peer-chosen label. Display only; never used for authorization.
    pub display_name: String,
    pub link_kind: LinkKind,
    pub handle: PeerHandle,
}

/// Which side of the link we ended up on. Decides who opens the transport socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    /// We host the group/AP: the engine listens and the peer connects to us.
    Host,
    /// We joined the peer's group/AP (or plain LAN): the engine connects to `peer_ip`.
    Client,
}

/// Result of a successful radio-level [`connect`](crate::PeerDiscovery::connect).
///
/// Deviation from manual §5 (`connect -> RawSocket`): discovery hands back *addressing*,
/// not an already-connected socket. The engine opens its own socket through the
/// `transport` crate. A plain address is trivially FFI-safe across uniffi (a socket fd
/// is not portable to Windows' WinRT `StreamSocket` or iOS' `NWConnection`) and keeps
/// all socket configuration (buffers, `TCP_NODELAY`, QUIC) inside the shared Rust core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    /// Our address on the new link, when the platform reports it.
    pub local_ip: Option<IpAddr>,
    /// The peer's address. `None` when we are [`LinkRole::Host`] and the peer's address is
    /// only learned when it connects, or when address assignment (DHCP) is still pending:
    /// run [`LanDiscovery`](crate::lan::LanDiscovery) on the new interface to learn it.
    pub peer_ip: Option<IpAddr>,
    /// The peer's engine port, when the discovery channel carried it (LAN beacon, QR).
    pub peer_port: Option<u16>,
    /// OS interface name of the link (`p2p-wlan0-0`, `wlan-dfte`, ...), when known.
    pub interface: Option<String>,
    pub link_kind: LinkKind,
    pub role: LinkRole,
}

/// Events delivered on a [`PeerStream`](crate::PeerStream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// A new peer appeared, or a known peer's advertised details changed.
    PeerFound(Peer),
    /// A previously reported peer went away (radio `DeviceLost` or beacon expiry).
    PeerLost(PeerHandle),
}
