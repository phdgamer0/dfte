// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! FFI-safe mirrors of the core's plain data (manual §22): immutable records
//! and field-less enums only.

use dfte_core as engine;

use crate::error::ErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransportKind {
    Tcp,
    Quic,
}

impl From<transport::TransportKind> for TransportKind {
    fn from(k: transport::TransportKind) -> Self {
        match k {
            transport::TransportKind::Tcp => Self::Tcp,
            transport::TransportKind::Quic => Self::Quic,
        }
    }
}

impl From<TransportKind> for transport::TransportKind {
    fn from(k: TransportKind) -> Self {
        match k {
            TransportKind::Tcp => Self::Tcp,
            TransportKind::Quic => Self::Quic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Direction {
    Send,
    Receive,
}

impl From<engine::Direction> for Direction {
    fn from(d: engine::Direction) -> Self {
        match d {
            engine::Direction::Send => Self::Send,
            engine::Direction::Receive => Self::Receive,
        }
    }
}

/// Mirrors [`dfte_core::TransferState`] (manual §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransferState {
    Pending,
    Negotiating,
    Transferring,
    Paused,
    Interrupted,
    Completed,
    Cancelled,
    Failed { code: ErrorCode },
}

impl From<engine::TransferState> for TransferState {
    fn from(s: engine::TransferState) -> Self {
        match s {
            engine::TransferState::Pending => Self::Pending,
            engine::TransferState::Negotiating => Self::Negotiating,
            engine::TransferState::Transferring => Self::Transferring,
            engine::TransferState::Paused => Self::Paused,
            engine::TransferState::Interrupted => Self::Interrupted,
            engine::TransferState::Completed => Self::Completed,
            engine::TransferState::Cancelled => Self::Cancelled,
            engine::TransferState::Failed(c) => Self::Failed { code: c.into() },
        }
    }
}

/// Snapshot of one job; see [`dfte_core::Transfer`].
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Transfer {
    pub id: String,
    pub direction: Direction,
    pub state: TransferState,
    pub transport: TransportKind,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub resumed_bytes: u64,
    pub throughput_bytes_per_sec: u64,
    pub peer_fingerprint: Option<String>,
    pub peer_name: Option<String>,
}

impl From<engine::Transfer> for Transfer {
    fn from(t: engine::Transfer) -> Self {
        Self { id: t.id, direction: t.direction.into(), state: t.state.into(), transport: t.transport.into(), bytes_total: t.bytes_total, bytes_done: t.bytes_done, resumed_bytes: t.resumed_bytes, throughput_bytes_per_sec: t.throughput_bytes_per_sec, peer_fingerprint: t.peer_fingerprint, peer_name: t.peer_name }
    }
}

/// What the handshake established; contains no key material.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PeerAuth {
    pub fingerprint: String,
    /// 6 digits to compare with the peer's screen.
    pub sas: String,
    /// Self-reported, unauthenticated.
    pub device_name: String,
}

impl From<engine::PeerAuth> for PeerAuth {
    fn from(p: engine::PeerAuth) -> Self {
        Self { fingerprint: p.fingerprint, sas: p.sas, device_name: p.device_name }
    }
}

/// Answer with `TransferManager.confirmPeer(requestId, accept)`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifyRequest {
    pub request_id: u64,
    pub transfer_id: String,
    pub peer: PeerAuth,
}

impl From<engine::VerifyRequest> for VerifyRequest {
    fn from(r: engine::VerifyRequest) -> Self {
        Self { request_id: r.request_id, transfer_id: r.transfer_id, peer: r.peer.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OfferedFile {
    /// Untrusted relative path from the peer, `/`-separated.
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Answer with `acceptIncoming(transferId, destination)` or `rejectIncoming`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingOffer {
    pub transfer_id: String,
    pub peer_fingerprint: String,
    pub peer_name: String,
    pub files: Vec<OfferedFile>,
    pub bytes_total: u64,
}

impl From<engine::IncomingOffer> for IncomingOffer {
    fn from(o: engine::IncomingOffer) -> Self {
        let files = o.files.into_iter().map(|f| OfferedFile { path: f.path, size: f.size, is_dir: f.is_dir }).collect();
        Self { transfer_id: o.transfer_id, peer_fingerprint: o.peer_fingerprint, peer_name: o.peer_name, files, bytes_total: o.bytes_total }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LinkKind {
    WifiDirect,
    WifiAware,
    SoftApJoin,
    AwdlPeerToPeer,
    Lan,
}

impl From<discovery::LinkKind> for LinkKind {
    fn from(k: discovery::LinkKind) -> Self {
        match k {
            discovery::LinkKind::WifiDirect => Self::WifiDirect,
            discovery::LinkKind::WifiAware => Self::WifiAware,
            discovery::LinkKind::SoftApJoin => Self::SoftApJoin,
            discovery::LinkKind::AwdlPeerToPeer => Self::AwdlPeerToPeer,
            discovery::LinkKind::Lan => Self::Lan,
        }
    }
}

impl From<LinkKind> for discovery::LinkKind {
    fn from(k: LinkKind) -> Self {
        match k {
            LinkKind::WifiDirect => Self::WifiDirect,
            LinkKind::WifiAware => Self::WifiAware,
            LinkKind::SoftApJoin => Self::SoftApJoin,
            LinkKind::AwdlPeerToPeer => Self::AwdlPeerToPeer,
            LinkKind::Lan => Self::Lan,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LinkRole {
    Host,
    Client,
}

/// A nearby device reported by discovery (manual §5).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Peer {
    /// Identity fingerprint when the discovery channel carries an authenticated one.
    pub fingerprint: Option<String>,
    /// Untrusted label, display only.
    pub display_name: String,
    pub link_kind: LinkKind,
    /// Opaque backend handle, passed back verbatim to `connect`.
    pub handle: String,
}

impl From<discovery::Peer> for Peer {
    fn from(p: discovery::Peer) -> Self {
        Self { fingerprint: p.fingerprint, display_name: p.display_name, link_kind: p.link_kind.into(), handle: p.handle.as_str().to_owned() }
    }
}

impl From<Peer> for discovery::Peer {
    fn from(p: Peer) -> Self {
        Self { fingerprint: p.fingerprint, display_name: p.display_name, link_kind: p.link_kind.into(), handle: discovery::PeerHandle::new(p.handle) }
    }
}

/// Result of a platform `connect`: addressing for the engine's own socket.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LinkInfo {
    pub local_ip: Option<String>,
    pub peer_ip: Option<String>,
    pub peer_port: Option<u16>,
    pub interface: Option<String>,
    pub link_kind: LinkKind,
    pub role: LinkRole,
}

/// OS permissions discovery can be blocked on (manual §26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Permission {
    LocalNetwork,
    NearbyWifiDevices,
    Location,
    Camera,
    WifiControl,
}

impl From<discovery::Permission> for Permission {
    fn from(p: discovery::Permission) -> Self {
        match p {
            discovery::Permission::LocalNetwork => Self::LocalNetwork,
            discovery::Permission::NearbyWifiDevices => Self::NearbyWifiDevices,
            discovery::Permission::Location => Self::Location,
            discovery::Permission::Camera => Self::Camera,
            discovery::Permission::WifiControl => Self::WifiControl,
        }
    }
}

impl From<Permission> for discovery::Permission {
    fn from(p: Permission) -> Self {
        match p {
            Permission::LocalNetwork => Self::LocalNetwork,
            Permission::NearbyWifiDevices => Self::NearbyWifiDevices,
            Permission::Location => Self::Location,
            Permission::Camera => Self::Camera,
            Permission::WifiControl => Self::WifiControl,
        }
    }
}
