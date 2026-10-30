// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Platform discovery as a uniffi callback interface (manual §5): Android
//! (`WifiP2pManager`/`WifiAwareManager`/`startLocalOnlyHotspot`), iOS
//! (`NEHotspotConfigurationManager`, AWDL) and Windows (`WiFiDirect`) implement
//! [`PlatformDiscovery`] natively; [`ForeignDiscovery`] adapts it to the core's
//! `PeerDiscovery` trait. Only radio work happens on the platform side.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use dfte_core::DeviceIdentity;
use discovery::{DiscoveryError, DiscoveryEvent, PeerDiscovery, PeerStream};
use tokio::sync::mpsc;

use crate::types::{LinkInfo, LinkRole, Peer, Permission};

/// Errors a platform discovery backend reports (mapped to manual §36 variants).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DiscoveryFailure {
    #[error("radio unavailable: {detail}")]
    RadioUnavailable { detail: String },
    #[error("permission denied: {permission:?}")]
    PermissionDenied { permission: Permission },
    #[error("peer lost")]
    PeerLost,
    #[error("connection rejected by peer")]
    ConnectionRejected,
    #[error("timed out")]
    Timeout,
    #[error("unknown peer")]
    UnknownPeer,
    /// Any other platform error; `detail` is for logs (OS error code, ...).
    #[error("backend: {detail}")]
    Backend { detail: String },
}

/// A foreign implementation threw something uniffi could not map.
impl From<uniffi::UnexpectedUniFFICallbackError> for DiscoveryFailure {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Backend { detail: e.reason }
    }
}

impl From<DiscoveryFailure> for DiscoveryError {
    fn from(e: DiscoveryFailure) -> Self {
        match e {
            DiscoveryFailure::RadioUnavailable { detail } => Self::RadioUnavailable(detail),
            DiscoveryFailure::PermissionDenied { permission } => Self::PermissionDenied(permission.into()),
            DiscoveryFailure::PeerLost => Self::PeerLost,
            DiscoveryFailure::ConnectionRejected => Self::ConnectionRejected,
            DiscoveryFailure::Timeout => Self::Timeout,
            DiscoveryFailure::UnknownPeer => Self::UnknownPeer,
            DiscoveryFailure::Backend { detail } => Self::Backend(detail),
        }
    }
}

/// Radio discovery implemented by the platform (manual §5). Every method may
/// suspend; the engine calls them from its own runtime threads.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PlatformDiscovery: Send + Sync {
    /// Make this device discoverable. Only public identity data is passed.
    async fn start_advertising(&self, fingerprint: String, public_key: Vec<u8>) -> Result<(), DiscoveryFailure>;
    /// Start reporting peers into `sink` until `stop` (or a new scan). Scan on
    /// user action only (Android throttles scans, manual §5).
    async fn start_scanning(&self, sink: Arc<PeerSink>) -> Result<(), DiscoveryFailure>;
    /// Bring up a radio link to `peer` and return its addressing.
    async fn connect(&self, peer: Peer) -> Result<LinkInfo, DiscoveryFailure>;
    /// Stop advertising/scanning and tear down links this backend formed.
    async fn stop(&self) -> Result<(), DiscoveryFailure>;
}

/// Where a platform scan reports peers. Calls never block: radio callbacks
/// arrive on platform threads, so a full queue drops the event (logged) rather
/// than stalling them (manual §28).
#[derive(uniffi::Object)]
pub struct PeerSink {
    tx: Mutex<Option<mpsc::Sender<DiscoveryEvent>>>,
}

impl PeerSink {
    fn send(&self, ev: DiscoveryEvent) -> bool {
        let g = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(tx) = g.as_ref() else { return false };
        match tx.try_send(ev) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(ev)) => {
                tracing::warn!(?ev, "discovery event queue full; dropping event");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

#[uniffi::export]
impl PeerSink {
    /// Returns `false` if the scan is over or the event was dropped.
    pub fn peer_found(&self, peer: Peer) -> bool {
        self.send(DiscoveryEvent::PeerFound(peer.into()))
    }

    pub fn peer_lost(&self, handle: String) -> bool {
        self.send(DiscoveryEvent::PeerLost(discovery::PeerHandle::new(handle)))
    }

    /// Ends the scan's event stream.
    pub fn finish(&self) {
        self.tx.lock().unwrap_or_else(PoisonError::into_inner).take();
    }
}

/// Adapts a [`PlatformDiscovery`] to the core's [`PeerDiscovery`].
pub(crate) struct ForeignDiscovery(pub Arc<dyn PlatformDiscovery>);

fn parse_ip(s: Option<String>, what: &str) -> discovery::Result<Option<IpAddr>> {
    s.map(|s| s.parse().map_err(|_| DiscoveryError::Backend(format!("platform returned an invalid {what} address: {s:?}")))).transpose()
}

impl PeerDiscovery for ForeignDiscovery {
    async fn start_advertising(&self, identity: &DeviceIdentity) -> discovery::Result<()> {
        Ok(self.0.start_advertising(identity.fingerprint(), identity.public_key_bytes().to_vec()).await?)
    }

    async fn start_scanning(&self) -> discovery::Result<PeerStream> {
        let (tx, stream) = PeerStream::channel();
        let sink = Arc::new(PeerSink { tx: Mutex::new(Some(tx)) });
        self.0.start_scanning(sink).await?;
        Ok(stream)
    }

    async fn connect(&self, peer: &discovery::Peer) -> discovery::Result<discovery::LinkInfo> {
        let l = self.0.connect(peer.clone().into()).await?;
        let role = match l.role {
            LinkRole::Host => discovery::LinkRole::Host,
            LinkRole::Client => discovery::LinkRole::Client,
        };
        Ok(discovery::LinkInfo { local_ip: parse_ip(l.local_ip, "local")?, peer_ip: parse_ip(l.peer_ip, "peer")?, peer_port: l.peer_port, interface: l.interface, link_kind: l.link_kind.into(), role })
    }

    async fn stop(&self) -> discovery::Result<()> {
        Ok(self.0.stop().await?)
    }
}
