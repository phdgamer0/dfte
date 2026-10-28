//! The exported `TransferManager` object and its observer callback interface.
//!
//! Every async method is a Kotlin `suspend fun` / Swift `async` function. The
//! work runs on the engine's own runtime, so cancelling the foreign coroutine
//! only stops waiting for the result: the operation itself still completes
//! (see `dfte_core::manager`, "Cancellation of the async methods").

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dfte_core as engine;
use dfte_core::DeviceIdentity;

use crate::discovery::{ForeignDiscovery, PlatformDiscovery};
use crate::error::{EngineError, ErrorInfo};
use crate::types::{IncomingOffer, Peer, Transfer, TransferState, TransportKind, VerifyRequest};

type Result<T> = std::result::Result<T, EngineError>;

/// Construction parameters. `None` fields take the engine defaults.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ManagerConfig {
    /// 32-byte Ed25519 secret, kept in the OS keystore by the platform (manual §6).
    pub identity_secret: Vec<u8>,
    /// App-private directory (manual §14); staging lives under it.
    pub storage_root: String,
    pub device_name: String,
    /// Default: TCP on Windows, QUIC elsewhere (manual §15).
    pub transport: Option<TransportKind>,
    pub verify_timeout_ms: Option<u64>,
    pub accept_timeout_ms: Option<u64>,
    pub progress_interval_ms: Option<u64>,
}

/// UI callbacks. Called on an engine-owned dispatcher thread, never the UI
/// thread: hop to the main thread before touching UI state (manual §22).
/// Progress is coalesced to at most one call per transfer per progress
/// interval; a slow callback never slows a transfer.
#[uniffi::export(with_foreign)]
pub trait TransferObserver: Send + Sync {
    fn on_progress(&self, transfer: Transfer);
    fn on_state_changed(&self, transfer_id: String, state: TransferState);
    fn on_peer_found(&self, peer: Peer);
    fn on_peer_lost(&self, handle: String);
    fn on_error(&self, transfer_id: Option<String>, error: ErrorInfo);
    fn on_incoming(&self, offer: IncomingOffer);
    /// Show the SAS; answer with `confirm_peer`. Unanswered = rejected (manual §35).
    fn on_verify_peer(&self, request: VerifyRequest);
}

struct ObserverAdapter(Arc<dyn TransferObserver>);

impl engine::TransferObserver for ObserverAdapter {
    fn on_progress(&self, t: engine::Transfer) {
        self.0.on_progress(t.into());
    }
    fn on_state_changed(&self, id: String, s: engine::TransferState) {
        self.0.on_state_changed(id, s.into());
    }
    fn on_peer_found(&self, p: discovery::Peer) {
        self.0.on_peer_found(p.into());
    }
    fn on_peer_lost(&self, h: discovery::PeerHandle) {
        self.0.on_peer_lost(h.as_str().to_owned());
    }
    fn on_error(&self, id: Option<String>, e: engine::EngineError) {
        self.0.on_error(id, ErrorInfo::from(&e));
    }
    fn on_incoming(&self, o: engine::IncomingOffer) {
        self.0.on_incoming(o.into());
    }
    fn on_verify_peer(&self, r: engine::VerifyRequest) {
        self.0.on_verify_peer(r.into());
    }
}

fn parse_addr(addr: &str) -> Result<SocketAddr> {
    addr.parse().map_err(|_| EngineError::InvalidInput { detail: format!("not a socket address: {addr:?}") })
}

fn secret(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| EngineError::InvalidInput { detail: format!("identity secret must be 32 bytes, got {}", bytes.len()) })
}

/// A fresh identity secret to store in the OS keystore on first launch (manual §6).
#[uniffi::export]
pub fn generate_identity() -> Result<Vec<u8>> {
    let id = DeviceIdentity::generate().map_err(|e| EngineError::Internal { detail: e.to_string() })?;
    Ok(id.secret_bytes().to_vec())
}

/// The fingerprint peers will see for this identity secret.
#[uniffi::export]
pub fn fingerprint_of_identity(identity_secret: Vec<u8>) -> Result<String> {
    Ok(DeviceIdentity::from_secret_bytes(&secret(&identity_secret)?).fingerprint())
}

/// One per process; keep a single strong reference for the app's lifetime and
/// call `shutdown()` before exiting (manual §22).
#[derive(uniffi::Object)]
pub struct TransferManager {
    inner: engine::TransferManager,
}

#[uniffi::export]
impl TransferManager {
    /// `discovery`: the platform backend (Android/iOS/Windows); `None` uses LAN
    /// beacons on desktop.
    #[uniffi::constructor]
    pub fn new(config: ManagerConfig, discovery: Option<Arc<dyn PlatformDiscovery>>) -> Result<Arc<Self>> {
        let identity = Arc::new(DeviceIdentity::from_secret_bytes(&secret(&config.identity_secret)?));
        let mut cfg = engine::ManagerConfig::new(identity, PathBuf::from(config.storage_root), config.device_name);
        if let Some(t) = config.transport {
            cfg.transport = t.into();
        }
        if let Some(ms) = config.verify_timeout_ms {
            cfg.verify_timeout = Duration::from_millis(ms);
        }
        if let Some(ms) = config.accept_timeout_ms {
            cfg.accept_timeout = Duration::from_millis(ms);
        }
        if let Some(ms) = config.progress_interval_ms {
            cfg.progress_interval = Duration::from_millis(ms);
        }
        if let Some(d) = discovery {
            cfg.discovery = Some(Arc::new(ForeignDiscovery(d)));
        }
        Ok(Arc::new(Self { inner: engine::TransferManager::new(cfg)? }))
    }

    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    pub fn set_observer(&self, observer: Arc<dyn TransferObserver>) {
        self.inner.set_observer(Box::new(ObserverAdapter(observer)));
    }

    /// Answers a `VerifyRequest`. Safe to call from inside a callback.
    pub fn confirm_peer(&self, request_id: u64, accept: bool) -> Result<()> {
        Ok(self.inner.confirm_peer(request_id, accept)?)
    }

    /// Listens on `addr` (e.g. `"0.0.0.0:0"`); returns the bound address.
    pub async fn listen(&self, addr: String) -> Result<String> {
        Ok(self.inner.listen(parse_addr(&addr)?).await?.to_string())
    }

    pub async fn stop_listening(&self) -> Result<()> {
        Ok(self.inner.stop_listening().await?)
    }

    /// Sends to a known address (QR code / manual entry). With
    /// `expected_fingerprint` (QR) the peer must be exactly that identity.
    pub async fn send_to_address(&self, addr: String, expected_fingerprint: Option<String>, paths: Vec<String>) -> Result<String> {
        let target = engine::SendTarget::Address { addr: parse_addr(&addr)?, expected_fingerprint };
        Ok(self.inner.send_files(target, paths.into_iter().map(PathBuf::from).collect()).await?)
    }

    /// Sends to a discovered peer (the platform backend forms the link first).
    pub async fn send_to_peer(&self, peer: Peer, paths: Vec<String>) -> Result<String> {
        Ok(self.inner.send_files(engine::SendTarget::Peer(peer.into()), paths.into_iter().map(PathBuf::from).collect()).await?)
    }

    pub async fn accept_incoming(&self, transfer_id: String, destination: String) -> Result<()> {
        Ok(self.inner.accept_incoming(&transfer_id, PathBuf::from(destination)).await?)
    }

    pub async fn reject_incoming(&self, transfer_id: String) -> Result<()> {
        Ok(self.inner.reject_incoming(&transfer_id).await?)
    }

    pub async fn cancel(&self, transfer_id: String) -> Result<()> {
        Ok(self.inner.cancel(&transfer_id).await?)
    }

    pub async fn pause(&self, transfer_id: String) -> Result<()> {
        Ok(self.inner.pause(&transfer_id).await?)
    }

    pub async fn resume(&self, transfer_id: String) -> Result<()> {
        Ok(self.inner.resume(&transfer_id).await?)
    }

    pub async fn transfers(&self) -> Vec<Transfer> {
        self.inner.transfers().await.into_iter().map(Into::into).collect()
    }

    pub async fn transfer(&self, transfer_id: String) -> Option<Transfer> {
        self.inner.transfer(&transfer_id).await.map(Into::into)
    }

    pub async fn forget_finished(&self) -> u64 {
        self.inner.forget_finished().await as u64
    }

    pub async fn start_scan(&self) -> Result<()> {
        Ok(self.inner.start_scan().await?)
    }

    pub async fn stop_scan(&self) -> Result<()> {
        Ok(self.inner.stop_scan().await?)
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.inner.peers().into_iter().map(Into::into).collect()
    }

    /// Stops everything and drains QUIC so final messages reach peers.
    pub async fn shutdown(&self) -> Result<()> {
        Ok(self.inner.shutdown().await?)
    }
}
