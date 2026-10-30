//! Plain data the [`TransferManager`](super::TransferManager) hands out, its
//! configuration and the observer callback interface (manual §22).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crypto::DeviceIdentity;
use discovery::{DynPeerDiscovery, Peer, PeerHandle};
use transport::{QuicConfig, TcpConfig, TransportKind};

use crate::error::{EngineError, ErrorCode};
use crate::options::{PeerAuth, PeerVerifier};
use crate::report::Direction;

/// Opaque job id (a UUID string). Not the manifest's transfer id: a resumed
/// send keeps its job id across attempts.
pub type TransferId = String;

/// Where a job is in its life (manual §9.2), as shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferState {
    /// Sender: hashing sources. Receiver: offer received, waiting for
    /// [`accept_incoming`](super::TransferManager::accept_incoming).
    Pending,
    /// Connecting, handshake, peer verification and manifest exchange.
    Negotiating,
    /// Chunks are flowing.
    Transferring,
    /// Stopped by [`pause`](super::TransferManager::pause); resume state kept.
    Paused,
    /// The link dropped or the peer went silent; resume state kept (manual §19).
    Interrupted,
    Completed,
    /// Cancelled by either side, or an incoming offer was declined.
    Cancelled,
    Failed(ErrorCode),
}

impl TransferState {
    /// A job in this state is running and owns a task.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Pending | Self::Negotiating | Self::Transferring)
    }

    /// [`resume`](super::TransferManager::resume) may restart a send job in this state.
    pub fn is_resumable(self) -> bool {
        matches!(self, Self::Paused | Self::Interrupted | Self::Failed(_))
    }
}

/// Immutable snapshot of one job (manual §22). Cloned out of the manager; never
/// a live reference.
#[derive(Debug, Clone, PartialEq)]
pub struct Transfer {
    pub id: TransferId,
    pub direction: Direction,
    pub state: TransferState,
    pub transport: TransportKind,
    /// 0 until the manifest is known.
    pub bytes_total: u64,
    /// Integrity-confirmed bytes, including bytes resumed from an earlier attempt.
    pub bytes_done: u64,
    /// Bytes the receiver already held when the current attempt started (manual §19).
    pub resumed_bytes: u64,
    /// Rolling 1 s goodput, computed in the core (manual §23), 0 when idle.
    pub throughput_bytes_per_sec: u64,
    /// Set once the handshake has authenticated the peer.
    pub peer_fingerprint: Option<String>,
    /// Self-reported, unauthenticated display name.
    pub peer_name: Option<String>,
}

/// One entry of an incoming manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedFile {
    /// Untrusted relative path as the peer sent it (validated before any write).
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

/// An authenticated peer offers files; answer with
/// [`accept_incoming`](super::TransferManager::accept_incoming) or
/// [`reject_incoming`](super::TransferManager::reject_incoming) before
/// [`ManagerConfig::accept_timeout`], or it is declined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingOffer {
    pub transfer_id: TransferId,
    pub peer_fingerprint: String,
    pub peer_name: String,
    pub files: Vec<OfferedFile>,
    pub bytes_total: u64,
}

/// The handshake finished; the user must compare the SAS (or fingerprint) with
/// the peer's screen and answer with
/// [`confirm_peer`](super::TransferManager::confirm_peer) before
/// [`ManagerConfig::verify_timeout`]. Unanswered means rejected (manual §35).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRequest {
    pub request_id: u64,
    pub transfer_id: TransferId,
    pub peer: PeerAuth,
}

/// Who to send to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendTarget {
    /// A known address (manual IP entry, a scanned QR code). With
    /// `expected_fingerprint` (QR, pinned peer) the handshake must authenticate
    /// exactly that identity, and the user still confirms.
    Address { addr: SocketAddr, expected_fingerprint: Option<String> },
    /// A peer from discovery: the manager asks the discovery backend for a link
    /// first (manual §5), and checks the fingerprint the peer advertised.
    Peer(Peer),
}

/// Callbacks from the manager (manual §22).
///
/// Threading: every method is called on one dedicated dispatcher thread owned by
/// the manager, never on the platform's UI thread; platform shims hop to their
/// UI thread themselves (`DispatchQueue.main.async`, `withContext(Dispatchers.Main)`,
/// `DispatcherQueue.TryEnqueue`, `glib::idle_add`). Calls are serialized, so a
/// slow callback delays later callbacks but never a transfer: progress is
/// coalesced to at most one [`on_progress`](Self::on_progress) per transfer per
/// [`ManagerConfig::progress_interval`] and intermediate values are dropped.
/// A panicking callback is logged and does not stop later callbacks.
///
/// Callbacks may call back into the manager: the sync methods
/// ([`confirm_peer`](super::TransferManager::confirm_peer)) directly, the async
/// ones by spawning.
pub trait TransferObserver: Send + Sync {
    fn on_progress(&self, _transfer: Transfer) {}
    fn on_state_changed(&self, _transfer_id: TransferId, _state: TransferState) {}
    fn on_peer_found(&self, _peer: Peer) {}
    fn on_peer_lost(&self, _handle: PeerHandle) {}
    /// `transfer_id` is `None` for errors outside any job (listener, discovery).
    fn on_error(&self, _transfer_id: Option<TransferId>, _error: EngineError) {}
    fn on_incoming(&self, _offer: IncomingOffer) {}
    /// The default never answers, so every peer is rejected after the timeout.
    fn on_verify_peer(&self, _request: VerifyRequest) {}
}

/// Everything [`TransferManager::new`](super::TransferManager::new) needs.
#[derive(Clone)]
pub struct ManagerConfig {
    /// Long-term identity, loaded from the OS keystore by the platform (manual §6).
    pub identity: Arc<DeviceIdentity>,
    /// App-private root (manual §14); partial files and resume sidecars live in
    /// `<storage_root>/staging`.
    pub storage_root: PathBuf,
    /// Shown to peers; unauthenticated.
    pub device_name: String,
    /// Backend this device sends with (manual §15); defaults to
    /// [`TransportKind::platform_default`]. [`listen`](super::TransferManager::listen)
    /// accepts both, since the sender's own kernel decides.
    pub transport: TransportKind,
    /// Data streams per send (manual §11).
    pub streams: usize,
    /// Sender in-flight window in 4 MiB chunks (manual §14/§28).
    pub in_flight_chunks: usize,
    /// Platform discovery (manual §5). `None` on desktop means LAN beacons
    /// ([`discovery::lan::LanDiscovery`]) on the listening port.
    pub discovery: Option<Arc<dyn DynPeerDiscovery>>,
    /// Replaces the observer prompt for peer verification. Only for tests
    /// ([`TrustAny`](crate::TrustAny)) and pinned peers
    /// ([`ExpectFingerprint`](crate::ExpectFingerprint)); never offered in a UI
    /// (manual §35).
    pub verifier: Option<Arc<dyn PeerVerifier>>,
    pub verify_timeout: Duration,
    /// How long an incoming offer waits for an answer. Keep it below the
    /// sender's `idle_timeout`.
    pub accept_timeout: Duration,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    /// Progress callback period per transfer (100 ms = 10 Hz).
    pub progress_interval: Duration,
    /// After a cancel, how long the engine gets to tell the peer and persist
    /// resume state before its task is dropped.
    pub cancel_grace: Duration,
    /// Incoming connections handled at once; more wait in the accept queue
    /// (manual §35 connection flooding).
    pub max_incoming: usize,
    /// Runtime worker threads; `None` = one per core (manual §27).
    pub worker_threads: Option<usize>,
    pub tcp: TcpConfig,
    pub quic: QuicConfig,
}

impl ManagerConfig {
    pub fn new(identity: Arc<DeviceIdentity>, storage_root: impl Into<PathBuf>, device_name: impl Into<String>) -> Self {
        Self { identity, storage_root: storage_root.into(), device_name: device_name.into(), transport: TransportKind::platform_default(), streams: 2, in_flight_chunks: crate::options::DEFAULT_WINDOW_CHUNKS, discovery: None, verifier: None, verify_timeout: Duration::from_secs(120), accept_timeout: Duration::from_secs(120), handshake_timeout: Duration::from_secs(30), idle_timeout: Duration::from_secs(300), progress_interval: Duration::from_millis(100), cancel_grace: Duration::from_secs(5), max_incoming: 8, worker_threads: None, tcp: TcpConfig::default(), quic: QuicConfig::default() }
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.storage_root.join("staging")
    }

    /// `<storage_root>/hashes`: the sender's hash cache, so a retry or resume doesn't
    /// re-read every file before offering it (manual §19).
    pub fn hash_cache_dir(&self) -> PathBuf {
        self.storage_root.join("hashes")
    }
}
