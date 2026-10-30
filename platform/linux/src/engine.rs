//! The GTK side of the engine (manual §22/§23): one [`TransferManager`] for the
//! process, its observer callbacks forwarded to the GTK main loop, and a small
//! tokio runtime for the async calls the UI makes. No transfer logic lives here.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use dfte_cli::trust::TrustStore;
use dfte_core::{DeviceIdentity, EngineError, IncomingOffer, ManagerConfig, Transfer, TransferId, TransferManager, TransferObserver, TransferState, VerifyRequest};
use discovery::{Peer, PeerHandle};

/// The engine's default port, shared with the CLI and the Android app.
pub const PORT: u16 = 47_821;
/// Engine worker threads for the desktop app.
const MAX_WORKERS: usize = 4;
/// How often running transfers report progress to the window.
const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);
/// Observer events waiting for the main loop. The manager already coalesces
/// progress, so this only fills if the UI thread stalls (manual §28: bounded).
const EVENT_CAPACITY: usize = 256;

/// What the engine tells the UI, in delivery order.
#[derive(Debug)]
pub enum Event {
    Progress(Transfer),
    State(TransferId, TransferState),
    PeerFound(Peer),
    PeerLost(PeerHandle),
    Error(Option<TransferId>, EngineError),
    Incoming(IncomingOffer),
    Verify(VerifyRequest),
}

/// Forwards callbacks from the manager's dispatcher thread. Blocking there is
/// fine: that thread exists so a slow observer never stalls a transfer.
struct Forward(async_channel::Sender<Event>);

impl Forward {
    fn send(&self, ev: Event) {
        if self.0.send_blocking(ev).is_err() {
            tracing::debug!("UI closed; dropping engine event");
        }
    }
}

impl TransferObserver for Forward {
    fn on_progress(&self, t: Transfer) {
        self.send(Event::Progress(t));
    }
    fn on_state_changed(&self, id: TransferId, s: TransferState) {
        self.send(Event::State(id, s));
    }
    fn on_peer_found(&self, p: Peer) {
        self.send(Event::PeerFound(p));
    }
    fn on_peer_lost(&self, h: PeerHandle) {
        self.send(Event::PeerLost(h));
    }
    fn on_error(&self, id: Option<TransferId>, e: EngineError) {
        self.send(Event::Error(id, e));
    }
    fn on_incoming(&self, o: IncomingOffer) {
        self.send(Event::Incoming(o));
    }
    fn on_verify_peer(&self, r: VerifyRequest) {
        self.send(Event::Verify(r));
    }
}

pub struct Engine {
    pub manager: Arc<TransferManager>,
    /// Runs the UI's async calls (manager methods, NetworkManager over zbus, which
    /// needs tokio); the GTK main loop only awaits their results.
    rt: tokio::runtime::Runtime,
    pub data_dir: PathBuf,
    pub device_name: String,
    pub fingerprint: String,
}

impl Engine {
    /// Loads (or creates) the identity the CLI also uses, so this machine is one
    /// device whichever front end runs; same trust store and staging directory.
    pub fn start() -> Result<(Self, async_channel::Receiver<Event>), String> {
        let data_dir = dfte_cli::paths::data_dir().map_err(|e| e.user_message(None))?;
        let (identity, _) = dfte_cli::identity::load_or_create(&data_dir).map_err(|e| e.user_message(None))?;
        let identity: Arc<DeviceIdentity> = Arc::new(identity);
        let device_name = dfte_cli::identity::device_name();
        let fingerprint = identity.fingerprint();
        let mut cfg = ManagerConfig::new(identity, data_dir.clone(), device_name.clone());
        // Network and AEAD work for Wi-Fi-speed links; one worker per core (12 on a
        // laptop) only adds idle threads. Hashing and disk I/O use the blocking pool.
        cfg.worker_threads = Some(std::thread::available_parallelism().map_or(2, |n| n.get().min(MAX_WORKERS)));
        // The window refreshes at most 4 times a second while a transfer runs.
        cfg.progress_interval = PROGRESS_INTERVAL;
        // Same place as the CLI's, so either app reuses the other's hashes.
        cfg.hash_cache_dir = dfte_cli::paths::cache_dir().map_err(|e| e.user_message(None))?.join("hashes");
        let manager = Arc::new(TransferManager::new(cfg).map_err(|e| format!("The transfer engine could not start: {e}."))?);
        let (tx, rx) = async_channel::bounded(EVENT_CAPACITY);
        manager.set_observer(Box::new(Forward(tx)));
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).thread_name("dfte-gtk-io").enable_all().build().map_err(|e| format!("cannot start the I/O runtime: {e}"))?;
        Ok((Self { manager, rt, data_dir, device_name, fingerprint }, rx))
    }

    /// Runs `fut` on the engine side; await the handle from the GTK main loop.
    pub fn spawn<F>(&self, fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.rt.spawn(fut)
    }

    /// Listens on the shared default port (any port if it's taken) and becomes
    /// discoverable on the local network. Returns the bound address.
    pub async fn go_online(manager: Arc<TransferManager>) -> Result<SocketAddr, EngineError> {
        let addr = match manager.listen(SocketAddr::from(([0, 0, 0, 0], PORT))).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "port {PORT} unavailable, using any free port");
                manager.listen(SocketAddr::from(([0, 0, 0, 0], 0))).await?
            }
        };
        manager.start_scan().await?;
        Ok(addr)
    }

    pub fn trust(&self) -> Result<TrustStore, String> {
        TrustStore::load(&self.data_dir).map_err(|e| e.user_message(None))
    }

    /// Stops listeners and jobs (resume state kept) before the process exits.
    pub fn shutdown(&self) {
        let m = Arc::clone(&self.manager);
        if let Err(e) = self.rt.block_on(async move { m.shutdown().await }) {
            tracing::error!(error = %e, "engine shutdown");
        }
    }
}
