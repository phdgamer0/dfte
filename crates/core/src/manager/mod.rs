//! The app-facing Transfer Manager (manual §22, §23, §27).
//!
//! One [`TransferManager`] per process. It owns:
//!
//! * a multi-thread tokio runtime (manual §27). Every async method spawns its work
//!   onto it and awaits the result, so callers may await from any executor
//!   (Kotlin coroutines, Swift tasks, another tokio runtime);
//! * the job map, behind a `tokio::sync::RwLock`, holding one entry per send or
//!   receive. Only immutable [`Transfer`] snapshots ever leave it;
//! * the TCP and QUIC transports, listeners, and the discovery backend;
//! * a dispatcher thread that calls the [`TransferObserver`].
//!
//! # Cancellation of the async methods (manual §50)
//!
//! Each async method's work runs as a task on the manager's runtime. Dropping the
//! returned future *detaches* that task: the operation still completes and only
//! its result is lost. In particular a dropped [`send_files`](TransferManager::send_files)
//! still creates and runs the job (the observer still hears about it), and a
//! dropped [`shutdown`](TransferManager::shutdown) still shuts down. Transfers
//! themselves are stopped only by [`cancel`](TransferManager::cancel),
//! [`pause`](TransferManager::pause) and [`shutdown`](TransferManager::shutdown).
//!
//! # Peer verification
//!
//! Every handshake ends with a [`VerifyRequest`] to the observer; the user
//! compares the SAS and the platform answers with
//! [`confirm_peer`](TransferManager::confirm_peer). No answer within
//! [`ManagerConfig::verify_timeout`] rejects the peer. There is no auto-accept
//! (manual §35); [`ManagerConfig::verifier`] exists for tests and pinned peers.

mod job;
mod notify;
mod types;

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use discovery::lan::{LanConfig, LanDiscovery};
use discovery::{DiscoveryEvent, DynPeerDiscovery, LinkInfo, LinkRole, Peer, PeerHandle};
use protocol::Manifest;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{RwLock, Semaphore, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use transport::{Connection, Listener, QuicTransport, TcpTransport, Transport, TransportError, TransportKind};

use self::job::{Inner, Job, Stop};
use self::notify::{NOTICE_CAPACITY, Notice, ObserverSlot};
pub use self::types::{IncomingOffer, ManagerConfig, OfferedFile, SendTarget, Transfer, TransferId, TransferObserver, TransferState, VerifyRequest};
use crate::error::{EngineError, Result};
use crate::hooks::{BoxFuture, Phase};
use crate::options::{CancelHandle, ExpectFingerprint, PeerAuth, PeerVerifier, Progress, ProgressFn, ReceiveOptions, SendOptions};
use crate::receiver::{Dest, receive_connection};
use crate::report::{Direction, TransferReport};
use crate::sender::send_files_hooked;

/// Pause after a failing `accept` so a broken listener can't spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long shutdown waits for the observer to receive the last callbacks.
const DISPATCH_DRAIN: Duration = Duration::from_secs(5);

/// The app-facing engine handle (manual §22). See the [module docs](self).
pub struct TransferManager {
    shared: Arc<Shared>,
    /// `Some` until drop; owning it here keeps the runtime's lifetime the manager's.
    runtime: Option<Runtime>,
}

struct ListenerEntry {
    kind: TransportKind,
    addr: SocketAddr,
    task: JoinHandle<()>,
}

struct PendingVerify {
    transfer_id: TransferId,
    reply: SyncSender<bool>,
}

struct Shared {
    cfg: ManagerConfig,
    rt: Handle,
    jobs: RwLock<HashMap<TransferId, Arc<Job>>>,
    next_seq: AtomicU64,
    notices: mpsc::Sender<Notice>,
    observer: ObserverSlot,
    verifies: Mutex<HashMap<u64, PendingVerify>>,
    next_request: AtomicU64,
    tcp: TcpTransport,
    quic: QuicTransport,
    listeners: Mutex<Vec<ListenerEntry>>,
    discovery: Mutex<Option<Arc<dyn DynPeerDiscovery>>>,
    scan: Mutex<Option<JoinHandle<()>>>,
    peers: Mutex<HashMap<PeerHandle, Peer>>,
    /// Job tasks, reaped by the ticker and joined on shutdown.
    tasks: Mutex<JoinSet<()>>,
    ticker: Mutex<Option<JoinHandle<()>>>,
    incoming: Arc<Semaphore>,
    shutting_down: AtomicBool,
}

/// Locks a std mutex; every critical section here leaves its data consistent,
/// so a poisoned lock (a panic elsewhere) is still safe to use.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TransferManager {
    /// Builds the runtime, transports and dispatcher. Nothing listens or scans yet.
    pub fn new(cfg: ManagerConfig) -> Result<Self> {
        if cfg.streams == 0 || cfg.streams > transport::MAX_DATA_STREAMS {
            return Err(EngineError::InvalidInput(format!("streams must be 1..={}", transport::MAX_DATA_STREAMS)));
        }
        if cfg.in_flight_chunks == 0 || cfg.max_incoming == 0 || cfg.progress_interval.is_zero() {
            return Err(EngineError::InvalidInput("in_flight_chunks, max_incoming and progress_interval must be nonzero".into()));
        }
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all().thread_name("dfte-worker");
        if let Some(n) = cfg.worker_threads {
            builder.worker_threads(n.max(1));
        }
        let runtime = builder.build()?;
        let quic = QuicTransport::new(&cfg.identity, cfg.quic.clone())?;
        let tcp = TcpTransport::new(cfg.tcp);
        let (tx, rx) = mpsc::channel(NOTICE_CAPACITY);
        let observer = ObserverSlot::default();
        // Detached on purpose: it exits on `Notice::Stop` or when every sender is
        // gone, and joining it from an observer callback would deadlock.
        let _detached = notify::spawn_dispatcher(rx, Arc::clone(&observer))?;
        let shared = Arc::new(Shared { discovery: Mutex::new(cfg.discovery.clone()), incoming: Arc::new(Semaphore::new(cfg.max_incoming)), cfg, rt: runtime.handle().clone(), jobs: RwLock::new(HashMap::new()), next_seq: AtomicU64::new(0), notices: tx, observer, verifies: Mutex::new(HashMap::new()), next_request: AtomicU64::new(1), tcp, quic, listeners: Mutex::new(Vec::new()), scan: Mutex::new(None), peers: Mutex::new(HashMap::new()), tasks: Mutex::new(JoinSet::new()), ticker: Mutex::new(None), shutting_down: AtomicBool::new(false) });
        let ticker = runtime.spawn(ticker(Arc::downgrade(&shared), shared.cfg.progress_interval));
        *lock(&shared.ticker) = Some(ticker);
        Ok(Self { shared, runtime: Some(runtime) })
    }

    /// Runs `fut` on the manager's runtime (see the module docs on cancellation).
    async fn run<T: Send + 'static>(&self, fut: impl Future<Output = Result<T>> + Send + 'static) -> Result<T> {
        self.shared.rt.spawn(fut).await?
    }

    /// Registers the observer, replacing any previous one. Callbacks already
    /// queued go to the new observer.
    pub fn set_observer(&self, observer: Box<dyn TransferObserver>) {
        *self.shared.observer.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(observer));
    }

    /// This device's identity fingerprint, as peers will see it (manual §6).
    pub fn fingerprint(&self) -> String {
        self.shared.cfg.identity.fingerprint()
    }

    /// Replaces the discovery backend (e.g. a platform one created after the
    /// manager). Takes effect on the next [`start_scan`](Self::start_scan).
    pub fn set_discovery(&self, discovery: Arc<dyn DynPeerDiscovery>) {
        *lock(&self.shared.discovery) = Some(discovery);
    }

    /// Accepts incoming transfers on `addr` with the configured transport.
    /// Returns the bound address (useful with port 0).
    pub async fn listen(&self, addr: SocketAddr) -> Result<SocketAddr> {
        let kind = self.shared.cfg.transport;
        self.listen_on(kind, addr).await
    }

    /// [`listen`](Self::listen) with an explicit backend. TCP and QUIC can listen
    /// on the same port number.
    pub async fn listen_on(&self, kind: TransportKind, addr: SocketAddr) -> Result<SocketAddr> {
        let s = Arc::clone(&self.shared);
        self.run(async move { s.listen(kind, addr).await }).await
    }

    /// Stops accepting new connections. Running transfers continue.
    pub async fn stop_listening(&self) -> Result<()> {
        for l in std::mem::take(&mut *lock(&self.shared.listeners)) {
            tracing::debug!(kind = ?l.kind, addr = %l.addr, "stopping listener");
            l.task.abort();
        }
        Ok(())
    }

    /// Addresses currently listened on.
    pub fn listening(&self) -> Vec<(TransportKind, SocketAddr)> {
        lock(&self.shared.listeners).iter().map(|l| (l.kind, l.addr)).collect()
    }

    /// Starts a send job and returns its id once the job exists; hashing,
    /// connecting and the transfer run in the background (watch the observer).
    pub async fn send_files(&self, target: SendTarget, paths: Vec<PathBuf>) -> Result<TransferId> {
        let s = Arc::clone(&self.shared);
        self.run(async move { s.start_send(target, paths).await }).await
    }

    /// Accepts a pending [`IncomingOffer`]; files are verified in the staging
    /// directory and renamed under `destination` (created if missing). Returns
    /// once the decision is delivered, not when the transfer ends.
    pub async fn accept_incoming(&self, transfer_id: &str, destination: PathBuf) -> Result<()> {
        let (s, id) = (Arc::clone(&self.shared), transfer_id.to_owned());
        self.run(async move { s.accept_incoming(&id, destination).await }).await
    }

    /// Declines a pending [`IncomingOffer`]; the sender sees `ConnectionRejected`.
    pub async fn reject_incoming(&self, transfer_id: &str) -> Result<()> {
        let (s, id) = (Arc::clone(&self.shared), transfer_id.to_owned());
        self.run(async move {
            let job = s.job(&id).await?;
            s.answer_offer(&job, None)
        })
        .await
    }

    /// Answers a [`VerifyRequest`]. Synchronous so an observer callback can call it.
    pub fn confirm_peer(&self, request_id: u64, accept: bool) -> Result<()> {
        self.shared.confirm_peer(request_id, accept)
    }

    /// Cancels a running job (the peer is told; a receiver keeps its resume
    /// state), or abandons a paused/interrupted one. Returns once the cancel is
    /// signalled; the final state arrives through the observer.
    pub async fn cancel(&self, transfer_id: &str) -> Result<()> {
        let (s, id) = (Arc::clone(&self.shared), transfer_id.to_owned());
        self.run(async move { s.cancel(&id).await }).await
    }

    /// Stops a running job, keeping resume state; the job ends `Paused`.
    pub async fn pause(&self, transfer_id: &str) -> Result<()> {
        let (s, id) = (Arc::clone(&self.shared), transfer_id.to_owned());
        self.run(async move {
            let job = s.job(&id).await?;
            if !job.request_stop(Stop::Pause) {
                return Err(EngineError::InvalidInput(format!("transfer {id} is not running")));
            }
            s.reject_verifications(&id);
            Ok(())
        })
        .await
    }

    /// Restarts a `Paused`/`Interrupted`/`Failed` send job under the same id.
    /// The receiver resumes from its sidecar (manual §19) once its user accepts
    /// the new offer. A receive job resumes when its sender sends again, so this
    /// rejects receive jobs.
    pub async fn resume(&self, transfer_id: &str) -> Result<()> {
        let (s, id) = (Arc::clone(&self.shared), transfer_id.to_owned());
        self.run(async move { s.resume(&id).await }).await
    }

    /// Snapshots of every known job, oldest first.
    pub async fn transfers(&self) -> Vec<Transfer> {
        let jobs = self.shared.jobs.read().await;
        let mut v: Vec<&Arc<Job>> = jobs.values().collect();
        v.sort_by_key(|j| j.seq);
        v.into_iter().map(|j| j.snapshot()).collect()
    }

    pub async fn transfer(&self, transfer_id: &str) -> Option<Transfer> {
        self.shared.jobs.read().await.get(transfer_id).map(|j| j.snapshot())
    }

    /// Drops finished jobs (anything not running and not resumable) from the
    /// list; returns how many.
    pub async fn forget_finished(&self) -> usize {
        let mut jobs = self.shared.jobs.write().await;
        let before = jobs.len();
        jobs.retain(|_, j| {
            let s = j.state();
            s.is_active() || s.is_resumable()
        });
        before - jobs.len()
    }

    /// Makes this device discoverable and starts reporting peers through
    /// [`TransferObserver::on_peer_found`]/[`on_peer_lost`](TransferObserver::on_peer_lost).
    /// Desktop default (no backend configured): LAN beacons advertising the
    /// first listening port, so call [`listen`](Self::listen) first.
    pub async fn start_scan(&self) -> Result<()> {
        let s = Arc::clone(&self.shared);
        self.run(async move { s.start_scan().await }).await
    }

    pub async fn stop_scan(&self) -> Result<()> {
        let s = Arc::clone(&self.shared);
        self.run(async move { s.stop_scan().await }).await
    }

    /// Peers currently known from discovery.
    pub fn peers(&self) -> Vec<Peer> {
        lock(&self.shared.peers).values().cloned().collect()
    }

    /// Stops listeners and discovery, stops running jobs (resume state kept; they
    /// end `Interrupted`), waits for their tasks, drains the transports so final
    /// QUIC messages are delivered before the process exits, then delivers the
    /// last observer callbacks. Idempotent; afterwards new work is refused with
    /// [`EngineError::ShuttingDown`]. The first error is returned after every
    /// step has run.
    pub async fn shutdown(&self) -> Result<()> {
        let s = Arc::clone(&self.shared);
        self.run(async move { s.shutdown().await }).await
    }
}

impl Drop for TransferManager {
    fn drop(&mut self) {
        if !self.shared.shutting_down.load(Ordering::SeqCst) {
            tracing::warn!("TransferManager dropped without shutdown(): undelivered QUIC data may be lost");
        }
        self.shared.reject_all_verifications();
        if self.shared.notices.try_send(Notice::Stop(None)).is_err() {
            tracing::debug!("observer dispatcher already stopped or busy; it exits once its queue closes");
        }
        if let Some(rt) = self.runtime.take() {
            // Safe from inside another runtime, unlike a plain drop.
            rt.shutdown_background();
        }
    }
}

async fn ticker(shared: Weak<Shared>, period: Duration) {
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(s) = shared.upgrade() else { return };
        s.tick(Instant::now()).await;
    }
}

/// Runs `fut`; once `cancel` fires it gets `grace` to wind down politely (tell
/// the peer, persist resume state) before it is dropped.
async fn with_grace<T>(fut: impl Future<Output = Result<T>>, cancel: &CancelHandle, grace: Duration) -> Result<T> {
    tokio::pin!(fut);
    tokio::select! {
        r = &mut fut => r,
        () = cancel.cancelled() => match tokio::time::timeout(grace, &mut fut).await {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!("engine did not stop within the cancel grace period; dropping it");
                Err(EngineError::Cancelled)
            }
        },
    }
}

fn link_addr(link: &LinkInfo) -> Result<SocketAddr> {
    match (link.role, link.peer_ip, link.peer_port) {
        (LinkRole::Client, Some(ip), Some(port)) => Ok(SocketAddr::new(ip, port)),
        (LinkRole::Host, ..) => Err(EngineError::Discovery("this device hosts the link; the peer has to connect to us".into())),
        _ => Err(EngineError::Discovery("link has no peer address yet".into())),
    }
}

fn offer_of(id: &str, m: &Manifest, peer: &PeerAuth) -> IncomingOffer {
    let files = m.files.iter().map(|f| OfferedFile { path: f.relative_path.clone(), size: f.size, is_dir: f.is_dir }).collect();
    IncomingOffer { transfer_id: id.to_owned(), peer_fingerprint: peer.fingerprint.clone(), peer_name: peer.device_name.clone(), files, bytes_total: m.total_bytes() }
}

/// Per-job verifier: records the peer, checks an expected fingerprint, then asks
/// the user through the observer (or the configured override).
struct JobVerifier {
    shared: Arc<Shared>,
    job: Arc<Job>,
    expected: Option<String>,
}

impl PeerVerifier for JobVerifier {
    fn verify(&self, peer: &PeerAuth) -> bool {
        {
            let mut g = self.job.lock();
            g.peer_fingerprint = Some(peer.fingerprint.clone());
            g.peer_name = Some(peer.device_name.clone());
        }
        if let Some(want) = &self.expected
            && !ExpectFingerprint(want.clone()).verify(peer)
        {
            tracing::warn!(id = %self.job.id, expected = %want, got = %peer.fingerprint, "peer identity differs from the discovered/scanned one");
            return false;
        }
        match &self.shared.cfg.verifier {
            Some(v) => v.verify(peer),
            None => self.shared.ask_user_blocking(&self.job, peer),
        }
    }
}

impl Shared {
    fn ensure_running(&self) -> Result<()> {
        if self.shutting_down.load(Ordering::SeqCst) { Err(EngineError::ShuttingDown) } else { Ok(()) }
    }

    async fn job(&self, id: &str) -> Result<Arc<Job>> {
        self.jobs.read().await.get(id).cloned().ok_or_else(|| EngineError::UnknownTransfer(id.to_owned()))
    }

    fn new_job(&self, direction: Direction, transport: TransportKind, send: Option<(SendTarget, Vec<PathBuf>)>, state: TransferState) -> Arc<Job> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        Arc::new(Job::new(uuid::Uuid::new_v4().to_string(), seq, direction, transport, send, state))
    }

    fn spawn_job(&self, fut: impl Future<Output = ()> + Send + 'static) {
        lock(&self.tasks).spawn_on(fut, &self.rt);
    }

    // ---- observer plumbing -------------------------------------------------

    /// Waits for room in the queue; for one-off notices off the data path.
    async fn notify(&self, n: Notice) {
        if self.notices.send(n).await.is_err() {
            tracing::debug!("observer dispatcher stopped; notice not delivered");
        }
    }

    /// Offers the job's current state; on a full queue the ticker retries.
    fn publish_state(&self, job: &Job, g: &mut Inner) {
        match self.notices.try_send(Notice::State(job.id.clone(), g.state)) {
            Ok(()) => g.state_dirty = false,
            Err(mpsc::error::TrySendError::Full(_)) => g.state_dirty = true,
            Err(mpsc::error::TrySendError::Closed(_)) => tracing::debug!("observer dispatcher stopped; state not delivered"),
        }
    }

    /// Queues a progress callback if the job changed since the last one and none
    /// is queued yet. The dispatcher snapshots the job when it delivers, so a
    /// slow observer gets the latest value, never a backlog (at most one
    /// progress notice per job sits in the queue).
    fn publish_progress(&self, job: &Arc<Job>, g: &Inner) {
        let bytes = job.bytes_done.load(Ordering::Relaxed);
        if (bytes == g.reported_bytes && g.throughput == g.reported_throughput) || job.progress_queued.swap(true, Ordering::AcqRel) {
            return;
        }
        match self.notices.try_send(Notice::Progress(Arc::clone(job))) {
            Ok(()) => {}
            // Coalesced: the next tick offers the then-current value.
            Err(mpsc::error::TrySendError::Full(_)) => job.progress_queued.store(false, Ordering::Release),
            Err(mpsc::error::TrySendError::Closed(_)) => tracing::debug!("observer dispatcher stopped; progress not delivered"),
        }
    }

    fn set_state(&self, job: &Job, state: TransferState, f: impl FnOnce(&mut Inner)) {
        let mut g = job.lock();
        f(&mut g);
        if g.state == state {
            return;
        }
        tracing::debug!(id = %job.id, from = ?g.state, to = ?state, "transfer state");
        if state == TransferState::Transferring {
            // Seed the window so the first tick already yields a rate.
            g.start_rate(Instant::now(), job.bytes_done.load(Ordering::Relaxed));
        } else if !state.is_active() {
            g.clear_rate();
        }
        g.state = state;
        self.publish_state(job, &mut g);
    }

    async fn tick(&self, now: Instant) {
        let jobs: Vec<Arc<Job>> = self.jobs.read().await.values().cloned().collect();
        for job in jobs {
            let mut g = job.lock();
            if g.state == TransferState::Transferring {
                g.sample(now, job.bytes_done.load(Ordering::Relaxed));
            }
            if g.state_dirty {
                self.publish_state(&job, &mut g);
            }
            self.publish_progress(&job, &g);
        }
        let mut tasks = lock(&self.tasks);
        while let Some(r) = tasks.try_join_next() {
            if let Err(e) = r
                && !e.is_cancelled()
            {
                tracing::error!(error = %e, "transfer job task panicked");
            }
        }
    }

    // ---- verification ----------------------------------------------------

    /// Runs on the engine's blocking thread: asks the observer and waits.
    fn ask_user_blocking(&self, job: &Job, peer: &PeerAuth) -> bool {
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = sync_channel(1);
        lock(&self.verifies).insert(request_id, PendingVerify { transfer_id: job.id.clone(), reply: tx });
        // A stop that raced the insert would have missed this request.
        if job.lock().stop.is_some() || self.shutting_down.load(Ordering::SeqCst) {
            lock(&self.verifies).remove(&request_id);
            return false;
        }
        let req = VerifyRequest { request_id, transfer_id: job.id.clone(), peer: peer.clone() };
        if self.notices.blocking_send(Notice::Verify(req)).is_err() {
            lock(&self.verifies).remove(&request_id);
            tracing::warn!(id = %job.id, "no observer dispatcher; rejecting peer");
            return false;
        }
        let answer = rx.recv_timeout(self.cfg.verify_timeout);
        lock(&self.verifies).remove(&request_id);
        match answer {
            Ok(a) => a,
            Err(RecvTimeoutError::Timeout) => {
                tracing::info!(id = %job.id, request_id, "peer verification unanswered; rejecting");
                false
            }
            Err(RecvTimeoutError::Disconnected) => false,
        }
    }

    fn confirm_peer(&self, request_id: u64, accept: bool) -> Result<()> {
        let pending = lock(&self.verifies).remove(&request_id).ok_or_else(|| EngineError::InvalidInput(format!("unknown or expired verification request {request_id}")))?;
        pending.reply.try_send(accept).map_err(|_| EngineError::InvalidInput(format!("verification request {request_id} expired")))
    }

    /// Rejects verification requests still open for `transfer_id`.
    fn reject_verifications(&self, transfer_id: &str) {
        let mut v = lock(&self.verifies);
        v.retain(|id, p| {
            if p.transfer_id != transfer_id {
                return true;
            }
            if p.reply.try_send(false).is_err() {
                tracing::debug!(request_id = id, "verification already answered");
            }
            false
        });
    }

    fn reject_all_verifications(&self) {
        for (id, p) in lock(&self.verifies).drain() {
            if p.reply.try_send(false).is_err() {
                tracing::debug!(request_id = id, "verification already answered");
            }
        }
    }

    // ---- job driving ----------------------------------------------------

    fn progress_fn(job: &Arc<Job>) -> ProgressFn {
        let j = Arc::clone(job);
        // Hot path (every confirmed chunk): two relaxed stores, nothing else.
        Arc::new(move |p: &Progress| {
            j.bytes_done.store(p.bytes_done, Ordering::Relaxed);
            j.bytes_total.store(p.bytes_total, Ordering::Relaxed);
        })
    }

    fn on_phase(&self, job: &Job, phase: Phase) {
        match phase {
            Phase::Hashed { bytes_total } => {
                job.bytes_total.store(bytes_total, Ordering::Relaxed);
                self.set_state(job, TransferState::Negotiating, |_| {});
            }
            Phase::Accepted { bytes_total, resumed_bytes } => {
                job.bytes_total.store(bytes_total, Ordering::Relaxed);
                job.bytes_done.store(resumed_bytes, Ordering::Relaxed);
                self.set_state(job, TransferState::Transferring, |g| g.resumed_bytes = resumed_bytes);
            }
        }
    }

    async fn start_send(self: Arc<Self>, target: SendTarget, paths: Vec<PathBuf>) -> Result<TransferId> {
        self.ensure_running()?;
        if paths.is_empty() {
            return Err(EngineError::InvalidInput("nothing to send".into()));
        }
        let job = self.new_job(Direction::Send, self.cfg.transport, Some((target, paths)), TransferState::Pending);
        let cancel = job.lock().reset_attempt();
        self.jobs.write().await.insert(job.id.clone(), Arc::clone(&job));
        {
            let mut g = job.lock();
            self.publish_state(&job, &mut g);
        }
        let id = job.id.clone();
        self.spawn_job(Arc::clone(&self).run_send(job, cancel));
        Ok(id)
    }

    async fn resume(self: Arc<Self>, id: &str) -> Result<()> {
        self.ensure_running()?;
        let job = self.job(id).await?;
        if job.direction != Direction::Send {
            return Err(EngineError::InvalidInput("a receive resumes when the sender sends again".into()));
        }
        let cancel = {
            let mut g = job.lock();
            if !g.state.is_resumable() {
                return Err(EngineError::InvalidInput(format!("transfer {id} is {:?}, not resumable", g.state)));
            }
            g.state = TransferState::Pending;
            self.publish_state(&job, &mut g);
            g.reset_attempt()
        };
        self.spawn_job(Arc::clone(&self).run_send(job, cancel));
        Ok(())
    }

    async fn run_send(self: Arc<Self>, job: Arc<Job>, cancel: CancelHandle) {
        let res = with_grace(self.attempt_send(&job, cancel.clone()), &cancel, self.cfg.cancel_grace).await;
        self.finish(&job, res).await;
    }

    async fn attempt_send(self: &Arc<Self>, job: &Arc<Job>, cancel: CancelHandle) -> Result<TransferReport> {
        let (target, paths) = job.send.clone().ok_or_else(|| EngineError::Internal("send job without sources".into()))?;
        let (addr, expected) = match target {
            SendTarget::Address { addr, expected_fingerprint } => (addr, expected_fingerprint),
            SendTarget::Peer(peer) => {
                self.set_state(job, TransferState::Negotiating, |_| {});
                let d = self.discovery_backend()?;
                let link = d.connect(&peer).await?;
                (link_addr(&link)?, peer.fingerprint.clone())
            }
        };
        let verifier = Arc::new(JobVerifier { shared: Arc::clone(self), job: Arc::clone(job), expected });
        let mut opts = SendOptions::new(Arc::clone(&self.cfg.identity), verifier);
        opts.streams = self.cfg.streams;
        opts.in_flight_chunks = self.cfg.in_flight_chunks;
        self.common(&mut opts.common, job, cancel);
        let on_phase = {
            let (s, j) = (Arc::clone(self), Arc::clone(job));
            move |p: Phase| s.on_phase(&j, p)
        };
        match job.transport {
            TransportKind::Tcp => send_files_hooked(&self.tcp, addr, &paths, &opts, Some(&on_phase)).await,
            TransportKind::Quic => send_files_hooked(&self.quic, addr, &paths, &opts, Some(&on_phase)).await,
        }
    }

    fn common(&self, c: &mut crate::options::CommonOptions, job: &Arc<Job>, cancel: CancelHandle) {
        c.device_name.clone_from(&self.cfg.device_name);
        c.handshake_timeout = self.cfg.handshake_timeout;
        c.idle_timeout = self.cfg.idle_timeout;
        c.cancel = Some(cancel);
        c.progress = Some(Self::progress_fn(job));
    }

    /// Maps an attempt's outcome to the job's final state and tells the observer.
    async fn finish(&self, job: &Arc<Job>, res: Result<TransferReport>) {
        let (state, error) = {
            let g = job.lock();
            match res {
                Ok(r) => {
                    job.bytes_total.store(r.bytes_total, Ordering::Relaxed);
                    job.bytes_done.store(r.bytes_total, Ordering::Relaxed);
                    (TransferState::Completed, None)
                }
                Err(e) => match (g.stop, e) {
                    (Some(Stop::Pause), _) => (TransferState::Paused, None),
                    (Some(Stop::Cancel), _) => (TransferState::Cancelled, None),
                    (Some(Stop::Shutdown), _) => (TransferState::Interrupted, None),
                    (None, EngineError::Declined) if g.accept_timed_out => (TransferState::Failed(crate::ErrorCode::Timeout), Some(EngineError::Timeout)),
                    (None, EngineError::Declined | EngineError::Cancelled) => (TransferState::Cancelled, None),
                    (None, e @ (EngineError::PeerLost | EngineError::Timeout)) => (TransferState::Interrupted, Some(e)),
                    (None, e) => (TransferState::Failed(e.code()), Some(e)),
                },
            }
        };
        match &error {
            Some(e) => tracing::warn!(id = %job.id, ?state, error = %e, "transfer ended"),
            None => tracing::info!(id = %job.id, ?state, "transfer ended"),
        }
        self.publish_progress(job, &job.lock());
        // The error first: an observer reacting to the terminal state already
        // has the reason (both go through the same FIFO queue).
        if let Some(e) = error {
            self.notify(Notice::Error(Some(job.id.clone()), e)).await;
        }
        self.set_state(job, state, |_| {});
    }

    // ---- receiving ------------------------------------------------------

    async fn listen(self: Arc<Self>, kind: TransportKind, addr: SocketAddr) -> Result<SocketAddr> {
        self.ensure_running()?;
        let (local, task) = match kind {
            TransportKind::Tcp => {
                let l = self.tcp.listen(addr).await?;
                let local = l.local_addr()?;
                (local, self.rt.spawn(Arc::clone(&self).accept_loop(l)))
            }
            TransportKind::Quic => {
                let l = self.quic.listen(addr).await?;
                let local = l.local_addr()?;
                (local, self.rt.spawn(Arc::clone(&self).accept_loop(l)))
            }
        };
        tracing::info!(?kind, addr = %local, "listening");
        lock(&self.listeners).push(ListenerEntry { kind, addr: local, task });
        Ok(local)
    }

    async fn accept_loop<L: Listener + 'static>(self: Arc<Self>, mut listener: L) {
        loop {
            // Bounds concurrent incoming jobs (manual §35); closed on shutdown.
            let Ok(permit) = Arc::clone(&self.incoming).acquire_owned().await else { return };
            let started = Instant::now();
            match listener.accept().await {
                Ok(conn) => {
                    let s = Arc::clone(&self);
                    self.spawn_job(async move {
                        s.handle_incoming(conn, started).await;
                        drop(permit);
                    });
                }
                Err(TransportError::Closed) => return,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    if matches!(e, TransportError::Io(_)) {
                        self.notify(Notice::Error(None, e.into())).await;
                    }
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    }

    async fn handle_incoming(self: Arc<Self>, conn: Connection, started: Instant) {
        if self.ensure_running().is_err() {
            tracing::debug!(peer = %conn.peer, "shutting down; dropping incoming connection");
            return;
        }
        let job = self.new_job(Direction::Receive, conn.kind, None, TransferState::Negotiating);
        let cancel = job.lock().reset_attempt();
        self.jobs.write().await.insert(job.id.clone(), Arc::clone(&job));
        {
            let mut g = job.lock();
            self.publish_state(&job, &mut g);
        }
        let verifier = Arc::new(JobVerifier { shared: Arc::clone(&self), job: Arc::clone(&job), expected: None });
        let mut opts = ReceiveOptions::new(Arc::clone(&self.cfg.identity), verifier);
        self.common(&mut opts.common, &job, cancel.clone());
        let staging = self.cfg.staging_dir();
        let gate = {
            let (s, j) = (Arc::clone(&self), Arc::clone(&job));
            move |m: &Manifest, peer: &PeerAuth| -> BoxFuture<Result<PathBuf>> { Arc::clone(&s).ask_offer(Arc::clone(&j), offer_of(&j.id, m, peer)) }
        };
        let on_phase = {
            let (s, j) = (Arc::clone(&self), Arc::clone(&job));
            move |p: Phase| s.on_phase(&j, p)
        };
        let res = with_grace(receive_connection(conn, started, &staging, Dest::Ask(&gate), &opts, Some(&on_phase)), &cancel, self.cfg.cancel_grace).await;
        self.finish(&job, res).await;
    }

    /// The receiver's offer gate: tells the observer and waits for
    /// `accept_incoming`/`reject_incoming`, a stop, or the accept timeout.
    fn ask_offer(self: Arc<Self>, job: Arc<Job>, offer: IncomingOffer) -> BoxFuture<Result<PathBuf>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let mut g = job.lock();
                if g.stop.is_some() {
                    return Err(EngineError::Cancelled);
                }
                g.offer = Some(tx);
            }
            job.bytes_total.store(offer.bytes_total, Ordering::Relaxed);
            self.set_state(&job, TransferState::Pending, |_| {});
            self.notify(Notice::Incoming(offer)).await;
            match tokio::time::timeout(self.cfg.accept_timeout, rx).await {
                Ok(Ok(Some(dest))) => {
                    self.set_state(&job, TransferState::Negotiating, |_| {});
                    Ok(dest)
                }
                Ok(Ok(None) | Err(_)) => Err(EngineError::Declined),
                Err(_) => {
                    let mut g = job.lock();
                    g.offer = None;
                    g.accept_timed_out = true;
                    tracing::info!(id = %job.id, "incoming offer unanswered; declining");
                    Err(EngineError::Declined)
                }
            }
        })
    }

    fn answer_offer(&self, job: &Job, dest: Option<PathBuf>) -> Result<()> {
        let reply = job.lock().offer.take().ok_or_else(|| EngineError::InvalidInput(format!("transfer {} has no pending offer", job.id)))?;
        reply.send(dest).map_err(|_| EngineError::InvalidInput(format!("offer for transfer {} is no longer pending", job.id)))
    }

    async fn accept_incoming(&self, id: &str, dest: PathBuf) -> Result<()> {
        let job = self.job(id).await?;
        if job.lock().offer.is_none() {
            return Err(EngineError::InvalidInput(format!("transfer {id} has no pending offer")));
        }
        let d = dest.clone();
        self.rt.spawn_blocking(move || std::fs::create_dir_all(&d)).await??;
        self.answer_offer(&job, Some(dest))
    }

    async fn cancel(&self, id: &str) -> Result<()> {
        let job = self.job(id).await?;
        if job.request_stop(Stop::Cancel) {
            self.reject_verifications(id);
            return Ok(());
        }
        let state = job.state();
        if state.is_resumable() {
            self.set_state(&job, TransferState::Cancelled, |_| {});
            Ok(())
        } else if state == TransferState::Cancelled {
            Ok(())
        } else {
            Err(EngineError::InvalidInput(format!("transfer {id} already ended ({state:?})")))
        }
    }

    // ---- discovery ------------------------------------------------------

    fn discovery_backend(&self) -> Result<Arc<dyn DynPeerDiscovery>> {
        let mut slot = lock(&self.discovery);
        if let Some(d) = slot.as_ref() {
            return Ok(Arc::clone(d));
        }
        if cfg!(any(target_os = "android", target_os = "ios")) {
            return Err(EngineError::Discovery("no platform discovery backend configured".into()));
        }
        let port = lock(&self.listeners).first().map(|l| l.addr.port()).ok_or_else(|| EngineError::InvalidInput("listen before scanning: LAN beacons advertise the listening port".into()))?;
        let lan: Arc<dyn DynPeerDiscovery> = Arc::new(LanDiscovery::new(LanConfig::new(self.cfg.device_name.clone(), port))?);
        *slot = Some(Arc::clone(&lan));
        Ok(lan)
    }

    async fn start_scan(self: Arc<Self>) -> Result<()> {
        self.ensure_running()?;
        let d = self.discovery_backend()?;
        d.start_advertising(&self.cfg.identity).await?;
        let mut stream = d.start_scanning().await?;
        let weak = Arc::downgrade(&self);
        let task = self.rt.spawn(async move {
            while let Some(ev) = stream.next().await {
                let Some(s) = weak.upgrade() else { return };
                match ev {
                    DiscoveryEvent::PeerFound(p) => {
                        lock(&s.peers).insert(p.handle.clone(), p.clone());
                        s.notify(Notice::PeerFound(p)).await;
                    }
                    DiscoveryEvent::PeerLost(h) => {
                        lock(&s.peers).remove(&h);
                        s.notify(Notice::PeerLost(h)).await;
                    }
                }
            }
        });
        if let Some(old) = lock(&self.scan).replace(task) {
            old.abort();
        }
        Ok(())
    }

    async fn stop_scan(&self) -> Result<()> {
        if let Some(t) = lock(&self.scan).take() {
            t.abort();
        }
        lock(&self.peers).clear();
        let d = lock(&self.discovery).clone();
        match d {
            Some(d) => Ok(d.stop().await?),
            None => Ok(()),
        }
    }

    // ---- shutdown -------------------------------------------------------

    async fn shutdown(&self) -> Result<()> {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut first: Option<EngineError> = None;
        let mut record = |e: EngineError, what: &str| {
            tracing::error!(error = %e, "shutdown: {what}");
            first.get_or_insert(e);
        };
        for l in std::mem::take(&mut *lock(&self.listeners)) {
            l.task.abort();
        }
        self.incoming.close();
        if let Err(e) = self.stop_scan().await {
            record(e, "stopping discovery");
        }
        let jobs: Vec<Arc<Job>> = self.jobs.read().await.values().cloned().collect();
        for j in &jobs {
            if j.request_stop(Stop::Shutdown) {
                self.reject_verifications(&j.id);
            }
        }
        let mut set = std::mem::take(&mut *lock(&self.tasks));
        let joined = tokio::time::timeout(self.cfg.cancel_grace + Duration::from_secs(5), async {
            let mut panicked = false;
            while let Some(r) = set.join_next().await {
                if let Err(e) = r
                    && !e.is_cancelled()
                {
                    tracing::error!(error = %e, "transfer job task panicked");
                    panicked = true;
                }
            }
            panicked
        })
        .await;
        match joined {
            Ok(false) => {}
            Ok(true) => record(EngineError::Internal("a transfer task panicked".into()), "joining jobs"),
            Err(_) => record(EngineError::Timeout, "jobs did not stop in time"),
        }
        // Manual §15 / transport docs: QUIC retransmits in userspace, so the final
        // Close/acks must be delivered before the runtime goes away.
        if let Err(e) = self.tcp.drain().await {
            record(e.into(), "draining TCP");
        }
        if let Err(e) = self.quic.drain().await {
            record(e.into(), "draining QUIC");
        }
        self.tick(Instant::now()).await;
        if let Some(t) = lock(&self.ticker).take() {
            t.abort();
        }
        let (tx, rx) = oneshot::channel();
        if self.notices.send(Notice::Stop(Some(tx))).await.is_ok() {
            match tokio::time::timeout(DISPATCH_DRAIN, rx).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => tracing::debug!("dispatcher exited before acknowledging"),
                Err(_) => tracing::warn!("observer still busy after shutdown; remaining callbacks may arrive late"),
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
