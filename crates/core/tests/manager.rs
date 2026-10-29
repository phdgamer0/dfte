//! TransferManager end to end: two managers in one process over loopback TCP
//! and QUIC (manual §22, §32).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use dfte_core::{DeviceIdentity, EngineError, ErrorCode, IncomingOffer, ManagerConfig, SendTarget, Transfer, TransferManager, TransferObserver, TransferState, VerifyRequest};
use tokio::sync::mpsc;
use transport::TransportKind;

const MIB: u64 = 1024 * 1024;
const WAIT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
enum Ev {
    Progress(Transfer),
    State(String, TransferState),
    Error(Option<String>, ErrorCode),
    Incoming(IncomingOffer),
    Verify(VerifyRequest),
}

/// Records every callback; optionally sleeps in progress callbacks to play a
/// slow UI.
struct Recorder {
    tx: mpsc::UnboundedSender<Ev>,
    slow_progress: Option<Duration>,
}

impl Recorder {
    fn push(&self, ev: Ev) {
        // The test may already have finished reading; that's fine for a recorder.
        if self.tx.send(ev).is_err() {
            eprintln!("recorder: test stopped listening");
        }
    }
}

impl TransferObserver for Recorder {
    fn on_progress(&self, t: Transfer) {
        if let Some(d) = self.slow_progress {
            std::thread::sleep(d);
        }
        self.push(Ev::Progress(t));
    }
    fn on_state_changed(&self, id: String, state: TransferState) {
        self.push(Ev::State(id, state));
    }
    fn on_error(&self, id: Option<String>, error: EngineError) {
        self.push(Ev::Error(id, error.code()));
    }
    fn on_incoming(&self, offer: IncomingOffer) {
        self.push(Ev::Incoming(offer));
    }
    fn on_verify_peer(&self, r: VerifyRequest) {
        self.push(Ev::Verify(r));
    }
}

#[derive(Clone)]
struct Policy {
    /// Answer to every verification request; `None` leaves them unanswered.
    verify: Option<bool>,
    /// Accept every incoming offer into this directory.
    accept_into: Option<PathBuf>,
}

struct Node {
    m: Arc<TransferManager>,
    events: mpsc::UnboundedReceiver<Ev>,
    log: Arc<Mutex<Vec<Ev>>>,
    _root: tempfile::TempDir,
    root: PathBuf,
}

fn config(kind: TransportKind, root: &Path, name: &str) -> ManagerConfig {
    let mut c = ManagerConfig::new(Arc::new(DeviceIdentity::generate().unwrap()), root.join("app"), name);
    c.transport = kind;
    c.handshake_timeout = Duration::from_secs(10);
    c.idle_timeout = Duration::from_secs(30);
    c.worker_threads = Some(2);
    c
}

fn node(kind: TransportKind, name: &str, policy: Policy, tweak: impl FnOnce(&mut ManagerConfig), slow_progress: Option<Duration>) -> Node {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = config(kind, root.path(), name);
    tweak(&mut cfg);
    let m = Arc::new(TransferManager::new(cfg).unwrap());
    let (raw_tx, mut raw_rx) = mpsc::unbounded_channel();
    m.set_observer(Box::new(Recorder { tx: raw_tx, slow_progress }));
    let (tx, events) = mpsc::unbounded_channel();
    let log = Arc::new(Mutex::new(Vec::new()));
    // Auto-responder. Holds the manager weakly so dropping the test's Arc
    // drops the manager (whose observer owns `raw_tx`, which ends this task).
    let weak: Weak<TransferManager> = Arc::downgrade(&m);
    let log2 = Arc::clone(&log);
    tokio::spawn(async move {
        while let Some(ev) = raw_rx.recv().await {
            log2.lock().unwrap().push(ev.clone());
            if let Some(m) = weak.upgrade() {
                match &ev {
                    Ev::Verify(r) => {
                        if let Some(answer) = policy.verify {
                            m.confirm_peer(r.request_id, answer).unwrap();
                        }
                    }
                    Ev::Incoming(o) => {
                        if let Some(dir) = &policy.accept_into {
                            m.accept_incoming(&o.transfer_id, dir.clone()).await.unwrap();
                        }
                    }
                    _ => {}
                }
            }
            if tx.send(ev).is_err() {
                return;
            }
        }
    });
    let path = root.path().to_path_buf();
    Node { m, events, log, _root: root, root: path }
}

fn trusting(kind: TransportKind, name: &str, accept_into: Option<PathBuf>) -> Node {
    node(kind, name, Policy { verify: Some(true), accept_into }, |_| {}, None)
}

impl Node {
    /// Next event matching `f`, skipping others.
    async fn wait<T>(&mut self, mut f: impl FnMut(&Ev) -> Option<T>) -> T {
        tokio::time::timeout(WAIT, async {
            loop {
                let ev = self.events.recv().await.expect("observer channel closed");
                if let Some(t) = f(&ev) {
                    return t;
                }
            }
        })
        .await
        .expect("timed out waiting for an observer event")
    }

    /// Waits for the job's next state that is no longer active.
    async fn final_state(&mut self, id: &str) -> TransferState {
        self.wait(|e| match e {
            Ev::State(i, s) if i == id && !s.is_active() => Some(*s),
            _ => None,
        })
        .await
    }

    async fn incoming(&mut self) -> IncomingOffer {
        self.wait(|e| match e {
            Ev::Incoming(o) => Some(o.clone()),
            _ => None,
        })
        .await
    }

    async fn listen(&self) -> SocketAddr {
        self.m.listen("127.0.0.1:0".parse().unwrap()).await.unwrap()
    }

    fn states_of(&self, id: &str) -> Vec<TransferState> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Ev::State(i, s) if i == id => Some(*s),
                _ => None,
            })
            .collect()
    }

    fn progress_of(&self, id: &str) -> Vec<Transfer> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Ev::Progress(t) if t.id == id => Some(t.clone()),
                _ => None,
            })
            .collect()
    }

    fn errors(&self) -> Vec<(Option<String>, ErrorCode)> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Ev::Error(i, c) => Some((i.clone(), *c)),
                _ => None,
            })
            .collect()
    }
}

/// Incompressible, deterministic bytes.
fn write_data(path: &Path, len: u64, seed: u64) {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let data: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(path, data).unwrap();
}

fn assert_same(a: &Path, b: &Path) {
    let (x, y) = (std::fs::read(a).unwrap(), std::fs::read(b).unwrap());
    assert!(x == y, "{} differs from {}", a.display(), b.display());
}

fn to(addr: SocketAddr, fingerprint: Option<String>) -> SendTarget {
    SendTarget::Address { addr, expected_fingerprint: fingerprint }
}

async fn full_transfer(kind: TransportKind) {
    let mut rx_node = trusting(kind, "receiver", None);
    let out = rx_node.root.join("out");
    let mut tx_node = trusting(kind, "sender", None);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("payload.bin");
    write_data(&src, 24 * MIB + 3, 1);

    let id = tx_node.m.send_files(to(addr, Some(rx_node.m.fingerprint())), vec![src.clone()]).await.unwrap();
    let offer = rx_node.incoming().await;
    assert_eq!(offer.peer_fingerprint, tx_node.m.fingerprint());
    assert_eq!(offer.peer_name, "sender");
    assert_eq!(offer.bytes_total, 24 * MIB + 3);
    assert_eq!(offer.files.len(), 1);
    assert_eq!(offer.files[0].path, "payload.bin");
    let pending = rx_node.m.transfer(&offer.transfer_id).await.unwrap();
    assert_eq!(pending.state, TransferState::Pending);
    rx_node.m.accept_incoming(&offer.transfer_id, out.clone()).await.unwrap();
    // A second answer is refused: the offer is no longer pending.
    assert!(matches!(rx_node.m.accept_incoming(&offer.transfer_id, out.clone()).await, Err(EngineError::InvalidInput(_))));

    assert_eq!(tx_node.final_state(&id).await, TransferState::Completed);
    assert_eq!(rx_node.final_state(&offer.transfer_id).await, TransferState::Completed);
    assert_same(&src, &out.join("payload.bin"));

    // Snapshots are consistent with each other and with the files.
    let s = tx_node.m.transfer(&id).await.unwrap();
    assert_eq!((s.state, s.bytes_total, s.bytes_done, s.resumed_bytes), (TransferState::Completed, 24 * MIB + 3, 24 * MIB + 3, 0));
    assert_eq!(s.direction, dfte_core::Direction::Send);
    assert_eq!(s.transport, kind);
    assert_eq!(s.peer_fingerprint.as_deref(), Some(rx_node.m.fingerprint().as_str()));
    assert_eq!(s.peer_name.as_deref(), Some("receiver"));
    assert_eq!(s.throughput_bytes_per_sec, 0, "idle job reports no throughput");
    let r = rx_node.m.transfers().await;
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].state, r[0].bytes_done, r[0].direction), (TransferState::Completed, 24 * MIB + 3, dfte_core::Direction::Receive));
    assert_eq!(r[0].peer_fingerprint.as_deref(), Some(tx_node.m.fingerprint().as_str()));

    // Observer saw the §9.2 path and monotonic, coalesced progress ending at 100%.
    assert_eq!(tx_node.states_of(&id), vec![TransferState::Pending, TransferState::Negotiating, TransferState::Transferring, TransferState::Completed]);
    assert_eq!(rx_node.states_of(&offer.transfer_id), vec![TransferState::Negotiating, TransferState::Pending, TransferState::Negotiating, TransferState::Transferring, TransferState::Completed]);
    for (n, tid) in [(&tx_node, &id), (&rx_node, &offer.transfer_id)] {
        let p = n.progress_of(tid);
        assert!(!p.is_empty());
        assert!(p.windows(2).all(|w| w[0].bytes_done <= w[1].bytes_done), "progress went backwards");
        assert_eq!(p.last().unwrap().bytes_done, 24 * MIB + 3);
    }
    assert!(tx_node.errors().is_empty() && rx_node.errors().is_empty());

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
    tx_node.m.shutdown().await.unwrap();
    assert!(matches!(tx_node.m.send_files(to(addr, None), vec![src]).await, Err(EngineError::ShuttingDown)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_accept_complete_over_tcp() {
    full_transfer(TransportKind::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_accept_complete_over_quic() {
    full_transfer(TransportKind::Quic).await;
}

/// One listen() serves senders on either backend: the phone↔laptop case, where
/// each side's default follows its own kernel (manual §15).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_listener_serves_tcp_and_quic_senders() {
    let mut rx_node = trusting(TransportKind::Quic, "receiver", None);
    let out = rx_node.root.join("out");
    let addr = rx_node.listen().await;
    for (i, kind) in [TransportKind::Tcp, TransportKind::Quic].into_iter().enumerate() {
        let mut tx_node = trusting(kind, "sender", None);
        let src = tx_node.root.join(format!("p{i}.bin"));
        write_data(&src, MIB + 7, i as u64);
        let id = tx_node.m.send_files(to(addr, None), vec![src.clone()]).await.unwrap();
        let offer = rx_node.incoming().await;
        rx_node.m.accept_incoming(&offer.transfer_id, out.clone()).await.unwrap();
        assert_eq!(tx_node.final_state(&id).await, TransferState::Completed, "{kind:?} sender");
        assert_eq!(rx_node.final_state(&offer.transfer_id).await, TransferState::Completed, "{kind:?} sender");
        assert_same(&src, &out.join(format!("p{i}.bin")));
        tx_node.m.shutdown().await.unwrap();
    }
    assert_eq!(rx_node.m.listening().iter().map(|l| l.0).collect::<Vec<_>>(), vec![TransportKind::Tcp, TransportKind::Quic]);
    rx_node.m.shutdown().await.unwrap();
}

/// Beacon targets need the built-in LAN backend, which advertises the listening port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn beacon_targets_need_a_listener_and_a_local_address() {
    let n = trusting(TransportKind::Tcp, "phone", None);
    let target: SocketAddr = "192.168.49.1:47820".parse().unwrap();
    assert!(matches!(n.m.add_beacon_target(target), Err(EngineError::InvalidInput(_))));
    n.listen().await;
    n.m.add_beacon_target(target).unwrap();
    assert!(n.m.add_beacon_target("8.8.8.8:47820".parse().unwrap()).is_err());
    n.m.shutdown().await.unwrap();
}

/// Engine logs (info and up) into the test's captured output, which libtest prints
/// only for a failing test: a CI-only failure then explains itself.
fn init_logs() {
    // Another test in this binary may have installed it already.
    let _ = tracing_subscriber::fmt().with_test_writer().with_ansi(false).with_env_filter("info").try_init();
}

/// Resume sidecars in a staging directory (panics with the reason if unreadable).
fn staging_report(staging: &Path) -> Vec<storage::ResumeState> {
    storage::scan_orphans_blocking(staging).unwrap_or_else(|e| panic!("cannot scan {}: {e}; contents: {:?}", staging.display(), list_dir(staging)))
}

/// Names and sizes in a directory, for failure messages.
fn list_dir(dir: &Path) -> Vec<(String, u64)> {
    std::fs::read_dir(dir).map(|rd| rd.filter_map(Result::ok).map(|e| (e.file_name().to_string_lossy().into_owned(), e.metadata().map_or(0, |m| m.len()))).collect()).unwrap_or_default()
}

/// Polls snapshots until the job has moved at least `bytes`.
async fn wait_bytes(m: &TransferManager, id: &str, bytes: u64) -> Transfer {
    let deadline = Instant::now() + WAIT;
    loop {
        let t = m.transfer(id).await.unwrap();
        if t.bytes_done >= bytes || !t.state.is_active() {
            return t;
        }
        assert!(Instant::now() < deadline, "transfer stalled: {t:?}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// A sender throttled to one chunk in flight on one stream, so tests can act mid-transfer.
fn slow_sender(kind: TransportKind) -> Node {
    node(
        kind,
        "sender",
        Policy { verify: Some(true), accept_into: None },
        |c| {
            c.streams = 1;
            c.in_flight_chunks = 1;
        },
        None,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_then_resume_continues_from_receiver_sidecar() {
    init_logs();
    let mut rx_node = trusting(TransportKind::Tcp, "receiver", None);
    let out = rx_node.root.join("out");
    let mut rx_policy_out = Some(out.clone());
    let mut tx_node = slow_sender(TransportKind::Tcp);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("big.bin");
    let size = 160 * MIB + 11;
    write_data(&src, size, 2);

    let id = tx_node.m.send_files(to(addr, None), vec![src.clone()]).await.unwrap();
    let first = rx_node.incoming().await;
    rx_node.m.accept_incoming(&first.transfer_id, rx_policy_out.take().unwrap()).await.unwrap();
    let mid = wait_bytes(&tx_node.m, &id, 12 * MIB).await;
    assert_eq!(mid.state, TransferState::Transferring, "transfer finished before it could be paused");
    tx_node.m.pause(&id).await.unwrap();
    assert_eq!(tx_node.final_state(&id).await, TransferState::Paused);
    // The peer cancelled; the receiver keeps its staged data and sidecar.
    assert_eq!(rx_node.final_state(&first.transfer_id).await, TransferState::Cancelled);
    assert!(!out.join("big.bin").exists());
    assert!(matches!(tx_node.m.pause(&id).await, Err(EngineError::InvalidInput(_))));
    // What the receiver persisted: the resume below must start exactly here (§19).
    let staging = rx_node.root.join("app").join("staging");
    let held = staging_report(&staging);
    let held_bytes: u64 = held.iter().map(|s| s.files.iter().map(storage::ResumeFile::contiguous_offset).sum::<u64>()).sum();
    assert!(held_bytes >= 12 * MIB, "receiver persisted only {held_bytes} bytes after 12 MiB were acked: {held:?}\nstaging: {:?}", list_dir(&staging));

    tx_node.m.resume(&id).await.unwrap();
    let second = rx_node.incoming().await;
    assert_ne!(second.transfer_id, first.transfer_id, "a resumed send is a new incoming job");
    rx_node.m.accept_incoming(&second.transfer_id, out.clone()).await.unwrap();
    assert_eq!(tx_node.final_state(&id).await, TransferState::Completed);
    assert_eq!(rx_node.final_state(&second.transfer_id).await, TransferState::Completed);
    let s = tx_node.m.transfer(&id).await.unwrap();
    assert_eq!(s.resumed_bytes, held_bytes, "resume did not start where the receiver left off: {s:?}\nstaging now: {:?}", list_dir(&staging));
    assert_eq!(rx_node.m.transfer(&second.transfer_id).await.unwrap().resumed_bytes, s.resumed_bytes);
    assert_same(&src, &out.join("big.bin"));
    // Same job id across attempts: Paused → Pending → … → Completed.
    let states = tx_node.states_of(&id);
    let paused_at = states.iter().position(|s| *s == TransferState::Paused).unwrap();
    assert_eq!(&states[paused_at..], &[TransferState::Paused, TransferState::Pending, TransferState::Negotiating, TransferState::Transferring, TransferState::Completed]);
    assert!(matches!(tx_node.m.resume(&id).await, Err(EngineError::InvalidInput(_))), "completed jobs don't resume");
    assert!(matches!(rx_node.m.resume(&second.transfer_id).await, Err(EngineError::InvalidInput(_))), "receive jobs don't resume");

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receiver_cancel_mid_transfer() {
    let mut rx_node = trusting(TransportKind::Quic, "receiver", None);
    let out = rx_node.root.join("out");
    let mut tx_node = slow_sender(TransportKind::Quic);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("big.bin");
    write_data(&src, 96 * MIB, 3);

    let id = tx_node.m.send_files(to(addr, None), vec![src]).await.unwrap();
    let offer = rx_node.incoming().await;
    rx_node.m.accept_incoming(&offer.transfer_id, out.clone()).await.unwrap();
    let mid = wait_bytes(&rx_node.m, &offer.transfer_id, 8 * MIB).await;
    assert_eq!(mid.state, TransferState::Transferring);
    rx_node.m.cancel(&offer.transfer_id).await.unwrap();
    assert_eq!(rx_node.final_state(&offer.transfer_id).await, TransferState::Cancelled);
    // On QUIC the receiver's stopped data streams can overtake its Cancel; the
    // sender must still report a cancel, not a lost peer.
    let st = tx_node.final_state(&id).await;
    assert_eq!(st, TransferState::Cancelled, "sender errors: {:?}", tx_node.errors());
    assert!(rx_node.errors().is_empty(), "a local cancel is not an error");
    // Cancelling again is idempotent; unknown ids are reported as such.
    rx_node.m.cancel(&offer.transfer_id).await.unwrap();
    assert!(matches!(rx_node.m.cancel("nope").await, Err(EngineError::UnknownTransfer(_))));

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_verification_fails_with_authentication_failed() {
    let mut rx_node = node(TransportKind::Tcp, "receiver", Policy { verify: Some(false), accept_into: None }, |_| {}, None);
    let mut tx_node = trusting(TransportKind::Tcp, "sender", None);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("a.txt");
    std::fs::write(&src, b"hello").unwrap();

    let id = tx_node.m.send_files(to(addr, None), vec![src]).await.unwrap();
    let rx_id = rx_node
        .wait(|e| match e {
            Ev::Verify(r) => Some(r.transfer_id.clone()),
            _ => None,
        })
        .await;
    assert_eq!(rx_node.final_state(&rx_id).await, TransferState::Failed(ErrorCode::AuthenticationFailed));
    // The sender learns that the peer declined; it never got to offer files.
    assert_eq!(tx_node.final_state(&id).await, TransferState::Failed(ErrorCode::ConnectionRejected));
    assert!(rx_node.errors().contains(&(Some(rx_id.clone()), ErrorCode::AuthenticationFailed)));
    assert!(!rx_node.log.lock().unwrap().iter().any(|e| matches!(e, Ev::Incoming(_))), "no offer from an unverified peer");

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_expected_fingerprint_fails_without_asking() {
    let rx_node = trusting(TransportKind::Quic, "receiver", None);
    let mut tx_node = trusting(TransportKind::Quic, "sender", None);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("a.txt");
    std::fs::write(&src, b"hello").unwrap();

    let id = tx_node.m.send_files(to(addr, Some("00-00-00".into())), vec![src]).await.unwrap();
    assert_eq!(tx_node.final_state(&id).await, TransferState::Failed(ErrorCode::AuthenticationFailed));
    assert!(!tx_node.log.lock().unwrap().iter().any(|e| matches!(e, Ev::Verify(_))), "a fingerprint mismatch is rejected before asking the user");

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unanswered_verification_is_rejected_after_timeout() {
    let rx_node = trusting(TransportKind::Tcp, "receiver", None);
    let mut tx_node = node(TransportKind::Tcp, "sender", Policy { verify: None, accept_into: None }, |c| c.verify_timeout = Duration::from_millis(500), None);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("a.txt");
    std::fs::write(&src, b"hello").unwrap();

    let id = tx_node.m.send_files(to(addr, None), vec![src]).await.unwrap();
    let req = tx_node
        .wait(|e| match e {
            Ev::Verify(r) => Some(r.clone()),
            _ => None,
        })
        .await;
    assert_eq!(req.transfer_id, id);
    assert_eq!(req.peer.fingerprint, rx_node.m.fingerprint());
    assert_eq!(req.peer.sas.len(), 6);
    assert_eq!(tx_node.final_state(&id).await, TransferState::Failed(ErrorCode::AuthenticationFailed));
    // Too late: the request expired.
    assert!(matches!(tx_node.m.confirm_peer(req.request_id, true), Err(EngineError::InvalidInput(_))));

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unaccepted_incoming_times_out_and_rejection_is_reported() {
    let mut rx_node = node(TransportKind::Tcp, "receiver", Policy { verify: Some(true), accept_into: None }, |c| c.accept_timeout = Duration::from_millis(500), None);
    let mut tx_node = trusting(TransportKind::Tcp, "sender", None);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("a.txt");
    std::fs::write(&src, b"hello").unwrap();

    // Nobody answers.
    let id = tx_node.m.send_files(to(addr, None), vec![src.clone()]).await.unwrap();
    let offer = rx_node.incoming().await;
    assert_eq!(rx_node.final_state(&offer.transfer_id).await, TransferState::Failed(ErrorCode::Timeout));
    assert_eq!(tx_node.final_state(&id).await, TransferState::Failed(ErrorCode::ConnectionRejected));
    assert!(rx_node.errors().contains(&(Some(offer.transfer_id.clone()), ErrorCode::Timeout)));
    assert!(matches!(rx_node.m.accept_incoming(&offer.transfer_id, rx_node.root.join("out")).await, Err(EngineError::InvalidInput(_))));

    // Explicitly declined: Cancelled locally, rejected on the sender.
    let id2 = tx_node.m.send_files(to(addr, None), vec![src]).await.unwrap();
    let offer2 = rx_node.incoming().await;
    rx_node.m.reject_incoming(&offer2.transfer_id).await.unwrap();
    assert_eq!(rx_node.final_state(&offer2.transfer_id).await, TransferState::Cancelled);
    assert_eq!(tx_node.final_state(&id2).await, TransferState::Failed(ErrorCode::ConnectionRejected));
    assert!(!rx_node.root.join("out").join("a.txt").exists());

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_interrupts_running_jobs_and_drains() {
    let mut rx_node = trusting(TransportKind::Quic, "receiver", None);
    let out = rx_node.root.join("out");
    let mut tx_node = slow_sender(TransportKind::Quic);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("big.bin");
    write_data(&src, 96 * MIB, 4);

    let id = tx_node.m.send_files(to(addr, None), vec![src]).await.unwrap();
    let offer = rx_node.incoming().await;
    rx_node.m.accept_incoming(&offer.transfer_id, out).await.unwrap();
    let mid = wait_bytes(&tx_node.m, &id, 8 * MIB).await;
    assert_eq!(mid.state, TransferState::Transferring);
    tx_node.m.shutdown().await.unwrap();
    // shutdown() returned only after the job ended and its last callbacks were delivered.
    assert_eq!(tx_node.m.transfer(&id).await.unwrap().state, TransferState::Interrupted);
    assert_eq!(tx_node.final_state(&id).await, TransferState::Interrupted);
    // The sender told the receiver before exiting (QUIC drained).
    assert_eq!(rx_node.final_state(&offer.transfer_id).await, TransferState::Cancelled);
    assert!(matches!(tx_node.m.listen("127.0.0.1:0".parse().unwrap()).await, Err(EngineError::ShuttingDown)));
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_observer_gets_coalesced_progress_and_does_not_stall_the_transfer() {
    let slow = Duration::from_millis(250);
    let mut rx_node = trusting(TransportKind::Tcp, "receiver", None);
    let out = rx_node.root.join("out");
    let mut tx_node = node(TransportKind::Tcp, "sender", Policy { verify: Some(true), accept_into: None }, |_| {}, Some(slow));
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("big.bin");
    let size = 64 * MIB;
    write_data(&src, size, 5);

    let started = Instant::now();
    let id = tx_node.m.send_files(to(addr, None), vec![src.clone()]).await.unwrap();
    let offer = rx_node.incoming().await;
    rx_node.m.accept_incoming(&offer.transfer_id, out.clone()).await.unwrap();
    assert_eq!(rx_node.final_state(&offer.transfer_id).await, TransferState::Completed);
    let took = started.elapsed();
    // The engine finished regardless of the observer: the sender's snapshot is
    // already Completed even if its callbacks are still queued behind slow ones.
    let deadline = Instant::now() + WAIT;
    while tx_node.m.transfer(&id).await.unwrap().state != TransferState::Completed {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(tx_node.final_state(&id).await, TransferState::Completed);
    let p = tx_node.progress_of(&id);
    // Each callback blocks 250 ms, so at most one per 250 ms got through, plus the final one.
    let bound = (took.as_millis() / slow.as_millis()) as usize + 2;
    assert!(p.len() <= bound, "{} progress callbacks in {took:?}", p.len());
    assert_eq!(p.last().unwrap().bytes_done, size);
    assert_same(&src, &out.join("big.bin"));

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progress_rate_is_capped_per_transfer() {
    let mut rx_node = trusting(TransportKind::Tcp, "receiver", None);
    let out = rx_node.root.join("out");
    let mut tx_node = slow_sender(TransportKind::Tcp);
    let addr = rx_node.listen().await;
    let src = tx_node.root.join("big.bin");
    write_data(&src, 64 * MIB, 6);

    let started = Instant::now();
    let id = tx_node.m.send_files(to(addr, None), vec![src]).await.unwrap();
    let offer = rx_node.incoming().await;
    rx_node.m.accept_incoming(&offer.transfer_id, out).await.unwrap();
    assert_eq!(tx_node.final_state(&id).await, TransferState::Completed);
    let took = started.elapsed();
    let p = tx_node.progress_of(&id);
    // 100 ms interval → ≤ 10 Hz, plus the final snapshot.
    let bound = (took.as_millis() / 100) as usize + 2;
    assert!(p.len() <= bound, "{} progress callbacks in {took:?}", p.len());
    // While transferring, the rolling rate is reported from the first tick (the
    // window is seeded when Transferring starts). A fast runner can move all
    // 64 MiB within one or two ticks; it used to report 0 B/s there. If the whole
    // data phase fell between ticks there are no Transferring snapshots to check.
    let transferring: Vec<_> = p.iter().filter(|t| t.state == TransferState::Transferring).collect();
    assert!(transferring.is_empty() || transferring.iter().any(|t| t.throughput_bytes_per_sec > 0), "no throughput in {p:?}");

    tx_node.m.shutdown().await.unwrap();
    rx_node.m.shutdown().await.unwrap();
}
