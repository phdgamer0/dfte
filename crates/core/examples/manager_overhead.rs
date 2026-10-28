//! Perf check: TransferManager vs the raw `send_files`/`receive` free functions,
//! loopback, same engine defaults (2 streams, 16 chunks in flight).
//!
//! `cargo run --release -p dfte-core --example manager_overhead -- <dir on tmpfs> [MiB] [runs]`
//!
//! Prints the median goodput per mode. "manager+slow-ui" uses an observer that
//! blocks 50 ms in every callback, to show a slow UI does not slow the transfer;
//! "raw + slow per-chunk callback" is the same 50 ms UI called directly from the
//! engine's per-chunk progress hook, i.e. without the manager's coalescing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dfte_core::{DeviceIdentity, IncomingOffer, ManagerConfig, ReceiveOptions, SendOptions, SendTarget, TransferManager, TransferObserver, TransferState, TrustAny, receive, send_files};
use tokio::sync::mpsc;
use transport::{Listener, QuicConfig, QuicTransport, TcpTransport, Transport, TransportKind};

fn id() -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::generate().unwrap())
}

fn fresh(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if p.exists() {
        std::fs::remove_dir_all(&p).unwrap();
    }
    std::fs::create_dir_all(&p).unwrap();
    p
}

async fn raw(kind: TransportKind, src: &Path, work: &Path, slow_progress: Option<Duration>) -> Duration {
    let (staging, out) = (fresh(work, "raw-staging"), fresh(work, "raw-out"));
    let cleanup = [staging.clone(), out.clone()];
    let mut sopts = SendOptions::new(id(), Arc::new(TrustAny));
    // Baseline for coalescing: a UI wired straight to the engine's per-chunk
    // progress callback, the way a front end on the free functions would be.
    if let Some(d) = slow_progress {
        sopts.common.progress = Some(Arc::new(move |_: &dfte_core::Progress| std::thread::sleep(d)));
    }
    let ropts = ReceiveOptions::new(id(), Arc::new(TrustAny));
    let paths = vec![src.to_path_buf()];
    let t = Instant::now();
    match kind {
        TransportKind::Tcp => {
            let mut l = TcpTransport::default().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = l.local_addr().unwrap();
            let rx = tokio::spawn(async move { receive(&mut l, &staging, &out, &ropts).await });
            send_files(&TcpTransport::default(), addr, &paths, &sopts).await.unwrap();
            rx.await.unwrap().unwrap();
        }
        TransportKind::Quic => {
            let rt = QuicTransport::new(&ropts.common.identity, QuicConfig::default()).unwrap();
            let mut l = rt.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = l.local_addr().unwrap();
            let rx = tokio::spawn(async move {
                let r = receive(&mut l, &staging, &out, &ropts).await;
                l.drain().await.unwrap();
                r
            });
            let st = QuicTransport::new(&sopts.common.identity, QuicConfig::default()).unwrap();
            send_files(&st, addr, &paths, &sopts).await.unwrap();
            rx.await.unwrap().unwrap();
            st.drain().await.unwrap();
        }
    }
    let took = t.elapsed();
    // Keep tmpfs usage at one payload copy per mode.
    for d in cleanup {
        std::fs::remove_dir_all(d).unwrap();
    }
    took
}

/// (transfer id, incoming offer, new state) as seen by the observer.
type Note = (String, Option<IncomingOffer>, Option<TransferState>);

struct Obs {
    tx: mpsc::UnboundedSender<Note>,
    delay: Option<Duration>,
    calls: Arc<AtomicU64>,
}

impl TransferObserver for Obs {
    fn on_progress(&self, _t: dfte_core::Transfer) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(d) = self.delay {
            std::thread::sleep(d);
        }
    }
    fn on_state_changed(&self, id: String, s: TransferState) {
        self.tx.send((id, None, Some(s))).unwrap();
    }
    fn on_incoming(&self, o: IncomingOffer) {
        self.tx.send((o.transfer_id.clone(), Some(o), None)).unwrap();
    }
}

fn manager(kind: TransportKind, root: &Path, delay: Option<Duration>, calls: &Arc<AtomicU64>) -> (TransferManager, mpsc::UnboundedReceiver<Note>) {
    let mut c = ManagerConfig::new(id(), root, "bench");
    c.transport = kind;
    c.verifier = Some(Arc::new(TrustAny));
    let m = TransferManager::new(c).unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    m.set_observer(Box::new(Obs { tx, delay, calls: Arc::clone(calls) }));
    (m, rx)
}

async fn until_done(rx: &mut mpsc::UnboundedReceiver<Note>, id: &str) {
    while let Some((i, _, s)) = rx.recv().await {
        if i == id
            && let Some(s) = s
            && !s.is_active()
        {
            assert_eq!(s, TransferState::Completed);
            return;
        }
    }
    panic!("observer closed");
}

async fn managed(kind: TransportKind, src: &Path, work: &Path, delay: Option<Duration>) -> (Duration, u64) {
    let calls = Arc::new(AtomicU64::new(0));
    let (r, mut rr) = manager(kind, &fresh(work, "m-rx"), None, &calls);
    let (s, mut sr) = manager(kind, &fresh(work, "m-tx"), delay, &calls);
    let out = fresh(work, "m-out");
    let out_dir = out.clone();
    let addr = r.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let t = Instant::now();
    let sid = s.send_files(SendTarget::Address { addr, expected_fingerprint: None }, vec![src.to_path_buf()]).await.unwrap();
    let offer = loop {
        if let Some((_, Some(o), _)) = rr.recv().await {
            break o;
        }
    };
    r.accept_incoming(&offer.transfer_id, out).await.unwrap();
    until_done(&mut rr, &offer.transfer_id).await;
    // The engine's own view: done when the snapshot says so, not when a slow
    // observer finally hears about it.
    while s.transfer(&sid).await.unwrap().state != TransferState::Completed {
        tokio::time::sleep(Duration::from_micros(200)).await;
    }
    let took = t.elapsed();
    s.shutdown().await.unwrap();
    r.shutdown().await.unwrap();
    if delay.is_none() {
        until_done(&mut sr, &sid).await;
    }
    std::fs::remove_dir_all(out_dir).unwrap();
    (took, calls.load(Ordering::Relaxed))
}

fn write_src(path: &Path, mib: u64) {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut buf = vec![0u8; (mib * 1024 * 1024) as usize];
    for chunk in buf.as_chunks_mut::<8>().0 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    std::fs::write(path, buf).unwrap();
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let work = PathBuf::from(args.get(1).expect("usage: manager_overhead <dir> [MiB] [runs]"));
    let mib: u64 = args.get(2).map_or(256, |s| s.parse().unwrap());
    let runs: usize = args.get(3).map_or(5, |s| s.parse().unwrap());
    std::fs::create_dir_all(&work).unwrap();
    let src = work.join("src.bin");
    write_src(&src, mib);
    let mb = (mib * 1024 * 1024) as f64 / 1e6;
    println!("payload {mib} MiB, {runs} runs, median MB/s");
    for kind in [TransportKind::Tcp, TransportKind::Quic] {
        let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
        let (mut calls_b, mut calls_c) = (0, 0);
        for _ in 0..runs {
            a.push(mb / raw(kind, &src, &work, None).await.as_secs_f64());
            let (d, n) = managed(kind, &src, &work, None).await;
            b.push(mb / d.as_secs_f64());
            calls_b = n;
            let (d, n) = managed(kind, &src, &work, Some(Duration::from_millis(50))).await;
            c.push(mb / d.as_secs_f64());
            calls_c = n;
        }
        let (ra, rb, rc) = (median(a), median(b), median(c));
        let direct = mb / raw(kind, &src, &work, Some(Duration::from_millis(50))).await.as_secs_f64();
        println!("{kind:?}: raw + slow per-chunk callback (uncoalesced) {direct:.0}");
        println!("{kind:?}: raw {ra:.0} | manager {rb:.0} ({:+.1}%, {calls_b} progress cb) | manager+slow-ui {rc:.0} ({:+.1}%, {calls_c} progress cb)", (rb / ra - 1.0) * 100.0, (rc / ra - 1.0) * 100.0);
    }
    std::fs::remove_dir_all(&work).unwrap();
}
