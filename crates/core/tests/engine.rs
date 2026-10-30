// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! End-to-end engine tests over loopback TCP (manual §32/§34).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dfte_core::secure::{Control, establish_initiator};
use dfte_core::{CommonOptions, DeviceIdentity, EngineError, ExpectFingerprint, PeerAuth, PeerVerifier, ReceiveOptions, SendOptions, TransferReport, TrustAny, receive, send_files};
use protocol::message::{CloseReason, Message};
use protocol::{FileEntry, Manifest};
use storage::{CHUNK_SIZE, hash_file_blocking};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::{Listener, TcpTransport, Transport};

const MIB: u64 = 1024 * 1024;

fn identity() -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::generate().unwrap())
}

fn send_opts(streams: usize, verifier: Arc<dyn PeerVerifier>) -> SendOptions {
    let mut o = SendOptions::new(identity(), verifier);
    o.streams = streams;
    o.common.handshake_timeout = Duration::from_secs(10);
    o.common.idle_timeout = Duration::from_secs(30);
    o.finalize_timeout = Duration::from_secs(60);
    o
}

fn recv_opts(verifier: Arc<dyn PeerVerifier>) -> ReceiveOptions {
    let mut o = ReceiveOptions::new(identity(), verifier);
    o.common.handshake_timeout = Duration::from_secs(10);
    o.common.idle_timeout = Duration::from_secs(30);
    o
}

/// Incompressible, deterministic bytes.
fn data(len: u64, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

struct Dirs {
    _root: tempfile::TempDir,
    src: PathBuf,
    staging: PathBuf,
    out: PathBuf,
}

fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    let staging = root.path().join("staging");
    let out = root.path().join("out");
    std::fs::create_dir_all(&src).unwrap();
    Dirs { src, staging, out, _root: root }
}

async fn listener() -> (transport::TcpListener, SocketAddr) {
    let l = TcpTransport::default().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, addr)
}

/// Runs one receive and one send concurrently; the receiver gets `connect_to`
/// overridden when a proxy sits in between.
async fn run_pair(d: &Dirs, paths: Vec<PathBuf>, sopts: SendOptions, ropts: ReceiveOptions, proxy: Option<Mode>) -> (Result<TransferReport, EngineError>, Result<TransferReport, EngineError>) {
    let (mut l, addr) = listener().await;
    let target = match proxy {
        Some(mode) => start_proxy(addr, mode).await,
        None => addr,
    };
    let (staging, out) = (d.staging.clone(), d.out.clone());
    let rx = tokio::spawn(async move { receive(&mut l, &staging, &out, &ropts).await });
    let tx = tokio::spawn(async move { send_files(&TcpTransport::default(), target, &paths, &sopts).await });
    let s = tokio::time::timeout(Duration::from_secs(120), tx).await.expect("sender hung").unwrap();
    let r = tokio::time::timeout(Duration::from_secs(120), rx).await.expect("receiver hung").unwrap();
    (s, r)
}

fn assert_same(a: &Path, b: &Path) {
    let (x, y) = (std::fs::read(a).unwrap(), std::fs::read(b).unwrap());
    assert!(x == y, "{} differs from {}", a.display(), b.display());
}

fn sidecars(staging: &Path) -> usize {
    std::fs::read_dir(staging).map(|rd| rd.filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".resume.json")).count()).unwrap_or(0)
}

fn build_tree(src: &Path) -> (PathBuf, PathBuf) {
    let dir = src.join("bundle");
    std::fs::create_dir_all(dir.join("nested/empty_dir")).unwrap();
    std::fs::write(dir.join("multi.bin"), data(2 * CHUNK_SIZE + 12_345, 1)).unwrap();
    std::fs::write(dir.join("empty.txt"), b"").unwrap();
    std::fs::write(dir.join("nested/ünïcødé 日本.txt"), "héllo wörld".repeat(100)).unwrap();
    let single = src.join("single.bin");
    std::fs::write(&single, data(MIB + 7, 2)).unwrap();
    (dir, single)
}

fn check_tree(d: &Dirs) {
    let b = d.out.join("bundle");
    assert_same(&d.src.join("bundle/multi.bin"), &b.join("multi.bin"));
    assert_same(&d.src.join("bundle/empty.txt"), &b.join("empty.txt"));
    assert_same(&d.src.join("bundle/nested/ünïcødé 日本.txt"), &b.join("nested/ünïcødé 日本.txt"));
    assert!(b.join("nested/empty_dir").is_dir());
    assert_same(&d.src.join("single.bin"), &d.out.join("single.bin"));
    assert_eq!(sidecars(&d.staging), 0, "sidecar removed after success");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_multi_file_round_trip() {
    let d = dirs();
    let (dir, single) = build_tree(&d.src);
    let seen: Arc<Mutex<Vec<PeerAuth>>> = Arc::default();
    let (s1, s2) = (seen.clone(), seen.clone());
    let sv = Arc::new(move |p: &PeerAuth| {
        s1.lock().unwrap().push(p.clone());
        true
    });
    let rv = Arc::new(move |p: &PeerAuth| {
        s2.lock().unwrap().push(p.clone());
        true
    });
    let sopts = send_opts(2, sv);
    let ropts = recv_opts(rv);
    let (sender_fp, receiver_fp) = (sopts.common.identity.fingerprint(), ropts.common.identity.fingerprint());
    let (s, r) = run_pair(&d, vec![dir, single], sopts, ropts, None).await;
    let (s, r) = (s.unwrap(), r.unwrap());
    check_tree(&d);

    assert_ne!(s.cipher, "plaintext");
    assert_eq!(s.cipher, r.cipher);
    assert_eq!(s.streams, 2);
    assert_eq!(s.files, 5);
    assert_eq!(s.bytes_total, r.bytes_total);
    assert_eq!(s.bytes_transferred, s.bytes_total);
    assert_eq!(s.chunks, 3 + 1 + 1);
    assert_eq!(s.retransmits, 0);
    assert_eq!(r.saved.len(), 5);
    assert_eq!(s.peer_fingerprint, receiver_fp);
    assert_eq!(r.peer_fingerprint, sender_fp);
    // Both screens showed the same SAS.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].sas, seen[1].sas);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_stream_and_many_streams() {
    for streams in [1, 4] {
        let d = dirs();
        let f = d.src.join("f.bin");
        std::fs::write(&f, data(5 * CHUNK_SIZE + 3, streams as u64)).unwrap();
        let mut sopts = send_opts(streams, Arc::new(TrustAny));
        sopts.in_flight_chunks = 2;
        let (s, r) = run_pair(&d, vec![f.clone()], sopts, recv_opts(Arc::new(TrustAny)), None).await;
        assert_eq!(s.unwrap().streams, streams);
        r.unwrap();
        assert_same(&f, &d.out.join("f.bin"));
    }
}

#[cfg(feature = "bench-insecure-plaintext")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plaintext_bench_mode_round_trip() {
    let d = dirs();
    let (dir, single) = build_tree(&d.src);
    let mut sopts = send_opts(2, Arc::new(TrustAny));
    sopts.insecure_plaintext = true;
    // Receiver didn't opt in: stays encrypted.
    let (s, r) = run_pair(&d, vec![dir.clone(), single.clone()], sopts.clone(), recv_opts(Arc::new(TrustAny)), None).await;
    assert_ne!(s.unwrap().cipher, "plaintext");
    r.unwrap();

    let d = dirs();
    let (dir, single) = build_tree(&d.src);
    let mut ropts = recv_opts(Arc::new(TrustAny));
    ropts.allow_insecure_plaintext = true;
    let (s, r) = run_pair(&d, vec![dir, single], sopts, ropts, None).await;
    assert_eq!(s.unwrap().cipher, "plaintext");
    assert_eq!(r.unwrap().cipher, "plaintext");
    check_tree(&d);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_after_sender_dies() {
    let d = dirs();
    let f = d.src.join("big.bin");
    std::fs::write(&f, data(10 * CHUNK_SIZE + 99, 3)).unwrap();
    let (mut l, addr) = listener().await;

    // First attempt: one stream, a 2-chunk window, and a progress hook that stalls
    // the sender after 3 confirmed chunks so the test can kill it mid-transfer.
    let (sig_tx, mut sig_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut sopts = send_opts(1, Arc::new(TrustAny));
    sopts.in_flight_chunks = 2;
    sopts.common.progress = Some(Arc::new(move |p: &dfte_core::Progress| {
        if p.chunks_done == 3 {
            let _ = sig_tx.send(());
            std::thread::sleep(Duration::from_millis(500));
        }
    }));
    let ropts = recv_opts(Arc::new(TrustAny));
    let (staging, out) = (d.staging.clone(), d.out.clone());
    let ropts2 = ropts.clone();
    let rx = tokio::spawn(async move {
        let r = receive(&mut l, &staging, &out, &ropts2).await;
        (r, l)
    });
    let paths = vec![f.clone()];
    let tx = tokio::spawn(async move { send_files(&TcpTransport::default(), addr, &paths, &sopts).await });
    tokio::time::timeout(Duration::from_secs(60), sig_rx.recv()).await.unwrap().unwrap();
    tx.abort();
    let (first, mut l) = tokio::time::timeout(Duration::from_secs(60), rx).await.unwrap().unwrap();
    assert!(matches!(first, Err(EngineError::PeerLost)), "{first:?}");
    assert_eq!(sidecars(&d.staging), 1, "resume sidecar kept");
    assert!(!d.out.join("big.bin").exists());

    // Second attempt resumes from the staged prefix.
    let (staging, out) = (d.staging.clone(), d.out.clone());
    let rx = tokio::spawn(async move { receive(&mut l, &staging, &out, &ropts).await });
    let s = send_files(&TcpTransport::default(), addr, std::slice::from_ref(&f), &send_opts(2, Arc::new(TrustAny))).await.unwrap();
    let r = rx.await.unwrap().unwrap();
    assert!(s.resumed_bytes >= 3 * CHUNK_SIZE, "resumed {}", s.resumed_bytes);
    assert_eq!(s.resumed_bytes, r.resumed_bytes);
    assert_eq!(s.bytes_transferred + s.resumed_bytes, s.bytes_total);
    assert_eq!(hash_file_blocking(d.out.join("big.bin")).unwrap(), hash_file_blocking(&f).unwrap());
    assert_eq!(sidecars(&d.staging), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malicious_manifest_path_is_rejected() {
    let d = dirs();
    let (mut l, addr) = listener().await;
    let (staging, out) = (d.staging.clone(), d.out.clone());
    let rx = tokio::spawn(async move { receive(&mut l, &staging, &out, &recv_opts(Arc::new(TrustAny))).await });

    // A hand-rolled sender that skips the engine's own manifest validation.
    let conn = TcpTransport::default().connect(addr, 1).await.unwrap();
    let mut sc = establish_initiator(conn, &CommonOptions::new(identity(), Arc::new(TrustAny)), false).await.unwrap();
    let mut m = Manifest::new(vec![FileEntry::file("ok.txt", 5, [0; 32]).unwrap()]).unwrap();
    m.files[0].relative_path = "../../etc/evil".into();
    sc.control_tx.send(&Message::ManifestOffer(m)).await.unwrap();
    let reply = sc.control_rx.recv().await.unwrap();
    assert_eq!(reply, Some(Control::Close(CloseReason::ProtocolViolation)));
    let r = rx.await.unwrap();
    assert!(matches!(r, Err(EngineError::UnsafePath(_))), "{r:?}");
    assert!(!d.out.parent().unwrap().join("etc").exists());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symlink_escape_is_rejected() {
    let d = dirs();
    let outside = d.out.parent().unwrap().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&d.out).unwrap();
    std::os::unix::fs::symlink(&outside, d.out.join("link")).unwrap();
    std::fs::create_dir_all(d.src.join("link")).unwrap();
    std::fs::write(d.src.join("link/x.txt"), b"payload").unwrap();
    let (s, r) = run_pair(&d, vec![d.src.join("link")], send_opts(1, Arc::new(TrustAny)), recv_opts(Arc::new(TrustAny)), None).await;
    assert!(matches!(r, Err(EngineError::UnsafePath(_))), "{r:?}");
    assert!(s.is_err());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "nothing written through the symlink");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_frame_tears_down_connection() {
    let d = dirs();
    let f = d.src.join("f.bin");
    std::fs::write(&f, data(3 * CHUNK_SIZE, 4)).unwrap();
    let (s, r) = run_pair(&d, vec![f], send_opts(1, Arc::new(TrustAny)), recv_opts(Arc::new(TrustAny)), Some(Mode::FlipBodyByte)).await;
    assert!(matches!(r, Err(EngineError::CorruptedData)), "{r:?}");
    assert!(s.is_err());
    assert!(!d.out.join("f.bin").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_frame_tears_down_connection() {
    let d = dirs();
    let f = d.src.join("f.bin");
    std::fs::write(&f, data(3 * CHUNK_SIZE, 5)).unwrap();
    let (s, r) = run_pair(&d, vec![f], send_opts(1, Arc::new(TrustAny)), recv_opts(Arc::new(TrustAny)), Some(Mode::ReplayFirstFrame)).await;
    assert!(matches!(r, Err(EngineError::CorruptedData)), "{r:?}");
    assert!(s.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_sas_blocks_transfer() {
    let d = dirs();
    let f = d.src.join("f.txt");
    std::fs::write(&f, b"secret").unwrap();
    let (s, r) = run_pair(&d, vec![f.clone()], send_opts(1, Arc::new(TrustAny)), recv_opts(Arc::new(|_: &PeerAuth| false)), None).await;
    assert!(matches!(r, Err(EngineError::AuthenticationFailed)), "{r:?}");
    assert!(matches!(s, Err(EngineError::ConnectionRejected | EngineError::PeerLost)), "{s:?}");
    assert!(!d.out.join("f.txt").exists());

    // Sender pinned to a different fingerprint (QR flow) refuses the receiver.
    let d = dirs();
    std::fs::write(d.src.join("f.txt"), b"secret").unwrap();
    let wrong = Arc::new(ExpectFingerprint("0000-0000-0000-0000-0000-0000".into()));
    let (s, r) = run_pair(&d, vec![d.src.join("f.txt")], send_opts(1, wrong), recv_opts(Arc::new(TrustAny)), None).await;
    assert!(matches!(s, Err(EngineError::AuthenticationFailed)), "{s:?}");
    assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manifest_hook_sees_offer_and_can_decline_before_any_write() {
    let d = dirs();
    let f = d.src.join("f.txt");
    std::fs::write(&f, b"hello").unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = Arc::clone(&seen);
    let mut ropts = recv_opts(Arc::new(TrustAny));
    ropts.on_manifest = Some(dfte_core::ManifestHook::new(move |m: &dfte_core::Manifest| {
        s2.lock().unwrap().extend(m.files.iter().map(|e| (e.relative_path.clone(), e.size)));
        false
    }));
    let (s, r) = run_pair(&d, vec![f], send_opts(1, Arc::new(TrustAny)), ropts, None).await;
    assert!(matches!(r, Err(EngineError::Cancelled)), "{r:?}");
    assert!(matches!(s, Err(EngineError::Cancelled)), "{s:?}");
    assert_eq!(*seen.lock().unwrap(), vec![("f.txt".to_owned(), 5)]);
    assert!(!d.staging.exists() || std::fs::read_dir(&d.staging).unwrap().next().is_none(), "nothing staged");
    assert!(!d.out.join("f.txt").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sender_cancel_keeps_receiver_resume_state() {
    let d = dirs();
    let f = d.src.join("f.bin");
    std::fs::write(&f, data(8 * CHUNK_SIZE, 6)).unwrap();
    let cancel = dfte_core::CancelHandle::new();
    let c = cancel.clone();
    let mut sopts = send_opts(1, Arc::new(TrustAny));
    sopts.in_flight_chunks = 2;
    sopts.common.cancel = Some(cancel);
    sopts.common.progress = Some(Arc::new(move |p: &dfte_core::Progress| {
        if p.chunks_done == 2 {
            c.cancel();
        }
    }));
    let (s, r) = run_pair(&d, vec![f], sopts, recv_opts(Arc::new(TrustAny)), None).await;
    assert!(matches!(s, Err(EngineError::Cancelled)), "{s:?}");
    assert!(matches!(r, Err(EngineError::Cancelled)), "{r:?}");
    assert_eq!(sidecars(&d.staging), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "1 GiB, run manually"]
async fn one_gib_round_trip() {
    let d = dirs();
    let f = d.src.join("big.bin");
    std::fs::write(&f, data(1024 * MIB, 7)).unwrap();
    let (s, r) = run_pair(&d, vec![f.clone()], send_opts(4, Arc::new(TrustAny)), recv_opts(Arc::new(TrustAny)), None).await;
    let s = s.unwrap();
    r.unwrap();
    eprintln!("1 GiB: {:.1} MiB/s", s.throughput_bytes_per_sec / MIB as f64);
    assert_eq!(hash_file_blocking(d.out.join("big.bin")).unwrap(), hash_file_blocking(&f).unwrap());
}

// --- adversarial proxy -------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Mode {
    /// Flip one byte inside the first data-stream frame body.
    FlipBodyByte,
    /// Forward the first data-stream frame twice.
    ReplayFirstFrame,
}

const PREAMBLE_LEN: usize = 26;
const HEADER_LEN: usize = protocol::header::HEADER_LEN;

async fn start_proxy(upstream: SocketAddr, mode: Mode) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            tokio::spawn(relay(c, upstream, mode));
        }
    });
    addr
}

async fn relay(client: tokio::net::TcpStream, upstream: SocketAddr, mode: Mode) {
    let Ok(server) = tokio::net::TcpStream::connect(upstream).await else { return };
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut sr, &mut cw).await;
    });
    let mut pre = [0u8; PREAMBLE_LEN];
    if cr.read_exact(&mut pre).await.is_err() || sw.write_all(&pre).await.is_err() {
        return;
    }
    // Preamble byte 24 is the stream index: 1 = first data stream.
    if pre[24] == 1 {
        let mut h = [0u8; HEADER_LEN];
        if cr.read_exact(&mut h).await.is_err() {
            return;
        }
        let len = u32::from_be_bytes([h[20], h[21], h[22], h[23]]) as usize;
        let mut body = vec![0u8; len];
        if cr.read_exact(&mut body).await.is_err() {
            return;
        }
        match mode {
            Mode::FlipBodyByte => {
                body[100] ^= 0x01;
                let _ = sw.write_all(&h).await;
                let _ = sw.write_all(&body).await;
            }
            Mode::ReplayFirstFrame => {
                for _ in 0..2 {
                    let _ = sw.write_all(&h).await;
                    let _ = sw.write_all(&body).await;
                }
            }
        }
    }
    let _ = tokio::io::copy(&mut cr, &mut sw).await;
    let _ = sw.shutdown().await;
}

/// A transport-proven key (QUIC TLS) that disagrees with the Noise identity must
/// fail authentication, even with a verifier that trusts anyone (manual §12.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_identity_must_match_noise_identity() {
    let (mut l, addr) = listener().await;
    let rx = tokio::spawn(async move {
        let conn = l.accept().await.unwrap();
        dfte_core::secure::establish_responder(conn, &CommonOptions::new(identity(), Arc::new(TrustAny)), 4, false).await
    });
    let mut conn = TcpTransport::default().connect(addr, 1).await.unwrap();
    conn.peer_key = Some([0x42; 32]);
    let r = establish_initiator(conn, &CommonOptions::new(identity(), Arc::new(TrustAny)), false).await;
    assert!(matches!(r, Err(EngineError::AuthenticationFailed)), "{:?}", r.as_ref().err());
    // The responder sees the session torn down rather than established-and-used.
    let _responder = rx.await.unwrap();
}

// --- QUIC backend ------------------------------------------------------------

fn quic(id: &DeviceIdentity) -> transport::QuicTransport {
    transport::QuicTransport::new(id, transport::QuicConfig::default()).unwrap()
}

/// The same encrypted, multi-file transfer over QUIC. Each side's TLS identity is
/// its engine identity, so the engine's TLS-vs-Noise identity check passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_encrypted_multi_file_round_trip() {
    let d = dirs();
    let (dir, single) = build_tree(&d.src);
    let sopts = send_opts(4, Arc::new(TrustAny));
    let ropts = recv_opts(Arc::new(TrustAny));
    let (sender_fp, receiver_fp) = (sopts.common.identity.fingerprint(), ropts.common.identity.fingerprint());
    let mut l = quic(&ropts.common.identity).listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let (staging, out) = (d.staging.clone(), d.out.clone());
    let rx = tokio::spawn(async move { receive(&mut l, &staging, &out, &ropts).await });
    let st = quic(&sopts.common.identity);
    let s = tokio::time::timeout(Duration::from_secs(120), send_files(&st, addr, &[dir, single], &sopts)).await.expect("sender hung").unwrap();
    let r = tokio::time::timeout(Duration::from_secs(120), rx).await.expect("receiver hung").unwrap().unwrap();
    check_tree(&d);
    assert_eq!((s.transport.as_str(), r.transport.as_str()), ("quic", "quic"));
    assert_ne!(s.cipher, "plaintext");
    assert_eq!(s.streams, 4);
    assert_eq!(s.bytes_transferred, s.bytes_total);
    assert_eq!(s.peer_fingerprint, receiver_fp);
    assert_eq!(r.peer_fingerprint, sender_fp);
}

/// A QUIC endpoint whose TLS identity differs from the engine identity is
/// rejected by the engine's identity cross-check (manual §12.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_tls_identity_must_be_the_engine_identity() {
    let d = dirs();
    let f = d.src.join("f.bin");
    std::fs::write(&f, data(MIB, 3)).unwrap();
    let ropts = recv_opts(Arc::new(TrustAny));
    let mut l = quic(&ropts.common.identity).listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let (staging, out) = (d.staging.clone(), d.out.clone());
    let rx = tokio::spawn(async move { receive(&mut l, &staging, &out, &ropts).await });
    let sopts = send_opts(1, Arc::new(TrustAny));
    // The sender's TLS certificate belongs to a different key than its Noise identity.
    let impostor = DeviceIdentity::generate().unwrap();
    let s = send_files(&quic(&impostor), addr, &[f], &sopts).await;
    assert!(s.is_err(), "sender must not succeed: {s:?}");
    let r = tokio::time::timeout(Duration::from_secs(60), rx).await.expect("receiver hung").unwrap();
    assert!(matches!(r, Err(EngineError::AuthenticationFailed)), "{r:?}");
    assert!(!d.out.join("f.bin").exists());
}

// --- hash cache ----------------------------------------------------------------

/// A re-send of an unchanged file reuses the cached hashes (no hashing pass) and
/// still delivers identical bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hash_cache_skips_rehash_on_resend() {
    let d = dirs();
    let f = d.src.join("f.bin");
    std::fs::write(&f, data(3 * CHUNK_SIZE + 99, 11)).unwrap();
    let cache = d.src.parent().unwrap().join("hash-cache");
    let mut first = send_opts(2, Arc::new(TrustAny));
    first.hash_cache_dir = Some(cache.clone());
    let (s, r) = run_pair(&d, vec![f.clone()], first, recv_opts(Arc::new(TrustAny)), None).await;
    s.unwrap();
    r.unwrap();
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1, "one cache entry written");

    std::fs::remove_dir_all(&d.out).unwrap();
    let mut again = send_opts(2, Arc::new(TrustAny));
    again.hash_cache_dir = Some(cache);
    let (s, r) = run_pair(&d, vec![f.clone()], again, recv_opts(Arc::new(TrustAny)), None).await;
    let (s, _r) = (s.unwrap(), r.unwrap());
    assert_eq!(hash_file_blocking(d.out.join("f.bin")).unwrap(), hash_file_blocking(&f).unwrap());
    // Asserted directly rather than by timing: on Windows CI a just-written cache
    // entry can be held by the virus scanner for ~0.2 s, longer than hashing 12 MiB.
    assert_eq!(s.hash_cache_hits, 1, "the resend must take its hashes from the cache");
}

/// A forged cache entry (wrong hashes for an unchanged file) must make the
/// transfer fail; it must never deliver a file (manual §20).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_hash_cache_entry_fails_safely() {
    let d = dirs();
    let f = d.src.join("f.bin");
    std::fs::write(&f, data(2 * CHUNK_SIZE + 5, 12)).unwrap();
    let cache_dir = d.src.parent().unwrap().join("hash-cache");
    let cache = storage::HashCache::open_blocking(&cache_dir).unwrap();
    let meta = std::fs::metadata(&f).unwrap();
    cache.put_blocking(&f, &meta, &[0xAB; 32], &[[0xCD; 32]; 3]).unwrap();
    let mut sopts = send_opts(1, Arc::new(TrustAny));
    sopts.hash_cache_dir = Some(cache_dir);
    let (s, r) = run_pair(&d, vec![f], sopts, recv_opts(Arc::new(TrustAny)), None).await;
    assert!(s.is_err(), "sender must fail: {s:?}");
    assert!(r.is_err(), "receiver must fail: {r:?}");
    assert!(!d.out.join("f.bin").exists(), "a file must never be delivered under forged hashes");
}
