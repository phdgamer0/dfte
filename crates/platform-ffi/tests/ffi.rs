// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Drives a transfer purely through the uniffi-exported surface, the way the
//! Kotlin/Swift bindings do: FFI records, string paths, the callback interfaces.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use platform_ffi::{DiscoveryFailure, EngineError, ErrorCode, ErrorInfo, IncomingOffer, LinkInfo, LinkKind, LinkRole, ManagerConfig, Peer, PeerSink, PlatformDiscovery, Transfer, TransferManager, TransferObserver, TransferState, TransportKind, VerifyRequest, fingerprint_of_identity, generate_identity};
use tokio::sync::mpsc;

#[derive(Debug)]
enum Ev {
    State(String, TransferState),
    Incoming(IncomingOffer),
    Verify(VerifyRequest),
    Progress(u64),
    Error(ErrorInfo),
    PeerFound(Peer),
}

struct Obs(mpsc::UnboundedSender<Ev>);

impl Obs {
    fn push(&self, e: Ev) {
        if self.0.send(e).is_err() {
            eprintln!("test stopped listening");
        }
    }
}

impl TransferObserver for Obs {
    fn on_progress(&self, t: Transfer) {
        self.push(Ev::Progress(t.bytes_done));
    }
    fn on_state_changed(&self, id: String, s: TransferState) {
        self.push(Ev::State(id, s));
    }
    fn on_peer_found(&self, p: Peer) {
        self.push(Ev::PeerFound(p));
    }
    fn on_peer_lost(&self, _h: String) {}
    fn on_error(&self, _id: Option<String>, e: ErrorInfo) {
        self.push(Ev::Error(e));
    }
    fn on_incoming(&self, o: IncomingOffer) {
        self.push(Ev::Incoming(o));
    }
    fn on_verify_peer(&self, r: VerifyRequest) {
        self.push(Ev::Verify(r));
    }
}

/// A fake platform backend: reports one peer pointing at `port` on loopback.
struct FakeRadio {
    port: Mutex<u16>,
    fingerprint: String,
}

#[async_trait::async_trait]
impl PlatformDiscovery for FakeRadio {
    async fn start_advertising(&self, fingerprint: String, public_key: Vec<u8>) -> Result<(), DiscoveryFailure> {
        assert_eq!(public_key.len(), 32);
        assert!(!fingerprint.is_empty());
        Ok(())
    }
    async fn start_scanning(&self, sink: Arc<PeerSink>) -> Result<(), DiscoveryFailure> {
        assert!(sink.peer_found(Peer { fingerprint: Some(self.fingerprint.clone()), display_name: "rx".into(), link_kind: LinkKind::WifiDirect, handle: "radio-1".into() }));
        Ok(())
    }
    async fn connect(&self, peer: Peer) -> Result<LinkInfo, DiscoveryFailure> {
        if peer.handle != "radio-1" {
            return Err(DiscoveryFailure::UnknownPeer);
        }
        let port = *self.port.lock().unwrap();
        Ok(LinkInfo { local_ip: Some("127.0.0.1".into()), peer_ip: Some("127.0.0.1".into()), peer_port: Some(port), interface: None, link_kind: LinkKind::WifiDirect, role: LinkRole::Client })
    }
    async fn stop(&self) -> Result<(), DiscoveryFailure> {
        Ok(())
    }
}

fn config(root: &std::path::Path, name: &str) -> ManagerConfig {
    ManagerConfig { identity_secret: generate_identity().unwrap(), storage_root: root.join(name).to_string_lossy().into_owned(), device_name: name.into(), transport: Some(TransportKind::Tcp), verify_timeout_ms: Some(10_000), accept_timeout_ms: Some(10_000), progress_interval_ms: None }
}

/// Answers verification requests and forwards everything else.
fn wire(m: &Arc<TransferManager>) -> mpsc::UnboundedReceiver<Ev> {
    let (raw_tx, mut raw) = mpsc::unbounded_channel();
    m.set_observer(Arc::new(Obs(raw_tx)));
    let (tx, rx) = mpsc::unbounded_channel();
    let weak = Arc::downgrade(m);
    tokio::spawn(async move {
        while let Some(ev) = raw.recv().await {
            if let (Ev::Verify(r), Some(m)) = (&ev, weak.upgrade()) {
                m.confirm_peer(r.request_id, true).unwrap();
            }
            if tx.send(ev).is_err() {
                return;
            }
        }
    });
    rx
}

async fn until<T>(rx: &mut mpsc::UnboundedReceiver<Ev>, mut f: impl FnMut(&Ev) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let ev = rx.recv().await.expect("observer gone");
            if let Some(t) = f(&ev) {
                return t;
            }
        }
    })
    .await
    .expect("timed out")
}

fn done(id: &str) -> impl FnMut(&Ev) -> Option<TransferState> + '_ {
    move |e| match e {
        Ev::State(i, s) if i == id && !matches!(s, TransferState::Pending | TransferState::Negotiating | TransferState::Transferring) => Some(*s),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfer_through_the_exported_api_with_platform_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let rx_cfg = config(dir.path(), "rx");
    let rx_fp = fingerprint_of_identity(rx_cfg.identity_secret.clone()).unwrap();
    let receiver = TransferManager::new(rx_cfg, None).unwrap();
    assert_eq!(receiver.fingerprint(), rx_fp);
    let radio = Arc::new(FakeRadio { port: Mutex::new(0), fingerprint: rx_fp.clone() });
    let sender = TransferManager::new(config(dir.path(), "tx"), Some(radio.clone())).unwrap();
    let mut rx_ev = wire(&receiver);
    let mut tx_ev = wire(&sender);

    let addr = receiver.listen("127.0.0.1:0".into()).await.unwrap();
    *radio.port.lock().unwrap() = addr.rsplit(':').next().unwrap().parse().unwrap();

    sender.start_scan().await.unwrap();
    let peer = until(&mut tx_ev, |e| match e {
        Ev::PeerFound(p) => Some(p.clone()),
        _ => None,
    })
    .await;
    assert_eq!(sender.peers(), vec![peer.clone()]);

    let src = dir.path().join("hello.bin");
    std::fs::write(&src, vec![7u8; 5 * 1024 * 1024 + 1]).unwrap();
    let id = sender.send_to_peer(peer, vec![src.to_string_lossy().into_owned()]).await.unwrap();

    let offer = until(&mut rx_ev, |e| match e {
        Ev::Incoming(o) => Some(o.clone()),
        _ => None,
    })
    .await;
    assert_eq!(offer.files.len(), 1);
    assert_eq!(offer.bytes_total, 5 * 1024 * 1024 + 1);
    let out = dir.path().join("out");
    receiver.accept_incoming(offer.transfer_id.clone(), out.to_string_lossy().into_owned()).await.unwrap();

    // Coalesced progress reaches 100% before the terminal state.
    until(&mut tx_ev, |e| matches!(e, Ev::Progress(b) if *b == 5 * 1024 * 1024 + 1).then_some(())).await;
    assert_eq!(until(&mut tx_ev, done(&id)).await, TransferState::Completed);
    assert_eq!(until(&mut rx_ev, done(&offer.transfer_id)).await, TransferState::Completed);
    assert_eq!(std::fs::read(out.join("hello.bin")).unwrap(), std::fs::read(&src).unwrap());
    let t = sender.transfer(id.clone()).await.unwrap();
    assert_eq!((t.state, t.bytes_done, t.transport), (TransferState::Completed, 5 * 1024 * 1024 + 1, TransportKind::Tcp));
    assert_eq!(t.peer_fingerprint.as_deref(), Some(rx_fp.as_str()));
    assert_eq!(receiver.transfers().await.len(), 1);

    // Errors cross as typed variants, not strings.
    assert!(matches!(sender.cancel("missing".into()).await, Err(EngineError::UnknownTransfer { .. })));
    assert!(matches!(sender.listen("not an address".into()).await, Err(EngineError::InvalidInput { .. })));
    assert!(matches!(TransferManager::new(ManagerConfig { identity_secret: vec![1, 2, 3], ..config(dir.path(), "bad") }, None), Err(EngineError::InvalidInput { .. })));

    sender.stop_scan().await.unwrap();
    sender.shutdown().await.unwrap();
    receiver.shutdown().await.unwrap();
    assert!(matches!(sender.send_to_address(addr, None, vec![]).await, Err(EngineError::ShuttingDown)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_peer_is_reported_with_an_error_code() {
    let dir = tempfile::tempdir().unwrap();
    let receiver = TransferManager::new(config(dir.path(), "rx"), None).unwrap();
    let sender = TransferManager::new(config(dir.path(), "tx"), None).unwrap();
    let _rx_ev = wire(&receiver);
    let mut tx_ev = wire(&sender);
    let addr = receiver.listen("127.0.0.1:0".into()).await.unwrap();
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"x").unwrap();
    // A QR code naming some other device: the handshake identity doesn't match.
    let id = sender.send_to_address(addr, Some("de-ad-be-ef".into()), vec![src.to_string_lossy().into_owned()]).await.unwrap();
    let err = until(&mut tx_ev, |e| match e {
        Ev::Error(i) => Some(i.clone()),
        _ => None,
    })
    .await;
    assert_eq!(err.code, ErrorCode::AuthenticationFailed);
    assert_eq!(until(&mut tx_ev, done(&id)).await, TransferState::Failed { code: ErrorCode::AuthenticationFailed });
    sender.shutdown().await.unwrap();
    receiver.shutdown().await.unwrap();
}
