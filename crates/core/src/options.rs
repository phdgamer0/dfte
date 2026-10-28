//! Caller-facing knobs: identity, peer verification, progress, cancellation.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crypto::DeviceIdentity;
use tokio::sync::Notify;

/// What the handshake established about the peer, shown to the user for the SAS /
/// fingerprint comparison (manual §12.1). Contains no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAuth {
    /// Short fingerprint of the peer's Ed25519 identity (manual §6).
    pub fingerprint: String,
    /// 6-digit short authentication string; identical on both screens unless MITM'd.
    pub sas: String,
    /// Self-reported, unauthenticated display name from `Hello`.
    pub device_name: String,
}

/// Decides whether an authenticated peer is the one the user means (manual §9.1
/// AUTHENTICATED → ESTABLISHED). `verify` may block (e.g. prompting on a terminal);
/// the engine calls it on a blocking-I/O thread.
pub trait PeerVerifier: Send + Sync {
    fn verify(&self, peer: &PeerAuth) -> bool;
}

impl<F: Fn(&PeerAuth) -> bool + Send + Sync> PeerVerifier for F {
    fn verify(&self, peer: &PeerAuth) -> bool {
        self(peer)
    }
}

/// Accepts every peer. Only for loopback benchmarks and tests: it removes the one
/// user-facing MITM protection (manual §35), so no UI may offer it.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustAny;

impl PeerVerifier for TrustAny {
    fn verify(&self, _peer: &PeerAuth) -> bool {
        true
    }
}

/// Accepts only a peer whose fingerprint matches (QR flow or a pinned peer,
/// manual §12.1). Comparison ignores case and separators.
#[derive(Debug, Clone)]
pub struct ExpectFingerprint(pub String);

impl PeerVerifier for ExpectFingerprint {
    fn verify(&self, peer: &PeerAuth) -> bool {
        let norm = |s: &str| s.chars().filter(char::is_ascii_hexdigit).map(|c| c.to_ascii_lowercase()).collect::<String>();
        let want = norm(&self.0);
        !want.is_empty() && want == norm(&peer.fingerprint)
    }
}

/// Snapshot passed to the progress callback.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub transfer_id: String,
    /// Bytes integrity-confirmed so far, including bytes resumed from a previous session.
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub chunks_done: u64,
    pub chunks_total: u64,
}

/// Progress callback. Called from the engine's event loop for every confirmed
/// chunk, so it must be cheap and must not block (hop to the UI thread, §22).
pub type ProgressFn = Arc<dyn Fn(&Progress) + Send + Sync>;

/// Cooperative cancellation (manual §9.2 Cancel). Cheap to clone; cancelling any
/// clone cancels the transfer. The peer is told with a `Cancel` message, and the
/// receiver keeps its resume state.
#[derive(Clone, Default)]
pub struct CancelHandle {
    inner: Arc<CancelInner>,
}

#[derive(Default)]
struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancelHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves once [`cancel`](Self::cancel) has been called.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl fmt::Debug for CancelHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelHandle").field("cancelled", &self.is_cancelled()).finish()
    }
}

/// Settings shared by both roles.
#[derive(Clone)]
pub struct CommonOptions {
    pub identity: Arc<DeviceIdentity>,
    pub verifier: Arc<dyn PeerVerifier>,
    /// Shown to the peer in `Hello`/`HelloAck`; unauthenticated.
    pub device_name: String,
    /// Bound on each Noise handshake round trip.
    pub handshake_timeout: Duration,
    /// Longest silence tolerated from the peer once established (covers the peer
    /// user's SAS confirmation and stalled transfers).
    pub idle_timeout: Duration,
    pub progress: Option<ProgressFn>,
    pub cancel: Option<CancelHandle>,
}

impl CommonOptions {
    pub fn new(identity: Arc<DeviceIdentity>, verifier: Arc<dyn PeerVerifier>) -> Self {
        Self { identity, verifier, device_name: default_device_name(), handshake_timeout: Duration::from_secs(30), idle_timeout: Duration::from_secs(300), progress: None, cancel: None }
    }
}

impl fmt::Debug for CommonOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonOptions").field("identity", &self.identity).field("device_name", &self.device_name).field("handshake_timeout", &self.handshake_timeout).field("idle_timeout", &self.idle_timeout).finish_non_exhaustive()
    }
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "dfte".to_owned())
}

/// Sender settings.
#[derive(Clone, Debug)]
pub struct SendOptions {
    pub common: CommonOptions,
    /// Parallel data streams to open (manual §11: 1–4 typical, transport max 16).
    pub streams: usize,
    /// Chunks sent but not yet integrity-acked; also the size of the sender's
    /// buffer pool, so memory is `in_flight_chunks × 4 MiB` (manual §14/§28).
    pub in_flight_chunks: usize,
    /// Resend a chunk whose `ChunkAck` hasn't arrived in this long (manual §9.3).
    pub ack_timeout: Duration,
    /// How long to wait for the receiver to verify and rename the files after the
    /// last chunk was acked.
    pub finalize_timeout: Duration,
    /// Threads for the pre-manifest BLAKE3 pass (0 = all cores).
    pub hash_threads: usize,
    /// Benchmark-only: ask the peer to skip data-stream AEAD (manual §30 #2).
    #[cfg(feature = "bench-insecure-plaintext")]
    pub insecure_plaintext: bool,
}

impl SendOptions {
    pub fn new(identity: Arc<DeviceIdentity>, verifier: Arc<dyn PeerVerifier>) -> Self {
        Self {
            common: CommonOptions::new(identity, verifier),
            streams: 2,
            in_flight_chunks: 16,
            ack_timeout: Duration::from_secs(30),
            finalize_timeout: Duration::from_secs(600),
            hash_threads: 0,
            #[cfg(feature = "bench-insecure-plaintext")]
            insecure_plaintext: false,
        }
    }
}

/// Receiver settings.
#[derive(Clone, Debug)]
pub struct ReceiveOptions {
    pub common: CommonOptions,
    /// Most data streams this side will use (the sender's request is clamped).
    pub max_streams: u8,
    /// Receive buffers (4 MiB each) shared by all data streams; bounds the bytes
    /// held between socket and disk.
    pub pool_buffers: usize,
    /// Persist the resume sidecar every N confirmed chunks (manual §19: 32 = 128 MiB).
    pub flush_every: u32,
    /// Benchmark-only: agree to unencrypted data streams if the sender asks.
    #[cfg(feature = "bench-insecure-plaintext")]
    pub allow_insecure_plaintext: bool,
}

impl ReceiveOptions {
    pub fn new(identity: Arc<DeviceIdentity>, verifier: Arc<dyn PeerVerifier>) -> Self {
        Self {
            common: CommonOptions::new(identity, verifier),
            max_streams: transport::MAX_DATA_STREAMS as u8,
            pool_buffers: 16,
            flush_every: storage::resume::DEFAULT_FLUSH_EVERY,
            #[cfg(feature = "bench-insecure-plaintext")]
            allow_insecure_plaintext: false,
        }
    }
}
