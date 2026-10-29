//! QUIC backend (manual §15: default on Linux/Android/iOS), built on `quinn`.
//!
//! # Identity = TLS (manual §12.1)
//! Each side presents a self-signed X.509 certificate whose key *is* the
//! device's Ed25519 identity key; there is no CA. Authentication is mutual:
//! the server demands a client certificate. The custom verifiers below accept
//! any certificate whose public key is Ed25519 (validity dates, names and the
//! self-signature are irrelevant: possession of the key is proven by the TLS 1.3
//! `CertificateVerify` signature, which *is* checked), and the authenticated key
//! is surfaced as [`Connection::peer_key`](crate::Connection::peer_key). Deciding
//! whether that key is the expected peer (SAS comparison, QR fingerprint, pinned
//! trust) is the caller's job; the transport only guarantees the peer holds it.
//!
//! # Stream grouping
//! A connection is one control bi-stream plus N data bi-streams. QUIC stream
//! opening is lazy (the peer only learns of a stream once a frame for it
//! arrives), so the connecting side writes a 4-byte preamble on every stream
//! right after opening it: `b"DQ" | index: u8 | total: u8`, index 0 being the
//! control stream. The accepting side reads the preamble of each accepted
//! stream and slots it by index, so arrival order does not matter.
//!
//! # Closing
//! Dropping every handle of a quinn connection closes it immediately and drops
//! unacknowledged data. To match TCP's "close after write still delivers"
//! behaviour, a dropped data/control writer finishes its stream and keeps the
//! connection alive on a background task until the peer has acknowledged all
//! of that stream's data (bounded by [`QuicConfig::linger`]).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crypto::DeviceIdentity;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{EndpointConfig, IdleTimeout, MtuDiscoveryConfig, RecvStream, SendStream, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, PeerMisbehaved, SignatureScheme};
use tokio::io::AsyncWrite;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::framed::FramedStream;
use crate::{Connection, Listener, MAX_DATA_STREAMS, Result, Transport, TransportError, TransportKind};

/// ALPN protocol id; QUIC requires one (RFC 9001 §8.1).
pub const ALPN: &[u8] = b"dfte/1";
/// SNI sent by clients. Ignored by the verifier: identity is the key, not a name.
const SERVER_NAME: &str = "dfte.peer";

const PREAMBLE_MAGIC: &[u8; 2] = b"DQ";
const PREAMBLE_LEN: usize = 4;
/// In-flight handshakes kept at once; bounds work under a connection flood (manual §34).
const MAX_PENDING_HANDSHAKES: usize = 32;

/// PKCS#8 v1 wrapper for a raw Ed25519 seed (RFC 8410 §7): `SEQUENCE { INTEGER 0,
/// SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }`.
const ED25519_PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
/// DER SubjectPublicKeyInfo prefix for an Ed25519 key (RFC 8410 §4); the 32 key bytes follow.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Congestion controller (manual §11: use quinn's, swappable, not hand-tuned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    #[default]
    Cubic,
    Bbr,
    NewReno,
}

/// Tuned for a single-hop, low-RTT bulk link (manual §11/§16): flow-control
/// windows far above quinn's WAN-oriented defaults so a 4 MiB chunk per stream
/// never waits on a window update.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Per-stream receive window (bytes). Keep at or below
    /// [`MAX_SAFE_STREAM_WINDOW`]: quinn kills a connection whose stream
    /// buffer holds more than 1024 separate out-of-order pieces ("too many
    /// gaps in stream buffer"), and a large window plus a burst of UDP loss
    /// can create that many holes. This happened on Windows CI with 16 MiB.
    pub stream_receive_window: u64,
    /// Connection-wide receive window (bytes).
    pub receive_window: u64,
    /// Connection-wide unacknowledged send buffer (bytes).
    pub send_window: u64,
    pub congestion: CongestionControl,
    /// Packets that must be acknowledged after a missing one before it is
    /// declared lost (RFC 9002 kPacketThreshold, default 3). Higher tolerates
    /// reordering better at the cost of slower loss detection.
    pub packet_threshold: u32,
    /// Time-based loss threshold as a multiple of RTT (RFC 9002 kTimeThreshold, 9/8).
    pub time_threshold: f32,
    pub keep_alive: Option<Duration>,
    pub idle_timeout: Duration,
    /// Time a peer gets to finish the TLS handshake and open every stream.
    pub handshake_timeout: Duration,
    /// Path MTU discovery (probes up from `initial_mtu`).
    pub mtu_discovery: bool,
    pub initial_mtu: u16,
    /// UDP socket buffers; `None` keeps the OS default. The kernel silently caps
    /// the request at `net.core.{r,w}mem_max` (4 MiB on the dev box).
    pub socket_send_buffer: Option<usize>,
    pub socket_recv_buffer: Option<usize>,
    /// Upper bound for keeping a connection alive after a writer is dropped, so its
    /// data is acknowledged before the connection closes (see module docs).
    pub linger: Duration,
}

/// quinn-proto's per-stream limit on separate buffered pieces (`MAX_CHUNKS`).
const QUINN_MAX_STREAM_GAPS: u64 = 1024;
/// Smallest datagram a QUIC packet carries (RFC 9000 §14); each lost packet
/// opens at most one hole of at least this size.
const MIN_QUIC_PACKET: u64 = 1200;
/// Largest per-stream window where even worst-case loss can't exceed quinn's
/// gap limit (~1.17 MiB). On a single-hop link (2-5 ms RTT) 1 MiB per stream
/// still allows hundreds of MiB/s per stream; measured on loopback: no loss.
pub const MAX_SAFE_STREAM_WINDOW: u64 = QUINN_MAX_STREAM_GAPS * MIN_QUIC_PACKET;

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            stream_receive_window: 1 << 20,
            receive_window: 64 << 20,
            send_window: 64 << 20,
            congestion: CongestionControl::Cubic,
            packet_threshold: 3,
            time_threshold: 9.0 / 8.0,
            keep_alive: Some(Duration::from_secs(5)),
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            mtu_discovery: true,
            initial_mtu: 1200,
            // The default ~208 KiB receive buffer overflowed under a 4 MiB-chunk
            // burst on loopback (~1.8k RcvbufErrors per bench run, each one a
            // loss event that halves Cubic's window); 8 MiB requested
            // (kernel-capped) brought that to 0. See the phase-5 perf notes.
            socket_send_buffer: Some(8 << 20),
            socket_recv_buffer: Some(8 << 20),
            linger: Duration::from_secs(10),
        }
    }
}

impl QuicConfig {
    fn transport(&self) -> Result<Arc<quinn::TransportConfig>> {
        // Deliberate clamp: a window above the 2^62 varint limit just means "unbounded".
        let var = |v: u64| VarInt::from_u64(v).unwrap_or(VarInt::MAX);
        let mut t = quinn::TransportConfig::default();
        if self.packet_threshold < 3 || !(self.time_threshold >= 1.0 && self.time_threshold.is_finite()) {
            return Err(TransportError::InvalidConfig("packet_threshold must be >= 3 and time_threshold >= 1.0 (RFC 9002)"));
        }
        if self.stream_receive_window > MAX_SAFE_STREAM_WINDOW {
            return Err(TransportError::InvalidConfig("stream_receive_window above MAX_SAFE_STREAM_WINDOW (quinn gap limit)"));
        }
        t.stream_receive_window(var(self.stream_receive_window)).receive_window(var(self.receive_window)).send_window(self.send_window).max_concurrent_bidi_streams(VarInt::from_u32(MAX_DATA_STREAMS as u32 + 1)).max_concurrent_uni_streams(VarInt::from_u32(0)).datagram_receive_buffer_size(None).keep_alive_interval(self.keep_alive).max_idle_timeout(Some(IdleTimeout::try_from(self.idle_timeout).map_err(|_| TransportError::InvalidConfig("idle_timeout"))?)).initial_mtu(self.initial_mtu).mtu_discovery_config(self.mtu_discovery.then(MtuDiscoveryConfig::default)).packet_threshold(self.packet_threshold).time_threshold(self.time_threshold);
        match self.congestion {
            CongestionControl::Cubic => t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            CongestionControl::Bbr => t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            CongestionControl::NewReno => t.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())),
        };
        Ok(Arc::new(t))
    }
}

/// Linger tasks and endpoints that must finish before the process may exit
/// (see [`Transport::drain`]). Shared by a transport, its listeners and writers.
#[derive(Clone, Default)]
struct Drainer(Arc<std::sync::Mutex<DrainState>>);

#[derive(Default)]
struct DrainState {
    lingers: Vec<tokio::task::JoinHandle<()>>,
    endpoints: Vec<quinn::Endpoint>,
}

impl Drainer {
    fn state(&self) -> std::sync::MutexGuard<'_, DrainState> {
        // A panic while holding this lock can only interrupt a Vec push or take;
        // the state is still consistent, so poisoning is recovered, not fatal.
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add_linger(&self, h: tokio::task::JoinHandle<()>) {
        let mut st = self.state();
        st.lingers.retain(|t| !t.is_finished());
        st.lingers.push(h);
    }

    fn add_endpoint(&self, ep: &quinn::Endpoint) {
        self.state().endpoints.push(ep.clone());
    }

    async fn drain(&self, linger: Duration) -> Result<()> {
        let (lingers, endpoints) = {
            let mut st = self.state();
            (std::mem::take(&mut st.lingers), st.endpoints.clone())
        };
        let mut timed_out = false;
        let deadline = tokio::time::Instant::now() + linger;
        for h in lingers {
            match tokio::time::timeout_at(deadline, h).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_cancelled() => {}
                Ok(Err(e)) => std::panic::resume_unwind(e.into_panic()),
                Err(_) => timed_out = true,
            }
        }
        // Every stream is delivered (or given up on); let the connections close
        // gracefully so the peer gets CONNECTION_CLOSE rather than silence.
        for ep in &endpoints {
            if tokio::time::timeout_at(deadline, ep.wait_idle()).await.is_err() {
                timed_out = true;
            }
        }
        if timed_out {
            tracing::warn!(?linger, "quic: drain timed out with data or connections still pending");
            return Err(TransportError::Timeout);
        }
        Ok(())
    }
}

/// QUIC transport bound to one device identity.
#[derive(Clone)]
pub struct QuicTransport {
    config: QuicConfig,
    client: quinn::ClientConfig,
    server: quinn::ServerConfig,
    drainer: Drainer,
}

impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransport").field("config", &self.config).finish_non_exhaustive()
    }
}

impl QuicTransport {
    /// Builds client and server TLS configs presenting `identity` (manual §12.1).
    pub fn new(identity: &DeviceIdentity, config: QuicConfig) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(Ed25519PeerVerifier { algs: provider.signature_verification_algorithms });
        let (cert, key) = identity_certificate(identity)?;
        let transport = config.transport()?;

        let mut tls_client = rustls::ClientConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&rustls::version::TLS13])?.dangerous().with_custom_certificate_verifier(verifier.clone()).with_client_auth_cert(vec![cert.clone()], key.clone_key())?;
        tls_client.alpn_protocols = vec![ALPN.to_vec()];
        let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_client).map_err(|_| TransportError::InvalidConfig("tls client"))?));
        client.transport_config(transport.clone());

        let mut tls_server = rustls::ServerConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13])?.with_client_cert_verifier(verifier).with_single_cert(vec![cert], key)?;
        tls_server.alpn_protocols = vec![ALPN.to_vec()];
        tls_server.max_early_data_size = 0;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_server).map_err(|_| TransportError::InvalidConfig("tls server"))?));
        server.transport_config(transport);

        Ok(Self { config, client, server, drainer: Drainer::default() })
    }

    pub fn config(&self) -> &QuicConfig {
        &self.config
    }

    fn endpoint(&self, bind: SocketAddr, server: Option<quinn::ServerConfig>) -> Result<quinn::Endpoint> {
        let sock = socket2::Socket::new(socket2::Domain::for_address(bind), socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        if let Some(n) = self.config.socket_send_buffer {
            sock.set_send_buffer_size(n)?;
        }
        if let Some(n) = self.config.socket_recv_buffer {
            sock.set_recv_buffer_size(n)?;
        }
        sock.bind(&bind.into())?;
        let ep = quinn::Endpoint::new(EndpointConfig::default(), server, sock.into(), Arc::new(quinn::TokioRuntime))?;
        self.drainer.add_endpoint(&ep);
        Ok(ep)
    }
}

impl Transport for QuicTransport {
    type Listener = QuicListener;

    fn kind(&self) -> TransportKind {
        TransportKind::Quic
    }

    async fn listen(&self, addr: SocketAddr) -> Result<QuicListener> {
        let endpoint = self.endpoint(addr, Some(self.server.clone()))?;
        Ok(QuicListener { endpoint, config: self.config.clone(), pending: JoinSet::new(), drainer: self.drainer.clone() })
    }

    async fn connect(&self, addr: SocketAddr, data_streams: usize) -> Result<Connection> {
        if data_streams == 0 || data_streams > MAX_DATA_STREAMS {
            return Err(TransportError::InvalidStreamCount(data_streams));
        }
        let bind = SocketAddr::new(if addr.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) }, 0);
        let endpoint = self.endpoint(bind, None)?;
        let (linger, drainer) = (self.config.linger, self.drainer.clone());
        let setup = async {
            let conn = endpoint.connect_with(self.client.clone(), addr, SERVER_NAME)?.await?;
            let peer_key = peer_key(&conn)?;
            let total = data_streams + 1;
            let mut streams = Vec::with_capacity(total);
            for index in 0..total {
                let (mut send, recv) = conn.open_bi().await?;
                send.write_all(&preamble(index as u8, total as u8)).await.map_err(io::Error::from)?;
                streams.push(framed(send, recv, linger, &drainer));
            }
            let mut streams = streams.into_iter();
            let control = streams.next().ok_or(TransportError::InvalidStreamCount(0))?;
            Ok(Connection { kind: TransportKind::Quic, peer: addr, peer_key: Some(peer_key), control, data: streams.collect() })
        };
        tokio::time::timeout(self.config.handshake_timeout, setup).await.map_err(|_| TransportError::Timeout)?
    }

    async fn drain(&self) -> Result<()> {
        self.drainer.drain(self.config.linger).await
    }
}

pub struct QuicListener {
    endpoint: quinn::Endpoint,
    config: QuicConfig,
    pending: JoinSet<Result<Connection>>,
    drainer: Drainer,
}

impl QuicListener {
    /// What [`Listener::drain`] needs, detached so the listener itself can move into a task.
    pub(crate) fn drain_handle(&self) -> ListenerDrain {
        ListenerDrain { drainer: self.drainer.clone(), linger: self.config.linger }
    }
}

pub(crate) struct ListenerDrain {
    drainer: Drainer,
    linger: Duration,
}

impl ListenerDrain {
    pub(crate) async fn drain(&self) -> Result<()> {
        self.drainer.drain(self.linger).await
    }
}

impl Listener for QuicListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Returns the next fully set-up connection. Handshakes run concurrently, so
    /// one slow or hostile peer cannot stall others; failed handshakes and bad
    /// preambles are dropped without failing the listener. Cancel-safe.
    async fn accept(&mut self) -> Result<Connection> {
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let incoming = incoming.ok_or(TransportError::Closed)?;
                    if self.pending.len() >= MAX_PENDING_HANDSHAKES {
                        incoming.refuse();
                        continue;
                    }
                    let (timeout, linger, drainer) = (self.config.handshake_timeout, self.config.linger, self.drainer.clone());
                    self.pending.spawn(async move { tokio::time::timeout(timeout, accept_one(incoming, linger, drainer)).await.map_err(|_| TransportError::Timeout)? });
                }
                Some(done) = self.pending.join_next(), if !self.pending.is_empty() => match done {
                    Ok(Ok(conn)) => return Ok(conn),
                    Ok(Err(e)) => tracing::debug!(error = %e, "quic: incoming connection rejected"),
                    Err(e) => tracing::debug!(error = %e, "quic: handshake task failed"),
                },
            }
        }
    }

    async fn drain(&self) -> Result<()> {
        self.drain_handle().drain().await
    }
}

async fn accept_one(incoming: quinn::Incoming, linger: Duration, drainer: Drainer) -> Result<Connection> {
    let conn = incoming.await?;
    let peer_key = peer_key(&conn)?;
    let mut slots: Vec<Option<FramedStream>> = Vec::new();
    loop {
        let (send, mut recv) = conn.accept_bi().await?;
        let mut p = [0u8; PREAMBLE_LEN];
        recv.read_exact(&mut p).await.map_err(|_| TransportError::BadPreamble)?;
        let (index, total) = parse_preamble(&p).ok_or(TransportError::BadPreamble)?;
        if slots.is_empty() {
            slots.resize_with(total, || None);
        }
        if total != slots.len() {
            return Err(TransportError::BadPreamble);
        }
        let slot = slots.get_mut(index).ok_or(TransportError::BadPreamble)?;
        if slot.replace(framed(send, recv, linger, &drainer)).is_some() {
            return Err(TransportError::BadPreamble);
        }
        if slots.iter().all(Option::is_some) {
            break;
        }
    }
    let mut streams = slots.into_iter().flatten();
    let control = streams.next().ok_or(TransportError::BadPreamble)?;
    Ok(Connection { kind: TransportKind::Quic, peer: conn.remote_address(), peer_key: Some(peer_key), control, data: streams.collect() })
}

fn framed(send: SendStream, recv: RecvStream, linger: Duration, drainer: &Drainer) -> FramedStream {
    FramedStream::new(Box::new(recv), Box::new(QuicWriter { stream: Some(send), linger, drainer: drainer.clone() }))
}

fn preamble(index: u8, total: u8) -> [u8; PREAMBLE_LEN] {
    [PREAMBLE_MAGIC[0], PREAMBLE_MAGIC[1], index, total]
}

/// `(index, total)` if well-formed.
fn parse_preamble(p: &[u8; PREAMBLE_LEN]) -> Option<(usize, usize)> {
    let (index, total) = (p[2] as usize, p[3] as usize);
    (&p[..2] == PREAMBLE_MAGIC && (2..=MAX_DATA_STREAMS + 1).contains(&total) && index < total).then_some((index, total))
}

/// The Ed25519 key the peer authenticated with during the TLS handshake.
fn peer_key(conn: &quinn::Connection) -> Result<[u8; 32]> {
    let certs = conn.peer_identity().and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok()).ok_or(TransportError::PeerIdentity)?;
    let leaf = certs.first().ok_or(TransportError::PeerIdentity)?;
    ed25519_key(leaf).map_err(|_| TransportError::PeerIdentity)
}

/// Extracts the Ed25519 public key from a certificate. Unparseable DER is
/// `BadEncoding`; a well-formed certificate with any other key type is
/// `ApplicationVerificationFailure`.
pub fn ed25519_key(cert: &CertificateDer<'_>) -> std::result::Result<[u8; 32], CertificateError> {
    let ee = webpki::EndEntityCert::try_from(cert).map_err(|_| CertificateError::BadEncoding)?;
    let spki = ee.subject_public_key_info();
    let spki: &[u8] = spki.as_ref();
    let key = spki.strip_prefix(&ED25519_SPKI_PREFIX[..]).ok_or(CertificateError::ApplicationVerificationFailure)?;
    key.try_into().map_err(|_| CertificateError::BadEncoding)
}

/// Self-signed certificate + PKCS#8 key for `identity`'s Ed25519 key.
fn identity_certificate(identity: &DeviceIdentity) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let seed = identity.secret_bytes();
    let mut pkcs8 = Zeroizing::new(Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + seed.len()));
    pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(seed.as_ref());
    let key = PrivatePkcs8KeyDer::from(pkcs8.to_vec());
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)?;
    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, identity.fingerprint());
    let cert = params.self_signed(&pair)?;
    Ok((cert.der().clone(), PrivateKeyDer::Pkcs8(key)))
}

/// Accepts any certificate carrying an Ed25519 key, for both TLS roles; the
/// handshake signature is still verified against that key (see module docs).
#[derive(Debug)]
struct Ed25519PeerVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl Ed25519PeerVerifier {
    fn check_cert(cert: &CertificateDer<'_>) -> std::result::Result<(), rustls::Error> {
        ed25519_key(cert).map(drop).map_err(rustls::Error::InvalidCertificate)
    }

    fn check_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
        }
        verify_tls13_signature(message, cert, dss, &self.algs)
    }
}

impl ServerCertVerifier for Ed25519PeerVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _server_name: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Self::check_cert(end_entity).map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only (RFC 9001).
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.check_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for Ed25519PeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _now: UnixTime) -> std::result::Result<ClientCertVerified, rustls::Error> {
        Self::check_cert(end_entity).map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.check_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// `SendStream` adapter whose `Drop` lingers until the stream's data is
/// acknowledged, instead of letting a last-handle drop close the connection
/// with data still in flight (see module docs).
struct QuicWriter {
    stream: Option<SendStream>,
    linger: Duration,
    drainer: Drainer,
}

impl QuicWriter {
    fn stream(&mut self) -> io::Result<Pin<&mut SendStream>> {
        self.stream.as_mut().map(Pin::new).ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
}

impl AsyncWrite for QuicWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut().stream() {
            Ok(s) => AsyncWrite::poll_write(s, cx, buf),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().stream() {
            Ok(s) => AsyncWrite::poll_flush(s, cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().stream() {
            Ok(s) => AsyncWrite::poll_shutdown(s, cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl Drop for QuicWriter {
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else { return };
        let rt = match tokio::runtime::Handle::try_current() {
            Ok(rt) => rt,
            Err(e) => {
                // Outside a runtime there is nothing to linger on; the stream's own
                // Drop still finishes it, delivery then depends on the connection staying up.
                tracing::debug!(error = %e, "quic: writer dropped outside a runtime, not lingering");
                return;
            }
        };
        let linger = self.linger;
        let task = rt.spawn(async move {
            // ClosedStream here means the caller already finished (shutdown) or the
            // stream was reset; both are expected, and stopped() below still applies.
            if let Err(e) = stream.finish() {
                tracing::trace!(error = %e, "quic: stream already finished");
            }
            match tokio::time::timeout(linger, stream.stopped()).await {
                Ok(Ok(None)) => {}
                Ok(Ok(Some(code))) => tracing::debug!(%code, "quic: peer stopped stream before reading it all"),
                Ok(Err(e)) => tracing::debug!(error = %e, "quic: connection ended before stream data was acknowledged"),
                Err(_) => tracing::debug!(?linger, "quic: linger expired before stream data was acknowledged"),
            }
        });
        // Registered so Transport::drain can wait for it before the process exits.
        self.drainer.add_linger(task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_stream_window_is_rejected() {
        let id = crypto::DeviceIdentity::generate().unwrap();
        let cfg = QuicConfig { stream_receive_window: MAX_SAFE_STREAM_WINDOW + 1, ..QuicConfig::default() };
        assert!(matches!(QuicTransport::new(&id, cfg), Err(TransportError::InvalidConfig(_))));
    }

    #[test]
    fn default_stream_window_stays_within_quinn_gap_limit() {
        assert!(QuicConfig::default().stream_receive_window <= MAX_SAFE_STREAM_WINDOW);
        // The connection window still covers every data stream at once.
        let c = QuicConfig::default();
        assert!(c.receive_window >= c.stream_receive_window * (MAX_DATA_STREAMS as u64 + 1));
    }

    #[test]
    fn preamble_roundtrip_and_rejects() {
        assert_eq!(parse_preamble(&preamble(1, 3)), Some((1, 3)));
        assert_eq!(parse_preamble(&preamble(3, 3)), None);
        assert_eq!(parse_preamble(&preamble(0, 1)), None);
        assert_eq!(parse_preamble(&preamble(0, 200)), None);
        let mut bad = preamble(0, 2);
        bad[0] = b'X';
        assert_eq!(parse_preamble(&bad), None);
    }

    #[test]
    fn identity_certificate_carries_identity_key() {
        let id = DeviceIdentity::from_secret_bytes(&[9u8; 32]);
        let (cert, key) = identity_certificate(&id).unwrap();
        assert_eq!(ed25519_key(&cert).unwrap(), id.public_key_bytes());
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
        assert_eq!(ed25519_key(&CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03])), Err(CertificateError::BadEncoding));
    }

    #[test]
    fn non_ed25519_certificate_is_rejected() {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x".to_owned()]).unwrap().self_signed(&pair).unwrap();
        assert_eq!(ed25519_key(cert.der()), Err(CertificateError::ApplicationVerificationFailure));
    }
}
