//! QUIC-specific behaviour: TLS identity binding (manual §12.1) and refusal of
//! peers whose certificate is not an Ed25519 identity (manual §34).
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crypto::{DeviceIdentity, fingerprint_of};
use protocol::MsgType;
use protocol::header::Header;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use transport::quic::ALPN;
use transport::{Listener, QuicConfig, QuicTransport, Transport, TransportError, TransportKind};

fn quic(id: &DeviceIdentity) -> QuicTransport {
    QuicTransport::new(id, QuicConfig::default()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_sides_report_the_authenticated_peer_key() {
    let (server_id, client_id) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
    let mut l = quic(&server_id).listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let client = quic(&client_id);
    let (c, s) = tokio::join!(client.connect(addr, 2), l.accept());
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    assert_eq!((c.kind, s.kind), (TransportKind::Quic, TransportKind::Quic));
    assert_eq!(c.peer_key, Some(server_id.public_key_bytes()));
    assert_eq!(s.peer_key, Some(client_id.public_key_bytes()));
    assert_eq!(c.peer_fingerprint(), Some(server_id.fingerprint()));
    assert_eq!(s.peer_fingerprint(), Some(client_id.fingerprint()));

    // A peer that is not the one the user scanned/confirmed is visible as such:
    // the transport reports who actually answered, the caller rejects it.
    let expected = DeviceIdentity::generate().unwrap();
    assert_ne!(c.peer_fingerprint(), Some(expected.fingerprint()));
    assert_ne!(c.peer_key.map(|k| fingerprint_of(&k)), Some(expected.fingerprint()));

    // The authenticated connection carries frames.
    c.control.writer.write_frame(&Header::new(MsgType::Ping, 0, 0, 7, 2), &[b"hi"]).await.unwrap();
    let (h, body) = s.control.reader.read_frame().await.unwrap().unwrap();
    assert_eq!((h.sequence_number, &body[..]), (7, &b"hi"[..]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_written_before_drop_is_delivered() {
    // Dropping every handle of a quinn connection would close it with data still
    // unacknowledged; the writer's linger must deliver it like TCP close does.
    let mut l = quic(&DeviceIdentity::generate().unwrap()).listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let client = quic(&DeviceIdentity::generate().unwrap());
    let (c, s) = tokio::join!(client.connect(addr, 1), l.accept());
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    let body = vec![5u8; 8 << 20];
    c.data[0].writer.write_frame(&Header::new(MsgType::ChunkData, 0, 0, 0, body.len() as u32), &[&body]).await.unwrap();
    drop(c);
    let h = s.data[0].reader.read_header().await.unwrap().unwrap();
    let mut dst = vec![0u8; body.len()];
    s.data[0].reader.read_body_into(&h, &mut dst).await.unwrap();
    assert!(dst == body);
    assert!(s.data[0].reader.read_header().await.unwrap().is_none());
}

/// A raw quinn server presenting `cert`/`key` instead of a DFTE identity.
fn rogue_server(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> quinn::Endpoint {
    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);
    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let signer = provider.key_provider.load_private_key(key).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_no_client_auth().with_cert_resolver(Arc::new(Fixed(Arc::new(CertifiedKey::new(vec![cert], signer)))));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server = ep.clone();
    tokio::spawn(async move {
        while let Some(inc) = server.accept().await {
            let _ = inc.await; // handshake must fail
        }
    });
    ep
}

async fn connect_to_rogue(addr: SocketAddr) -> transport::Result<transport::Connection> {
    let t = quic(&DeviceIdentity::generate().unwrap());
    tokio::time::timeout(Duration::from_secs(5), t.connect(addr, 1)).await.expect("refusal must be prompt, not a hang")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_ed25519_server_certificate_is_refused() {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["dfte.peer".to_owned()]).unwrap().self_signed(&pair).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der()));
    let ep = rogue_server(cert.der().clone(), key);
    let err = connect_to_rogue(ep.local_addr().unwrap()).await.err().unwrap();
    assert!(matches!(err, TransportError::QuicConnection(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_server_certificate_is_refused() {
    // Valid Ed25519 signing key, but the "certificate" is junk bytes.
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der()));
    let ep = rogue_server(CertificateDer::from(vec![0xAB; 300]), key);
    let err = connect_to_rogue(ep.local_addr().unwrap()).await.err().unwrap();
    assert!(matches!(err, TransportError::QuicConnection(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_without_identity_does_not_break_listener() {
    // A client that offers no certificate is refused (mutual auth), and the
    // listener keeps serving the next, legitimate peer.
    let mut l = quic(&DeviceIdentity::generate().unwrap()).listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move { l.accept().await.unwrap() });

    #[derive(Debug)]
    struct AcceptAny;
    impl rustls::client::danger::ServerCertVerifier for AcceptAny {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().dangerous().with_custom_certificate_verifier(Arc::new(AcceptAny)).with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let cfg = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()));
    let anon = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    // The TLS 1.3 client may consider the handshake done before the server
    // rejects it; either way no stream may ever be accepted for it.
    if let Ok(conn) = anon.connect_with(cfg, addr, "x").unwrap().await {
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
    }

    let good_id = DeviceIdentity::generate().unwrap();
    let _good = quic(&good_id).connect(addr, 1).await.unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    assert_eq!(accepted.peer_key, Some(good_id.public_key_bytes()));
}
