//! Handshake + session tests (manual §32 crypto crate, §34 adversarial cases).
#![allow(clippy::unwrap_used)]

use crypto::{CipherSuite, CryptoError, DeviceIdentity, Handshake, HandshakeOutcome, Session, TAG_LEN, negotiate};
use proptest::prelude::*;

/// Drive a full XX exchange between `init` and `resp`, returning both results.
fn run_xx(mut init: Handshake, mut resp: Handshake, suite: CipherSuite) -> ((Session, HandshakeOutcome), (Session, HandshakeOutcome)) {
    let m1 = init.write_message(b"hello").unwrap();
    assert_eq!(resp.read_message(&m1).unwrap(), b"hello");
    let m2 = resp.write_message(b"resp-payload").unwrap();
    assert_eq!(init.read_message(&m2).unwrap(), b"resp-payload");
    let m3 = init.write_message(b"").unwrap();
    assert_eq!(resp.read_message(&m3).unwrap(), b"");
    assert!(init.is_finished() && resp.is_finished());
    (init.into_session(suite).unwrap(), resp.into_session(suite).unwrap())
}

fn pair(suite: CipherSuite) -> (Session, Session) {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let ((sa, _), (sb, _)) = run_xx(Handshake::initiator(&a).unwrap(), Handshake::responder(&b).unwrap(), suite);
    (sa, sb)
}

#[test]
fn xx_round_trip_authenticates_both_sides() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let ((_, oa), (_, ob)) = run_xx(Handshake::initiator(&a).unwrap(), Handshake::responder(&b).unwrap(), CipherSuite::Aes256Gcm);

    assert_eq!(oa.remote_static, b.x25519_public_key());
    assert_eq!(ob.remote_static, a.x25519_public_key());
    assert_eq!(oa.remote_identity, b.public_key_bytes());
    assert_eq!(ob.remote_identity, a.public_key_bytes());
    assert_eq!(oa.remote_fingerprint, b.fingerprint());
    assert_eq!(ob.remote_fingerprint, a.fingerprint());

    assert_eq!(oa.sas, ob.sas);
    assert_eq!(oa.sas.len(), 6);
    assert!(oa.sas.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(oa.handshake_hash, ob.handshake_hash);

    oa.verify_fingerprint(&b.fingerprint()).unwrap();
    ob.verify_fingerprint(&b.fingerprint().to_uppercase().replace('-', "")).unwrap_err();
    ob.verify_fingerprint(&a.fingerprint().to_uppercase().replace('-', " ")).unwrap();
    assert!(matches!(oa.verify_fingerprint(""), Err(CryptoError::FingerprintMismatch)));
}

#[test]
fn turn_tracking() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut init = Handshake::initiator(&a).unwrap();
    let resp = Handshake::responder(&b).unwrap();
    assert!(init.is_my_turn() && !resp.is_my_turn());
    init.write_message(&[]).unwrap();
    assert!(!init.is_my_turn());
    assert!(matches!(init.into_session(CipherSuite::Aes256Gcm), Err(CryptoError::HandshakeNotFinished)));
}

#[test]
fn session_round_trip_both_suites_both_directions() {
    for suite in CipherSuite::ALL {
        let (mut a, mut b) = pair(suite);
        assert_eq!(a.suite(), suite);
        for seq in [0u64, 1, 2, 1 << 40, u64::MAX] {
            let aad = seq.to_be_bytes();
            let mut buf = b"chunk data".to_vec();
            a.seal_in_place(seq, &aad, &mut buf).unwrap();
            assert_eq!(buf.len(), 10 + TAG_LEN);
            assert_eq!(b.open_in_place(seq, &aad, &mut buf).unwrap(), b"chunk data");

            let mut back = b"reply".to_vec();
            b.seal_in_place(seq, &aad, &mut back).unwrap();
            assert_eq!(a.open_in_place(seq, &aad, &mut back).unwrap(), b"reply");
        }
    }
}

#[test]
fn directions_use_distinct_keys() {
    let (mut a, mut b) = pair(CipherSuite::ChaCha20Poly1305);
    let mut x = vec![0u8; 32];
    let mut y = vec![0u8; 32];
    a.seal_in_place(0, b"", &mut x).unwrap();
    b.seal_in_place(0, b"", &mut y).unwrap();
    assert_ne!(x, y);
    // A frame sealed by A must not open on A's own receive side.
    let (_, mut a_open) = a.split();
    assert!(matches!(a_open.open_in_place(0, b"", &mut x), Err(CryptoError::Tampered)));
}

#[test]
fn detached_seal_interoperates() {
    let (a, mut b) = pair(CipherSuite::Aes256Gcm);
    let (mut sealer, _) = a.split();
    let mut buf = vec![7u8; 4096];
    let tag = sealer.seal_in_place_detached(3, b"hdr", &mut buf).unwrap();
    buf.extend_from_slice(&tag);
    assert_eq!(b.open_in_place(3, b"hdr", &mut buf).unwrap(), &[7u8; 4096][..]);
}

#[test]
fn tampering_is_rejected() {
    for suite in CipherSuite::ALL {
        let (mut a, mut b) = pair(suite);
        let aad = b"header";
        let mut good = b"payload bytes".to_vec();
        a.seal_in_place(1, aad, &mut good).unwrap();

        let mut ct = good.clone();
        ct[0] ^= 1;
        assert!(matches!(b.open_in_place(1, aad, &mut ct), Err(CryptoError::Tampered)));

        let mut tag = good.clone();
        let last = tag.len() - 1;
        tag[last] ^= 0x80;
        assert!(matches!(b.open_in_place(1, aad, &mut tag), Err(CryptoError::Tampered)));

        let mut copy = good.clone();
        assert!(matches!(b.open_in_place(1, b"headeR", &mut copy), Err(CryptoError::Tampered)));

        let mut short = good[..TAG_LEN - 1].to_vec();
        assert!(matches!(b.open_in_place(1, aad, &mut short), Err(CryptoError::Tampered)));

        // Wrong sequence number = wrong nonce = authentication failure.
        let mut wrong_seq = good.clone();
        assert!(matches!(b.open_in_place(2, aad, &mut wrong_seq), Err(CryptoError::Tampered)));

        // Failed opens must not have advanced the replay window.
        assert_eq!(b.open_in_place(1, aad, &mut good).unwrap(), b"payload bytes");
    }
}

#[test]
fn replay_is_distinct_from_tamper() {
    let (mut a, mut b) = pair(CipherSuite::Aes256Gcm);
    let mut f5 = b"five".to_vec();
    a.seal_in_place(5, b"", &mut f5).unwrap();
    let captured = f5.clone();
    b.open_in_place(5, b"", &mut f5).unwrap();

    let mut replay = captured.clone();
    assert!(matches!(b.open_in_place(5, b"", &mut replay), Err(CryptoError::Replay { seq: 5, last: 5 })));
    let mut older = captured;
    assert!(matches!(b.open_in_place(4, b"", &mut older), Err(CryptoError::Replay { seq: 4, last: 5 })));
}

#[test]
fn sender_refuses_sequence_reuse() {
    let (mut a, _) = pair(CipherSuite::ChaCha20Poly1305);
    let mut buf = vec![1u8; 8];
    a.seal_in_place(10, b"", &mut buf).unwrap();
    let mut again = vec![1u8; 8];
    assert!(matches!(a.seal_in_place(10, b"", &mut again), Err(CryptoError::SequenceReuse { seq: 10, last: 10 })));
    assert!(matches!(a.seal_in_place(9, b"", &mut again), Err(CryptoError::SequenceReuse { .. })));
    assert_eq!(again, vec![1u8; 8], "buffer untouched on refusal");
}

#[test]
fn suite_mismatch_fails_closed() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut init = Handshake::initiator(&a).unwrap();
    let mut resp = Handshake::responder(&b).unwrap();
    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    init.read_message(&m2).unwrap();
    let m3 = init.write_message(&[]).unwrap();
    resp.read_message(&m3).unwrap();

    let (mut sa, _) = init.into_session(CipherSuite::Aes256Gcm).unwrap();
    let (mut sb, _) = resp.into_session(CipherSuite::ChaCha20Poly1305).unwrap();
    let mut buf = b"x".to_vec();
    sa.seal_in_place(0, b"", &mut buf).unwrap();
    assert!(matches!(sb.open_in_place(0, b"", &mut buf), Err(CryptoError::Tampered)));
}

#[test]
fn per_stream_sessions_are_independent_and_single_use() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut init = Handshake::initiator(&a).unwrap();
    let mut resp = Handshake::responder(&b).unwrap();
    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    init.read_message(&m2).unwrap();
    let m3 = init.write_message(&[]).unwrap();
    resp.read_message(&m3).unwrap();

    let suite = CipherSuite::Aes256Gcm;
    let (mut ka, _) = init.into_parts().unwrap();
    let (mut kb, _) = resp.into_parts().unwrap();
    let mut a1 = ka.session(suite, 1).unwrap();
    let mut b1 = kb.session(suite, 1).unwrap();
    let mut b2 = kb.session(suite, 2).unwrap();
    assert!(matches!(ka.session(suite, 1), Err(CryptoError::StreamAlreadyDerived(1))));

    let mut buf = b"stream one".to_vec();
    a1.seal_in_place(0, b"", &mut buf).unwrap();
    let mut wrong = buf.clone();
    assert!(matches!(b2.open_in_place(0, b"", &mut wrong), Err(CryptoError::Tampered)));
    assert_eq!(b1.open_in_place(0, b"", &mut buf).unwrap(), b"stream one");
}

#[test]
fn prologue_mismatch_fails_handshake() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut init = Handshake::initiator_with_prologue(&a, b"prefs: aes,chacha").unwrap();
    let mut resp = Handshake::responder_with_prologue(&b, b"prefs: chacha").unwrap();
    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    assert!(init.read_message(&m2).is_err());
}

#[test]
fn spoofed_identity_payload_is_rejected() {
    // A responder that authenticates with its own static key but claims someone else's
    // Ed25519 identity must be caught: the claimed key does not map to the Noise static.
    let a = DeviceIdentity::generate().unwrap();
    let victim = DeviceIdentity::generate().unwrap();
    let attacker = DeviceIdentity::generate().unwrap();

    let mut init = Handshake::initiator(&a).unwrap();
    let m1 = init.write_message(&[]).unwrap();

    // Hand-built attacker responder using raw snow so it can put arbitrary bytes in the
    // identity slot.
    let secret = attacker.secret_bytes();
    let sk = ed25519_scalar(&secret);
    let mut raw = snow::Builder::new(crypto::NOISE_PARAMS.parse().unwrap()).local_private_key(&sk).unwrap().prologue(b"dfte noise v1").unwrap().build_responder().unwrap();
    let mut scratch = vec![0u8; 65_535];
    raw.read_message(&m1, &mut scratch).unwrap();
    let n = raw.write_message(&victim.public_key_bytes(), &mut scratch).unwrap();
    assert!(matches!(init.read_message(&scratch[..n]), Err(CryptoError::IdentityMismatch)));
}

fn ed25519_scalar(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).to_scalar_bytes()
}

#[test]
fn mitm_relay_cannot_pass_fingerprint_check() {
    // Mallory sits between Alice and Bob, running one XX handshake with each side and
    // relaying payloads. Each victim ends up authenticated to Mallory's static key, so the
    // out-of-band fingerprint check (QR / pinned key) fails and the SAS values differ.
    let alice = DeviceIdentity::generate().unwrap();
    let bob = DeviceIdentity::generate().unwrap();
    let mallory = DeviceIdentity::generate().unwrap();

    let mut a_init = Handshake::initiator(&alice).unwrap();
    let mut m_resp = Handshake::responder(&mallory).unwrap();
    let mut m_init = Handshake::initiator(&mallory).unwrap();
    let mut b_resp = Handshake::responder(&bob).unwrap();

    let a1 = a_init.write_message(&[]).unwrap();
    let p = m_resp.read_message(&a1).unwrap();
    let r1 = m_init.write_message(&p).unwrap();
    b_resp.read_message(&r1).unwrap();

    let b2 = b_resp.write_message(&[]).unwrap();
    let p = m_init.read_message(&b2).unwrap();
    let r2 = m_resp.write_message(&p).unwrap();
    a_init.read_message(&r2).unwrap();

    let a3 = a_init.write_message(&[]).unwrap();
    let p = m_resp.read_message(&a3).unwrap();
    let r3 = m_init.write_message(&p).unwrap();
    b_resp.read_message(&r3).unwrap();

    let (_, alice_view) = a_init.into_session(CipherSuite::Aes256Gcm).unwrap();
    let (_, bob_view) = b_resp.into_session(CipherSuite::Aes256Gcm).unwrap();

    assert!(matches!(alice_view.verify_fingerprint(&bob.fingerprint()), Err(CryptoError::FingerprintMismatch)));
    assert!(matches!(bob_view.verify_fingerprint(&alice.fingerprint()), Err(CryptoError::FingerprintMismatch)));
    assert_eq!(alice_view.remote_fingerprint, mallory.fingerprint());
    assert_ne!(alice_view.handshake_hash, bob_view.handshake_hash);
    assert_ne!(alice_view.sas, bob_view.sas, "SAS collision (1e-6 chance) would hide the MITM");
}

#[test]
fn negotiate_with_detected_preferences() {
    let local = CipherSuite::local_preferences();
    assert_eq!(local[0], CipherSuite::detect());
    assert_eq!(negotiate(&local, &local).unwrap(), CipherSuite::detect());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_seal_open_round_trip(
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..2048), 1..8),
        start in any::<u64>(),
        gaps in proptest::collection::vec(1u64..1000, 8),
        aad in proptest::collection::vec(any::<u8>(), 0..64),
        chacha in any::<bool>(),
    ) {
        let suite = if chacha { CipherSuite::ChaCha20Poly1305 } else { CipherSuite::Aes256Gcm };
        let (mut a, mut b) = pair(suite);
        let mut seq = start;
        for (i, p) in payloads.iter().enumerate() {
            let mut buf = p.clone();
            a.seal_in_place(seq, &aad, &mut buf).unwrap();
            prop_assert_eq!(buf.len(), p.len() + TAG_LEN);
            prop_assert_eq!(b.open_in_place(seq, &aad, &mut buf).unwrap(), &p[..]);
            match seq.checked_add(gaps[i]) {
                Some(next) => seq = next,
                None => break,
            }
        }
    }
}
