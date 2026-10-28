//! Noise_XX handshake for the TCP backend (manual §12.1).
//!
//! Sans-I/O wrapper around `snow`: the caller moves the returned byte buffers over the
//! wire. XX message flow: `-> e`, `<- e, ee, s, es`, `-> s, se`. Each side's Ed25519
//! public key rides (encrypted) in the payload of the message that carries its `s`, and
//! is checked against the Noise static key so the authenticated X25519 key is bound to
//! the identity users compare (fingerprint / SAS / QR).

use std::collections::HashSet;

use ring::hkdf;
use zeroize::Zeroizing;

use crate::identity::{self, DeviceIdentity, fingerprint_of, normalize_fingerprint};
use crate::session::{CipherSuite, Session};
use crate::{CryptoError, Result};

/// Noise protocol name, fixed by manual §12.1.
pub const NOISE_PARAMS: &str = "Noise_XX_25519_AESGCM_SHA256";

const PROLOGUE_LABEL: &[u8] = b"dfte noise v1";
const SAS_INFO: &[u8] = b"dfte sas v1";
const MAX_NOISE_MSG: usize = 65_535;
const IDENTITY_LEN: usize = 32;

/// One side of an in-progress Noise_XX handshake.
pub struct Handshake {
    state: snow::HandshakeState,
    local_identity: [u8; 32],
    sent_identity: bool,
    remote_identity: Option<[u8; 32]>,
    messages: usize,
}

impl Handshake {
    /// Start as initiator (the side that sends `Hello`, manual §9.1).
    pub fn initiator(identity: &DeviceIdentity) -> Result<Self> {
        Self::build(identity, &[], true)
    }

    /// Start as responder.
    pub fn responder(identity: &DeviceIdentity) -> Result<Self> {
        Self::build(identity, &[], false)
    }

    /// Like [`Handshake::initiator`], additionally binding `prologue` (e.g. the raw
    /// `Hello`/`HelloAck` bytes carrying version and cipher preferences) into the
    /// transcript, so tampering with that negotiation makes the handshake fail.
    /// Both sides must pass identical bytes.
    pub fn initiator_with_prologue(identity: &DeviceIdentity, prologue: &[u8]) -> Result<Self> {
        Self::build(identity, prologue, true)
    }

    /// Responder counterpart of [`Handshake::initiator_with_prologue`].
    pub fn responder_with_prologue(identity: &DeviceIdentity, prologue: &[u8]) -> Result<Self> {
        Self::build(identity, prologue, false)
    }

    fn build(identity: &DeviceIdentity, prologue: &[u8], initiator: bool) -> Result<Self> {
        let secret = identity.x25519_secret();
        let mut full_prologue = Vec::with_capacity(PROLOGUE_LABEL.len() + prologue.len());
        full_prologue.extend_from_slice(PROLOGUE_LABEL);
        full_prologue.extend_from_slice(prologue);

        let builder = snow::Builder::new(NOISE_PARAMS.parse()?).local_private_key(secret.as_ref())?.prologue(&full_prologue)?;
        let state = if initiator { builder.build_initiator()? } else { builder.build_responder()? };
        Ok(Self { state, local_identity: identity.public_key_bytes(), sent_identity: false, remote_identity: None, messages: 0 })
    }

    pub fn is_initiator(&self) -> bool {
        self.state.is_initiator()
    }

    /// Whether the next step is [`Handshake::write_message`] (else [`Handshake::read_message`]).
    pub fn is_my_turn(&self) -> bool {
        self.state.is_my_turn()
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Produce the next handshake message carrying `payload`.
    ///
    /// The payload of the first XX message is sent in the clear; later payloads are
    /// encrypted. Do not put anything confidential in the initiator's first payload.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let attach_identity = self.messages > 0 && !self.sent_identity;
        let mut body = Vec::with_capacity(IDENTITY_LEN + payload.len());
        if attach_identity {
            body.extend_from_slice(&self.local_identity);
        }
        body.extend_from_slice(payload);

        let mut out = vec![0u8; MAX_NOISE_MSG];
        let n = self.state.write_message(&body, &mut out)?;
        out.truncate(n);
        self.sent_identity |= attach_identity;
        self.messages += 1;
        Ok(out)
    }

    /// Consume a handshake message from the peer and return its application payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; MAX_NOISE_MSG];
        let n = self.state.read_message(message, &mut out)?;
        out.truncate(n);
        self.messages += 1;

        if self.remote_identity.is_none()
            && let Some(remote_static) = self.state.get_remote_static()
        {
            if out.len() < IDENTITY_LEN {
                return Err(CryptoError::MalformedHandshake);
            }
            let mut claimed = [0u8; IDENTITY_LEN];
            claimed.copy_from_slice(&out[..IDENTITY_LEN]);
            if identity::x25519_from_ed25519(&claimed)? != remote_static {
                return Err(CryptoError::IdentityMismatch);
            }
            self.remote_identity = Some(claimed);
            out.drain(..IDENTITY_LEN);
        }
        Ok(out)
    }

    /// Finish the handshake and derive the stream-0 data-plane session with `suite`
    /// (chosen beforehand via [`crate::negotiate`]).
    pub fn into_session(self, suite: CipherSuite) -> Result<(Session, HandshakeOutcome)> {
        let (mut secrets, outcome) = self.into_parts()?;
        let session = secrets.session(suite, 0)?;
        Ok((session, outcome))
    }

    /// Finish the handshake, returning key material from which per-stream sessions can
    /// be derived (manual §11: 2–4 parallel streams per transfer, each needs its own
    /// keys/nonce space because sequence numbers are per stream, manual §8).
    pub fn into_parts(mut self) -> Result<(SessionSecrets, HandshakeOutcome)> {
        if !self.is_finished() {
            return Err(CryptoError::HandshakeNotFinished);
        }
        let remote_identity = self.remote_identity.ok_or(CryptoError::MalformedHandshake)?;
        let remote_static: [u8; 32] = self.state.get_remote_static().and_then(|s| s.try_into().ok()).ok_or(CryptoError::MalformedHandshake)?;
        let handshake_hash: [u8; 32] = self.state.get_handshake_hash().try_into().map_err(|_| CryptoError::MalformedHandshake)?;

        // Split keys: k1 = initiator->responder, k2 = responder->initiator (Noise §5.2).
        let (k1, k2) = self.state.dangerously_get_raw_split();
        let (k1, k2) = (Zeroizing::new(k1), Zeroizing::new(k2));
        let (send, recv) = if self.state.is_initiator() { (k1, k2) } else { (k2, k1) };

        let outcome = HandshakeOutcome { remote_static, remote_identity, remote_fingerprint: fingerprint_of(&remote_identity), sas: derive_sas(&handshake_hash)?, handshake_hash };
        let secrets = SessionSecrets { send, recv, handshake_hash, derived: HashSet::new() };
        Ok((secrets, outcome))
    }
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake").field("initiator", &self.is_initiator()).field("messages", &self.messages).field("finished", &self.is_finished()).finish_non_exhaustive()
    }
}

/// Per-connection key material after a finished handshake. Zeroized on drop.
pub struct SessionSecrets {
    send: Zeroizing<[u8; 32]>,
    recv: Zeroizing<[u8; 32]>,
    handshake_hash: [u8; 32],
    derived: HashSet<u32>,
}

impl SessionSecrets {
    /// Derive the session for `stream_id`. Each stream id can be derived once only:
    /// deriving it twice would hand out two sealers sharing a nonce space.
    pub fn session(&mut self, suite: CipherSuite, stream_id: u32) -> Result<Session> {
        if !self.derived.insert(stream_id) {
            return Err(CryptoError::StreamAlreadyDerived(stream_id));
        }
        Session::derive(&self.send, &self.recv, &self.handshake_hash, suite, stream_id)
    }
}

impl core::fmt::Debug for SessionSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionSecrets").finish_non_exhaustive()
    }
}

/// What the handshake established about the peer (manual §9.1, §12.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeOutcome {
    /// Peer's authenticated Noise X25519 static key.
    pub remote_static: [u8; 32],
    /// Peer's Ed25519 identity key, verified to map to `remote_static`.
    pub remote_identity: [u8; 32],
    /// `fingerprint_of(remote_identity)`, for display / trust-store pinning (manual §6).
    pub remote_fingerprint: String,
    /// 6-digit short authentication string shown on both screens (manual §12.1).
    pub sas: String,
    /// Noise handshake hash (channel binding). Public value, not a key.
    pub handshake_hash: [u8; 32],
}

impl HandshakeOutcome {
    /// QR-flow check (manual §12.1): the fingerprint scanned out of band must match the
    /// peer the handshake actually authenticated. Comparison ignores case and separators.
    pub fn verify_fingerprint(&self, expected: &str) -> Result<()> {
        let expected = normalize_fingerprint(expected);
        if !expected.is_empty() && expected == normalize_fingerprint(&self.remote_fingerprint) { Ok(()) } else { Err(CryptoError::FingerprintMismatch) }
    }
}

/// `SAS = HKDF-SHA256(ikm = handshake_hash, info = "dfte sas v1")[..8] mod 10^6`,
/// zero-padded to 6 digits. Modulo bias over 64 bits is negligible.
fn derive_sas(handshake_hash: &[u8; 32]) -> Result<String> {
    struct Len8;
    impl hkdf::KeyType for Len8 {
        fn len(&self) -> usize {
            8
        }
    }
    let mut out = [0u8; 8];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(handshake_hash).expand(&[SAS_INFO], Len8).and_then(|okm| okm.fill(&mut out)).map_err(|_| CryptoError::KeyDerivation)?;
    Ok(format!("{:06}", u64::from_be_bytes(out) % 1_000_000))
}
