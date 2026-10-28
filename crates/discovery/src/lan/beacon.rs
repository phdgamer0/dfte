//! Signed LAN announcement ("beacon") wire format.
//!
//! ```text
//! magic      4   "DFB1"
//! flags      1   reserved, must be 0
//! name_len   1   0..=64
//! port       2   u16 BE, engine port, nonzero
//! timestamp  8   u64 BE, sender wall clock, unix milliseconds
//! nonce      16  random per beacon
//! public_key 32  Ed25519 identity key (fingerprint = crypto::fingerprint_of(public_key))
//! name       name_len bytes, UTF-8, no control characters
//! signature  64  Ed25519 over DOMAIN || all bytes above
//! ```
//!
//! The signature binds the advertised name/port/timestamp to the identity key, so a LAN
//! attacker cannot advertise someone else's fingerprint at its own port. The *source IP*
//! is not (and cannot usefully be) signed; reaching a peer at a forged address still fails
//! the transport handshake, whose static key must match the advertised fingerprint.

use std::borrow::Cow;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crypto::DeviceIdentity;

pub const MAGIC: [u8; 4] = *b"DFB1";
/// Domain separation for the signature: these Ed25519 keys sign nothing else today, but a
/// future signed message type must never be confusable with a beacon.
const DOMAIN: &[u8] = b"dfte/lan-beacon/v1\0";
pub const MAX_NAME_LEN: usize = 64;
pub const NONCE_LEN: usize = 16;
const FIXED_LEN: usize = 4 + 1 + 1 + 2 + 8 + NONCE_LEN + 32;
pub const SIG_LEN: usize = 64;
pub const MIN_BEACON_LEN: usize = FIXED_LEN + SIG_LEN;
pub const MAX_BEACON_LEN: usize = FIXED_LEN + MAX_NAME_LEN + SIG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BeaconError {
    #[error("wrong length")]
    Length,
    #[error("bad magic")]
    Magic,
    #[error("reserved flags set")]
    Flags,
    #[error("zero port")]
    ZeroPort,
    #[error("invalid name")]
    Name,
    #[error("invalid public key")]
    Key,
    #[error("bad signature")]
    Signature,
}

/// Holds the signing key derived from the device identity. Zeroized on drop
/// (`ed25519-dalek`'s `zeroize` feature).
pub struct BeaconSigner {
    signing: SigningKey,
}

impl std::fmt::Debug for BeaconSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconSigner").finish_non_exhaustive()
    }
}

impl BeaconSigner {
    /// The `crypto` crate does not expose raw Ed25519 signing, so the signer is rebuilt
    /// from the identity's keystore seed. The seed copy is zeroized as soon as it is consumed.
    pub fn new(identity: &DeviceIdentity) -> Self {
        let seed = identity.secret_bytes();
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Encode and sign a beacon. `name` is truncated (on a char boundary) to 64 bytes and
    /// stripped of control characters.
    pub fn encode(&self, name: &str, port: u16, timestamp_ms: u64, nonce: [u8; NONCE_LEN]) -> Vec<u8> {
        let mut out = [0u8; MAX_BEACON_LEN];
        let n = self.encode_into(name, port, timestamp_ms, nonce, &mut out);
        out[..n].to_vec()
    }

    /// Allocation-free [`encode`](Self::encode): writes into `out`, returns the length.
    pub fn encode_into(&self, name: &str, port: u16, timestamp_ms: u64, nonce: [u8; NONCE_LEN], out: &mut [u8; MAX_BEACON_LEN]) -> usize {
        let name = sanitize_name(name);
        // DOMAIN || body in one stack buffer, so signing needs no heap copy.
        let mut msg = [0u8; DOMAIN.len() + MAX_BEACON_LEN];
        let (domain, body) = msg.split_at_mut(DOMAIN.len());
        domain.copy_from_slice(DOMAIN);
        body[0..4].copy_from_slice(&MAGIC);
        body[4] = 0;
        body[5] = name.len() as u8;
        body[6..8].copy_from_slice(&port.to_be_bytes());
        body[8..16].copy_from_slice(&timestamp_ms.to_be_bytes());
        body[16..32].copy_from_slice(&nonce);
        body[32..64].copy_from_slice(self.signing.verifying_key().as_bytes());
        let body_len = FIXED_LEN + name.len();
        body[FIXED_LEN..body_len].copy_from_slice(name.as_bytes());
        let sig = self.signing.sign(&msg[..DOMAIN.len() + body_len]);
        out[..body_len].copy_from_slice(&msg[DOMAIN.len()..DOMAIN.len() + body_len]);
        out[body_len..body_len + SIG_LEN].copy_from_slice(&sig.to_bytes());
        body_len + SIG_LEN
    }
}

/// Drop control characters and cap at 64 bytes on a char boundary. Borrows when the name
/// is already clean (the common case), so the announce loop does not allocate.
fn sanitize_name(name: &str) -> Cow<'_, str> {
    if !name.chars().any(char::is_control) {
        let mut end = name.len().min(MAX_NAME_LEN);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        return Cow::Borrowed(&name[..end]);
    }
    let mut out = String::with_capacity(name.len().min(MAX_NAME_LEN));
    for c in name.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_NAME_LEN {
            break;
        }
        out.push(c);
    }
    Cow::Owned(out)
}

/// A structurally valid, not yet verified beacon borrowing the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconView<'a> {
    pub port: u16,
    pub timestamp_ms: u64,
    pub nonce: [u8; NONCE_LEN],
    pub public_key: [u8; 32],
    pub name: &'a str,
    signed: &'a [u8],
    signature: [u8; SIG_LEN],
}

impl<'a> BeaconView<'a> {
    /// Structural parse only: cheap, allocation-free, no signature check.
    pub fn parse(buf: &'a [u8]) -> Result<Self, BeaconError> {
        if !(MIN_BEACON_LEN..=MAX_BEACON_LEN).contains(&buf.len()) {
            return Err(BeaconError::Length);
        }
        if buf[0..4] != MAGIC {
            return Err(BeaconError::Magic);
        }
        if buf[4] != 0 {
            return Err(BeaconError::Flags);
        }
        let name_len = usize::from(buf[5]);
        if name_len > MAX_NAME_LEN || buf.len() != FIXED_LEN + name_len + SIG_LEN {
            return Err(BeaconError::Length);
        }
        let port = u16::from_be_bytes([buf[6], buf[7]]);
        if port == 0 {
            return Err(BeaconError::ZeroPort);
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&buf[8..16]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[16..32]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&buf[32..64]);
        let name = std::str::from_utf8(&buf[FIXED_LEN..FIXED_LEN + name_len]).map_err(|_| BeaconError::Name)?;
        if name.chars().any(char::is_control) {
            return Err(BeaconError::Name);
        }
        let split = FIXED_LEN + name_len;
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[split..]);
        Ok(Self { port, timestamp_ms: u64::from_be_bytes(ts), nonce, public_key, name, signed: &buf[..split], signature })
    }

    /// Verify the signature and return the decompressed key for caching (strict: rejects small-order keys and malleable signatures).
    pub fn verify(&self) -> Result<VerifyingKey, BeaconError> {
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| BeaconError::Key)?;
        self.verify_with(&key)?;
        Ok(key)
    }

    /// Verify with an already-decompressed key (the peer table caches these).
    pub fn verify_with(&self, key: &VerifyingKey) -> Result<(), BeaconError> {
        let mut msg = [0u8; DOMAIN.len() + MAX_BEACON_LEN];
        let len = DOMAIN.len() + self.signed.len();
        msg[..DOMAIN.len()].copy_from_slice(DOMAIN);
        msg[DOMAIN.len()..len].copy_from_slice(self.signed);
        key.verify_strict(&msg[..len], &Signature::from_bytes(&self.signature)).map_err(|_| BeaconError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn signer() -> BeaconSigner {
        BeaconSigner::new(&DeviceIdentity::from_secret_bytes(&[3; 32]))
    }

    #[test]
    fn round_trip_and_verify() {
        let s = signer();
        let b = s.encode("Alice's laptop", 47_821, 1_700_000_000_000, [9; 16]);
        let v = BeaconView::parse(&b).unwrap();
        assert_eq!(v.name, "Alice's laptop");
        assert_eq!(v.port, 47_821);
        assert_eq!(v.timestamp_ms, 1_700_000_000_000);
        assert_eq!(v.nonce, [9; 16]);
        assert_eq!(v.public_key, s.public_key());
        v.verify().unwrap();
    }

    #[test]
    fn name_is_sanitized_and_capped() {
        let s = signer();
        let long = "é".repeat(100);
        let b = s.encode(&format!("a\nb{long}"), 1, 0, [0; 16]);
        let v = BeaconView::parse(&b).unwrap();
        assert!(v.name.starts_with("ab"));
        assert!(v.name.len() <= MAX_NAME_LEN);
        v.verify().unwrap();
    }

    #[test]
    fn tampering_any_byte_fails() {
        let s = signer();
        let b = s.encode("bob", 4000, 42, [1; 16]);
        for i in 0..b.len() {
            let mut t = b.clone();
            t[i] ^= 0x01;
            let ok = BeaconView::parse(&t).and_then(|v| v.verify());
            assert!(ok.is_err(), "flip at byte {i} accepted");
        }
    }

    #[test]
    fn signature_from_other_key_fails() {
        let a = signer();
        let other = BeaconSigner::new(&DeviceIdentity::from_secret_bytes(&[4; 32]));
        let mut b = a.encode("x", 1, 0, [0; 16]);
        // Swap in another key: structurally valid, cryptographically not.
        b[32..64].copy_from_slice(&other.public_key());
        assert_eq!(BeaconView::parse(&b).unwrap().verify(), Err(BeaconError::Signature));
    }

    #[test]
    fn structural_rejects() {
        let b = signer().encode("x", 1, 0, [0; 16]);
        assert_eq!(BeaconView::parse(&b[..b.len() - 1]), Err(BeaconError::Length));
        let mut t = b.clone();
        t[0] = b'X';
        assert_eq!(BeaconView::parse(&t), Err(BeaconError::Magic));
        let mut t = b.clone();
        t[4] = 1;
        assert_eq!(BeaconView::parse(&t), Err(BeaconError::Flags));
        let mut t = b.clone();
        t[6] = 0;
        t[7] = 0;
        assert_eq!(BeaconView::parse(&t), Err(BeaconError::ZeroPort));
        let mut t = b.clone();
        t[5] = 2;
        assert_eq!(BeaconView::parse(&t), Err(BeaconError::Length));
    }

    proptest! {
        #[test]
        fn garbage_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(v) = BeaconView::parse(&buf) {
                prop_assert!(v.verify().is_err());
            }
        }

        #[test]
        fn arbitrary_fields_round_trip(name in ".{0,80}", port in 1u16.., ts in any::<u64>(), nonce in any::<[u8; 16]>()) {
            let s = signer();
            let b = s.encode(&name, port, ts, nonce);
            let v = BeaconView::parse(&b).unwrap();
            prop_assert_eq!(v.port, port);
            prop_assert_eq!(v.timestamp_ms, ts);
            prop_assert!(v.verify().is_ok());
        }
    }
}
