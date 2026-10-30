// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Data-plane AEAD (manual §12.2, §13, §14).
//!
//! Keys come from the completed Noise_XX split (see [`crate::handshake`]); this module
//! only does nonce construction, replay/reuse enforcement and in-place seal/open via
//! `ring`. No primitive is implemented here.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// AEAD tag length appended by [`Sealer::seal_in_place`] (manual §8: 16-byte tag).
pub const TAG_LEN: usize = 16;
const NONCE_LEN: usize = aead::NONCE_LEN;

const KEY_INFO: &[u8] = b"dfte data key v1";
const SALT_INFO: &[u8] = b"dfte nonce salt v1";

/// Data-plane AEAD selection (manual §12.2, §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherSuite {
    /// All suites, in canonical order.
    pub const ALL: [CipherSuite; 2] = [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305];

    /// Stable one-byte identifier, used in key derivation and capability negotiation.
    pub const fn id(self) -> u8 {
        match self {
            CipherSuite::Aes256Gcm => 0x01,
            CipherSuite::ChaCha20Poly1305 => 0x02,
        }
    }

    /// Inverse of [`CipherSuite::id`].
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(CipherSuite::Aes256Gcm),
            0x02 => Some(CipherSuite::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// AES-256-GCM when the CPU has AES + carry-less multiply, else ChaCha20-Poly1305
    /// (manual §13: follow hardware capability, never hardcode).
    pub fn detect() -> Self {
        if hardware_aes() { CipherSuite::Aes256Gcm } else { CipherSuite::ChaCha20Poly1305 }
    }

    /// Local preference list: detected suite first, the other as fallback.
    pub fn local_preferences() -> [CipherSuite; 2] {
        match Self::detect() {
            CipherSuite::Aes256Gcm => [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305],
            CipherSuite::ChaCha20Poly1305 => [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm],
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            CipherSuite::Aes256Gcm => &aead::AES_256_GCM,
            CipherSuite::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn hardware_aes() -> bool {
    std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("pclmulqdq")
}

#[cfg(target_arch = "aarch64")]
fn hardware_aes() -> bool {
    std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn hardware_aes() -> bool {
    false
}

/// Pick the suite both peers will use. Symmetric: `negotiate(a, b) == negotiate(b, a)`,
/// so each side computes the same answer from the two preference lists exchanged in
/// `Hello`/`HelloAck` (manual §9.1, §37).
///
/// Among mutually supported suites the lowest combined preference rank wins; on a tie
/// ChaCha20-Poly1305 wins, because it is fast everywhere while AES on a peer without
/// hardware support is slow and not constant-time.
pub fn negotiate(local: &[CipherSuite], remote: &[CipherSuite]) -> Result<CipherSuite> {
    let rank = |list: &[CipherSuite], s: CipherSuite| list.iter().position(|&x| x == s);
    CipherSuite::ALL.iter().filter_map(|&s| Some((rank(local, s)? + rank(remote, s)?, s))).min_by_key(|&(score, s)| (score, s != CipherSuite::ChaCha20Poly1305)).map(|(_, s)| s).ok_or(CryptoError::NoCommonCipherSuite)
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Build one direction's key + nonce salt.
///
/// `HKDF-SHA256(salt = handshake_hash, ikm = noise_split_key, info = label || suite || stream)`.
/// The suite id is in `info`, so peers that disagree on the suite derive different keys and
/// every frame fails closed as `Tampered`.
fn derive_direction(split_key: &[u8; 32], handshake_hash: &[u8; 32], suite: CipherSuite, stream_id: u32) -> Result<(LessSafeKey, [u8; NONCE_LEN])> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, handshake_hash).extract(split_key);
    let suite_id = [suite.id()];
    let stream = stream_id.to_be_bytes();

    let key_info = [KEY_INFO, &suite_id[..], &stream[..]];
    let okm = prk.expand(&key_info, suite.algorithm()).map_err(|_| CryptoError::KeyDerivation)?;
    let key = LessSafeKey::new(UnboundKey::from(okm));

    let salt_info = [SALT_INFO, &suite_id[..], &stream[..]];
    let mut salt = [0u8; NONCE_LEN];
    prk.expand(&salt_info, HkdfLen(NONCE_LEN)).and_then(|okm| okm.fill(&mut salt)).map_err(|_| CryptoError::KeyDerivation)?;
    Ok((key, salt))
}

/// `nonce = salt XOR (0^32 || seq_be64)` (manual §12.2).
fn nonce_for(salt: &[u8; NONCE_LEN], seq: u64) -> Nonce {
    let mut n = *salt;
    for (dst, src) in n[NONCE_LEN - 8..].iter_mut().zip(seq.to_be_bytes()) {
        *dst ^= src;
    }
    Nonce::assume_unique_for_key(n)
}

/// Sending half. Enforces strictly increasing sequence numbers so a nonce is never reused.
pub struct Sealer {
    key: LessSafeKey,
    salt: [u8; NONCE_LEN],
    last: Option<u64>,
}

impl Sealer {
    fn check(&self, seq: u64) -> Result<()> {
        match self.last {
            Some(last) if seq <= last => Err(CryptoError::SequenceReuse { seq, last }),
            _ => Ok(()),
        }
    }

    /// Encrypt `buf` in place and append the 16-byte tag. `aad` is the cleartext frame
    /// header (manual §8). `seq` must be strictly greater than every previously sealed seq.
    pub fn seal_in_place(&mut self, seq: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        self.check(seq)?;
        self.key.seal_in_place_append_tag(nonce_for(&self.salt, seq), Aad::from(aad), buf).map_err(|_| CryptoError::Tampered)?;
        self.last = Some(seq);
        Ok(())
    }

    /// Like [`Sealer::seal_in_place`] but returns the tag instead of appending it, for
    /// fixed-size pool buffers (manual §14).
    pub fn seal_in_place_detached(&mut self, seq: u64, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        self.check(seq)?;
        let tag = self.key.seal_in_place_separate_tag(nonce_for(&self.salt, seq), Aad::from(aad), buf).map_err(|_| CryptoError::Tampered)?;
        self.last = Some(seq);
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}

/// Receiving half. Enforces strictly increasing sequence numbers (replay protection,
/// manual §12.2/§34).
pub struct Opener {
    key: LessSafeKey,
    salt: [u8; NONCE_LEN],
    last: Option<u64>,
}

impl Opener {
    /// Verify and decrypt `buf` (ciphertext || tag) in place, returning the plaintext slice.
    ///
    /// A `seq` not above the last accepted one yields [`CryptoError::Replay`]; a bad
    /// tag/ciphertext/AAD yields [`CryptoError::Tampered`]. The replay window only
    /// advances on successful authentication, so a forged frame cannot burn sequence numbers.
    pub fn open_in_place<'a>(&mut self, seq: u64, aad: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8]> {
        if let Some(last) = self.last
            && seq <= last
        {
            return Err(CryptoError::Replay { seq, last });
        }
        let plain = self.key.open_in_place(nonce_for(&self.salt, seq), Aad::from(aad), buf).map_err(|_| CryptoError::Tampered)?;
        self.last = Some(seq);
        Ok(plain)
    }
}

/// A bidirectional data-plane session for one stream (manual §12.3: keys are per
/// connection, never long-lived). Use [`Session::split`] to hand the halves to separate
/// send/receive tasks (manual §27).
pub struct Session {
    suite: CipherSuite,
    sealer: Sealer,
    opener: Opener,
}

impl Session {
    pub(crate) fn derive(send_key: &Zeroizing<[u8; 32]>, recv_key: &Zeroizing<[u8; 32]>, handshake_hash: &[u8; 32], suite: CipherSuite, stream_id: u32) -> Result<Self> {
        let (sk, ss) = derive_direction(send_key, handshake_hash, suite, stream_id)?;
        let (rk, rs) = derive_direction(recv_key, handshake_hash, suite, stream_id)?;
        Ok(Self { suite, sealer: Sealer { key: sk, salt: ss, last: None }, opener: Opener { key: rk, salt: rs, last: None } })
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// See [`Sealer::seal_in_place`].
    pub fn seal_in_place(&mut self, seq: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        self.sealer.seal_in_place(seq, aad, buf)
    }

    /// See [`Opener::open_in_place`].
    pub fn open_in_place<'a>(&mut self, seq: u64, aad: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8]> {
        self.opener.open_in_place(seq, aad, buf)
    }

    pub fn split(self) -> (Sealer, Opener) {
        (self.sealer, self.opener)
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").field("suite", &self.suite).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CipherSuite::*;

    #[test]
    fn negotiate_is_symmetric_and_sane() {
        let lists: [&[CipherSuite]; 5] = [&[Aes256Gcm, ChaCha20Poly1305], &[ChaCha20Poly1305, Aes256Gcm], &[Aes256Gcm], &[ChaCha20Poly1305], &[]];
        for a in lists {
            for b in lists {
                let ab = negotiate(a, b).ok();
                let ba = negotiate(b, a).ok();
                assert_eq!(ab, ba);
                if let Some(s) = ab {
                    assert!(a.contains(&s) && b.contains(&s));
                }
            }
        }
        assert_eq!(negotiate(lists[0], lists[0]).unwrap(), Aes256Gcm);
        assert_eq!(negotiate(lists[0], lists[1]).unwrap(), ChaCha20Poly1305);
        assert!(matches!(negotiate(lists[2], lists[3]), Err(CryptoError::NoCommonCipherSuite)));
    }

    #[test]
    fn suite_id_round_trip() {
        for s in CipherSuite::ALL {
            assert_eq!(CipherSuite::from_id(s.id()), Some(s));
        }
        assert_eq!(CipherSuite::from_id(0), None);
    }

    #[test]
    fn nonce_xors_seq_into_low_bytes() {
        let salt = [0xFFu8; NONCE_LEN];
        let n = nonce_for(&salt, 1);
        let bytes = n.as_ref();
        assert_eq!(&bytes[..4], &[0xFF; 4]);
        assert_eq!(bytes[NONCE_LEN - 1], 0xFE);
    }
}
