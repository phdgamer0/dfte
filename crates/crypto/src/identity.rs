//! Long-term device identity (manual §6, §12.2).

use core::fmt;
use core::fmt::Write as _;

use ed25519_dalek::{SigningKey, VerifyingKey};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// Fingerprint bytes rendered: 6 groups x 2 bytes = 6 groups of 4 hex chars.
const FINGERPRINT_BYTES: usize = 12;

/// An install's long-term Ed25519 identity (manual §6).
///
/// The Noise X25519 static key is *derived* from this key using the standard
/// Ed25519 -> X25519 birational map (`SigningKey::to_scalar_bytes` /
/// `VerifyingKey::to_montgomery`), so exactly one secret lives in the OS keystore and a
/// peer can bind the Noise static key back to the Ed25519 key shown in its fingerprint
/// or QR code (manual §12.1).
///
/// The secret is zeroized on drop (`ed25519-dalek`'s `zeroize` feature). `Debug` prints
/// only the public fingerprint.
pub struct DeviceIdentity {
    signing: SigningKey,
}

impl DeviceIdentity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        SystemRandom::new().fill(seed.as_mut()).map_err(|_| CryptoError::Rng)?;
        Ok(Self::from_secret_bytes(&seed))
    }

    /// Restore an identity from its 32-byte Ed25519 seed (as persisted in the keystore).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(secret) }
    }

    /// The 32-byte Ed25519 seed, for persisting into the OS keystore. Zeroized on drop.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Ed25519 public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Short human-readable fingerprint of the public key (see [`fingerprint_of`]).
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.public_key_bytes())
    }

    /// X25519 public key used as the Noise static key.
    pub fn x25519_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_montgomery().to_bytes()
    }

    /// X25519 secret scalar used as the Noise static key. Never leaves the crate.
    pub(crate) fn x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_scalar_bytes())
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity").field("fingerprint", &self.fingerprint()).finish_non_exhaustive()
    }
}

/// SHA-256 of an Ed25519 public key, truncated to 12 bytes and rendered as six
/// dash-separated groups of four lowercase hex chars, e.g. `a1b2-c3d4-e5f6-0718-293a-4b5c`.
/// This is what users compare and what the QR payload carries (manual §6, §12.1).
pub fn fingerprint_of(public_key: &[u8; 32]) -> String {
    let hash = digest::digest(&digest::SHA256, public_key);
    let mut out = String::with_capacity(FINGERPRINT_BYTES * 2 + 5);
    for (i, pair) in hash.as_ref()[..FINGERPRINT_BYTES].chunks(2).enumerate() {
        if i > 0 {
            out.push('-');
        }
        for b in pair {
            // Writing to a String cannot fail.
            let _ = write!(out, "{b:02x}");
        }
    }
    out
}

/// Map an Ed25519 public key to its X25519 (Montgomery) form.
pub(crate) fn x25519_from_ed25519(public_key: &[u8; 32]) -> Result<[u8; 32]> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    Ok(vk.to_montgomery().to_bytes())
}

/// Normalise a user/QR-supplied fingerprint for comparison (case- and separator-insensitive).
pub(crate) fn normalize_fingerprint(fp: &str) -> String {
    fp.chars().filter(char::is_ascii_hexdigit).map(|c| c.to_ascii_lowercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format() {
        let id = DeviceIdentity::from_secret_bytes(&[7u8; 32]);
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 29);
        let groups: Vec<_> = fp.split('-').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_hexdigit())));
    }

    #[test]
    fn secret_round_trip() {
        let id = DeviceIdentity::generate().unwrap();
        let restored = DeviceIdentity::from_secret_bytes(&id.secret_bytes());
        assert_eq!(id.public_key_bytes(), restored.public_key_bytes());
        assert_eq!(id.fingerprint(), restored.fingerprint());
    }

    #[test]
    fn distinct_identities_have_distinct_fingerprints() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let id = DeviceIdentity::from_secret_bytes(&[0xAB; 32]);
        let dbg = format!("{id:?}");
        assert!(dbg.contains(&id.fingerprint()));
        assert!(!dbg.to_lowercase().contains("abab"));
    }

    #[test]
    fn x25519_mapping_matches() {
        let id = DeviceIdentity::generate().unwrap();
        assert_eq!(x25519_from_ed25519(&id.public_key_bytes()).unwrap(), id.x25519_public_key());
    }

    #[test]
    fn normalize_ignores_case_and_separators() {
        assert_eq!(normalize_fingerprint("A1B2-c3d4 "), "a1b2c3d4");
    }
}
