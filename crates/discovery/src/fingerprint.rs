// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Binary form of `crypto::fingerprint_of` fingerprints, for compact wire/QR encodings.
//!
//! The text form (`a1b2-c3d4-e5f6-0718-293a-4b5c`) stays defined by the `crypto` crate;
//! this module only converts it to and from its 12 raw bytes, so both encodings always
//! agree with what users see on screen.

use std::fmt::Write as _;

/// Raw fingerprint length (12 bytes = 96 bits of SHA-256 over the Ed25519 public key).
pub const FINGERPRINT_LEN: usize = 12;

pub type FingerprintBytes = [u8; FINGERPRINT_LEN];

/// Raw fingerprint bytes of an Ed25519 public key (same value `crypto::fingerprint_of` renders).
///
/// Same definition as `crypto::fingerprint_of` (SHA-256, first 12 bytes), computed directly;
/// a unit test pins the two together.
pub fn fingerprint_bytes(public_key: &[u8; 32]) -> FingerprintBytes {
    let hash = ring::digest::digest(&ring::digest::SHA256, public_key);
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(&hash.as_ref()[..FINGERPRINT_LEN]);
    out
}

/// Render raw bytes in the `crypto::fingerprint_of` text format.
pub fn format_fingerprint(fp: &FingerprintBytes) -> String {
    let mut out = String::with_capacity(FINGERPRINT_LEN * 2 + 5);
    for (i, pair) in fp.chunks(2).enumerate() {
        if i > 0 {
            out.push('-');
        }
        for b in pair {
            // Deliberately ignored: `fmt::Write` for `String` is infallible.
            let _ = write!(out, "{b:02x}");
        }
    }
    out
}

/// Parse a user/QR-supplied fingerprint, ignoring case and any `-`/space separators.
/// Returns `None` unless exactly 24 hex digits are present and nothing else but separators.
pub fn parse_fingerprint(text: &str) -> Option<FingerprintBytes> {
    let mut out = [0u8; FINGERPRINT_LEN];
    let mut nibbles = 0usize;
    for c in text.chars() {
        if c == '-' || c == ' ' {
            continue;
        }
        let v = c.to_digit(16)? as u8;
        if nibbles >= FINGERPRINT_LEN * 2 {
            return None;
        }
        out[nibbles / 2] |= if nibbles.is_multiple_of(2) { v << 4 } else { v };
        nibbles += 1;
    }
    (nibbles == FINGERPRINT_LEN * 2).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::DeviceIdentity;

    #[test]
    fn bytes_round_trip_with_crypto_text_form() {
        let id = DeviceIdentity::generate().unwrap();
        let bytes = fingerprint_bytes(&id.public_key_bytes());
        assert_eq!(format_fingerprint(&bytes), id.fingerprint());
        assert_eq!(parse_fingerprint(&id.fingerprint().to_uppercase()), Some(bytes));
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert_eq!(parse_fingerprint(""), None);
        assert_eq!(parse_fingerprint("a1b2"), None);
        assert_eq!(parse_fingerprint("a1b2-c3d4-e5f6-0718-293a-4b5c-00"), None);
        assert_eq!(parse_fingerprint("g1b2-c3d4-e5f6-0718-293a-4b5c"), None);
        assert!(parse_fingerprint("a1b2c3d4e5f60718293a4b5c").is_some());
    }
}
