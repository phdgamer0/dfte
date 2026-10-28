//! QR bootstrap payload for the iOS↔non-Apple SoftAP path (manual §6, §7, §12.1).
//!
//! The non-Apple peer starts a SoftAP and renders this payload as a QR code; iOS scans it,
//! joins the network with `NEHotspotConfigurationManager.apply(_:)`, connects to `ip:port`
//! and checks the handshake's peer key against `fingerprint`. The QR scan *is* the
//! out-of-band authentication on this path, replacing the SAS comparison (manual §12.1).
//!
//! # Text encoding (version 1)
//!
//! `dfte1:` followed by unpadded base64url of this fixed binary layout:
//!
//! ```text
//! port        u16 BE, nonzero
//! ip_tag      u8: 4 or 6
//! ip          4 or 16 bytes
//! fingerprint 12 bytes (raw form of crypto::fingerprint_of)
//! ssid_len    u8 (1..=32), then ssid bytes (UTF-8, no control characters)
//! psk_len     u8 (8..=63), then psk bytes (printable ASCII, WPA2 passphrase rules)
//! ```
//!
//! The version lives in the prefix, so a future layout is a new prefix (`dfte2:`) and an
//! old app rejects it cleanly instead of misparsing it (manual §37). The whole text is at
//! most [`MAX_TEXT_LEN`] (178) characters, comfortably inside a QR version 10 at medium ECC.
//!
//! Scanned text is untrusted: the parser caps length before decoding, requires exactly the
//! declared bytes (no trailing data), and validates every field.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::fingerprint::{FINGERPRINT_LEN, FingerprintBytes, format_fingerprint, parse_fingerprint};

/// Current (and only) payload version.
pub const QR_VERSION: u8 = 1;
const PREFIX: &str = "dfte1:";
const PREFIX_FAMILY: &str = "dfte";

pub const MAX_SSID_LEN: usize = 32;
pub const MIN_PSK_LEN: usize = 8;
pub const MAX_PSK_LEN: usize = 63;
/// Largest possible binary body.
pub const MAX_BINARY_LEN: usize = 2 + 1 + 16 + FINGERPRINT_LEN + 1 + MAX_SSID_LEN + 1 + MAX_PSK_LEN;
/// Largest possible text form; longer scans are rejected before any decoding.
pub const MAX_TEXT_LEN: usize = PREFIX.len() + (MAX_BINARY_LEN * 4).div_ceil(3);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QrError {
    #[error("payload too long")]
    TooLong,
    #[error("not a dfte QR code")]
    BadPrefix,
    #[error("unsupported QR payload version")]
    UnsupportedVersion,
    #[error("bad base64")]
    Base64,
    #[error("truncated payload")]
    Truncated,
    #[error("trailing bytes after payload")]
    TrailingBytes,
    #[error("bad address family tag {0}")]
    BadIpTag(u8),
    #[error("address is not usable as a peer address")]
    BadAddress,
    #[error("port must be nonzero")]
    ZeroPort,
    #[error("SSID must be 1..=32 bytes, got {0}")]
    SsidLength(usize),
    #[error("SSID must be UTF-8 without control characters")]
    SsidInvalid,
    #[error("PSK must be 8..=63 characters, got {0}")]
    PskLength(usize),
    #[error("PSK must be printable ASCII")]
    PskInvalid,
    #[error("invalid fingerprint")]
    BadFingerprint,
}

/// Everything iOS needs to join a SoftAP and authenticate the host (manual §6 table).
#[derive(Clone, PartialEq, Eq)]
pub struct QrPayload {
    pub ssid: String,
    pub psk: String,
    /// Host's identity fingerprint, raw form. See [`QrPayload::fingerprint_string`].
    pub fingerprint: FingerprintBytes,
    /// Host's address on its own SoftAP (also its DHCP server, manual §7).
    pub ip: IpAddr,
    /// Engine port on `ip`.
    pub port: u16,
}

impl std::fmt::Debug for QrPayload {
    // The PSK is a credential: keep it out of logs (manual §38).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrPayload").field("ssid", &self.ssid).field("psk", &"<redacted>").field("fingerprint", &self.fingerprint_string()).field("ip", &self.ip).field("port", &self.port).finish()
    }
}

impl QrPayload {
    /// Build and validate a payload.
    pub fn new(ssid: impl Into<String>, psk: impl Into<String>, fingerprint: FingerprintBytes, ip: IpAddr, port: u16) -> Result<Self, QrError> {
        let p = Self { ssid: ssid.into(), psk: psk.into(), fingerprint, ip, port };
        p.validate()?;
        Ok(p)
    }

    /// Payload version this value encodes as.
    pub fn version(&self) -> u8 {
        QR_VERSION
    }

    pub fn fingerprint_string(&self) -> String {
        format_fingerprint(&self.fingerprint)
    }

    /// Whether `fingerprint` (any case/separators) names the same identity as this payload.
    /// Used by the initiator to check the handshake's actual peer key (manual §12.1).
    pub fn matches_fingerprint(&self, fingerprint: &str) -> bool {
        parse_fingerprint(fingerprint).is_some_and(|fp| constant_time_eq(&fp, &self.fingerprint))
    }

    pub fn validate(&self) -> Result<(), QrError> {
        validate_ssid(self.ssid.as_bytes())?;
        validate_psk(self.psk.as_bytes())?;
        validate_ip(self.ip)?;
        if self.port == 0 {
            return Err(QrError::ZeroPort);
        }
        Ok(())
    }

    /// Encode to the QR text form.
    pub fn encode(&self) -> Result<String, QrError> {
        self.validate()?;
        // Fixed stack buffer plus one exact-capacity String: no intermediate allocations.
        let mut bin = [0u8; MAX_BINARY_LEN];
        let mut w = Writer { buf: &mut bin, pos: 0 };
        w.put(&self.port.to_be_bytes());
        match self.ip {
            IpAddr::V4(v4) => {
                w.put(&[4]);
                w.put(&v4.octets());
            }
            IpAddr::V6(v6) => {
                w.put(&[6]);
                w.put(&v6.octets());
            }
        }
        w.put(&self.fingerprint);
        // Lengths were validated above (<= 32 and <= 63), so the casts are lossless.
        w.put(&[self.ssid.len() as u8]);
        w.put(self.ssid.as_bytes());
        w.put(&[self.psk.len() as u8]);
        w.put(self.psk.as_bytes());
        let n = w.pos;
        let mut text = String::with_capacity(PREFIX.len() + (n * 4).div_ceil(3));
        text.push_str(PREFIX);
        URL_SAFE_NO_PAD.encode_string(&bin[..n], &mut text);
        Ok(text)
    }

    /// Parse scanned QR text. Treats `text` as hostile.
    pub fn parse(text: &str) -> Result<Self, QrError> {
        if text.len() > MAX_TEXT_LEN {
            return Err(QrError::TooLong);
        }
        let Some(body) = text.strip_prefix(PREFIX) else {
            return Err(if text.starts_with(PREFIX_FAMILY) && text.contains(':') { QrError::UnsupportedVersion } else { QrError::BadPrefix });
        };
        // Length was capped above, so the body always fits this stack buffer.
        let mut bin = [0u8; MAX_BINARY_LEN + 3];
        let n = URL_SAFE_NO_PAD.decode_slice(body, &mut bin).map_err(|_| QrError::Base64)?;
        let mut r = Reader { buf: &bin[..n] };
        let port = u16::from_be_bytes(r.array()?);
        let ip = match r.u8()? {
            4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
            t => return Err(QrError::BadIpTag(t)),
        };
        let fingerprint = r.array::<FINGERPRINT_LEN>()?;
        let ssid_len = usize::from(r.u8()?);
        let ssid = r.take(ssid_len)?;
        validate_ssid(ssid)?;
        let psk_len = usize::from(r.u8()?);
        let psk = r.take(psk_len)?;
        validate_psk(psk)?;
        if !r.buf.is_empty() {
            return Err(QrError::TrailingBytes);
        }
        validate_ip(ip)?;
        if port == 0 {
            return Err(QrError::ZeroPort);
        }
        // SSID/PSK were validated as UTF-8 / ASCII above; these conversions cannot fail.
        let ssid = std::str::from_utf8(ssid).map_err(|_| QrError::SsidInvalid)?.to_owned();
        let psk = std::str::from_utf8(psk).map_err(|_| QrError::PskInvalid)?.to_owned();
        Ok(Self { ssid, psk, fingerprint, ip, port })
    }
}

struct Writer<'a> {
    buf: &'a mut [u8; MAX_BINARY_LEN],
    pos: usize,
}

impl Writer<'_> {
    /// Callers only write validated fields whose total is bounded by `MAX_BINARY_LEN`.
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], QrError> {
        if self.buf.len() < n {
            return Err(QrError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, QrError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], QrError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

fn validate_ssid(ssid: &[u8]) -> Result<(), QrError> {
    if ssid.is_empty() || ssid.len() > MAX_SSID_LEN {
        return Err(QrError::SsidLength(ssid.len()));
    }
    let s = std::str::from_utf8(ssid).map_err(|_| QrError::SsidInvalid)?;
    // Control characters would let a hostile QR inject lines into a generated hostapd /
    // wpa_supplicant config and garble the join prompt.
    if s.chars().any(char::is_control) {
        return Err(QrError::SsidInvalid);
    }
    Ok(())
}

fn validate_psk(psk: &[u8]) -> Result<(), QrError> {
    if !(MIN_PSK_LEN..=MAX_PSK_LEN).contains(&psk.len()) {
        return Err(QrError::PskLength(psk.len()));
    }
    if !psk.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(QrError::PskInvalid);
    }
    Ok(())
}

fn validate_ip(ip: IpAddr) -> Result<(), QrError> {
    let bad = ip.is_unspecified()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(v4) => v4.is_broadcast(),
            IpAddr::V6(_) => false,
        };
    if bad { Err(QrError::BadAddress) } else { Ok(()) }
}

fn constant_time_eq(a: &FingerprintBytes, b: &FingerprintBytes) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> QrPayload {
        QrPayload::new("dfte-ABCD2345", "k3yk3yk3yk3yk3yk3yk3yk3y", [0xA5; 12], IpAddr::V4(Ipv4Addr::new(192, 168, 49, 1)), 47_821).unwrap()
    }

    #[test]
    fn round_trip_v4_and_v6() {
        let p = sample();
        let text = p.encode().unwrap();
        assert!(text.starts_with("dfte1:"));
        assert!(text.len() <= MAX_TEXT_LEN);
        assert_eq!(QrPayload::parse(&text).unwrap(), p);

        let mut p6 = sample();
        p6.ip = "fe80::1".parse().unwrap();
        assert_eq!(QrPayload::parse(&p6.encode().unwrap()).unwrap(), p6);
        assert_eq!(p6.version(), 1);
    }

    #[test]
    fn max_size_payload_fits_text_cap() {
        let p = QrPayload::new("x".repeat(32), "y".repeat(63), [1; 12], "2001:db8::1".parse().unwrap(), 1).unwrap();
        let text = p.encode().unwrap();
        assert_eq!(text.len(), MAX_TEXT_LEN);
        assert_eq!(QrPayload::parse(&text).unwrap(), p);
    }

    #[test]
    fn fingerprint_matching() {
        let p = sample();
        assert!(p.matches_fingerprint(&p.fingerprint_string()));
        assert!(p.matches_fingerprint(&p.fingerprint_string().to_uppercase().replace('-', "")));
        assert!(!p.matches_fingerprint("a5a5-a5a5-a5a5-a5a5-a5a5-a5a4"));
        assert!(!p.matches_fingerprint("garbage"));
    }

    #[test]
    fn debug_redacts_psk() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("k3yk3y"));
    }

    #[test]
    fn field_validation() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(QrPayload::new("", "12345678", [0; 12], ip, 1), Err(QrError::SsidLength(0)));
        assert_eq!(QrPayload::new("x".repeat(33), "12345678", [0; 12], ip, 1), Err(QrError::SsidLength(33)));
        assert_eq!(QrPayload::new("a\nb", "12345678", [0; 12], ip, 1), Err(QrError::SsidInvalid));
        assert_eq!(QrPayload::new("ok", "1234567", [0; 12], ip, 1), Err(QrError::PskLength(7)));
        assert_eq!(QrPayload::new("ok", "y".repeat(64), [0; 12], ip, 1), Err(QrError::PskLength(64)));
        assert_eq!(QrPayload::new("ok", "1234567\n", [0; 12], ip, 1), Err(QrError::PskInvalid));
        assert_eq!(QrPayload::new("ok", "12345678", [0; 12], ip, 0), Err(QrError::ZeroPort));
        assert_eq!(QrPayload::new("ok", "12345678", [0; 12], IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1), Err(QrError::BadAddress));
        assert_eq!(QrPayload::new("ok", "12345678", [0; 12], IpAddr::V4(Ipv4Addr::BROADCAST), 1), Err(QrError::BadAddress));
        assert_eq!(QrPayload::new("ok", "12345678", [0; 12], "224.0.0.1".parse().unwrap(), 1), Err(QrError::BadAddress));
    }

    #[test]
    fn hostile_text_rejected() {
        let good = sample().encode().unwrap();
        assert_eq!(QrPayload::parse(""), Err(QrError::BadPrefix));
        assert_eq!(QrPayload::parse("https://evil.example/"), Err(QrError::BadPrefix));
        assert_eq!(QrPayload::parse("dfte2:AAAA"), Err(QrError::UnsupportedVersion));
        assert_eq!(QrPayload::parse("dfte1:!!!!"), Err(QrError::Base64));
        assert_eq!(QrPayload::parse("dfte1:"), Err(QrError::Truncated));
        assert_eq!(QrPayload::parse(&"A".repeat(MAX_TEXT_LEN + 1)), Err(QrError::TooLong));
        // Truncate the body at every possible length: always a clean error, never a panic.
        for cut in PREFIX.len()..good.len() {
            assert!(QrPayload::parse(&good[..cut]).is_err(), "cut at {cut}");
        }
        // Trailing data is rejected.
        let mut bin = URL_SAFE_NO_PAD.decode(&good[PREFIX.len()..]).unwrap();
        bin.push(0);
        assert_eq!(QrPayload::parse(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&bin))), Err(QrError::TrailingBytes));
        // Bad address tag.
        let mut bin = URL_SAFE_NO_PAD.decode(&good[PREFIX.len()..]).unwrap();
        bin[2] = 5;
        assert_eq!(QrPayload::parse(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&bin))), Err(QrError::BadIpTag(5)));
    }

    fn arb_payload() -> impl Strategy<Value = QrPayload> {
        let ip = prop_oneof![any::<[u8; 4]>().prop_map(|o| IpAddr::V4(Ipv4Addr::from(o))), any::<[u8; 16]>().prop_map(|o| IpAddr::V6(Ipv6Addr::from(o)))];
        ("[a-zA-Z0-9 _.-]{1,32}", "[ -~]{8,63}", any::<[u8; 12]>(), ip, 1u16..).prop_filter_map("valid", |(ssid, psk, fp, ip, port)| QrPayload::new(ssid, psk, fp, ip, port).ok())
    }

    proptest! {
        #[test]
        fn prop_round_trip(p in arb_payload()) {
            let text = p.encode().unwrap();
            prop_assert!(text.len() <= MAX_TEXT_LEN);
            prop_assert_eq!(QrPayload::parse(&text).unwrap(), p);
        }

        /// Arbitrary text and arbitrary base64 bodies never panic; anything accepted
        /// re-encodes to an equivalent valid payload.
        #[test]
        fn prop_garbage_never_panics(text in ".{0,256}", body in proptest::collection::vec(any::<u8>(), 0..160)) {
            let _ = QrPayload::parse(&text);
            let framed = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&body));
            if let Ok(p) = QrPayload::parse(&framed) {
                prop_assert!(p.validate().is_ok());
                prop_assert_eq!(QrPayload::parse(&p.encode().unwrap()).unwrap(), p);
            }
        }

        /// Single-byte corruptions of a valid code never panic.
        #[test]
        fn prop_bitflips_never_panic(idx in 0usize..256, byte in any::<u8>()) {
            let good = sample().encode().unwrap();
            let mut bytes = good.into_bytes();
            let i = idx % bytes.len();
            bytes[i] = byte;
            if let Ok(s) = String::from_utf8(bytes) {
                let _ = QrPayload::parse(&s);
            }
        }
    }
}
