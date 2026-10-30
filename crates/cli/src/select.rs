// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Interpreting `--to` and choosing among discovered peers.

use std::net::SocketAddr;

use discovery::Peer;

use crate::trust::{TrustStore, normalize_fingerprint};

/// What the user asked to send to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Manual address (manual §41); verified by SAS, `--expect`, or a pin.
    Addr(SocketAddr),
    /// Full fingerprint: the pinned/QR case, no SAS prompt.
    Fingerprint(String),
    /// A trusted device's local name, resolved to its fingerprint.
    Trusted { name: String, fingerprint: String },
    /// A peer's self-reported (untrusted) name.
    Name(String),
}

/// Parse `--to`. Address first, then fingerprint, then trusted names, then raw names.
pub fn parse_target(text: &str, trust: &TrustStore) -> Result<Target, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("--to needs a device name, fingerprint or IP:PORT.".into());
    }
    if let Ok(a) = t.parse::<SocketAddr>() {
        return Ok(Target::Addr(a));
    }
    if let Some(fp) = normalize_fingerprint(t) {
        return Ok(Target::Fingerprint(fp));
    }
    match trust.by_name(t).as_slice() {
        [one] => Ok(Target::Trusted { name: one.name.clone(), fingerprint: one.fingerprint.clone() }),
        [] => Ok(Target::Name(t.to_owned())),
        _ => Err(format!("Several trusted devices are called {t:?}; use a fingerprint instead.")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick<'a> {
    Found(&'a Peer),
    NotFound,
    Ambiguous(Vec<&'a Peer>),
}

/// The discovered peer `target` refers to (`Addr` targets never need discovery).
pub fn pick<'a>(peers: &'a [Peer], target: &Target) -> Pick<'a> {
    let hits: Vec<&Peer> = match target {
        Target::Addr(_) => Vec::new(),
        Target::Fingerprint(fp) | Target::Trusted { fingerprint: fp, .. } => peers.iter().filter(|p| p.fingerprint.as_deref().and_then(normalize_fingerprint).as_deref() == Some(fp.as_str())).collect(),
        Target::Name(n) => peers.iter().filter(|p| p.display_name.eq_ignore_ascii_case(n)).collect(),
    };
    match hits.as_slice() {
        [] => Pick::NotFound,
        [one] => Pick::Found(one),
        _ => Pick::Ambiguous(hits),
    }
}

/// Parse a menu choice `1..=n`; `None` for anything else.
pub fn parse_choice(line: &str, n: usize) -> Option<usize> {
    line.trim().parse::<usize>().ok().filter(|&i| (1..=n).contains(&i)).map(|i| i - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery::{LinkKind, PeerHandle};

    const FP_A: &str = "a1b2-c3d4-e5f6-0718-293a-4b5c";
    const FP_B: &str = "0000-1111-2222-3333-4444-5555";

    fn peer(name: &str, fp: Option<&str>) -> Peer {
        Peer { fingerprint: fp.map(Into::into), display_name: name.into(), link_kind: LinkKind::Lan, handle: PeerHandle::new(name) }
    }

    #[test]
    fn target_parsing() {
        let d = tempfile::tempdir().unwrap();
        let mut t = TrustStore::load(d.path()).unwrap();
        t.add(FP_A, "laptop").unwrap();
        assert_eq!(parse_target("192.168.1.4:47821", &t), Ok(Target::Addr("192.168.1.4:47821".parse().unwrap())));
        assert_eq!(parse_target("[fe80::1]:5", &t), Ok(Target::Addr("[fe80::1]:5".parse().unwrap())));
        assert_eq!(parse_target("0000111122223333 44445555", &t), Ok(Target::Fingerprint(FP_B.into())));
        assert_eq!(parse_target("Laptop", &t), Ok(Target::Trusted { name: "laptop".into(), fingerprint: FP_A.into() }));
        assert_eq!(parse_target("phone", &t), Ok(Target::Name("phone".into())));
        assert!(parse_target("  ", &t).is_err());
    }

    #[test]
    fn picking() {
        let peers = vec![peer("alpha", Some(FP_A)), peer("beta", Some(FP_B)), peer("Beta", None)];
        assert_eq!(pick(&peers, &Target::Fingerprint(FP_A.into())), Pick::Found(&peers[0]));
        assert_eq!(pick(&peers, &Target::Trusted { name: "x".into(), fingerprint: FP_B.into() }), Pick::Found(&peers[1]));
        assert_eq!(pick(&peers, &Target::Name("ALPHA".into())), Pick::Found(&peers[0]));
        assert!(matches!(pick(&peers, &Target::Name("beta".into())), Pick::Ambiguous(v) if v.len() == 2));
        assert_eq!(pick(&peers, &Target::Name("gamma".into())), Pick::NotFound);
        assert_eq!(pick(&peers, &Target::Addr("127.0.0.1:1".parse().unwrap())), Pick::NotFound);
    }

    #[test]
    fn menu_choices() {
        assert_eq!(parse_choice("1\n", 3), Some(0));
        assert_eq!(parse_choice(" 3 ", 3), Some(2));
        assert_eq!(parse_choice("0", 3), None);
        assert_eq!(parse_choice("4", 3), None);
        assert_eq!(parse_choice("x", 3), None);
        assert_eq!(parse_choice("", 1), None);
    }
}
