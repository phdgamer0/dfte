// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Bounded, rate-limited peer table fed by LAN beacons (manual §34: resource exhaustion).
//!
//! Pure and synchronous: callers pass the monotonic `now` and the wall-clock time in
//! milliseconds, so expiry, rate limits and freshness checks are deterministic in tests.
//!
//! Every limit here is a hard bound: at most `max_peers` peers, at most `max_sources`
//! tracked source addresses, and at most `verify_budget_per_sec` signature verifications per
//! second regardless of how many spoofed source addresses an attacker floods from. Cheap
//! structural checks and per-source rate limits run *before* the expensive Ed25519 verify.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;

use crate::lan::beacon::{BeaconView, MAGIC, MIN_BEACON_LEN};
use crate::{LinkKind, Peer, PeerHandle};

/// Limits and timings for a [`PeerTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableConfig {
    pub max_peers: usize,
    /// A peer not heard from for this long is reported lost.
    pub peer_ttl: Duration,
    /// Maximum |sender clock − our clock|. Bounds how long a captured beacon can be replayed.
    pub max_clock_skew: Duration,
    /// Per-source token bucket: burst size and refill rate (datagrams).
    pub per_source_burst: u32,
    pub per_source_per_sec: u32,
    /// Distinct source addresses tracked for rate limiting.
    pub max_sources: usize,
    /// Global cap on signature verifications per second.
    pub verify_budget_per_sec: u32,
}

impl Default for TableConfig {
    fn default() -> Self {
        Self { max_peers: 64, peer_ttl: Duration::from_secs(10), max_clock_skew: Duration::from_secs(120), per_source_burst: 8, per_source_per_sec: 4, max_sources: 256, verify_budget_per_sec: 256 }
    }
}

/// A peer known from a verified beacon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPeer {
    pub public_key: [u8; 32],
    pub fingerprint: String,
    pub name: String,
    pub addr: SocketAddr,
    pub last_seen: Instant,
    last_timestamp_ms: u64,
    /// Decompressed key, so re-announcements skip point decompression on verify.
    verifying_key: VerifyingKey,
}

impl LanPeer {
    pub fn handle(&self) -> PeerHandle {
        handle_for(&self.public_key)
    }

    pub fn to_peer(&self) -> Peer {
        Peer { fingerprint: Some(self.fingerprint.clone()), display_name: self.name.clone(), link_kind: LinkKind::Lan, handle: self.handle() }
    }
}

/// Handle of a LAN peer: lowercase hex of its full Ed25519 public key.
pub fn handle_for(public_key: &[u8; 32]) -> PeerHandle {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in public_key {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0xf)]));
    }
    PeerHandle::new(s)
}

/// Why a datagram was not accepted. Diagnostics only; never sent anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    RateLimited,
    OwnBeacon,
    Stale,
    Replay,
    VerifyBudget,
    BadSignature,
    TableFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingest {
    /// New peer, or a known peer whose name/address changed: emit `PeerFound`.
    Found(Peer),
    /// Known peer, nothing user-visible changed.
    Refreshed,
    Dropped(DropReason),
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: u32, now: Instant) -> Self {
        Self { tokens: f64::from(burst), last: now }
    }

    fn take(&mut self, burst: u32, per_sec: u32, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * f64::from(per_sec)).min(f64::from(burst));
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct PeerTable {
    config: TableConfig,
    own_key: Option<[u8; 32]>,
    peers: HashMap<[u8; 32], LanPeer>,
    sources: HashMap<IpAddr, Bucket>,
    verify_budget: Bucket,
}

impl PeerTable {
    pub fn new(config: TableConfig, now: Instant) -> Self {
        Self { config, own_key: None, peers: HashMap::new(), sources: HashMap::new(), verify_budget: Bucket::full(config.verify_budget_per_sec, now) }
    }

    /// Ignore beacons carrying this key (our own, looped back by multicast).
    pub fn set_own_key(&mut self, key: [u8; 32]) {
        self.own_key = Some(key);
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LanPeer> {
        self.peers.values()
    }

    pub(crate) fn peers_snapshot(&self) -> Vec<Peer> {
        self.iter().map(LanPeer::to_peer).collect()
    }

    pub fn get(&self, handle: &PeerHandle) -> Option<&LanPeer> {
        self.peers.values().find(|p| p.handle() == *handle)
    }

    /// Process one received datagram.
    pub fn ingest(&mut self, src: SocketAddr, datagram: &[u8], now: Instant, wall_ms: u64) -> Ingest {
        // 1. Free structural pre-check, before spending any state on the sender.
        if datagram.len() < MIN_BEACON_LEN || datagram[..4] != MAGIC {
            return Ingest::Dropped(DropReason::Malformed);
        }
        // 2. Per-source rate limit (bounded map: when full, unknown sources share no state
        //    and are refused, so a spoofing flood cannot grow memory).
        if !self.take_source_token(src.ip(), now) {
            return Ingest::Dropped(DropReason::RateLimited);
        }
        let Ok(view) = BeaconView::parse(datagram) else {
            return Ingest::Dropped(DropReason::Malformed);
        };
        if self.own_key == Some(view.public_key) {
            return Ingest::Dropped(DropReason::OwnBeacon);
        }
        // 3. Freshness: bounds replay of captured beacons to the skew window.
        // Saturating on purpose: a skew too large for u64 milliseconds means "no limit".
        let skew_ms = u64::try_from(self.config.max_clock_skew.as_millis()).unwrap_or(u64::MAX);
        if view.timestamp_ms.abs_diff(wall_ms) > skew_ms {
            return Ingest::Dropped(DropReason::Stale);
        }
        let known = self.peers.get(&view.public_key);
        // 4. Replay inside the window: timestamps must strictly increase per key.
        if known.is_some_and(|p| view.timestamp_ms <= p.last_timestamp_ms) {
            return Ingest::Dropped(DropReason::Replay);
        }
        if known.is_none() && self.peers.len() >= self.config.max_peers {
            self.expire(now);
            if self.peers.len() >= self.config.max_peers {
                return Ingest::Dropped(DropReason::TableFull);
            }
        }
        // 5. Global verify budget, then the expensive part.
        if !self.verify_budget.take(self.config.verify_budget_per_sec, self.config.verify_budget_per_sec, now) {
            return Ingest::Dropped(DropReason::VerifyBudget);
        }
        let verified = match self.peers.get(&view.public_key) {
            Some(p) => view.verify_with(&p.verifying_key).map(|()| p.verifying_key),
            None => view.verify(),
        };
        let Ok(key) = verified else {
            return Ingest::Dropped(DropReason::BadSignature);
        };
        self.upsert(&view, key, src, now)
    }

    fn take_source_token(&mut self, ip: IpAddr, now: Instant) -> bool {
        let (burst, rate) = (self.config.per_source_burst, self.config.per_source_per_sec);
        if let Some(b) = self.sources.get_mut(&ip) {
            return b.take(burst, rate, now);
        }
        if self.sources.len() >= self.config.max_sources {
            // Reclaim buckets that have fully refilled (idle sources carry no information).
            let refill = Duration::from_secs_f64(f64::from(burst) / f64::from(rate.max(1)));
            self.sources.retain(|_, b| now.saturating_duration_since(b.last) < refill);
            if self.sources.len() >= self.config.max_sources {
                return false;
            }
        }
        let mut b = Bucket::full(burst, now);
        let ok = b.take(burst, rate, now);
        self.sources.insert(ip, b);
        ok
    }

    fn upsert(&mut self, view: &BeaconView<'_>, verifying_key: VerifyingKey, src: SocketAddr, now: Instant) -> Ingest {
        let addr = SocketAddr::new(src.ip(), view.port);
        match self.peers.get_mut(&view.public_key) {
            Some(p) => {
                p.last_seen = now;
                p.last_timestamp_ms = view.timestamp_ms;
                if p.addr == addr && p.name == view.name {
                    return Ingest::Refreshed;
                }
                p.addr = addr;
                p.name = view.name.to_owned();
                Ingest::Found(p.to_peer())
            }
            None => {
                let p = LanPeer { public_key: view.public_key, fingerprint: crypto::fingerprint_of(&view.public_key), name: view.name.to_owned(), addr, last_seen: now, last_timestamp_ms: view.timestamp_ms, verifying_key };
                let peer = p.to_peer();
                self.peers.insert(view.public_key, p);
                Ingest::Found(peer)
            }
        }
    }

    /// Drop peers not heard from within the TTL; returns their handles (emit `PeerLost`).
    pub fn expire(&mut self, now: Instant) -> Vec<PeerHandle> {
        let ttl = self.config.peer_ttl;
        let mut lost = Vec::new();
        self.peers.retain(|_, p| {
            let keep = now.saturating_duration_since(p.last_seen) < ttl;
            if !keep {
                lost.push(p.handle());
            }
            keep
        });
        lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::beacon::BeaconSigner;
    use crypto::DeviceIdentity;

    const WALL: u64 = 1_700_000_000_000;

    fn signer(seed: u8) -> BeaconSigner {
        BeaconSigner::new(&DeviceIdentity::from_secret_bytes(&[seed; 32]))
    }

    fn src(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, last], 47_820))
    }

    #[test]
    fn new_peer_then_refresh_then_change() {
        let t0 = Instant::now();
        let mut t = PeerTable::new(TableConfig::default(), t0);
        let s = signer(1);
        let Ingest::Found(p) = t.ingest(src(2), &s.encode("a", 5000, WALL, [0; 16]), t0, WALL) else { panic!() };
        assert_eq!(p.fingerprint.as_deref(), Some(DeviceIdentity::from_secret_bytes(&[1; 32]).fingerprint().as_str()));
        assert_eq!(p.link_kind, LinkKind::Lan);
        assert_eq!(t.get(&p.handle).unwrap().addr, SocketAddr::from(([192, 168, 1, 2], 5000)));
        assert_eq!(t.ingest(src(2), &s.encode("a", 5000, WALL + 1, [1; 16]), t0, WALL), Ingest::Refreshed);
        assert!(matches!(t.ingest(src(2), &s.encode("renamed", 5000, WALL + 2, [2; 16]), t0, WALL), Ingest::Found(_)));
    }

    #[test]
    fn replay_stale_own_and_forged_are_dropped() {
        let t0 = Instant::now();
        let mut t = PeerTable::new(TableConfig::default(), t0);
        let s = signer(1);
        let b = s.encode("a", 5000, WALL, [0; 16]);
        assert!(matches!(t.ingest(src(2), &b, t0, WALL), Ingest::Found(_)));
        assert_eq!(t.ingest(src(3), &b, t0, WALL), Ingest::Dropped(DropReason::Replay));
        assert_eq!(t.ingest(src(2), &s.encode("a", 5000, WALL - 10, [0; 16]), t0, WALL), Ingest::Dropped(DropReason::Replay));
        assert_eq!(t.ingest(src(4), &signer(2).encode("x", 1, WALL - 200_000, [0; 16]), t0, WALL), Ingest::Dropped(DropReason::Stale));
        let own = signer(9);
        t.set_own_key(own.public_key());
        assert_eq!(t.ingest(src(5), &own.encode("me", 1, WALL, [0; 16]), t0, WALL), Ingest::Dropped(DropReason::OwnBeacon));
        let mut forged = signer(3).encode("x", 1, WALL, [0; 16]);
        let n = forged.len();
        forged[n - 1] ^= 1;
        assert_eq!(t.ingest(src(6), &forged, t0, WALL), Ingest::Dropped(DropReason::BadSignature));
        assert_eq!(t.ingest(src(7), b"hello", t0, WALL), Ingest::Dropped(DropReason::Malformed));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn expiry_reports_lost_peers() {
        let t0 = Instant::now();
        let mut t = PeerTable::new(TableConfig::default(), t0);
        let Ingest::Found(p) = t.ingest(src(2), &signer(1).encode("a", 5000, WALL, [0; 16]), t0, WALL) else { panic!() };
        assert!(t.expire(t0 + Duration::from_secs(9)).is_empty());
        assert_eq!(t.expire(t0 + Duration::from_secs(10)), vec![p.handle]);
        assert!(t.is_empty());
    }

    #[test]
    fn per_source_rate_limit() {
        let t0 = Instant::now();
        let cfg = TableConfig::default();
        let mut t = PeerTable::new(cfg, t0);
        let s = signer(1);
        let mut accepted = 0;
        for i in 0..100u64 {
            if !matches!(t.ingest(src(2), &s.encode("a", 1, WALL + i, [0; 16]), t0, WALL), Ingest::Dropped(DropReason::RateLimited)) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, cfg.per_source_burst);
        // Refills over time.
        let later = t0 + Duration::from_secs(1);
        assert!(!matches!(t.ingest(src(2), &s.encode("a", 1, WALL + 1000, [0; 16]), later, WALL), Ingest::Dropped(DropReason::RateLimited)));
    }

    #[test]
    fn table_and_source_map_are_bounded_under_flood() {
        let t0 = Instant::now();
        let cfg = TableConfig { max_peers: 8, max_sources: 16, verify_budget_per_sec: 1000, ..TableConfig::default() };
        let mut t = PeerTable::new(cfg, t0);
        for i in 0..64u8 {
            let b = signer(i).encode("flood", 1, WALL, [0; 16]);
            t.ingest(SocketAddr::from(([10, 0, 0, i], 1)), &b, t0, WALL);
        }
        assert_eq!(t.len(), 8);
        assert!(t.sources.len() <= 16);
    }

    #[test]
    fn verify_budget_caps_signature_checks() {
        let t0 = Instant::now();
        let cfg = TableConfig { verify_budget_per_sec: 4, max_sources: 1024, max_peers: 1024, ..TableConfig::default() };
        let mut t = PeerTable::new(cfg, t0);
        let results: Vec<_> = (0..10u8).map(|i| t.ingest(SocketAddr::from(([10, 0, 0, i], 1)), &signer(i).encode("x", 1, WALL, [0; 16]), t0, WALL)).collect();
        assert_eq!(results.iter().filter(|r| matches!(r, Ingest::Found(_))).count(), 4);
        assert_eq!(results.iter().filter(|r| **r == Ingest::Dropped(DropReason::VerifyBudget)).count(), 6);
    }

    #[test]
    fn handle_is_hex_public_key() {
        let h = handle_for(&[0xab; 32]);
        assert_eq!(h.as_str().len(), 64);
        assert!(h.as_str().starts_with("abab"));
    }
}
