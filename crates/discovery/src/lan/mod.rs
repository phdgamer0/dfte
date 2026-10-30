// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! LAN development backend (manual §41: a shared network is acceptable before radios).
//!
//! Each instance periodically sends a signed [`beacon`] to an administratively scoped IPv4
//! multicast group (TTL 1, never routed) and, optionally, to configured unicast targets on
//! private/link-local addresses (for networks that drop multicast, and for tests). There is
//! no Internet rendezvous of any kind (manual §49): configuration rejects global targets.
//!
//! Received beacons go through a bounded, rate-limited [`PeerTable`]. After a Wi-Fi Direct
//! group forms without in-band IP allocation, running this backend on the new interface is
//! also how the two ends learn each other's address and engine port.
//!
//! Every newly verified peer also becomes a unicast destination ("reply to whoever found
//! us"), capped at [`MAX_LEARNED_TARGETS`]. Multicast leaves through the default route
//! only, so on a phone hosting a Wi-Fi Direct group while also on home Wi-Fi, a laptop in
//! the group would otherwise never hear it: the laptop beacons to the group owner's
//! address, and the phone answers it directly.

pub mod beacon;
pub mod table;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crypto::DeviceIdentity;
use ring::rand::{SecureRandom, SystemRandom};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::{DiscoveryError, DiscoveryEvent, LinkInfo, LinkKind, LinkRole, Peer, PeerDiscovery, PeerStream, Result};
pub use beacon::{BeaconSigner, BeaconView};
pub use table::{DropReason, Ingest, LanPeer, PeerTable, TableConfig};

/// Default beacon UDP port.
pub const DEFAULT_BEACON_PORT: u16 = 47_820;
/// Most unicast destinations learned from received beacons (oldest replaced first).
pub const MAX_LEARNED_TARGETS: usize = 16;
/// Default multicast group, in the IPv4 organization-local scope (239.255.0.0/16, RFC 2365).
pub const DEFAULT_MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 70, 84);

#[derive(Debug, Clone)]
pub struct LanConfig {
    /// Untrusted display label advertised to peers.
    pub display_name: String,
    /// The engine's transport port, advertised in beacons.
    pub service_port: u16,
    /// Local address to bind the beacon socket to (port included). Use port 0 for an
    /// ephemeral port (tests); peers then need it as an explicit unicast target.
    pub bind: SocketAddr,
    /// Multicast group to announce to and join. `None` disables multicast.
    pub multicast_group: Option<Ipv4Addr>,
    /// Port beacons are sent to on the multicast group.
    pub multicast_port: u16,
    /// Extra unicast destinations. Must be private, link-local or loopback addresses.
    pub unicast_targets: Vec<SocketAddr>,
    pub announce_interval: Duration,
    pub table: TableConfig,
}

impl LanConfig {
    pub fn new(display_name: impl Into<String>, service_port: u16) -> Self {
        Self { display_name: display_name.into(), service_port, bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_BEACON_PORT)), multicast_group: Some(DEFAULT_MULTICAST_GROUP), multicast_port: DEFAULT_BEACON_PORT, unicast_targets: Vec::new(), announce_interval: Duration::from_secs(2), table: TableConfig::default() }
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_port == 0 {
            return Err(DiscoveryError::InvalidConfig("service_port must be nonzero".into()));
        }
        if self.announce_interval < Duration::from_millis(100) {
            return Err(DiscoveryError::InvalidConfig("announce_interval below 100 ms".into()));
        }
        if let Some(g) = self.multicast_group
            && !g.is_multicast()
        {
            return Err(DiscoveryError::InvalidConfig(format!("{g} is not a multicast group")));
        }
        if let Some(t) = self.unicast_targets.iter().find(|t| !is_local_scope(t.ip()) || t.port() == 0) {
            // Manual §49: no Internet rendezvous. Only same-link/private destinations.
            return Err(DiscoveryError::InvalidConfig(format!("unicast target {t} is not a local-scope address")));
        }
        Ok(())
    }
}

/// Loopback, RFC 1918 private, link-local, or IPv6 ULA / link-local.
fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

#[derive(Debug, Default)]
struct Tasks {
    announce: Option<JoinHandle<()>>,
    receive: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct Shared {
    table: Mutex<PeerTable>,
    socket: tokio::sync::Mutex<Option<Arc<UdpSocket>>>,
    tasks: Mutex<Tasks>,
    /// Multicast group (if any) plus unicast targets; read by the announce task every tick.
    destinations: Mutex<Vec<SocketAddr>>,
    /// Beacon sources of verified peers, also announced to (see the module docs).
    learned: Mutex<std::collections::VecDeque<SocketAddr>>,
    /// Datagrams dropped by the peer table (malformed, rate-limited, replayed, forged...).
    dropped: AtomicU64,
}

/// LAN beacon discovery. Cheap to clone; clones share state.
#[derive(Debug, Clone)]
pub struct LanDiscovery {
    config: Arc<LanConfig>,
    shared: Arc<Shared>,
}

impl LanDiscovery {
    pub fn new(config: LanConfig) -> Result<Self> {
        config.validate()?;
        let table = PeerTable::new(config.table, Instant::now());
        let mut destinations: Vec<SocketAddr> = config.multicast_group.map(|g| SocketAddr::from((g, config.multicast_port))).into_iter().collect();
        destinations.extend(config.unicast_targets.iter().copied());
        let shared = Shared { table: Mutex::new(table), socket: tokio::sync::Mutex::new(None), tasks: Mutex::new(Tasks::default()), destinations: Mutex::new(destinations), learned: Mutex::new(std::collections::VecDeque::new()), dropped: AtomicU64::new(0) };
        Ok(Self { config: Arc::new(config), shared: Arc::new(shared) })
    }

    /// Also announce to `target` (manual IP entry, §41; or a peer learned out of band).
    /// Only local-scope addresses are accepted (manual §49).
    pub fn add_unicast_target(&self, target: SocketAddr) -> Result<()> {
        if !is_local_scope(target.ip()) || target.port() == 0 {
            return Err(DiscoveryError::InvalidConfig(format!("unicast target {target} is not a local-scope address")));
        }
        let mut d = lock(&self.shared.destinations);
        if !d.contains(&target) {
            d.push(target);
        }
        Ok(())
    }

    /// Local address of the beacon socket (binds it if not yet bound).
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket().await?.local_addr()?)
    }

    /// Number of received datagrams the peer table refused, for diagnostics (manual §39).
    pub fn dropped_beacons(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// Snapshot of currently known peers.
    pub fn peers(&self) -> Vec<Peer> {
        lock(&self.shared.table).peers_snapshot()
    }

    async fn socket(&self) -> Result<Arc<UdpSocket>> {
        let mut guard = self.shared.socket.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(Arc::clone(s));
        }
        let s = Arc::new(UdpSocket::from_std(bind_socket(&self.config)?)?);
        *guard = Some(Arc::clone(&s));
        Ok(s)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock means a panic mid-update of plain data; the data is still
    // structurally valid (every update is a single insert/retain), so keep going.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bind_socket(config: &LanConfig) -> Result<StdUdpSocket> {
    let domain = if config.bind.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    // SO_REUSEADDR (not SO_REUSEPORT): on Linux every socket bound this way receives a copy
    // of each multicast datagram, so several instances on one host all see beacons.
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&config.bind.into())?;
    if let (Some(group), true) = (config.multicast_group, config.bind.is_ipv4()) {
        socket.set_multicast_ttl_v4(1)?; // never leaves the link
        socket.set_multicast_loop_v4(true)?;
        if let Err(e) = socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED) {
            // No multicast route (e.g. container without a default route): unicast still works.
            tracing::warn!(error = %e, %group, "multicast join failed; LAN discovery limited to unicast targets");
        }
    }
    Ok(socket.into())
}

fn wall_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        // Saturating on purpose: u64 milliseconds overflow ~584 million years from now.
        Ok(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        Err(e) => {
            // A clock set before 1970 makes our beacons look stale to peers (and theirs to
            // us); report it loudly instead of guessing a time.
            tracing::warn!(error = %e, "system clock is before the unix epoch");
            0
        }
    }
}

/// Our address on the route towards `peer`. A connected UDP socket sends nothing; it only
/// asks the kernel which source address it would use.
///
/// `LinkInfo::local_ip` is optional, so a failure here is logged and reported as `None`
/// rather than failing `connect`.
fn local_ip_towards(peer: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if peer.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
    let probe = || -> std::io::Result<IpAddr> {
        let s = StdUdpSocket::bind(bind)?;
        s.connect((peer, 9))?;
        Ok(s.local_addr()?.ip())
    };
    match probe() {
        Ok(ip) => Some(ip),
        Err(e) => {
            tracing::debug!(error = %e, %peer, "could not determine local address towards peer");
            None
        }
    }
}

impl PeerDiscovery for LanDiscovery {
    async fn start_advertising(&self, identity: &DeviceIdentity) -> Result<()> {
        let signer = BeaconSigner::new(identity);
        lock(&self.shared.table).set_own_key(signer.public_key());
        let socket = self.socket().await?;
        let shared = Arc::clone(&self.shared);
        let (name, port, interval) = (self.config.display_name.clone(), self.config.service_port, self.config.announce_interval);
        let task = tokio::spawn(async move {
            let rng = SystemRandom::new();
            let mut ticker = tokio::time::interval(interval);
            let mut buf = [0u8; beacon::MAX_BEACON_LEN];
            let mut dests = Vec::new();
            loop {
                ticker.tick().await;
                let mut nonce = [0u8; beacon::NONCE_LEN];
                if rng.fill(&mut nonce).is_err() {
                    tracing::error!("system RNG failure; stopping LAN announcements");
                    return;
                }
                let n = signer.encode_into(&name, port, wall_ms(), nonce, &mut buf);
                dests.clone_from(&lock(&shared.destinations));
                for t in lock(&shared.learned).iter() {
                    if !dests.contains(t) {
                        dests.push(*t);
                    }
                }
                for d in &dests {
                    if let Err(e) = socket.send_to(&buf[..n], d).await {
                        tracing::debug!(error = %e, dest = %d, "beacon send failed");
                    }
                }
            }
        });
        if let Some(old) = lock(&self.shared.tasks).announce.replace(task) {
            old.abort();
        }
        Ok(())
    }

    async fn start_scanning(&self) -> Result<PeerStream> {
        let socket = self.socket().await?;
        let (tx, stream) = PeerStream::channel();
        let shared = Arc::clone(&self.shared);
        let ttl = self.config.table.peer_ttl;
        let task = tokio::spawn(receive_loop(socket, shared, tx, ttl));
        if let Some(old) = lock(&self.shared.tasks).receive.replace(task) {
            old.abort();
        }
        Ok(stream)
    }

    async fn connect(&self, peer: &Peer) -> Result<LinkInfo> {
        let addr = lock(&self.shared.table).get(&peer.handle).map(|p| p.addr).ok_or(DiscoveryError::UnknownPeer)?;
        Ok(LinkInfo { local_ip: local_ip_towards(addr.ip()), peer_ip: Some(addr.ip()), peer_port: Some(addr.port()), interface: None, link_kind: LinkKind::Lan, role: LinkRole::Client })
    }

    async fn stop(&self) -> Result<()> {
        let handles = {
            let mut tasks = lock(&self.shared.tasks);
            [tasks.announce.take(), tasks.receive.take()]
        };
        for t in handles.into_iter().flatten() {
            t.abort();
        }
        *self.shared.socket.lock().await = None;
        lock(&self.shared.learned).clear();
        Ok(())
    }
}

/// Remembers a verified peer's beacon address as a unicast destination.
fn learn(shared: &Shared, src: SocketAddr) {
    if !is_local_scope(src.ip()) || lock(&shared.destinations).contains(&src) {
        return;
    }
    let mut l = lock(&shared.learned);
    if l.contains(&src) {
        return;
    }
    if l.len() == MAX_LEARNED_TARGETS {
        l.pop_front();
    }
    l.push_back(src);
}

async fn receive_loop(socket: Arc<UdpSocket>, shared: Arc<Shared>, tx: mpsc::Sender<DiscoveryEvent>, ttl: Duration) {
    let mut buf = [0u8; 512];
    let mut expiry = tokio::time::interval((ttl / 4).max(Duration::from_millis(50)));
    // Report peers already known (e.g. from an earlier scan) to the new stream.
    let known = lock(&shared.table).peers_snapshot();
    for p in known {
        if tx.send(DiscoveryEvent::PeerFound(p)).await.is_err() {
            return;
        }
    }
    loop {
        let events: Vec<DiscoveryEvent> = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok((n, src)) => match lock(&shared.table).ingest(src, &buf[..n], Instant::now(), wall_ms()) {
                    Ingest::Found(p) => {
                        learn(&shared, src);
                        vec![DiscoveryEvent::PeerFound(p)]
                    }
                    Ingest::Refreshed => Vec::new(),
                    Ingest::Dropped(reason) => {
                        // Dropping hostile/malformed datagrams is the point; count and log them.
                        shared.dropped.fetch_add(1, Ordering::Relaxed);
                        tracing::trace!(?reason, %src, "beacon dropped");
                        Vec::new()
                    }
                },
                Err(e) => {
                    // ICMP port-unreachable from a unicast target surfaces here on some OSes.
                    tracing::debug!(error = %e, "beacon recv error");
                    Vec::new()
                }
            },
            _ = expiry.tick() => lock(&shared.table).expire(Instant::now()).into_iter().map(DiscoveryEvent::PeerLost).collect(),
            () = tx.closed() => return,
        };
        for ev in events {
            if tx.send(ev).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_config(name: &str, service_port: u16) -> LanConfig {
        LanConfig { bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), multicast_group: None, announce_interval: Duration::from_millis(100), ..LanConfig::new(name, service_port) }
    }

    async fn wait_found(stream: &mut PeerStream) -> Peer {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
                Ok(Some(DiscoveryEvent::PeerFound(p))) => return p,
                Ok(Some(_)) => {}
                other => panic!("no PeerFound: {other:?}"),
            }
        }
    }

    #[test]
    fn config_rejects_internet_targets_and_bad_values() {
        let mut c = LanConfig::new("x", 1);
        c.unicast_targets = vec!["8.8.8.8:47820".parse().unwrap()];
        assert!(c.validate().is_err());
        c.unicast_targets = vec!["192.168.1.5:47820".parse().unwrap(), "[fe80::1]:47820".parse().unwrap(), "127.0.0.1:1".parse().unwrap()];
        c.validate().unwrap();
        c.multicast_group = Some(Ipv4Addr::new(10, 0, 0, 1));
        assert!(c.validate().is_err());
        assert!(LanConfig::new("x", 0).validate().is_err());
    }

    /// Two instances on loopback, unicast-targeted at each other: each finds the other
    /// with the right fingerprint and engine port, and `connect` returns its address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_instances_find_each_other_over_unicast() {
        let id_a = DeviceIdentity::generate().unwrap();
        let id_b = DeviceIdentity::generate().unwrap();
        let a = LanDiscovery::new(loopback_config("A", 5001)).unwrap();
        let b = LanDiscovery::new(loopback_config("B", 5002)).unwrap();
        a.add_unicast_target(b.local_addr().await.unwrap()).unwrap();
        b.add_unicast_target(a.local_addr().await.unwrap()).unwrap();
        assert!(a.add_unicast_target("1.1.1.1:47820".parse().unwrap()).is_err());

        let mut sa = a.start_scanning().await.unwrap();
        let mut sb = b.start_scanning().await.unwrap();
        a.start_advertising(&id_a).await.unwrap();
        b.start_advertising(&id_b).await.unwrap();

        let seen_by_a = wait_found(&mut sa).await;
        let seen_by_b = wait_found(&mut sb).await;
        assert_eq!(seen_by_a.fingerprint.as_deref(), Some(id_b.fingerprint().as_str()));
        assert_eq!(seen_by_a.display_name, "B");
        assert_eq!(seen_by_b.fingerprint.as_deref(), Some(id_a.fingerprint().as_str()));

        let link = a.connect(&seen_by_a).await.unwrap();
        assert_eq!(link.peer_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(link.peer_port, Some(5002));
        assert_eq!(link.link_kind, LinkKind::Lan);
        assert_eq!(link.role, LinkRole::Client);
        assert_eq!(a.peers().len(), 1);

        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    /// Only B knows A's address; A learns B's from B's beacon and answers it, so both
    /// find each other (the phone-hosts-a-Wi-Fi-Direct-group case).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_sided_target_is_answered() {
        let (id_a, id_b) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        let a = LanDiscovery::new(loopback_config("A", 5011)).unwrap();
        let b = LanDiscovery::new(loopback_config("B", 5012)).unwrap();
        b.add_unicast_target(a.local_addr().await.unwrap()).unwrap();
        let mut sa = a.start_scanning().await.unwrap();
        let mut sb = b.start_scanning().await.unwrap();
        a.start_advertising(&id_a).await.unwrap();
        b.start_advertising(&id_b).await.unwrap();
        assert_eq!(wait_found(&mut sa).await.display_name, "B");
        assert_eq!(wait_found(&mut sb).await.display_name, "A");
        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    #[test]
    fn learned_targets_are_bounded_and_local_only() {
        let a = LanDiscovery::new(loopback_config("A", 1)).unwrap();
        learn(&a.shared, "8.8.8.8:47820".parse().unwrap());
        for i in 0..40u16 {
            learn(&a.shared, SocketAddr::from((Ipv4Addr::new(192, 168, 49, 2), 1000 + i)));
        }
        learn(&a.shared, SocketAddr::from((Ipv4Addr::new(192, 168, 49, 2), 1039)));
        let l = lock(&a.shared.learned);
        assert_eq!(l.len(), MAX_LEARNED_TARGETS);
        assert!(l.iter().all(|t| t.ip().is_ipv4() && t.port() >= 1024));
    }

    #[tokio::test]
    async fn connect_unknown_peer_fails() {
        let a = LanDiscovery::new(loopback_config("A", 1)).unwrap();
        let p = Peer { fingerprint: None, display_name: "?".into(), link_kind: LinkKind::Lan, handle: crate::PeerHandle::new("nope") };
        assert!(matches!(a.connect(&p).await, Err(DiscoveryError::UnknownPeer)));
    }

    /// Multicast between two instances on one host. Skips (passes vacuously, with a note)
    /// when the environment has no multicast route, e.g. sandboxed CI containers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_instances_over_multicast_when_available() {
        // A dedicated port/group so parallel test runs do not cross-talk.
        let port = 47_900 + (std::process::id() % 50) as u16;
        let group = Ipv4Addr::new(239, 255, 70, 85);
        let cfg = |name: &str, svc| LanConfig { bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)), multicast_group: Some(group), multicast_port: port, announce_interval: Duration::from_millis(100), ..LanConfig::new(name, svc) };
        let probe = StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        if probe.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED).is_err() || probe.send_to(b"probe", (group, port)).is_err() {
            eprintln!("multicast unavailable here; skipping (unicast test covers the logic)");
            return;
        }
        let a = LanDiscovery::new(cfg("A", 6001)).unwrap();
        let b = LanDiscovery::new(cfg("B", 6002)).unwrap();
        let mut sa = a.start_scanning().await.unwrap();
        b.start_scanning().await.unwrap();
        let (id_a, id_b) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        a.start_advertising(&id_a).await.unwrap();
        b.start_advertising(&id_b).await.unwrap();
        let found = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match sa.next().await {
                    Some(DiscoveryEvent::PeerFound(p)) if p.fingerprint.as_deref() == Some(id_b.fingerprint().as_str()) => return Some(p),
                    Some(_) => {}
                    None => return None,
                }
            }
        })
        .await;
        match found {
            Ok(Some(p)) => assert_eq!(p.display_name, "B"),
            _ => eprintln!("multicast joined but nothing delivered (filtered network?); skipping"),
        }
        a.stop().await.unwrap();
        b.stop().await.unwrap();
    }

    #[tokio::test]
    async fn peer_expiry_emits_peer_lost() {
        let id_b = DeviceIdentity::generate().unwrap();
        let mut cfg_a = loopback_config("A", 1);
        cfg_a.table.peer_ttl = Duration::from_millis(400);
        let a = LanDiscovery::new(cfg_a).unwrap();
        let b = LanDiscovery::new(loopback_config("B", 2)).unwrap();
        b.add_unicast_target(a.local_addr().await.unwrap()).unwrap();
        let mut sa = a.start_scanning().await.unwrap();
        b.start_advertising(&id_b).await.unwrap();
        let p = wait_found(&mut sa).await;
        b.stop().await.unwrap();
        let lost = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(DiscoveryEvent::PeerLost(h)) = sa.next().await {
                    return h;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(lost, p.handle);
    }
}
