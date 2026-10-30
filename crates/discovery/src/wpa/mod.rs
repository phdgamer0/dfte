// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Linux Wi-Fi Direct backend over `wpa_supplicant`'s D-Bus P2P API (manual §5 Linux, §6).
//!
//! Split in two so the logic is testable without a bus or a radio:
//!
//! * [`P2pBus`]: a deliberately small trait mirroring the handful of
//!   `fi.w1.wpa_supplicant1.Interface.P2PDevice` calls and signals we use. The real
//!   implementation, [`ZbusP2pBus`] (feature `linux-wpa`), talks to the system bus with
//!   `zbus`; tests use an in-memory mock.
//! * [`WpaDiscovery`]: the [`PeerDiscovery`] implementation translating bus signals into
//!   [`DiscoveryEvent`]s and group formation into a [`LinkInfo`]. Always compiled, so the
//!   translation logic is unit-tested in default CI.
//!
//! Flow: `Find` → `DeviceFound(path)` / `DeviceLost(path)` signals → `PeerFound` / `PeerLost`
//! (device name looked up on the `Peer` object) · `Connect{wps_method: pbc}` →
//! `GroupStarted{interface_object, role, IpAddr*}` → read `Ifname` → [`LinkInfo`].
//!
//! Addressing: when wpa_supplicant is configured for in-band IP allocation in EAPOL
//! (`ip_addr_go`, `ip_addr_mask`, `ip_addr_start`, `ip_addr_end` in wpa_supplicant.conf),
//! `GroupStarted` carries both addresses and `LinkInfo` is complete. Otherwise the group
//! falls back to DHCP and `peer_ip` is `None`: run [`LanDiscovery`](crate::lan::LanDiscovery)
//! on the group interface to learn the peer's address, port and fingerprint.
//!
//! Peers found via plain `p2p_find` carry no fingerprint (`Peer::fingerprint == None`);
//! identity is established by the handshake's SAS comparison (manual §12.1).
//!
//! Not validated on hardware yet: signal ordering across drivers, PBC timing, and
//! `GONegotiationFailure` status codes on real chipsets (manual §5: driver quality varies).

#[cfg(feature = "linux-wpa")]
mod zbus_bus;
#[cfg(feature = "linux-wpa")]
pub use zbus_bus::ZbusP2pBus;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crypto::DeviceIdentity;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::{DiscoveryError, DiscoveryEvent, LinkInfo, LinkKind, LinkRole, Peer, PeerDiscovery, PeerHandle, PeerStream, Result};

/// `GroupStarted` signal properties we use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupStarted {
    /// Object path of the group's network interface.
    pub interface_object: String,
    /// `"GO"` or `"client"`.
    pub role: String,
    /// Our address, when allocated in EAPOL (client role).
    pub ip_addr: Option<Vec<u8>>,
    /// The group owner's address, when in-band allocation is configured.
    pub ip_addr_go: Option<Vec<u8>>,
}

/// The subset of `P2PDevice` signals we react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pSignal {
    DeviceFound(String),
    DeviceLost(String),
    GroupStarted(GroupStarted),
    /// `GONegotiationFailure{status}`; P2P status code (11 = rejected by user).
    GoNegotiationFailure(i32),
    GroupFormationFailure(String),
    GroupFinished,
    FindStopped,
}

/// Properties of a `fi.w1.wpa_supplicant1.Peer` object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerProperties {
    pub device_name: String,
    pub device_address: Vec<u8>,
}

/// P2P status code for "rejected by user" (Wi-Fi P2P spec, Table 6).
pub const P2P_STATUS_REJECTED_BY_USER: i32 = 11;

/// Minimal async view of wpa_supplicant's P2P D-Bus interface. Object paths are plain strings
/// so implementations other than zbus (tests) need no D-Bus types.
pub trait P2pBus: Send + Sync + 'static {
    fn set_device_name(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    /// `Listen(timeout)`: stay discoverable.
    fn listen(&self, timeout_secs: i32) -> impl Future<Output = Result<()>> + Send;
    /// `Find({Timeout})`.
    fn find(&self, timeout_secs: i32) -> impl Future<Output = Result<()>> + Send;
    fn stop_find(&self) -> impl Future<Output = Result<()>> + Send;
    /// `Connect({peer, wps_method: "pbc", go_intent, join: false, persistent: false})`.
    fn connect_pbc(&self, peer_path: &str, go_intent: i32) -> impl Future<Output = Result<()>> + Send;
    /// `Disconnect()`: tear down the current group.
    fn disconnect(&self) -> impl Future<Output = Result<()>> + Send;
    fn peer_properties(&self, peer_path: &str) -> impl Future<Output = Result<PeerProperties>> + Send;
    /// `Ifname` of an interface object (the group interface after `GroupStarted`).
    fn interface_name(&self, interface_path: &str) -> impl Future<Output = Result<String>> + Send;
    /// A fresh subscription to P2P signals. Dropping the receiver unsubscribes.
    fn subscribe(&self) -> impl Future<Output = Result<mpsc::Receiver<P2pSignal>>> + Send;
}

#[derive(Debug, Clone)]
pub struct WpaConfig {
    /// WPS device name shown on peers (max 32 bytes; longer names are truncated).
    pub device_name: String,
    /// GO intent 0..=15 for `Connect` (higher = prefer to be group owner).
    pub go_intent: i32,
    pub find_timeout: Duration,
    pub listen_timeout: Duration,
    /// How long to wait for `GroupStarted` after `Connect` (PBC needs the peer to accept).
    pub group_timeout: Duration,
}

impl WpaConfig {
    pub fn new(device_name: impl Into<String>) -> Self {
        Self { device_name: device_name.into(), go_intent: 7, find_timeout: Duration::from_secs(30), listen_timeout: Duration::from_secs(300), group_timeout: Duration::from_secs(60) }
    }
}

/// `wpa_supplicant` P2P discovery over any [`P2pBus`].
pub struct WpaDiscovery<B: P2pBus> {
    bus: Arc<B>,
    config: WpaConfig,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    scan_task: Mutex<Option<JoinHandle<()>>>,
}

impl<B: P2pBus> std::fmt::Debug for WpaDiscovery<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WpaDiscovery").field("config", &self.config).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Poison recovery is deliberate: guarded data is plain maps updated in single steps.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<B: P2pBus> WpaDiscovery<B> {
    pub fn new(bus: B, config: WpaConfig) -> Result<Self> {
        if !(0..=15).contains(&config.go_intent) {
            return Err(DiscoveryError::InvalidConfig(format!("go_intent {} outside 0..=15", config.go_intent)));
        }
        Ok(Self { bus: Arc::new(bus), config, peers: Arc::new(Mutex::new(HashMap::new())), scan_task: Mutex::new(None) })
    }
}

fn secs(d: Duration) -> i32 {
    // Saturating on purpose: timeouts beyond i32::MAX seconds mean "effectively forever".
    i32::try_from(d.as_secs()).unwrap_or(i32::MAX).max(1)
}

/// Peer-chosen names are untrusted: strip control characters, cap at the WPS limit.
fn sanitize_device_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > 32 {
            break;
        }
        out.push(c);
    }
    out
}

fn ip_from_bytes(b: Option<&[u8]>) -> Option<IpAddr> {
    match b? {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        other => {
            // Malformed address from the bus: ignore it (LinkInfo leaves it None) but say so.
            tracing::warn!(len = other.len(), "ignoring malformed IP address in GroupStarted");
            None
        }
    }
}

/// Map a `GroupStarted` (plus the resolved interface name) to a [`LinkInfo`].
pub fn link_info_from_group(group: &GroupStarted, interface: String) -> LinkInfo {
    let go_ip = ip_from_bytes(group.ip_addr_go.as_deref());
    let (role, local_ip, peer_ip) = if group.role.eq_ignore_ascii_case("GO") { (LinkRole::Host, go_ip, None) } else { (LinkRole::Client, ip_from_bytes(group.ip_addr.as_deref()), go_ip) };
    LinkInfo { local_ip, peer_ip, peer_port: None, interface: Some(interface), link_kind: LinkKind::WifiDirect, role }
}

async fn scan_loop<B: P2pBus>(bus: Arc<B>, mut rx: mpsc::Receiver<P2pSignal>, peers: Arc<Mutex<HashMap<String, Peer>>>, tx: mpsc::Sender<DiscoveryEvent>) {
    while let Some(sig) = tokio::select! { s = rx.recv() => s, () = tx.closed() => None } {
        let ev = match sig {
            P2pSignal::DeviceFound(path) => match bus.peer_properties(&path).await {
                Ok(props) => {
                    let peer = Peer { fingerprint: None, display_name: sanitize_device_name(&props.device_name), link_kind: LinkKind::WifiDirect, handle: PeerHandle::new(path.clone()) };
                    lock(&peers).insert(path, peer.clone());
                    DiscoveryEvent::PeerFound(peer)
                }
                Err(e) => {
                    // The peer object can vanish between the signal and the lookup.
                    tracing::debug!(error = %e, "peer property lookup failed");
                    continue;
                }
            },
            P2pSignal::DeviceLost(path) => match lock(&peers).remove(&path) {
                Some(p) => DiscoveryEvent::PeerLost(p.handle),
                None => continue,
            },
            _ => continue,
        };
        if tx.send(ev).await.is_err() {
            return;
        }
    }
}

impl<B: P2pBus> PeerDiscovery for WpaDiscovery<B> {
    async fn start_advertising(&self, _identity: &DeviceIdentity) -> Result<()> {
        // Plain P2P device discovery has no room for a signed identity; the fingerprint is
        // verified in the handshake (manual §12.1). Advertising = being findable by name.
        self.bus.set_device_name(&sanitize_device_name(&self.config.device_name)).await?;
        self.bus.listen(secs(self.config.listen_timeout)).await
    }

    async fn start_scanning(&self) -> Result<PeerStream> {
        let rx = self.bus.subscribe().await?;
        self.bus.find(secs(self.config.find_timeout)).await?;
        let (tx, stream) = PeerStream::channel();
        let task = tokio::spawn(scan_loop(Arc::clone(&self.bus), rx, Arc::clone(&self.peers), tx));
        if let Some(old) = lock(&self.scan_task).replace(task) {
            old.abort();
        }
        Ok(stream)
    }

    /// Only one `connect` at a time: `GroupStarted` does not name the peer, so concurrent
    /// group formations could not be told apart.
    async fn connect(&self, peer: &Peer) -> Result<LinkInfo> {
        if !lock(&self.peers).contains_key(peer.handle.as_str()) {
            return Err(DiscoveryError::UnknownPeer);
        }
        // Subscribe before connecting so a fast GroupStarted cannot be missed.
        let mut rx = self.bus.subscribe().await?;
        // Scanning while forming a group is unreliable on many drivers.
        if let Err(e) = self.bus.stop_find().await {
            tracing::debug!(error = %e, "StopFind before Connect failed");
        }
        self.bus.connect_pbc(peer.handle.as_str(), self.config.go_intent).await?;
        let wait = async {
            loop {
                match rx.recv().await {
                    Some(P2pSignal::GroupStarted(g)) => {
                        let ifname = self.bus.interface_name(&g.interface_object).await?;
                        return Ok(link_info_from_group(&g, ifname));
                    }
                    Some(P2pSignal::GoNegotiationFailure(P2P_STATUS_REJECTED_BY_USER)) => return Err(DiscoveryError::ConnectionRejected),
                    Some(P2pSignal::GoNegotiationFailure(status)) => return Err(DiscoveryError::Backend(format!("GO negotiation failed, status {status}"))),
                    Some(P2pSignal::GroupFormationFailure(reason)) => return Err(DiscoveryError::Backend(format!("group formation failed: {reason}"))),
                    Some(P2pSignal::GroupFinished) | None => return Err(DiscoveryError::PeerLost),
                    Some(_) => {}
                }
            }
        };
        match tokio::time::timeout(self.config.group_timeout, wait).await {
            Ok(r) => r,
            Err(_) => {
                // Cancel the pending negotiation so the radio is not left mid-formation.
                if let Err(e) = self.bus.disconnect().await {
                    tracing::debug!(error = %e, "Disconnect after timeout failed");
                }
                Err(DiscoveryError::Timeout)
            }
        }
    }

    async fn stop(&self) -> Result<()> {
        if let Some(t) = lock(&self.scan_task).take() {
            t.abort();
        }
        lock(&self.peers).clear();
        let find = self.bus.stop_find().await;
        let disc = self.bus.disconnect().await;
        // Disconnect fails harmlessly when no group exists; StopFind is the meaningful one.
        if let Err(e) = disc {
            tracing::debug!(error = %e, "Disconnect during stop failed");
        }
        find
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    /// In-memory bus: records calls, lets the test inject signals.
    struct MockBus {
        calls: Mutex<Vec<String>>,
        signals: broadcast::Sender<P2pSignal>,
        names: HashMap<String, String>,
        /// Signals to emit right after `connect_pbc` (simulates the radio answering).
        on_connect: Vec<P2pSignal>,
    }

    impl MockBus {
        fn new() -> Self {
            Self { calls: Mutex::new(Vec::new()), signals: broadcast::channel(64).0, names: HashMap::from([("/peers/1".into(), "Phone\u{7}One".into()), ("/peers/2".into(), "Laptop".into())]), on_connect: Vec::new() }
        }
        fn calls(&self) -> Vec<String> {
            lock(&self.calls).clone()
        }
        fn record(&self, s: String) {
            lock(&self.calls).push(s);
        }
    }

    impl P2pBus for MockBus {
        async fn set_device_name(&self, name: &str) -> Result<()> {
            self.record(format!("name {name}"));
            Ok(())
        }
        async fn listen(&self, t: i32) -> Result<()> {
            self.record(format!("listen {t}"));
            Ok(())
        }
        async fn find(&self, t: i32) -> Result<()> {
            self.record(format!("find {t}"));
            Ok(())
        }
        async fn stop_find(&self) -> Result<()> {
            self.record("stop_find".into());
            Ok(())
        }
        async fn connect_pbc(&self, peer: &str, go: i32) -> Result<()> {
            self.record(format!("connect {peer} {go}"));
            for s in &self.on_connect {
                let _ = self.signals.send(s.clone());
            }
            Ok(())
        }
        async fn disconnect(&self) -> Result<()> {
            self.record("disconnect".into());
            Ok(())
        }
        async fn peer_properties(&self, path: &str) -> Result<PeerProperties> {
            let name = self.names.get(path).ok_or_else(|| DiscoveryError::Backend("no such peer".into()))?;
            Ok(PeerProperties { device_name: name.clone(), device_address: vec![2, 0, 0, 0, 0, 1] })
        }
        async fn interface_name(&self, path: &str) -> Result<String> {
            Ok(if path == "/ifaces/7" { "p2p-wlan0-0".into() } else { "?".into() })
        }
        async fn subscribe(&self) -> Result<mpsc::Receiver<P2pSignal>> {
            let mut b = self.signals.subscribe();
            let (tx, rx) = mpsc::channel(64);
            tokio::spawn(async move {
                while let Ok(s) = b.recv().await {
                    if tx.send(s).await.is_err() {
                        return;
                    }
                }
            });
            Ok(rx)
        }
    }

    async fn next(stream: &mut PeerStream) -> DiscoveryEvent {
        tokio::time::timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap()
    }

    fn client_group() -> GroupStarted {
        GroupStarted { interface_object: "/ifaces/7".into(), role: "client".into(), ip_addr: Some(vec![192, 168, 49, 23]), ip_addr_go: Some(vec![192, 168, 49, 1]) }
    }

    #[tokio::test]
    async fn advertising_sets_name_and_listens() {
        let d = WpaDiscovery::new(MockBus::new(), WpaConfig::new("My \u{1b}[31mLaptop with a rather long name")).unwrap();
        d.start_advertising(&DeviceIdentity::generate().unwrap()).await.unwrap();
        let calls = d.bus.calls();
        assert_eq!(calls[0], "name My [31mLaptop with a rather long");
        assert_eq!(calls[1], "listen 300");
    }

    #[tokio::test]
    async fn signals_translate_to_events() {
        let d = WpaDiscovery::new(MockBus::new(), WpaConfig::new("me")).unwrap();
        let mut s = d.start_scanning().await.unwrap();
        assert_eq!(d.bus.calls(), ["find 30"]);
        let send = |sig| d.bus.signals.send(sig).unwrap();
        send(P2pSignal::DeviceFound("/peers/1".into()));
        send(P2pSignal::DeviceFound("/peers/unknown".into())); // lookup fails: skipped
        send(P2pSignal::DeviceLost("/peers/never-seen".into())); // unknown: skipped
        send(P2pSignal::DeviceFound("/peers/2".into()));
        send(P2pSignal::DeviceLost("/peers/1".into()));
        let DiscoveryEvent::PeerFound(p1) = next(&mut s).await else { panic!() };
        assert_eq!(p1.display_name, "PhoneOne");
        assert_eq!(p1.link_kind, LinkKind::WifiDirect);
        assert_eq!(p1.fingerprint, None);
        assert_eq!(p1.handle.as_str(), "/peers/1");
        let DiscoveryEvent::PeerFound(p2) = next(&mut s).await else { panic!() };
        assert_eq!(p2.display_name, "Laptop");
        assert_eq!(next(&mut s).await, DiscoveryEvent::PeerLost(PeerHandle::new("/peers/1")));
        d.stop().await.unwrap();
    }

    async fn connect_with(on_connect: Vec<P2pSignal>, cfg: WpaConfig) -> (Result<LinkInfo>, Vec<String>) {
        let mut bus = MockBus::new();
        bus.on_connect = on_connect;
        let d = WpaDiscovery::new(bus, cfg).unwrap();
        let mut s = d.start_scanning().await.unwrap();
        d.bus.signals.send(P2pSignal::DeviceFound("/peers/2".into())).unwrap();
        let DiscoveryEvent::PeerFound(p) = next(&mut s).await else { panic!() };
        let r = d.connect(&p).await;
        (r, d.bus.calls())
    }

    #[tokio::test]
    async fn connect_as_client_yields_full_link_info() {
        let (r, calls) = connect_with(vec![P2pSignal::DeviceFound("/peers/1".into()), P2pSignal::GroupStarted(client_group())], WpaConfig::new("me")).await;
        let link = r.unwrap();
        assert_eq!(link, LinkInfo { local_ip: Some("192.168.49.23".parse().unwrap()), peer_ip: Some("192.168.49.1".parse().unwrap()), peer_port: None, interface: Some("p2p-wlan0-0".into()), link_kind: LinkKind::WifiDirect, role: LinkRole::Client });
        assert_eq!(calls, ["find 30", "stop_find", "connect /peers/2 7"]);
    }

    #[test]
    fn group_owner_and_dhcp_fallback_mapping() {
        let go = GroupStarted { role: "GO".into(), ip_addr: None, ip_addr_go: Some(vec![192, 168, 49, 1]), ..client_group() };
        let l = link_info_from_group(&go, "p2p-wlan0-0".into());
        assert_eq!((l.role, l.local_ip, l.peer_ip), (LinkRole::Host, Some("192.168.49.1".parse().unwrap()), None));
        // No EAPOL IP allocation: addresses unknown, the engine falls back to LAN beacons.
        let dhcp = GroupStarted { ip_addr: None, ip_addr_go: None, ..client_group() };
        let l = link_info_from_group(&dhcp, "p2p-wlan0-0".into());
        assert_eq!((l.role, l.local_ip, l.peer_ip), (LinkRole::Client, None, None));
        // Malformed address bytes are ignored, not trusted.
        let bad = GroupStarted { ip_addr_go: Some(vec![1, 2, 3]), ..client_group() };
        assert_eq!(link_info_from_group(&bad, "x".into()).peer_ip, None);
    }

    #[tokio::test]
    async fn connect_failures_map_to_errors() {
        let (r, _) = connect_with(vec![P2pSignal::GoNegotiationFailure(P2P_STATUS_REJECTED_BY_USER)], WpaConfig::new("me")).await;
        assert!(matches!(r, Err(DiscoveryError::ConnectionRejected)));
        let (r, _) = connect_with(vec![P2pSignal::GoNegotiationFailure(1)], WpaConfig::new("me")).await;
        assert!(matches!(r, Err(DiscoveryError::Backend(_))));
        let (r, _) = connect_with(vec![P2pSignal::GroupFormationFailure("WpsFail".into())], WpaConfig::new("me")).await;
        assert!(matches!(r, Err(DiscoveryError::Backend(_))));
        let (r, _) = connect_with(vec![P2pSignal::GroupFinished], WpaConfig::new("me")).await;
        assert!(matches!(r, Err(DiscoveryError::PeerLost)));
    }

    #[tokio::test]
    async fn connect_timeout_disconnects() {
        let cfg = WpaConfig { group_timeout: Duration::from_millis(50), ..WpaConfig::new("me") };
        let (r, calls) = connect_with(vec![], cfg).await;
        assert!(matches!(r, Err(DiscoveryError::Timeout)));
        assert_eq!(calls.last().map(String::as_str), Some("disconnect"));
    }

    #[tokio::test]
    async fn connect_unknown_peer_and_bad_config() {
        let d = WpaDiscovery::new(MockBus::new(), WpaConfig::new("me")).unwrap();
        let p = Peer { fingerprint: None, display_name: String::new(), link_kind: LinkKind::WifiDirect, handle: PeerHandle::new("/peers/9") };
        assert!(matches!(d.connect(&p).await, Err(DiscoveryError::UnknownPeer)));
        assert!(WpaDiscovery::new(MockBus::new(), WpaConfig { go_intent: 16, ..WpaConfig::new("me") }).is_err());
    }
}
