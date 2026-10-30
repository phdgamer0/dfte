// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Linux Wi-Fi Direct through NetworkManager's D-Bus API (manual §5 Linux), feature `linux-nm`.
//!
//! Why next to [`crate::wpa`]: on desktops NetworkManager owns `wpa_supplicant`, whose bus
//! policy admits only root, while NetworkManager authorizes ordinary users through polkit
//! (`network-control`). So this path needs no root and leaves the desktop's own Wi-Fi alone;
//! on Wi-Fi cards that allow it (Intel `iwlwifi`: managed + P2P on up to two channels) the
//! machine stays on its normal network while the group runs on its own `p2p-*` interface.
//!
//! Measured limits (Intel AX201, NetworkManager 1.58, Galaxy A30 on Android 11):
//! * NetworkManager starts P2P connections but never answers incoming ones, so this side
//!   always initiates ([`NmP2p::join`]); the phone only has to be discoverable.
//! * It always negotiates a new group: it cannot join one a phone already hosts (Android
//!   refuses the negotiation). Negotiation picks the owner; either way works:
//!   - we own the group: NetworkManager serves DHCP through `dnsmasq` (an ordinary package,
//!     shipped by most distributions alongside NetworkManager). Android drops a group that
//!     gives it no IPv4 address, so without `dnsmasq` this case fails.
//!   - the phone owns it: Android's DHCP (192.168.49.0/24), our gateway is the phone.
//!
//! Group formation only yields addresses. The member beacons to the owner (on Android the
//! app learns the owner's address from the framework), the owner answers (see `lan`'s
//! module docs), and both ends learn port and fingerprint. The handshake then verifies the
//! identity (§12.1).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use zbus::proxy::CacheProperties;
use zbus::{Connection, Proxy};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

use crate::{DiscoveryError, Permission, Result};

const DEST: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_IFACE: &str = "org.freedesktop.NetworkManager";
const DEVICE_IFACE: &str = "org.freedesktop.NetworkManager.Device";
const P2P_IFACE: &str = "org.freedesktop.NetworkManager.Device.WifiP2P";
const PEER_IFACE: &str = "org.freedesktop.NetworkManager.WifiP2PPeer";
const ACTIVE_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IP4_IFACE: &str = "org.freedesktop.NetworkManager.IP4Config";
/// `NM_DEVICE_TYPE_WIFI_P2P`.
const DEVICE_TYPE_WIFI_P2P: u32 = 30;
/// `NM_ACTIVE_CONNECTION_STATE_*`.
const ACTIVE_ACTIVATED: u32 = 2;
const ACTIVE_DEACTIVATED: u32 = 4;
const POLL: Duration = Duration::from_millis(250);

/// A Wi-Fi Direct device NetworkManager has seen nearby.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmPeer {
    /// Untrusted, peer-chosen name (display and matching only).
    pub name: String,
    /// P2P device address, `AA:BB:CC:DD:EE:FF`.
    pub hw_address: String,
    /// Signal strength, 0–100.
    pub strength: u8,
    path: OwnedObjectPath,
}

/// A group we formed with a peer. Leave it with [`NmP2p::leave`]; the connection is
/// volatile, so NetworkManager forgets it once deactivated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedGroup {
    /// The peer's address when it owns the group (it is our gateway). `None` when we own
    /// it: the peer then announces itself with a beacon to us.
    pub peer_ip: Option<IpAddr>,
    pub local_ip: Option<IpAddr>,
    /// The group's network interface (`p2p-wlp0s20-0`, ...).
    pub interface: Option<String>,
    active: OwnedObjectPath,
}

/// NetworkManager's Wi-Fi P2P device.
#[derive(Debug, Clone)]
pub struct NmP2p {
    conn: Connection,
    device: OwnedObjectPath,
}

impl NmP2p {
    /// Finds the first Wi-Fi P2P device on the system bus.
    pub async fn system() -> Result<Self> {
        let conn = Connection::system().await.map_err(map_err)?;
        let nm = proxy(&conn, NM_PATH, NM_IFACE).await?;
        let devices: Vec<OwnedObjectPath> = nm.call("GetDevices", &()).await.map_err(map_err)?;
        for d in devices {
            let kind: u32 = proxy(&conn, d.as_str(), DEVICE_IFACE).await?.get_property("DeviceType").await.map_err(map_err)?;
            if kind == DEVICE_TYPE_WIFI_P2P {
                return Ok(Self { conn, device: d });
            }
        }
        Err(DiscoveryError::RadioUnavailable("NetworkManager has no Wi-Fi Direct device (Wi-Fi off, or the card/driver lacks P2P)".into()))
    }

    /// Looks for peers for `timeout` (1–600 s). Results accumulate in [`peers`](Self::peers).
    pub async fn start_find(&self, timeout: Duration) -> Result<()> {
        let secs = i32::try_from(timeout.as_secs().clamp(1, 600)).unwrap_or(600);
        let opts: HashMap<&str, Variant<'_>> = HashMap::from([("timeout", Variant::from(secs))]);
        self.p2p().await?.call::<_, _, ()>("StartFind", &(opts,)).await.map_err(map_err)
    }

    pub async fn stop_find(&self) -> Result<()> {
        self.p2p().await?.call::<_, _, ()>("StopFind", &()).await.map_err(map_err)
    }

    /// Peers currently known, strongest first.
    pub async fn peers(&self) -> Result<Vec<NmPeer>> {
        let paths: Vec<OwnedObjectPath> = self.p2p().await?.get_property("Peers").await.map_err(map_err)?;
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            let p = proxy(&self.conn, path.as_str(), PEER_IFACE).await?;
            // A peer can vanish between listing and reading it; skip it then.
            let (Ok(name), Ok(hw_address), Ok(strength)) = (p.get_property::<String>("Name").await, p.get_property::<String>("HwAddress").await, p.get_property::<u8>("Strength").await) else {
                tracing::debug!(peer = %path, "Wi-Fi Direct peer disappeared while being read");
                continue;
            };
            out.push(NmPeer { name, hw_address, strength, path });
        }
        out.sort_by_key(|p| std::cmp::Reverse(p.strength));
        Ok(out)
    }

    /// Finds a peer by name or address (see [`find_peer`]), searching up to `timeout`.
    pub async fn find(&self, wanted: &str, timeout: Duration) -> Result<NmPeer> {
        self.start_find(timeout + Duration::from_secs(5)).await?;
        let deadline = Instant::now() + timeout;
        loop {
            let peers = self.peers().await?;
            match find_peer(&peers, wanted) {
                Ok(p) => return Ok(p.clone()),
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    /// Joins `peer`'s group (or forms one with it) and waits until addresses are assigned.
    /// The peer may ask its user to accept, so allow tens of seconds.
    pub async fn join(&self, peer: &NmPeer, timeout: Duration) -> Result<JoinedGroup> {
        let settings = connection_settings(&peer.name, &peer.hw_address);
        let opts: HashMap<&str, Variant<'_>> = HashMap::from([("persist", Variant::from("volatile"))]);
        let nm = proxy(&self.conn, NM_PATH, NM_IFACE).await?;
        let (_conn, active, _result): (OwnedObjectPath, OwnedObjectPath, HashMap<String, OwnedVariant>) = nm.call("AddAndActivateConnection2", &(settings, &self.device, &peer.path, opts)).await.map_err(map_err)?;
        let deadline = Instant::now() + timeout;
        let ac = proxy(&self.conn, active.as_str(), ACTIVE_IFACE).await?;
        loop {
            // The object disappears once a failed activation is cleaned up.
            let state: u32 = ac.get_property("State").await.unwrap_or(ACTIVE_DEACTIVATED);
            match state {
                ACTIVE_ACTIVATED => break,
                ACTIVE_DEACTIVATED => return Err(DiscoveryError::ConnectionRejected),
                _ if Instant::now() >= deadline => {
                    self.deactivate(&active).await;
                    return Err(DiscoveryError::Timeout);
                }
                _ => tokio::time::sleep(POLL).await,
            }
        }
        match self.addressing(&ac).await {
            Ok((peer_ip, local_ip, interface)) => Ok(JoinedGroup { peer_ip, local_ip, interface, active }),
            Err(e) => {
                self.deactivate(&active).await;
                Err(e)
            }
        }
    }

    /// Leaves a joined group. NetworkManager deletes the volatile connection.
    pub async fn leave(&self, group: &JoinedGroup) -> Result<()> {
        let nm = proxy(&self.conn, NM_PATH, NM_IFACE).await?;
        nm.call::<_, _, ()>("DeactivateConnection", &(&group.active,)).await.map_err(map_err)
    }

    async fn deactivate(&self, active: &OwnedObjectPath) {
        let r = async { proxy(&self.conn, NM_PATH, NM_IFACE).await?.call::<_, _, ()>("DeactivateConnection", &(active,)).await.map_err(map_err) }.await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "could not deactivate the Wi-Fi Direct connection");
        }
    }

    async fn addressing(&self, ac: &Proxy<'_>) -> Result<(Option<IpAddr>, Option<IpAddr>, Option<String>)> {
        let ip4: OwnedObjectPath = ac.get_property("Ip4Config").await.map_err(map_err)?;
        let devices: Vec<OwnedObjectPath> = ac.get_property("Devices").await.map_err(map_err)?;
        let interface = match devices.first() {
            Some(d) => proxy(&self.conn, d.as_str(), DEVICE_IFACE).await?.get_property::<String>("IpInterface").await.ok().filter(|s| !s.is_empty()),
            None => None,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        // DHCP can finish a moment after the connection reports "activated".
        loop {
            let (gateway, local) = if ip4.as_str() == "/" {
                (String::new(), None)
            } else {
                let p = proxy(&self.conn, ip4.as_str(), IP4_IFACE).await?;
                let gateway: String = p.get_property("Gateway").await.map_err(map_err)?;
                let data: Vec<HashMap<String, OwnedVariant>> = p.get_property("AddressData").await.map_err(map_err)?;
                let local = data.iter().find_map(|m| m.get("address").and_then(|v| String::try_from(v.clone()).ok())).and_then(|s| s.parse::<Ipv4Addr>().ok());
                (gateway, local)
            };
            match (group_owner_ip(&gateway, local), local) {
                (Some(peer), _) => return Ok((Some(peer), local.map(IpAddr::V4), interface)),
                // An address but no gateway: we own the group (NetworkManager's shared mode).
                (None, Some(ours)) => return Ok((None, Some(IpAddr::V4(ours)), interface)),
                (None, None) if Instant::now() >= deadline => {
                    return Err(DiscoveryError::Backend("the Wi-Fi Direct group formed but has no IPv4 address (as group owner NetworkManager needs dnsmasq installed)".into()));
                }
                (None, None) => {}
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn p2p(&self) -> Result<Proxy<'_>> {
        proxy(&self.conn, self.device.as_str(), P2P_IFACE).await
    }
}

/// Picks the peer the user named: an exact address, else a case-insensitive name match
/// (exact before substring). Ambiguity is an error rather than a guess.
pub fn find_peer<'a>(peers: &'a [NmPeer], wanted: &str) -> Result<&'a NmPeer> {
    let w = wanted.trim();
    if let Some(p) = peers.iter().find(|p| p.hw_address.eq_ignore_ascii_case(w)) {
        return Ok(p);
    }
    let lw = w.to_lowercase();
    let exact: Vec<_> = peers.iter().filter(|p| p.name.to_lowercase() == lw).collect();
    let pool = if exact.is_empty() { peers.iter().filter(|p| p.name.to_lowercase().contains(&lw)).collect() } else { exact };
    match pool.as_slice() {
        [one] => Ok(one),
        [] => Err(DiscoveryError::UnknownPeer),
        many => Err(DiscoveryError::InvalidConfig(format!("{} Wi-Fi Direct devices match {w:?}: {}; give the address instead", many.len(), many.iter().map(|p| format!("{} ({})", p.name, p.hw_address)).collect::<Vec<_>>().join(", ")))),
    }
}

/// The group owner's address when it isn't us: the DHCP gateway, else Android's fixed
/// group-owner address when we sit in its subnet (some DHCP servers omit the router option).
pub fn group_owner_ip(gateway: &str, local: Option<Ipv4Addr>) -> Option<IpAddr> {
    if let Ok(ip) = gateway.parse::<IpAddr>() {
        return Some(ip);
    }
    let local = local?;
    let [a, b, c, _] = local.octets();
    ((a, b, c) == (192, 168, 49)).then(|| IpAddr::V4(Ipv4Addr::new(192, 168, 49, 1)))
}

type Settings<'a> = HashMap<&'static str, HashMap<&'static str, Variant<'a>>>;

fn connection_settings<'a>(name: &str, hw_address: &'a str) -> Settings<'a> {
    HashMap::from([("connection", HashMap::from([("type", Variant::from("wifi-p2p")), ("id", Variant::from(format!("DFTE {name}"))), ("autoconnect", Variant::from(false))])), ("wifi-p2p", HashMap::from([("peer", Variant::from(hw_address))])), ("ipv4", HashMap::from([("method", Variant::from("auto"))])), ("ipv6", HashMap::from([("method", Variant::from("link-local"))]))])
}

async fn proxy<'a>(conn: &Connection, path: &'a str, interface: &'a str) -> Result<Proxy<'a>> {
    zbus::proxy::Builder::new(conn).destination(DEST).path(path).interface(interface).cache_properties(CacheProperties::No).build().await.map_err(map_err)
}

fn map_err(e: zbus::Error) -> DiscoveryError {
    match e {
        zbus::Error::FDO(fdo) => match *fdo {
            zbus::fdo::Error::AccessDenied(_) => DiscoveryError::PermissionDenied(Permission::WifiControl),
            zbus::fdo::Error::ServiceUnknown(_) => DiscoveryError::RadioUnavailable("NetworkManager is not running".into()),
            other => DiscoveryError::Backend(other.to_string()),
        },
        zbus::Error::MethodError(name, detail, _) if name.as_str() == "org.freedesktop.NetworkManager.PermissionDenied" => {
            tracing::debug!(?detail, "NetworkManager refused");
            DiscoveryError::PermissionDenied(Permission::WifiControl)
        }
        other => DiscoveryError::Backend(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, hw: &str) -> NmPeer {
        NmPeer { name: name.into(), hw_address: hw.into(), strength: 50, path: OwnedObjectPath::try_from("/x").unwrap() }
    }

    #[test]
    fn finds_peers_by_address_then_exact_then_partial_name() {
        let peers = [peer("Yazdan's A30", "DE:F7:56:7A:FA:7E"), peer("A30 kitchen", "02:00:00:00:00:01"), peer("Laptop", "02:00:00:00:00:02")];
        assert_eq!(find_peer(&peers, "de:f7:56:7a:fa:7e").unwrap().name, "Yazdan's A30");
        assert_eq!(find_peer(&peers, "laptop").unwrap().name, "Laptop");
        assert_eq!(find_peer(&peers, "kitchen").unwrap().name, "A30 kitchen");
        assert!(matches!(find_peer(&peers, "A30"), Err(DiscoveryError::InvalidConfig(_))));
        assert!(matches!(find_peer(&peers, "toaster"), Err(DiscoveryError::UnknownPeer)));
    }

    #[test]
    fn group_owner_from_gateway_or_android_subnet() {
        assert_eq!(group_owner_ip("192.168.49.1", None), Some("192.168.49.1".parse().unwrap()));
        assert_eq!(group_owner_ip("", Some(Ipv4Addr::new(192, 168, 49, 77))), Some("192.168.49.1".parse().unwrap()));
        assert_eq!(group_owner_ip("", Some(Ipv4Addr::new(10, 42, 0, 1))), None);
        assert_eq!(group_owner_ip("", None), None);
    }

    #[test]
    fn settings_are_a_volatile_friendly_wifi_p2p_profile() {
        let s = connection_settings("A30", "DE:F7:56:7A:FA:7E");
        assert_eq!(s["connection"]["type"], Variant::from("wifi-p2p"));
        assert_eq!(s["wifi-p2p"]["peer"], Variant::from("DE:F7:56:7A:FA:7E"));
        assert_eq!(s["ipv4"]["method"], Variant::from("auto"));
    }
}
