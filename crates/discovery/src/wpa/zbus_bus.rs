//! [`P2pBus`] over the system D-Bus with `zbus` (feature `linux-wpa`).
//!
//! Interfaces used (wpa_supplicant `doc/dbus.doxygen`):
//! `fi.w1.wpa_supplicant1.GetInterface`, `…Interface.P2PDevice.{Find, StopFind, Listen,
//! Connect, Disconnect, P2PDeviceConfig}` and its signals, `…Peer.{DeviceName,
//! DeviceAddress}`, `…Interface.Ifname`. Needs D-Bus policy permitting the caller to talk
//! to `fi.w1.wpa_supplicant1` (root or a polkit/bus-policy grant).

use std::collections::HashMap;

use futures_util::StreamExt as _;
use tokio::sync::mpsc;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use super::{GroupStarted, P2pBus, P2pSignal, PeerProperties};
use crate::{DiscoveryError, Permission, Result};

const DEST: &str = "fi.w1.wpa_supplicant1";
const ROOT_PATH: &str = "/fi/w1/wpa_supplicant1";
const IFACE: &str = "fi.w1.wpa_supplicant1.Interface";
const P2P_IFACE: &str = "fi.w1.wpa_supplicant1.Interface.P2PDevice";
const PEER_IFACE: &str = "fi.w1.wpa_supplicant1.Peer";

fn map_err(e: zbus::Error) -> DiscoveryError {
    if let zbus::Error::MethodError(name, _, _) = &e {
        match name.as_str() {
            "org.freedesktop.DBus.Error.AccessDenied" => return DiscoveryError::PermissionDenied(Permission::WifiControl),
            "org.freedesktop.DBus.Error.ServiceUnknown" => return DiscoveryError::RadioUnavailable("wpa_supplicant is not running".into()),
            "fi.w1.wpa_supplicant1.InterfaceUnknown" => return DiscoveryError::RadioUnavailable("wireless interface unknown to wpa_supplicant".into()),
            _ => {}
        }
    }
    DiscoveryError::Backend(e.to_string())
}

fn map_fdo(e: zbus::fdo::Error) -> DiscoveryError {
    match e {
        zbus::fdo::Error::AccessDenied(_) => DiscoveryError::PermissionDenied(Permission::WifiControl),
        zbus::fdo::Error::ServiceUnknown(_) => DiscoveryError::RadioUnavailable("wpa_supplicant is not running".into()),
        other => DiscoveryError::Backend(other.to_string()),
    }
}

/// wpa_supplicant P2P over the system bus, bound to one wireless interface.
#[derive(Debug, Clone)]
pub struct ZbusP2pBus {
    conn: Connection,
    iface_path: OwnedObjectPath,
}

impl ZbusP2pBus {
    /// Connect to the system bus and resolve `ifname` (e.g. `wlan0`) with `GetInterface`.
    pub async fn system(ifname: &str) -> Result<Self> {
        let conn = Connection::system().await.map_err(map_err)?;
        Self::with_connection(conn, ifname).await
    }

    pub async fn with_connection(conn: Connection, ifname: &str) -> Result<Self> {
        let root = proxy(&conn, ROOT_PATH, DEST).await?;
        let iface_path: OwnedObjectPath = root.call("GetInterface", &(ifname,)).await.map_err(map_err)?;
        Ok(Self { conn, iface_path })
    }

    async fn p2p(&self) -> Result<Proxy<'_>> {
        proxy(&self.conn, self.iface_path.as_str(), P2P_IFACE).await
    }
}

async fn proxy<'a>(conn: &Connection, path: &'a str, interface: &'a str) -> Result<Proxy<'a>> {
    zbus::proxy::Builder::new(conn).destination(DEST).and_then(|b| b.path(path)).and_then(|b| b.interface(interface)).map_err(map_err)?.cache_properties(CacheProperties::No).build().await.map_err(map_err)
}

/// Remove and convert one property. Absent → `None`; present with the wrong D-Bus type →
/// `None` plus a warning (a malformed property is dropped on purpose, never trusted).
fn take<T: TryFrom<OwnedValue>>(props: &mut HashMap<String, OwnedValue>, key: &str) -> Option<T>
where
    T::Error: std::fmt::Display,
{
    match T::try_from(props.remove(key)?) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, key, "ignoring wpa_supplicant property with unexpected type");
            None
        }
    }
}

/// Deserialize a signal body. A malformed body is dropped on purpose (logged), so one bad
/// signal cannot tear down the subscription.
fn body<T>(msg: &zbus::Message, member: &str) -> Option<T>
where
    T: zbus::export::serde::de::DeserializeOwned + zbus::zvariant::Type,
{
    match msg.body().deserialize::<T>() {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, member, "dropping malformed wpa_supplicant signal");
            None
        }
    }
}

/// Translate a P2PDevice signal. `None` for signals we do not use and (logged) malformed ones.
fn parse_signal(msg: &zbus::Message) -> Option<P2pSignal> {
    let header = msg.header();
    let member = header.member()?.as_str().to_owned();
    let m = member.as_str();
    Some(match m {
        "DeviceFound" => P2pSignal::DeviceFound(body::<(OwnedObjectPath,)>(msg, m)?.0.to_string()),
        "DeviceLost" => P2pSignal::DeviceLost(body::<(OwnedObjectPath,)>(msg, m)?.0.to_string()),
        "GroupStarted" => {
            let (mut p,) = body::<(HashMap<String, OwnedValue>,)>(msg, m)?;
            let Some(interface_object) = take::<OwnedObjectPath>(&mut p, "interface_object") else {
                tracing::warn!("dropping GroupStarted without interface_object");
                return None;
            };
            let Some(role) = take::<String>(&mut p, "role") else {
                tracing::warn!("dropping GroupStarted without role");
                return None;
            };
            P2pSignal::GroupStarted(GroupStarted { interface_object: interface_object.to_string(), role, ip_addr: take::<Vec<u8>>(&mut p, "IpAddr"), ip_addr_go: take::<Vec<u8>>(&mut p, "IpAddrGo") })
        }
        "GONegotiationFailure" => {
            let (mut p,) = body::<(HashMap<String, OwnedValue>,)>(msg, m)?;
            // The failure itself is what matters; a missing status code (logged by `take`
            // only when mistyped) is reported as -1, i.e. "unknown", never as a success.
            P2pSignal::GoNegotiationFailure(take::<i32>(&mut p, "status").unwrap_or(-1))
        }
        "GroupFormationFailure" => P2pSignal::GroupFormationFailure(body::<(String,)>(msg, m)?.0),
        "GroupFinished" => P2pSignal::GroupFinished,
        "FindStopped" => P2pSignal::FindStopped,
        _ => return None,
    })
}

impl P2pBus for ZbusP2pBus {
    async fn set_device_name(&self, name: &str) -> Result<()> {
        let cfg: HashMap<&str, Value<'_>> = HashMap::from([("DeviceName", Value::from(name))]);
        self.p2p().await?.set_property("P2PDeviceConfig", cfg).await.map_err(map_fdo)
    }

    async fn listen(&self, timeout_secs: i32) -> Result<()> {
        self.p2p().await?.call::<_, _, ()>("Listen", &(timeout_secs,)).await.map_err(map_err)
    }

    async fn find(&self, timeout_secs: i32) -> Result<()> {
        let args: HashMap<&str, Value<'_>> = HashMap::from([("Timeout", Value::from(timeout_secs))]);
        self.p2p().await?.call::<_, _, ()>("Find", &(args,)).await.map_err(map_err)
    }

    async fn stop_find(&self) -> Result<()> {
        self.p2p().await?.call::<_, _, ()>("StopFind", &()).await.map_err(map_err)
    }

    async fn connect_pbc(&self, peer_path: &str, go_intent: i32) -> Result<()> {
        let peer = ObjectPath::try_from(peer_path).map_err(|e| DiscoveryError::Backend(e.to_string()))?;
        let args: HashMap<&str, Value<'_>> = HashMap::from([("peer", Value::from(peer)), ("wps_method", Value::from("pbc")), ("go_intent", Value::from(go_intent)), ("join", Value::from(false)), ("persistent", Value::from(false))]);
        // Returns the generated PIN, meaningless for PBC.
        self.p2p().await?.call::<_, _, String>("Connect", &(args,)).await.map(drop).map_err(map_err)
    }

    async fn disconnect(&self) -> Result<()> {
        self.p2p().await?.call::<_, _, ()>("Disconnect", &()).await.map_err(map_err)
    }

    async fn peer_properties(&self, peer_path: &str) -> Result<PeerProperties> {
        let p = proxy(&self.conn, peer_path, PEER_IFACE).await?;
        let device_name: String = p.get_property("DeviceName").await.map_err(map_err)?;
        let device_address: Vec<u8> = p.get_property("DeviceAddress").await.map_err(map_err)?;
        Ok(PeerProperties { device_name, device_address })
    }

    async fn interface_name(&self, interface_path: &str) -> Result<String> {
        proxy(&self.conn, interface_path, IFACE).await?.get_property("Ifname").await.map_err(map_err)
    }

    async fn subscribe(&self) -> Result<mpsc::Receiver<P2pSignal>> {
        // A 'static proxy (owned path) so the forwarding task can own the signal stream.
        let p2p: Proxy<'static> = zbus::proxy::Builder::new(&self.conn).destination(DEST).and_then(|b| b.path(self.iface_path.clone())).and_then(|b| b.interface(P2P_IFACE)).map_err(map_err)?.cache_properties(CacheProperties::No).build().await.map_err(map_err)?;
        let mut signals = p2p.receive_all_signals().await.map_err(map_err)?;
        let (tx, rx) = mpsc::channel(crate::PEER_STREAM_CAPACITY);
        tokio::spawn(async move {
            // Keep the proxy alive for the life of the subscription.
            let _p2p = p2p;
            loop {
                tokio::select! {
                    msg = signals.next() => match msg {
                        Some(msg) => {
                            if let Some(sig) = parse_signal(&msg)
                                && tx.send(sig).await.is_err()
                            {
                                return;
                            }
                        }
                        None => return,
                    },
                    () = tx.closed() => return,
                }
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal<B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType>(member: &str, body: &B) -> zbus::Message {
        zbus::Message::signal("/fi/w1/wpa_supplicant1/Interfaces/1", P2P_IFACE, member).unwrap().build(body).unwrap()
    }

    #[test]
    fn parses_device_signals() {
        let path = ObjectPath::try_from("/fi/w1/wpa_supplicant1/Interfaces/1/Peers/aabbccddeeff").unwrap();
        assert_eq!(parse_signal(&signal("DeviceFound", &(path.clone(),))), Some(P2pSignal::DeviceFound(path.to_string())));
        assert_eq!(parse_signal(&signal("DeviceLost", &(path.clone(),))), Some(P2pSignal::DeviceLost(path.to_string())));
        assert_eq!(parse_signal(&signal("GroupFinished", &(HashMap::<&str, Value<'_>>::new(),))), Some(P2pSignal::GroupFinished));
        assert_eq!(parse_signal(&signal("GroupFormationFailure", &("WpsFail",))), Some(P2pSignal::GroupFormationFailure("WpsFail".into())));
        assert_eq!(parse_signal(&signal("SomethingElse", &())), None);
        // Wrong body type: ignored, not a panic.
        assert_eq!(parse_signal(&signal("DeviceFound", &(42u32,))), None);
    }

    #[test]
    fn parses_group_started_and_negotiation_failure() {
        let iface = ObjectPath::try_from("/fi/w1/wpa_supplicant1/Interfaces/2").unwrap();
        let props: HashMap<&str, Value<'_>> = HashMap::from([("interface_object", Value::from(iface.clone())), ("role", Value::from("client")), ("group_object", Value::from(ObjectPath::try_from("/fi/w1/wpa_supplicant1/Interfaces/2/Groups/x").unwrap())), ("IpAddr", Value::from(vec![192u8, 168, 49, 23])), ("IpAddrGo", Value::from(vec![192u8, 168, 49, 1]))]);
        let Some(P2pSignal::GroupStarted(g)) = parse_signal(&signal("GroupStarted", &(props,))) else { panic!() };
        assert_eq!(g, GroupStarted { interface_object: iface.to_string(), role: "client".into(), ip_addr: Some(vec![192, 168, 49, 23]), ip_addr_go: Some(vec![192, 168, 49, 1]) });

        let fail: HashMap<&str, Value<'_>> = HashMap::from([("status", Value::from(11i32))]);
        assert_eq!(parse_signal(&signal("GONegotiationFailure", &(fail,))), Some(P2pSignal::GoNegotiationFailure(11)));
        // GroupStarted without an interface object is unusable: dropped.
        let empty: HashMap<&str, Value<'_>> = HashMap::new();
        assert_eq!(parse_signal(&signal("GroupStarted", &(empty,))), None);
    }
}
