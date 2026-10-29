//! `--wifi-direct DEVICE`: join a group the other device hosts before running a command
//! (manual §5 Linux, §7), through NetworkManager so no root is needed (see `discovery::nm`).
//!
//! The group only provides addresses. The command then runs as usual, with beacons also
//! sent to the group owner; it answers them, which is how both sides learn each other's
//! engine port and fingerprint. The code comparison still authenticates the peer (§12.1).

use crate::app::BeaconArgs;
use crate::error::CliError;

/// How long to look for the named device, and to wait for the group (the other device
/// may ask its user to accept).
#[cfg(target_os = "linux")]
const FIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
#[cfg(target_os = "linux")]
const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// A joined group, left by [`leave`].
#[cfg(target_os = "linux")]
pub struct Link {
    nm: discovery::nm::NmP2p,
    group: discovery::nm::JoinedGroup,
}

#[cfg(not(target_os = "linux"))]
pub struct Link;

/// Joins the group of `beacon.wifi_direct` (if set) and adds its owner as a beacon target.
/// Ctrl-C while joining stops cleanly.
#[cfg(target_os = "linux")]
pub async fn join(beacon: &mut BeaconArgs, quiet: bool) -> Result<Option<Link>, CliError> {
    let Some(wanted) = beacon.wifi_direct.clone() else { return Ok(None) };
    let work = async {
        let nm = discovery::nm::NmP2p::system().await?;
        if !quiet {
            eprintln!("Looking for \"{wanted}\" over Wi-Fi Direct… (on a phone, open DFTE's Send or Receive screen)");
        }
        let peer = match nm.find(&wanted, FIND_TIMEOUT).await {
            Ok(p) => p,
            Err(discovery::DiscoveryError::UnknownPeer) => {
                let seen = nm.peers().await.map(|ps| ps.iter().map(|p| format!("{} ({})", crate::offer::printable(&p.name), p.hw_address)).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                stop_find(&nm).await;
                let seen = if seen.is_empty() { "none".to_owned() } else { seen };
                return Err(CliError::NotFound(format!("No Wi-Fi Direct device matching {wanted:?} was found (seen: {seen}).")));
            }
            Err(e) => {
                stop_find(&nm).await;
                return Err(e.into());
            }
        };
        stop_find(&nm).await;
        if !quiet {
            eprintln!("Joining {}'s Wi-Fi Direct group; accept the request there if it asks…", crate::offer::printable(&peer.name));
        }
        let group = nm.join(&peer, JOIN_TIMEOUT).await.map_err(|e| match e {
            discovery::DiscoveryError::ConnectionRejected => CliError::NotFound(format!("{} declined or dropped the Wi-Fi Direct connection.", crate::offer::printable(&peer.name))),
            discovery::DiscoveryError::Timeout => CliError::NotFound(format!("{} did not accept the Wi-Fi Direct connection in time.", crate::offer::printable(&peer.name))),
            other => other.into(),
        })?;
        if !quiet {
            match group.peer_ip {
                Some(ip) => eprintln!("Connected over Wi-Fi Direct ({}, peer {ip}).", group.interface.as_deref().unwrap_or("?")),
                None => eprintln!("Connected over Wi-Fi Direct ({}, this machine owns the group).", group.interface.as_deref().unwrap_or("?")),
            }
        }
        Ok::<_, CliError>(Link { nm, group })
    };
    let link = tokio::select! {
        r = work => r?,
        r = tokio::signal::ctrl_c() => {
            r.map_err(|e| CliError::io("cannot watch for Ctrl-C", e))?;
            return Err(CliError::Stopped);
        }
    };
    // As a member, announce ourselves to the owner. As the owner, the member announces
    // itself to us (and we answer).
    if let Some(ip) = link.group.peer_ip {
        let target = std::net::SocketAddr::new(ip, discovery::lan::DEFAULT_BEACON_PORT);
        if !beacon.beacon_to.contains(&target) {
            beacon.beacon_to.push(target);
        }
    }
    Ok(Some(link))
}

#[cfg(not(target_os = "linux"))]
pub async fn join(beacon: &mut BeaconArgs, _quiet: bool) -> Result<Option<Link>, CliError> {
    match beacon.wifi_direct {
        Some(_) => Err(CliError::Usage("--wifi-direct is only available on Linux.".into())),
        None => Ok(None),
    }
}

/// When the peer owns the joined group and no `--to IP:PORT` was given, the address to send
/// to: the owner, on the engine's default port (the phone app listens there). It can't be
/// found by scanning (a scanner stays silent, and an owner only answers devices that
/// announce themselves); there is exactly one other device in the group anyway. When we
/// own the group, the member announces itself to us, so the normal scan finds it.
pub fn receiver(link: Option<&Link>, to: Option<&str>) -> Option<std::net::SocketAddr> {
    #[cfg(target_os = "linux")]
    if let Some(ip) = link.and_then(|l| l.group.peer_ip)
        && to.is_none_or(|t| t.parse::<std::net::SocketAddr>().is_err())
    {
        return Some(std::net::SocketAddr::new(ip, crate::app::DEFAULT_PORT));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (link, to);
    None
}

/// Leaves the group; failures are reported, not fatal (NetworkManager also drops the
/// volatile connection when the other device stops hosting).
pub async fn leave(link: Option<Link>) {
    #[cfg(target_os = "linux")]
    if let Some(l) = link
        && let Err(e) = l.nm.leave(&l.group).await
    {
        eprintln!("Could not leave the Wi-Fi Direct group: {e}. It ends when the other device stops hosting.");
    }
    #[cfg(not(target_os = "linux"))]
    drop(link);
}

#[cfg(target_os = "linux")]
async fn stop_find(nm: &discovery::nm::NmP2p) {
    if let Err(e) = nm.stop_find().await {
        tracing::debug!(error = %e, "StopFind failed");
    }
}
