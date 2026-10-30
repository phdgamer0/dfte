// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Peer discovery and direct-link establishment (manual §5, §6, §7).
//!
//! # What lives here
//!
//! * [`PeerDiscovery`]: the platform abstraction. A backend finds peers and brings up a
//!   radio-level link, then returns a [`LinkInfo`] (addressing), after which the shared
//!   engine opens its own transport socket. [`DynPeerDiscovery`] is its object-safe twin.
//! * [`state::DiscoveryMachine`]: the manual §6 discovery state machine, pure and
//!   synchronous with an injected clock.
//! * [`qr::QrPayload`]: the iOS↔non-Apple bootstrap payload (SoftAP SSID/PSK, host
//!   fingerprint, address), with strict parsing of scanned (untrusted) text.
//! * [`softap`]: CSPRNG SoftAP credentials and the Linux `hostapd`/`dnsmasq` plan.
//! * [`lan::LanDiscovery`]: signed UDP beacons on the local network, for development before
//!   radios (manual §41) and for address discovery on a freshly formed P2P group.
//! * [`wpa::WpaDiscovery`]: Linux Wi-Fi Direct over `wpa_supplicant`'s D-Bus API. The zbus
//!   bus implementation is behind the `linux-wpa` feature; the translation logic is always
//!   compiled and tested against a mock bus.
//! * `nm::NmP2p` (feature `linux-nm`): Linux Wi-Fi Direct through NetworkManager, which
//!   needs no root. Joins a group a phone hosts; beacons then exchange port and fingerprint.
//!
//! # Per-platform notes
//!
//! Only Linux (and the LAN dev backend) implement [`PeerDiscovery`] in Rust. The others
//! implement the same contract natively and call into the core through a uniffi callback
//! interface shaped like [`DynPeerDiscovery`] (manual §1.4: no protocol logic in shims):
//!
//! * **Android** (Kotlin): `WifiP2pManager` for Android↔Android/PC, `WifiAwareManager` as an
//!   opportunistic upgrade, `WifiManager.startLocalOnlyHotspot()` to host iOS peers (its
//!   SSID/PSK go into a [`qr::QrPayload`]). Scans are throttled by the OS (4 per 2 min), so
//!   scan on user action only. Needs `NEARBY_WIFI_DEVICES` (API 33+) or location, and a
//!   `dataSync` foreground service during transfers.
//! * **Windows** (C#/WinRT): `Windows.Devices.WiFiDirect` for P2P; the Mobile Hotspot API to
//!   host iOS peers.
//! * **iOS** (Swift): cannot do Wi-Fi Direct/Aware or host an AP. Joins a peer's SoftAP via
//!   `NEHotspotConfigurationManager.apply(_:)` after scanning a [`qr::QrPayload`], and uses
//!   `Network.framework` peer-to-peer (AWDL) only as an iOS↔iOS fast path.
//!
//! No backend ever uses Internet rendezvous or relays (manual §49), nor Bluetooth.

mod error;
pub mod fingerprint;
pub mod lan;
#[cfg(feature = "linux-nm")]
pub mod nm;
pub mod qr;
pub mod softap;
pub mod state;
mod traits;
mod types;
pub mod wpa;

pub use error::{DiscoveryError, Permission};
pub use traits::{BoxFuture, DynPeerDiscovery, PEER_STREAM_CAPACITY, PeerDiscovery, PeerStream};
pub use types::{DiscoveryEvent, LinkInfo, LinkKind, LinkRole, Peer, PeerHandle};

pub type Result<T> = std::result::Result<T, DiscoveryError>;
