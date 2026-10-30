// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Hardware probe for the wpa_supplicant backend (needs `--features linux-wpa`).
//!
//! `cargo run -p discovery --features linux-wpa --example wpa_probe -- wlan0`
//!     resolves the interface over D-Bus (read-only).
//! `... -- wlan0 --find 20`
//!     additionally runs a 20 s P2P find and prints discovery events. This puts the radio
//!     into P2P search and can briefly disturb an active Wi-Fi connection.

#[cfg(feature = "linux-wpa")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use discovery::PeerDiscovery as _;
    use discovery::wpa::{WpaConfig, WpaDiscovery, ZbusP2pBus};

    let mut args = std::env::args().skip(1);
    let ifname = args.next().unwrap_or_else(|| "wlan0".into());
    let find_secs: Option<u64> = match (args.next().as_deref(), args.next()) {
        (Some("--find"), Some(s)) => Some(s.parse()?),
        _ => None,
    };
    let bus = ZbusP2pBus::system(&ifname).await?;
    println!("resolved {ifname} via wpa_supplicant: {bus:?}");
    let Some(secs) = find_secs else { return Ok(()) };
    let cfg = WpaConfig { find_timeout: std::time::Duration::from_secs(secs), ..WpaConfig::new("dfte-probe") };
    let d = WpaDiscovery::new(bus, cfg)?;
    let mut stream = d.start_scanning().await?;
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            ev = stream.next() => match ev { Some(ev) => println!("{ev:?}"), None => break },
            () = &mut deadline => break,
        }
    }
    d.stop().await?;
    Ok(())
}

#[cfg(not(feature = "linux-wpa"))]
fn main() {
    eprintln!("build with --features linux-wpa");
}
