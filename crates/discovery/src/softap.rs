//! SoftAP host role for iOS peers (manual §5, §7): credential generation plus the Linux
//! `hostapd` plan.
//!
//! The non-Apple device always hosts when the peer is iOS (manual §7). Credentials come
//! from the OS CSPRNG and are shown to iOS only through the QR code ([`QrPayload`]).
//!
//! The Linux helper only *generates* the hostapd/dnsmasq configuration and the command
//! lines to run: creating a virtual AP interface needs `CAP_NET_ADMIN`, so actually running
//! them is the job of a privileged helper (or the user), never of this library or its tests.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use ring::rand::{SecureRandom, SystemRandom};

use crate::fingerprint::FingerprintBytes;
use crate::qr::{QrError, QrPayload};
use crate::{DiscoveryError, Result};

/// SSID prefix; the rest is random so two hosts in one room never collide.
pub const SSID_PREFIX: &str = "dfte-";
const SSID_RANDOM_LEN: usize = 8;
/// 24 characters from a 56-symbol alphabet ≈ 139 bits: far beyond offline-guessing reach
/// for WPA2-PSK, still typeable by hand if a camera is unavailable.
pub const PSK_LEN: usize = 24;

/// Crockford-style base32 (no I, L, O, U) for the SSID: readable on a join prompt.
const SSID_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Alphanumerics minus look-alikes (0/O, 1/l/I) for the passphrase.
const PSK_ALPHABET: &[u8] = b"23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

/// Freshly generated SoftAP credentials. `Debug` redacts the passphrase.
#[derive(Clone, PartialEq, Eq)]
pub struct SoftApCredentials {
    pub ssid: String,
    pub psk: String,
}

impl std::fmt::Debug for SoftApCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftApCredentials").field("ssid", &self.ssid).field("psk", &"<redacted>").finish()
    }
}

impl SoftApCredentials {
    /// Generate an SSID and WPA2 passphrase from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut ssid = String::from(SSID_PREFIX);
        ssid.push_str(&random_string(&rng, SSID_ALPHABET, SSID_RANDOM_LEN)?);
        let psk = random_string(&rng, PSK_ALPHABET, PSK_LEN)?;
        Ok(Self { ssid, psk })
    }
}

/// Uniform random string over `alphabet` (rejection sampling, no modulo bias).
fn random_string(rng: &SystemRandom, alphabet: &[u8], len: usize) -> Result<String> {
    let n = alphabet.len();
    debug_assert!((1..=256).contains(&n));
    // Largest multiple of n that fits in a byte: bytes at or above it are rejected.
    let limit = 256 - (256 % n);
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        rng.fill(&mut buf).map_err(|_| DiscoveryError::Backend("system RNG failure".into()))?;
        for &b in &buf {
            if usize::from(b) < limit && out.len() < len {
                out.push(char::from(alphabet[usize::from(b) % n]));
            }
        }
    }
    Ok(out)
}

/// A command line to be run by a privileged helper. Arguments are kept separate (never a
/// shell string), so nothing in them can be interpreted by a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl std::fmt::Display for CommandLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.program)?;
        for a in &self.args {
            write!(f, " {a}")?;
        }
        Ok(())
    }
}

/// Settings for a Linux hostapd SoftAP on an isolated virtual interface (manual §5 Linux:
/// `iw dev wlan0 interface add wlan-p2p type __ap`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostapdConfig {
    /// Physical interface the virtual AP is created on, e.g. `wlan0`.
    pub phy_interface: String,
    /// Name of the virtual AP interface, e.g. `wlan-dfte`.
    pub ap_interface: String,
    /// 2.4 GHz channel 1..=13 (5 GHz needs regulatory/DFS handling we cannot test here).
    pub channel: u8,
    /// Host address on the AP subnet (/24); DHCP hands out .10–.250 of the same /24.
    pub host_ip: Ipv4Addr,
    pub credentials: SoftApCredentials,
}

impl HostapdConfig {
    /// Defaults: `wlan0` → `wlan-dfte`, channel 6, 192.168.50.1/24.
    pub fn new(credentials: SoftApCredentials) -> Self {
        Self { phy_interface: "wlan0".into(), ap_interface: "wlan-dfte".into(), channel: 6, host_ip: Ipv4Addr::new(192, 168, 50, 1), credentials }
    }

    pub fn validate(&self) -> Result<()> {
        validate_ifname(&self.phy_interface)?;
        validate_ifname(&self.ap_interface)?;
        if !(1..=13).contains(&self.channel) {
            return Err(DiscoveryError::InvalidConfig(format!("channel {} outside 1..=13", self.channel)));
        }
        let o = self.host_ip.octets();
        if !self.host_ip.is_private() || o[3] == 0 || o[3] == 255 || (10..=250).contains(&o[3]) {
            return Err(DiscoveryError::InvalidConfig("host_ip must be a private /24 host address outside the DHCP range .10-.250".into()));
        }
        // Reuse the QR validators: anything that would not survive the QR code would not
        // survive the config file either (they forbid newlines, which would let a value
        // inject extra hostapd directives).
        QrPayload::new(self.credentials.ssid.clone(), self.credentials.psk.clone(), [0; 12], IpAddr::V4(self.host_ip), 1)?;
        if !self.credentials.ssid.is_ascii() {
            return Err(QrError::SsidInvalid.into());
        }
        Ok(())
    }

    /// The hostapd.conf contents (WPA2-PSK/CCMP, 802.11n on 2.4 GHz, client isolation off
    /// so the two peers can talk).
    pub fn hostapd_conf(&self) -> Result<String> {
        self.validate()?;
        let mut s = String::with_capacity(512);
        // Deliberately ignored: `fmt::Write` for `String` is infallible.
        let _ = write!(
            s,
            "# generated by dfte; do not edit\n\
             interface={iface}\n\
             driver=nl80211\n\
             ssid={ssid}\n\
             country_code=00\n\
             hw_mode=g\n\
             channel={ch}\n\
             ieee80211n=1\n\
             wmm_enabled=1\n\
             auth_algs=1\n\
             ignore_broadcast_ssid=0\n\
             ap_isolate=0\n\
             wpa=2\n\
             wpa_key_mgmt=WPA-PSK\n\
             rsn_pairwise=CCMP\n\
             wpa_passphrase={psk}\n",
            iface = self.ap_interface,
            ssid = self.credentials.ssid,
            ch = self.channel,
            psk = self.credentials.psk,
        );
        Ok(s)
    }

    /// dnsmasq arguments: DHCP only (`--port=0` disables DNS), bound to the AP interface.
    pub fn dnsmasq_command(&self) -> Result<CommandLine> {
        self.validate()?;
        let [a, b, c, _] = self.host_ip.octets();
        Ok(CommandLine { program: "dnsmasq", args: vec!["--keep-in-foreground".into(), "--port=0".into(), "--no-resolv".into(), format!("--interface={}", self.ap_interface), "--bind-interfaces".into(), format!("--dhcp-range={a}.{b}.{c}.10,{a}.{b}.{c}.250,255.255.255.0,1h")] })
    }

    /// Ordered commands to bring the AP up, given where the hostapd.conf was written.
    pub fn up_commands(&self, hostapd_conf_path: &str) -> Result<Vec<CommandLine>> {
        self.validate()?;
        if hostapd_conf_path.is_empty() || hostapd_conf_path.chars().any(char::is_control) {
            return Err(DiscoveryError::InvalidConfig("bad hostapd.conf path".into()));
        }
        let ap = self.ap_interface.clone();
        Ok(vec![CommandLine { program: "iw", args: vec!["dev".into(), self.phy_interface.clone(), "interface".into(), "add".into(), ap.clone(), "type".into(), "__ap".into()] }, CommandLine { program: "ip", args: vec!["addr".into(), "add".into(), format!("{}/24", self.host_ip), "dev".into(), ap.clone()] }, CommandLine { program: "ip", args: vec!["link".into(), "set".into(), ap.clone(), "up".into()] }, CommandLine { program: "hostapd", args: vec!["-B".into(), hostapd_conf_path.into()] }, self.dnsmasq_command()?])
    }

    /// Commands to tear the AP down again (removing the interface stops hostapd's BSS).
    pub fn down_commands(&self) -> Result<Vec<CommandLine>> {
        self.validate()?;
        Ok(vec![CommandLine { program: "iw", args: vec!["dev".into(), self.ap_interface.clone(), "del".into()] }])
    }

    /// The QR payload iOS scans to join this AP and reach the engine (manual §6).
    pub fn qr_payload(&self, fingerprint: FingerprintBytes, engine_port: u16) -> Result<QrPayload> {
        self.validate()?;
        Ok(QrPayload::new(self.credentials.ssid.clone(), self.credentials.psk.clone(), fingerprint, IpAddr::V4(self.host_ip), engine_port)?)
    }
}

/// Linux interface names: 1..=15 bytes (IFNAMSIZ-1), `[A-Za-z0-9_-]`, not starting with `-`.
fn validate_ifname(name: &str) -> Result<()> {
    let ok = !name.is_empty() && name.len() <= 15 && !name.starts_with('-') && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok { Ok(()) } else { Err(DiscoveryError::InvalidConfig(format!("invalid interface name {name:?}"))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> SoftApCredentials {
        SoftApCredentials { ssid: "dfte-ABCD2345".into(), psk: "abcdefghjkmnpqrstuvwxyz2".into() }
    }

    #[test]
    fn generated_credentials_are_valid_and_random() {
        let a = SoftApCredentials::generate().unwrap();
        let b = SoftApCredentials::generate().unwrap();
        assert_ne!(a, b);
        assert!(a.ssid.starts_with(SSID_PREFIX) && a.ssid.len() == SSID_PREFIX.len() + SSID_RANDOM_LEN);
        assert_eq!(a.psk.len(), PSK_LEN);
        assert!(a.psk.bytes().all(|c| PSK_ALPHABET.contains(&c)));
        HostapdConfig::new(a.clone()).validate().unwrap();
        assert!(!format!("{a:?}").contains(&a.psk));
    }

    #[test]
    fn hostapd_conf_contents() {
        let conf = HostapdConfig::new(creds()).hostapd_conf().unwrap();
        for line in ["interface=wlan-dfte", "driver=nl80211", "ssid=dfte-ABCD2345", "channel=6", "wpa=2", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", "wpa_passphrase=abcdefghjkmnpqrstuvwxyz2"] {
            assert!(conf.lines().any(|l| l == line), "missing {line}");
        }
        // Exactly one of each security-relevant directive.
        assert_eq!(conf.lines().filter(|l| l.starts_with("wpa_passphrase=")).count(), 1);
    }

    #[test]
    fn command_lines() {
        let cfg = HostapdConfig::new(creds());
        let cmds: Vec<String> = cfg.up_commands("/run/dfte/hostapd.conf").unwrap().iter().map(ToString::to_string).collect();
        assert_eq!(cmds, ["iw dev wlan0 interface add wlan-dfte type __ap", "ip addr add 192.168.50.1/24 dev wlan-dfte", "ip link set wlan-dfte up", "hostapd -B /run/dfte/hostapd.conf", "dnsmasq --keep-in-foreground --port=0 --no-resolv --interface=wlan-dfte --bind-interfaces --dhcp-range=192.168.50.10,192.168.50.250,255.255.255.0,1h",]);
        assert_eq!(cfg.down_commands().unwrap()[0].to_string(), "iw dev wlan-dfte del");
    }

    #[test]
    fn config_injection_rejected() {
        let mut cfg = HostapdConfig::new(SoftApCredentials { ssid: "x\nwpa=0".into(), psk: "abcdefgh".into() });
        assert!(cfg.hostapd_conf().is_err());
        cfg.credentials = SoftApCredentials { ssid: "ok".into(), psk: "abcdefgh\nwpa=0".into() };
        assert!(cfg.hostapd_conf().is_err());
        cfg.credentials = creds();
        cfg.ap_interface = "wlan0; rm -rf /".into();
        assert!(cfg.hostapd_conf().is_err());
        cfg.ap_interface = "-bad".into();
        assert!(cfg.validate().is_err());
        cfg.ap_interface = "a-very-long-interface".into();
        assert!(cfg.validate().is_err());
        cfg.ap_interface = "wlan-dfte".into();
        assert!(cfg.up_commands("/tmp/x\n").is_err());
        cfg.channel = 14;
        assert!(cfg.validate().is_err());
        cfg.channel = 6;
        cfg.host_ip = Ipv4Addr::new(8, 8, 8, 8);
        assert!(cfg.validate().is_err());
        cfg.host_ip = Ipv4Addr::new(192, 168, 50, 20);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn qr_payload_matches_ap() {
        let cfg = HostapdConfig::new(creds());
        let qr = cfg.qr_payload([7; 12], 47_821).unwrap();
        assert_eq!(qr.ssid, cfg.credentials.ssid);
        assert_eq!(qr.psk, cfg.credentials.psk);
        assert_eq!(qr.ip, IpAddr::V4(cfg.host_ip));
        assert_eq!(QrPayload::parse(&qr.encode().unwrap()).unwrap(), qr);
    }
}
