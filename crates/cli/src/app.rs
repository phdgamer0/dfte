//! Command definitions and wiring (clap → engine).

use std::future::Future;
use std::io::{BufRead, IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use dfte_core::{CancelHandle, DeviceIdentity, EngineError, ManifestHook, PeerAuth, Progress, ReceiveOptions, SendOptions, TransferReport, receive, send_files};
use discovery::fingerprint::fingerprint_bytes;
use discovery::lan::{DEFAULT_BEACON_PORT, LanConfig, LanDiscovery};
use discovery::qr::QrPayload;
use discovery::softap::SoftApCredentials;
use discovery::{DiscoveryEvent, Peer, PeerDiscovery};
use transport::{Listener, QuicConfig, QuicTransport, TcpTransport, Transport};

use crate::error::{CliError, ExitCode};
use crate::progress::{Reporter, human_bytes, human_rate};
use crate::select::{Pick, Target, parse_choice, parse_target, pick};
use crate::trust::{TrustStore, normalize_fingerprint};
use crate::verify::{Expected, Role, TerminalVerifier, stdin_is_interactive};
use crate::{identity, offer, paths};

/// Default engine port (TCP and UDP/QUIC), next to the beacon port.
pub const DEFAULT_PORT: u16 = 47_821;

const EXIT_CODES: &str = "\
Exit codes:
  0 success            1 unexpected error      2 usage error
  3 connection lost    4 security check failed 5 declined by the other device
  6 not enough space   7 source file problem   8 integrity check failed
  9 incompatible app  10 peer misbehaved      11 identity/config problem
 12 device not found 130 interrupted (resume state kept)

State lives in $XDG_DATA_HOME/dfte (default ~/.local/share/dfte).";

#[derive(Parser, Debug)]
#[command(name = "dfte", version, about = "Direct device-to-device file transfer (no Internet, no cloud).", after_help = EXIT_CODES)]
pub struct Cli {
    /// More log output on stderr (-v info, -vv debug, -vvv trace). Logs never contain keys or file contents.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Machine-readable output on stdout (transfer reports as one JSON object per line).
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum TransportArg {
    Tcp,
    Quic,
}

/// Manual §15 per-platform default: QUIC, except TCP on Windows.
pub fn default_transport() -> TransportArg {
    if cfg!(windows) { TransportArg::Tcp } else { TransportArg::Quic }
}

/// LAN discovery socket settings (beacons are signed; manual §41 dev backend).
#[derive(Args, Debug, Clone)]
pub struct BeaconArgs {
    /// Local address for discovery beacons.
    #[arg(long, default_value_t = SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_BEACON_PORT)))]
    pub beacon_bind: SocketAddr,
    /// Also exchange beacons with this local-network address (repeatable), for networks that drop multicast.
    #[arg(long = "beacon-to", value_name = "IP:PORT")]
    pub beacon_to: Vec<SocketAddr>,
    /// Don't use multicast discovery (only --beacon-to targets).
    #[arg(long)]
    pub no_multicast: bool,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Show this device's name and fingerprint.
    Id,
    /// Wait for files from another device.
    Receive {
        /// Where finished files go (default: your Downloads folder).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Port to listen on (0 = any free port).
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Address to listen on.
        #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
        bind: IpAddr,
        /// Must match the sender's --transport.
        #[arg(long, value_enum, default_value_t = default_transport())]
        transport: TransportArg,
        /// Exit after one transfer attempt instead of waiting for more.
        #[arg(long)]
        once: bool,
        /// Accept only this device, without the code prompt (its fingerprint, compared out of band).
        #[arg(long, value_name = "FINGERPRINT")]
        accept_from: Option<String>,
        #[command(flatten)]
        beacon: BeaconArgs,
    },
    /// Send files or folders to another device.
    Send {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Receiving device: fingerprint, trusted name, advertised name, or IP:PORT. Asks if omitted.
        #[arg(long)]
        to: Option<String>,
        /// With --to IP:PORT: the receiver's fingerprint (e.g. read from its screen or QR code); skips the code prompt.
        #[arg(long, value_name = "FINGERPRINT")]
        expect: Option<String>,
        /// Parallel data streams (1–16).
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=16))]
        streams: u8,
        /// Must match the receiver's --transport.
        #[arg(long, value_enum, default_value_t = default_transport())]
        transport: TransportArg,
        /// Seconds to look for devices.
        #[arg(long, default_value_t = 5)]
        scan_timeout: u64,
        #[command(flatten)]
        beacon: BeaconArgs,
    },
    /// List devices that are ready to receive nearby.
    Peers {
        /// Seconds to listen for devices.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
        #[command(flatten)]
        beacon: BeaconArgs,
    },
    /// Manage trusted devices (they skip the code comparison).
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    /// List unfinished incoming transfers (they resume when the sender sends the same files again).
    Resumable {
        /// Delete the partial data of this transfer id.
        #[arg(long, value_name = "ID")]
        discard: Option<String>,
    },
    /// Print the QR payload an iPhone scans to join this device's hotspot (preview).
    Qr {
        /// Hotspot name (generated if omitted).
        #[arg(long, requires = "psk")]
        ssid: Option<String>,
        /// Hotspot passphrase, 8–63 characters (generated if omitted).
        #[arg(long, requires = "ssid")]
        psk: Option<String>,
        /// This device's address on its hotspot.
        #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)))]
        ip: IpAddr,
        /// Engine port the iPhone connects to.
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrustCmd {
    /// List trusted devices.
    List,
    /// Trust a device whose fingerprint you compared on its screen.
    Add { fingerprint: String, name: String },
    /// Stop trusting a device (by fingerprint or name).
    Remove { who: String },
}

/// Parse args, run, and return the process exit code.
pub fn main_entry() -> i32 {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return ExitCode::Failure.code();
        }
    };
    let json = cli.json;
    let peer_name: Arc<Mutex<Option<String>>> = Arc::default();
    match rt.block_on(run(cli, Arc::clone(&peer_name))) {
        Ok(()) => ExitCode::Ok.code(),
        Err(e) => {
            let who = lock(&peer_name).clone();
            let msg = e.user_message(who.as_deref());
            if json {
                let v = serde_json::json!({ "error": format!("{:?}", e.exit_code()), "exit_code": e.exit_code().code(), "message": msg });
                println!("{v}");
            }
            eprintln!("{msg}");
            tracing::debug!(error = %e, "command failed");
            e.exit_code().code()
        }
    }
    // The runtime is intentionally not dropped here: the caller exits the
    // process, which also ends a blocking thread still waiting on stdin.
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "error,dfte_cli=warn,discovery=warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    // An unset or invalid RUST_LOG falls back to the -v level.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn run(cli: Cli, peer_name: Arc<Mutex<Option<String>>>) -> Result<(), CliError> {
    let data = paths::data_dir()?;
    match cli.cmd {
        Cmd::Id => cmd_id(&data, cli.json),
        Cmd::Trust { cmd } => cmd_trust(&data, cmd, cli.json),
        Cmd::Resumable { discard } => cmd_resumable(&data, discard, cli.json),
        Cmd::Qr { ssid, psk, ip, port } => cmd_qr(&data, ssid, psk, ip, port, cli.json),
        Cmd::Peers { timeout, beacon } => cmd_peers(&data, timeout, &beacon, cli.json).await,
        Cmd::Receive { dir, port, bind, transport, once, accept_from, beacon } => {
            let a = ReceiveArgs { dir, listen: SocketAddr::new(bind, port), transport, once, accept_from, beacon, json: cli.json };
            cmd_receive(&data, a, peer_name).await
        }
        Cmd::Send { paths, to, expect, streams, transport, scan_timeout, beacon } => {
            let a = SendArgs { paths, to, expect, streams: usize::from(streams), transport, scan_timeout: Duration::from_secs(scan_timeout), beacon, json: cli.json };
            cmd_send(&data, a, peer_name).await
        }
    }
}

fn load_identity(data: &Path) -> Result<Arc<DeviceIdentity>, CliError> {
    let (id, origin) = identity::load_or_create(data)?;
    if origin == identity::Origin::Created {
        eprintln!("Created this device's identity: {}", id.fingerprint());
    }
    Ok(Arc::new(id))
}

fn print_json(v: &impl serde::Serialize) -> Result<(), CliError> {
    let s = serde_json::to_string(v).map_err(|e| CliError::Config(format!("cannot encode JSON output: {e}")))?;
    println!("{s}");
    Ok(())
}

// ---------------------------------------------------------------- id / trust

fn cmd_id(data: &Path, json: bool) -> Result<(), CliError> {
    let id = load_identity(data)?;
    let name = identity::device_name();
    if json {
        return print_json(&serde_json::json!({ "name": name, "fingerprint": id.fingerprint() }));
    }
    println!("Name:        {name}");
    println!("Fingerprint: {}", id.fingerprint());
    println!("Key file:    {}", identity::key_path(data).display());
    Ok(())
}

fn cmd_trust(data: &Path, cmd: TrustCmd, json: bool) -> Result<(), CliError> {
    let mut store = TrustStore::load(data)?;
    match cmd {
        TrustCmd::List => {
            if json {
                return print_json(&store.peers());
            }
            if store.peers().is_empty() {
                println!("No trusted devices. Answer \"a\" at the security-code prompt, or use `dfte trust add FINGERPRINT NAME`.");
            }
            let w = store.peers().iter().map(|p| p.name.chars().count()).max().unwrap_or(0);
            for p in store.peers() {
                println!("{:<w$}  {}", p.name, p.fingerprint);
            }
        }
        TrustCmd::Add { fingerprint, name } => {
            let p = store.add(&fingerprint, &name)?.clone();
            store.save()?;
            println!("Trusted \"{}\" ({}).", p.name, p.fingerprint);
        }
        TrustCmd::Remove { who } => {
            let p = store.remove(&who)?;
            store.save()?;
            println!("No longer trusting \"{}\" ({}).", p.name, p.fingerprint);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- resumable

#[derive(serde::Serialize)]
struct Unfinished {
    transfer_id: String,
    files: Vec<String>,
    bytes_total: u64,
    bytes_received: u64,
}

fn cmd_resumable(data: &Path, discard: Option<String>, json: bool) -> Result<(), CliError> {
    let staging = paths::staging_dir(data);
    let states = storage::scan_orphans_blocking(&staging).map_err(|e| CliError::Config(format!("cannot scan {}: {e}", staging.display())))?;
    if let Some(id) = discard {
        let s = states.iter().find(|s| s.transfer_id == id).ok_or_else(|| CliError::NotFound(format!("No unfinished transfer with id {id:?}. See `dfte resumable`.")))?;
        for i in 0..s.files.len() {
            let part = staging.join(format!("{}.part", storage::staging_name(&s.transfer_id, i)));
            match std::fs::remove_file(&part) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(CliError::io(format!("cannot delete {}", part.display()), e)),
            }
        }
        s.remove_blocking(&staging).map_err(|e| CliError::Config(format!("cannot delete the resume record: {e}")))?;
        println!("Discarded transfer {id}.");
        return Ok(());
    }
    let list: Vec<Unfinished> = states.iter().map(|s| Unfinished { transfer_id: s.transfer_id.clone(), files: s.files.iter().map(|f| offer::printable(&f.relative_path)).collect(), bytes_total: s.files.iter().map(|f| f.size).sum(), bytes_received: s.files.iter().map(|f| f.contiguous_offset().min(f.size)).sum() }).collect();
    if json {
        return print_json(&list);
    }
    if list.is_empty() {
        println!("No unfinished transfers.");
        return Ok(());
    }
    for u in &list {
        let pct = if u.bytes_total == 0 { 100.0 } else { u.bytes_received as f64 * 100.0 / u.bytes_total as f64 };
        let first = u.files.first().map_or("", String::as_str);
        let more = if u.files.len() > 1 { format!(" and {} more", u.files.len() - 1) } else { String::new() };
        println!("{}  {} of {} ({pct:.0}%)  {first}{more}", u.transfer_id, human_bytes(u.bytes_received), human_bytes(u.bytes_total));
    }
    println!("\nThese continue automatically when the sender sends the same files to this device again.\nTo delete one: dfte resumable --discard ID");
    Ok(())
}

// ---------------------------------------------------------------- qr

fn cmd_qr(data: &Path, ssid: Option<String>, psk: Option<String>, ip: IpAddr, port: u16, json: bool) -> Result<(), CliError> {
    let id = load_identity(data)?;
    let (ssid, psk) = match (ssid, psk) {
        (Some(s), Some(p)) => (s, p),
        _ => {
            let c = SoftApCredentials::generate().map_err(|e| CliError::Config(format!("cannot generate hotspot credentials: {e}")))?;
            (c.ssid, c.psk)
        }
    };
    let payload = QrPayload::new(ssid, psk, fingerprint_bytes(&id.public_key_bytes()), ip, port).map_err(|e| CliError::Usage(format!("Invalid QR payload: {e}.")))?;
    let text = payload.encode().map_err(|e| CliError::Usage(format!("Invalid QR payload: {e}.")))?;
    if json {
        return print_json(&serde_json::json!({ "payload": text, "ssid": payload.ssid, "ip": payload.ip, "port": payload.port, "fingerprint": payload.fingerprint_string() }));
    }
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| CliError::Config(format!("cannot render QR code: {e}")))?;
    let art = code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build();
    println!("{art}");
    println!("{text}");
    println!("\nHotspot \"{}\" at {}:{} — device {}", payload.ssid, payload.ip, payload.port, payload.fingerprint_string());
    eprintln!("\nPreview only: dfte does not start the hotspot. Hosting it needs root (hostapd + a DHCP server on an AP interface); that step is not implemented in this app yet. The QR code contains the hotspot passphrase: show it only to the person you're sending to.");
    Ok(())
}

// ---------------------------------------------------------------- discovery

fn lan(beacon: &BeaconArgs, name: &str, service_port: u16) -> Result<LanDiscovery, CliError> {
    let mut cfg = LanConfig::new(name, service_port);
    cfg.bind = beacon.beacon_bind;
    cfg.unicast_targets.clone_from(&beacon.beacon_to);
    if beacon.no_multicast {
        cfg.multicast_group = None;
    }
    Ok(LanDiscovery::new(cfg)?)
}

/// Listen for beacons until `done(peers)` or `timeout`; returns the backend
/// (still scanning, so it can resolve addresses) and the peers seen.
async fn scan(beacon: &BeaconArgs, timeout: Duration, done: impl Fn(&[Peer]) -> bool) -> Result<(LanDiscovery, Vec<Peer>), CliError> {
    // A scanner doesn't advertise, so the service port is never sent.
    let d = lan(beacon, "scanner", 1)?;
    let mut stream = d.start_scanning().await?;
    let mut peers: Vec<Peer> = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while !done(&peers) {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => break,
            Ok(None) => return Err(CliError::Discovery(discovery::DiscoveryError::Stopped)),
            Ok(Some(DiscoveryEvent::PeerFound(p))) => {
                peers.retain(|q| q.handle != p.handle);
                peers.push(p);
            }
            Ok(Some(DiscoveryEvent::PeerLost(h))) => peers.retain(|q| q.handle != h),
        }
    }
    Ok((d, peers))
}

async fn stop_discovery(d: &LanDiscovery) {
    if let Err(e) = d.stop().await {
        tracing::warn!(error = %e, "stopping discovery failed");
    }
}

async fn address_of(d: &LanDiscovery, p: &Peer) -> Result<SocketAddr, CliError> {
    let link = d.connect(p).await?;
    match (link.peer_ip, link.peer_port) {
        (Some(ip), Some(port)) => Ok(SocketAddr::new(ip, port)),
        _ => Err(CliError::NotFound(format!("{} did not advertise an address; use --to IP:PORT.", offer::printable(&p.display_name)))),
    }
}

#[derive(serde::Serialize)]
struct PeerRow {
    name: String,
    fingerprint: Option<String>,
    address: Option<String>,
    trusted_as: Option<String>,
}

async fn cmd_peers(data: &Path, timeout: u64, beacon: &BeaconArgs, json: bool) -> Result<(), CliError> {
    let trust = TrustStore::load(data)?;
    if !json {
        eprintln!("Looking for devices for {timeout} s…");
    }
    let (d, mut peers) = scan(beacon, Duration::from_secs(timeout), |_| false).await?;
    peers.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    let mut rows = Vec::with_capacity(peers.len());
    for p in &peers {
        let address = match address_of(&d, p).await {
            Ok(a) => Some(a.to_string()),
            Err(e) => {
                tracing::debug!(error = %e, "no address for peer");
                None
            }
        };
        let trusted_as = p.fingerprint.as_deref().and_then(|f| trust.get(f)).map(|t| t.name.clone());
        rows.push(PeerRow { name: offer::printable(&p.display_name), fingerprint: p.fingerprint.clone(), address, trusted_as });
    }
    stop_discovery(&d).await;
    if json {
        return print_json(&rows);
    }
    if rows.is_empty() {
        println!("No devices found. Is `dfte receive` running on the other device, on the same network?");
        return Ok(());
    }
    let w = rows.iter().map(|r| r.name.chars().count()).max().unwrap_or(0);
    for r in &rows {
        let trusted = r.trusted_as.as_ref().map_or_else(String::new, |n| format!("  trusted as \"{n}\""));
        println!("{:<w$}  {}  {}{trusted}", r.name, r.fingerprint.as_deref().unwrap_or("(no fingerprint)"), r.address.as_deref().unwrap_or("-"));
    }
    Ok(())
}

// ---------------------------------------------------------------- transfers

/// Runs `fut`; the first Ctrl-C cancels it cleanly through `cancel` (the
/// engine tells the peer and keeps resume state), a second one, or a prompt
/// in progress, stops at once.
async fn interruptible<T>(fut: impl Future<Output = Result<T, EngineError>>, cancel: &CancelHandle, prompting: &AtomicBool) -> Result<T, CliError> {
    tokio::pin!(fut);
    let signal = tokio::select! {
        r = &mut fut => return r.map_err(CliError::from),
        s = tokio::signal::ctrl_c() => s,
    };
    signal.map_err(|e| CliError::io("cannot listen for Ctrl-C", e))?;
    if prompting.load(Ordering::SeqCst) {
        eprintln!();
        return Err(CliError::Interrupted);
    }
    cancel.cancel();
    eprintln!("\nStopping… (Ctrl-C again to quit immediately)");
    tokio::select! {
        r = &mut fut => match r {
            Ok(v) => Ok(v), // finished just as Ctrl-C arrived
            Err(EngineError::Cancelled) => Err(CliError::Interrupted),
            Err(e) => {
                tracing::warn!(error = %e, "transfer ended with an error while cancelling");
                Err(CliError::Interrupted)
            }
        },
        s = tokio::signal::ctrl_c() => {
            s.map_err(|e| CliError::io("cannot listen for Ctrl-C", e))?;
            Err(CliError::Interrupted)
        }
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(CliError::Interrupted),
    }
}

fn drained(side: &str, r: transport::Result<()>) {
    if let Err(e) = r {
        eprintln!("Warning: the {side} connection did not close cleanly ({e}); the other device may report a lost connection.");
    }
}

fn progress_fn(reporter: &Arc<Reporter>) -> dfte_core::ProgressFn {
    let r = Arc::clone(reporter);
    Arc::new(move |p: &Progress| r.update(p))
}

fn report_line(r: &TransferReport, verb: &str, peer: &str) -> String {
    let resumed = if r.resumed_bytes > 0 { format!(", resumed: {} were already there", human_bytes(r.resumed_bytes)) } else { String::new() };
    format!("{verb} {} item{} ({}) {} \"{}\" in {:.1} s ({}{resumed}).", r.files, if r.files == 1 { "" } else { "s" }, human_bytes(r.bytes_total), if verb == "Sent" { "to" } else { "from" }, offer::printable(peer), r.total_secs, human_rate(r.end_to_end_bytes_per_sec))
}

struct ReceiveArgs {
    dir: Option<PathBuf>,
    listen: SocketAddr,
    transport: TransportArg,
    once: bool,
    accept_from: Option<String>,
    beacon: BeaconArgs,
    json: bool,
}

async fn cmd_receive(data: &Path, a: ReceiveArgs, peer_name: Arc<Mutex<Option<String>>>) -> Result<(), CliError> {
    let id = load_identity(data)?;
    let dest = match &a.dir {
        Some(d) => d.clone(),
        None => paths::download_dir()?,
    };
    std::fs::create_dir_all(&dest).map_err(|e| CliError::io(format!("cannot create {}", dest.display()), e))?;
    let staging = paths::staging_dir(data);
    crate::fsutil::ensure_private_dir(&staging)?;
    let expected = match &a.accept_from {
        Some(f) => Expected::Pinned(normalize_fingerprint(f).ok_or_else(|| CliError::Usage(format!("--accept-from {f:?} is not a fingerprint (24 hex digits).")))?),
        None => Expected::None,
    };
    let ctx = Ctx { id, data: data.to_path_buf(), json: a.json, peer_name };
    match a.transport {
        TransportArg::Tcp => receive_with(&TcpTransport::default(), &ctx, &a, &dest, &staging, expected).await,
        TransportArg::Quic => receive_with(&quic(&ctx.id)?, &ctx, &a, &dest, &staging, expected).await,
    }
}

struct Ctx {
    id: Arc<DeviceIdentity>,
    data: PathBuf,
    json: bool,
    peer_name: Arc<Mutex<Option<String>>>,
}

fn quic(id: &DeviceIdentity) -> Result<QuicTransport, CliError> {
    QuicTransport::new(id, QuicConfig::default()).map_err(|e| CliError::Config(format!("cannot set up QUIC: {e}")))
}

fn kind_name(t: TransportArg) -> &'static str {
    match t {
        TransportArg::Tcp => "tcp",
        TransportArg::Quic => "quic",
    }
}

async fn receive_with<T: Transport>(t: &T, ctx: &Ctx, a: &ReceiveArgs, dest: &Path, staging: &Path, expected: Expected) -> Result<(), CliError> {
    let mut listener = t.listen(a.listen).await.map_err(|e| CliError::Config(format!("Cannot listen on {}: {e}. Is another dfte receive running? Try --port.", a.listen)))?;
    let local = listener.local_addr().map_err(|e| CliError::Config(format!("cannot read the listening address: {e}")))?;
    let name = identity::device_name();
    eprintln!("Ready to receive as \"{name}\" ({}).", ctx.id.fingerprint());
    eprintln!("Listening on {local} ({}). Saving to {}.", kind_name(a.transport), dest.display());

    let discovery = match lan(&a.beacon, &name, local.port()) {
        Ok(d) => match d.start_advertising(&ctx.id).await {
            Ok(()) => Some(d),
            Err(e) => {
                eprintln!("Not discoverable on the network ({e}); senders can still use --to IP:{}.", local.port());
                None
            }
        },
        Err(e) => {
            eprintln!("Not discoverable on the network ({}); senders can still use --to IP:{}.", e.user_message(None), local.port());
            None
        }
    };

    let trust = Arc::new(Mutex::new(TrustStore::load(&ctx.data)?));
    let interactive = stdin_is_interactive();
    let tty = std::io::stderr().is_terminal();
    let result = loop {
        let prompting = Arc::new(AtomicBool::new(false));
        let verified: Arc<Mutex<Option<PeerAuth>>> = Arc::default();
        // Reload pins between transfers ("always" answers, `dfte trust add`).
        *lock(&trust) = TrustStore::load(&ctx.data)?;
        let verifier = TerminalVerifier { role: Role::Receive, expected: expected.clone(), trust: Arc::clone(&trust), interactive, prompting: Arc::clone(&prompting), verified: Arc::clone(&verified) };
        let mut opts = ReceiveOptions::new(Arc::clone(&ctx.id), Arc::new(verifier));
        opts.common.device_name.clone_from(&name);
        let reporter = Arc::new(Reporter::new("Receiving", tty));
        opts.common.progress = Some(progress_fn(&reporter));
        let cancel = CancelHandle::new();
        opts.common.cancel = Some(cancel.clone());
        let (v2, d2) = (Arc::clone(&verified), dest.to_path_buf());
        opts.on_manifest = Some(ManifestHook::new(move |m| {
            let from = lock(&v2).as_ref().map_or_else(|| "the other device".to_owned(), |p| format!("\"{}\"", offer::printable(&p.device_name)));
            eprintln!("Incoming from {from}: {}\nSaving to {}", offer::describe(&offer::summarize(m), 5), d2.display());
            true
        }));

        let r = interruptible(receive(&mut listener, staging, dest, &opts), &cancel, &prompting).await;
        reporter.finish();
        let peer = lock(&verified).clone();
        *lock(&ctx.peer_name) = peer.as_ref().map(|p| offer::printable(&p.device_name));
        match r {
            Ok(rep) => {
                if ctx.json {
                    print_json(&rep)?;
                } else {
                    println!("{}", report_line(&rep, "Received", &rep.peer_name));
                    for p in rep.saved.iter().take(5) {
                        println!("  {}", p.display());
                    }
                    if rep.saved.len() > 5 {
                        println!("  …and {} more", rep.saved.len() - 5);
                    }
                }
                if a.once {
                    break Ok(());
                }
            }
            Err(CliError::Interrupted) if peer.is_none() => break Err(CliError::Stopped),
            Err(e) if a.once || matches!(e, CliError::Interrupted) => break Err(e),
            Err(e) => {
                // Keep serving: one failed sender doesn't stop the receiver.
                eprintln!("{}", e.user_message(peer.as_ref().map(|p| p.device_name.as_str())));
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        // stderr, so it never mixes with --json output on stdout.
        eprintln!("Waiting for the next transfer (Ctrl-C to stop)…");
    };
    if let Some(d) = &discovery {
        stop_discovery(d).await;
    }
    drained("receiving", listener.drain().await);
    result
}

struct SendArgs {
    paths: Vec<PathBuf>,
    to: Option<String>,
    expect: Option<String>,
    streams: usize,
    transport: TransportArg,
    scan_timeout: Duration,
    beacon: BeaconArgs,
    json: bool,
}

/// Where to connect and what fingerprint to expect there.
async fn resolve(a: &SendArgs, trust: &TrustStore) -> Result<(SocketAddr, Expected, Option<String>), CliError> {
    let pinned_expect = match &a.expect {
        Some(f) => Some(normalize_fingerprint(f).ok_or_else(|| CliError::Usage(format!("--expect {f:?} is not a fingerprint (24 hex digits).")))?),
        None => None,
    };
    let target = match &a.to {
        Some(t) => Some(parse_target(t, trust).map_err(CliError::Usage)?),
        None => None,
    };
    if let Some(Target::Addr(addr)) = target {
        return Ok((addr, pinned_expect.map_or(Expected::None, Expected::Pinned), None));
    }
    let interactive = stdin_is_interactive();
    if target.is_none() && !interactive {
        return Err(CliError::Usage("No --to given and input is not a terminal, so dfte can't ask which device to use. Pass --to NAME, FINGERPRINT or IP:PORT.".into()));
    }
    if !a.json {
        eprintln!("Looking for devices…");
    }
    let (d, peers) = match &target {
        Some(t) => scan(&a.beacon, a.scan_timeout, |ps| matches!(pick(ps, t), Pick::Found(_))).await?,
        None => scan(&a.beacon, a.scan_timeout, |_| false).await?,
    };
    let chosen: Result<Peer, CliError> = match &target {
        Some(t) => match pick(&peers, t) {
            Pick::Found(p) => Ok(p.clone()),
            Pick::NotFound => Err(CliError::NotFound(format!("No device matching {:?} was found. Is `dfte receive` running there, on the same network? (Or use --to IP:PORT.)", a.to.as_deref().unwrap_or_default()))),
            Pick::Ambiguous(ps) => Err(CliError::Usage(format!("Several devices are called {:?}: {}. Use --to FINGERPRINT.", a.to.as_deref().unwrap_or_default(), ps.iter().map(|p| p.fingerprint.as_deref().unwrap_or("?")).collect::<Vec<_>>().join(", ")))),
        },
        None => choose_from_menu(&peers, trust),
    };
    let chosen = match chosen {
        Ok(p) => p,
        Err(e) => {
            stop_discovery(&d).await;
            return Err(e);
        }
    };
    let addr = address_of(&d, &chosen).await;
    stop_discovery(&d).await;
    let addr = addr?;
    let beacon_fp = chosen.fingerprint.clone();
    let expected = match (&target, pinned_expect, beacon_fp) {
        (_, Some(f), _) => Expected::Pinned(f),
        (Some(Target::Fingerprint(f) | Target::Trusted { fingerprint: f, .. }), None, _) => Expected::Pinned(f.clone()),
        (_, None, Some(f)) => Expected::Discovered(f),
        (_, None, None) => Expected::None,
    };
    Ok((addr, expected, Some(offer::printable(&chosen.display_name))))
}

fn choose_from_menu(peers: &[Peer], trust: &TrustStore) -> Result<Peer, CliError> {
    if peers.is_empty() {
        return Err(CliError::NotFound("No devices found. Run `dfte receive` on the other device (same network), or use --to IP:PORT.".into()));
    }
    let mut err = std::io::stderr();
    let io = |e| CliError::io("cannot prompt", e);
    for (i, p) in peers.iter().enumerate() {
        let trusted = p.fingerprint.as_deref().and_then(|f| trust.get(f)).map_or_else(String::new, |t| format!("  (trusted as \"{}\")", t.name));
        writeln!(err, "  {}. {}  {}{trusted}", i + 1, offer::printable(&p.display_name), p.fingerprint.as_deref().unwrap_or("")).map_err(io)?;
    }
    let stdin = std::io::stdin();
    for _ in 0..3 {
        write!(err, "Send to which device? [1-{}]: ", peers.len()).map_err(io)?;
        err.flush().map_err(io)?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).map_err(io)? == 0 {
            break;
        }
        if let Some(i) = parse_choice(&line, peers.len()) {
            return Ok(peers[i].clone());
        }
    }
    Err(CliError::Usage("No device chosen.".into()))
}

async fn cmd_send(data: &Path, a: SendArgs, peer_name: Arc<Mutex<Option<String>>>) -> Result<(), CliError> {
    let id = load_identity(data)?;
    let trust = TrustStore::load(data)?;
    let (addr, expected, shown) = resolve(&a, &trust).await?;
    *lock(&peer_name) = shown;
    let ctx = Ctx { id, data: data.to_path_buf(), json: a.json, peer_name };
    match a.transport {
        TransportArg::Tcp => send_with(&TcpTransport::default(), &ctx, &a, addr, expected, trust).await,
        TransportArg::Quic => send_with(&quic(&ctx.id)?, &ctx, &a, addr, expected, trust).await,
    }
}

async fn send_with<T: Transport>(t: &T, ctx: &Ctx, a: &SendArgs, addr: SocketAddr, expected: Expected, trust: TrustStore) -> Result<(), CliError> {
    let prompting = Arc::new(AtomicBool::new(false));
    let verified: Arc<Mutex<Option<PeerAuth>>> = Arc::default();
    let verifier = TerminalVerifier { role: Role::Send, expected, trust: Arc::new(Mutex::new(trust)), interactive: stdin_is_interactive(), prompting: Arc::clone(&prompting), verified: Arc::clone(&verified) };
    let mut opts = SendOptions::new(Arc::clone(&ctx.id), Arc::new(verifier));
    opts.common.device_name = identity::device_name();
    opts.streams = a.streams;
    // TODO(hash-cache, PR #15): set opts.hash_cache_dir to $XDG_CACHE_HOME/dfte/hashes once merged.
    let reporter = Arc::new(Reporter::new("Sending", std::io::stderr().is_terminal()));
    opts.common.progress = Some(progress_fn(&reporter));
    let cancel = CancelHandle::new();
    opts.common.cancel = Some(cancel.clone());

    if !ctx.json {
        eprintln!("Preparing {} item(s) and connecting to {addr} ({})…", a.paths.len(), kind_name(a.transport));
    }
    let started = Instant::now();
    let r = interruptible(send_files(t, addr, &a.paths, &opts), &cancel, &prompting).await;
    reporter.finish();
    if let Some(p) = lock(&verified).as_ref() {
        *lock(&ctx.peer_name) = Some(offer::printable(&p.device_name));
    }
    drained("sending", t.drain().await);
    let rep = r?;
    tracing::debug!(secs = started.elapsed().as_secs_f64(), "send finished");
    if ctx.json {
        print_json(&rep)?;
    } else {
        println!("{}", report_line(&rep, "Sent", &rep.peer_name));
    }
    Ok(())
}
