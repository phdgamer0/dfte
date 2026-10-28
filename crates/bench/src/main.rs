//! `engine-bench`: drives the real engine (same crates as the apps, manual §30).
//!
//! - `recv` / `send`: two processes, possibly on two machines (manual §41: manual
//!   IP entry is fine at this stage).
//! - `loopback`: both sides in one process over 127.0.0.1 in a temp dir.
//!   `--in-memory` puts source, staging and destination on tmpfs (`/dev/shm`), so
//!   the full code path still runs (pread/pwrite/fallocate/fsync/rename are real
//!   syscalls) but no block device is involved: fsync is a no-op and reads/writes
//!   are page-cache copies. That is the §30 #4 "storage removed from the loop"
//!   baseline; the default disk mode uses `--dir` (default: current directory),
//!   where the receiver's fsyncs really hit the disk. In both modes the freshly
//!   generated source file is in the page cache, so source reads are not disk reads.
//! - `--transport tcp|quic` on all three: each side's QUIC endpoint uses that
//!   side's engine identity as its TLS identity (the engine cross-checks them).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use dfte_core::{DeviceIdentity, PeerAuth, PeerVerifier, ReceiveOptions, SendOptions, TransferReport, TrustAny, receive, send_files};
use serde::Serialize;
use transport::{Listener, QuicConfig, QuicTransport, TcpTransport, Transport};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
#[command(name = "engine-bench", about = "Direct P2P file transfer engine benchmark/test CLI (manual §30/§41)")]
struct Cli {
    /// Print machine-readable JSON instead of the human summary.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum TransportArg {
    Tcp,
    Quic,
}

#[derive(Subcommand)]
enum Cmd {
    /// Receive one transfer.
    Recv {
        #[arg(long)]
        listen: SocketAddr,
        /// App-private staging dir (partial files + resume sidecars).
        #[arg(long)]
        staging: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Skip the SAS confirmation (loopback benchmarks only).
        #[arg(long)]
        trust_any: bool,
        #[arg(long, default_value_t = 16)]
        max_streams: u8,
        #[arg(long, value_enum, default_value_t = TransportArg::Tcp)]
        transport: TransportArg,
        /// Agree to unencrypted data streams if the sender asks (bench only).
        #[arg(long)]
        allow_plaintext: bool,
    },
    /// Send files/directories to a receiver.
    Send {
        #[arg(long)]
        target: SocketAddr,
        #[arg(long = "file", required = true, num_args = 1..)]
        files: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        streams: usize,
        #[arg(long, value_enum, default_value_t = TransportArg::Tcp)]
        transport: TransportArg,
        #[arg(long)]
        trust_any: bool,
        /// Ask for unencrypted data streams (§30 #2; receiver must --allow-plaintext).
        #[arg(long)]
        plaintext: bool,
        /// Chunks in flight (× 4 MiB of buffer memory).
        #[arg(long, default_value_t = 16)]
        in_flight: usize,
    },
    /// Both sides in one process over 127.0.0.1.
    Loopback {
        /// Total bytes, e.g. 1G, 512M, 1048576.
        #[arg(long, value_parser = parse_size)]
        size: u64,
        #[arg(long, value_enum, default_value_t = TransportArg::Tcp)]
        transport: TransportArg,
        /// Split `size` across this many files.
        #[arg(long, default_value_t = 1)]
        files: usize,
        #[arg(long, default_value_t = 2)]
        streams: usize,
        #[arg(long)]
        plaintext: bool,
        /// Source/staging/destination on tmpfs (/dev/shm) instead of disk.
        #[arg(long)]
        in_memory: bool,
        /// Base directory for disk mode.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long, default_value_t = 16)]
        in_flight: usize,
        #[arg(long, default_value_t = 16)]
        recv_buffers: usize,
        /// Run the transfer this many times (same source files).
        #[arg(long, default_value_t = 1)]
        repeat: usize,
    },
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().map_err(|_| format!("bad size {s:?}"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        u => return Err(format!("unknown unit {u:?}")),
    };
    Ok((n * mult as f64) as u64)
}

/// Terminal SAS prompt (manual §12.1): both users compare the 6 digits.
struct PromptVerifier;

impl PromptVerifier {
    fn ask(peer: &PeerAuth) -> std::io::Result<bool> {
        use std::io::{BufRead, Write};
        let mut err = std::io::stderr();
        writeln!(err, "\nPeer \"{}\"  fingerprint {}", peer.device_name, peer.fingerprint)?;
        write!(err, "Security code: {}\nDoes the other device show the same code? [y/N] ", peer.sas)?;
        err.flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
    }
}

impl PeerVerifier for PromptVerifier {
    fn verify(&self, peer: &PeerAuth) -> bool {
        // Fail closed: if the user can't be asked, the peer is not verified.
        Self::ask(peer).unwrap_or_else(|e| {
            eprintln!("cannot prompt for confirmation ({e}); rejecting peer");
            false
        })
    }
}

fn verifier(trust_any: bool) -> Arc<dyn PeerVerifier> {
    if trust_any { Arc::new(TrustAny) } else { Arc::new(PromptVerifier) }
}

fn identity() -> Result<Arc<DeviceIdentity>, BoxError> {
    // Ephemeral per run: the bench has no keystore (manual §6 applies to the apps).
    Ok(Arc::new(DeviceIdentity::generate()?))
}

const MIB: f64 = 1024.0 * 1024.0;

fn print_report(r: &TransferReport) {
    let t = &r.timings;
    println!("{:?}: {} entries, {:.1} MiB ({:.1} MiB resumed) via {} x{} [{}] peer {}", r.direction, r.files, r.bytes_total as f64 / MIB, r.resumed_bytes as f64 / MIB, r.transport, r.streams, r.cipher, r.peer_fingerprint);
    println!("  throughput {:.1} MiB/s ({:.2} Gbit/s), end-to-end incl. fsync {:.1} MiB/s, retransmits {}", r.throughput_bytes_per_sec / MIB, r.throughput_bytes_per_sec * 8.0 / 1e9, r.end_to_end_bytes_per_sec / MIB, r.retransmits);
    println!("  phases: hash {:.3}s  connect {:.3}s  handshake {:.3}s  manifest {:.3}s  transfer {:.3}s  finalize {:.3}s  total {:.3}s", t.hash_secs, t.connect_secs, t.handshake_secs, t.manifest_secs, t.transfer_secs, t.finalize_secs, r.total_secs);
}

#[tokio::main]
async fn main() {
    // No/invalid RUST_LOG simply means the default "warn" filter.
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into())).with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), BoxError> {
    match cli.cmd {
        Cmd::Recv { listen, staging, out, trust_any, max_streams, transport, allow_plaintext } => {
            let mut opts = ReceiveOptions::new(identity()?, verifier(trust_any));
            opts.max_streams = max_streams;
            opts.allow_insecure_plaintext = allow_plaintext;
            eprintln!("this device: {}", opts.common.identity.fingerprint());
            let r = match transport {
                TransportArg::Tcp => recv_on(&TcpTransport::default(), listen, &staging, &out, &opts).await?,
                TransportArg::Quic => recv_on(&quic(&opts.common.identity)?, listen, &staging, &out, &opts).await?,
            };
            emit(cli.json, &r, || print_report(&r))?;
        }
        Cmd::Send { target, files, streams, transport, trust_any, plaintext, in_flight } => {
            let mut opts = SendOptions::new(identity()?, verifier(trust_any));
            opts.streams = streams;
            opts.in_flight_chunks = in_flight;
            opts.insecure_plaintext = plaintext;
            eprintln!("this device: {}", opts.common.identity.fingerprint());
            let r = match transport {
                TransportArg::Tcp => send_on(&TcpTransport::default(), target, &files, &opts).await?,
                TransportArg::Quic => send_on(&quic(&opts.common.identity)?, target, &files, &opts).await?,
            };
            emit(cli.json, &r, || print_report(&r))?;
        }
        Cmd::Loopback { size, transport, files, streams, plaintext, in_memory, dir, in_flight, recv_buffers, repeat } => {
            let base = if in_memory { tmpfs_dir()? } else { dir };
            let root = tempfile::Builder::new().prefix("engine-bench-").tempdir_in(&base)?;
            let src = root.path().join("src");
            let t = Instant::now();
            let paths = generate(&src, size, files.max(1))?;
            if !cli.json {
                eprintln!("generated {:.1} MiB in {} file(s) under {} in {:.2}s", size as f64 / MIB, paths.len(), root.path().display(), t.elapsed().as_secs_f64());
            }
            let mut runs = Vec::new();
            for i in 0..repeat.max(1) {
                let run = loopback_once(root.path(), i, transport, &paths, streams, plaintext, in_flight, recv_buffers).await?;
                if !cli.json {
                    println!("--- run {} ({}, {})", i + 1, if in_memory { "tmpfs" } else { "disk" }, if plaintext { "plaintext" } else { "encrypted" });
                    print_report(&run.sender);
                    print_report(&run.receiver);
                }
                runs.push(run);
            }
            let mut tp: Vec<f64> = runs.iter().map(|r| r.sender.throughput_bytes_per_sec).collect();
            tp.sort_by(f64::total_cmp);
            let median = tp[tp.len() / 2];
            let summary = LoopbackSummary { size, files: paths.len(), streams, plaintext, in_memory, in_flight, recv_buffers, median_throughput_bytes_per_sec: median, runs };
            emit(cli.json, &summary, || println!("median sender throughput over {} run(s): {:.1} MiB/s", summary.runs.len(), median / MIB))?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct LoopbackRun {
    sender: TransferReport,
    receiver: TransferReport,
}

#[derive(Serialize)]
struct LoopbackSummary {
    size: u64,
    files: usize,
    streams: usize,
    plaintext: bool,
    in_memory: bool,
    in_flight: usize,
    recv_buffers: usize,
    median_throughput_bytes_per_sec: f64,
    runs: Vec<LoopbackRun>,
}

fn emit<T: Serialize>(json: bool, value: &T, human: impl FnOnce()) -> Result<(), BoxError> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        human();
    }
    Ok(())
}

fn tmpfs_dir() -> Result<PathBuf, BoxError> {
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() { Ok(shm) } else { Err("--in-memory needs a tmpfs at /dev/shm (Linux); use --dir on a RAM disk instead".into()) }
}

/// Writes `files` incompressible files totalling `size` bytes (xorshift stream).
fn generate(dir: &Path, size: u64, files: usize) -> Result<Vec<PathBuf>, BoxError> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let per = size / files as u64;
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut buf = vec![0u8; 1 << 20];
    let mut out = Vec::with_capacity(files);
    for i in 0..files {
        let len = if i + 1 == files { size - per * (files as u64 - 1) } else { per };
        let p = dir.join(format!("file-{i:04}.bin"));
        let mut f = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&p)?);
        let mut left = len;
        while left > 0 {
            for w in buf.as_chunks_mut::<8>().0 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *w = x.to_le_bytes();
            }
            let n = left.min(buf.len() as u64) as usize;
            f.write_all(&buf[..n])?;
            left -= n as u64;
        }
        f.flush()?;
        out.push(p);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn loopback_once(root: &Path, i: usize, transport: TransportArg, paths: &[PathBuf], streams: usize, plaintext: bool, in_flight: usize, recv_buffers: usize) -> Result<LoopbackRun, BoxError> {
    let staging = root.join(format!("staging-{i}"));
    let out = root.join(format!("out-{i}"));
    let mut ropts = ReceiveOptions::new(identity()?, Arc::new(TrustAny));
    ropts.allow_insecure_plaintext = plaintext;
    ropts.pool_buffers = recv_buffers;
    let mut sopts = SendOptions::new(identity()?, Arc::new(TrustAny));
    sopts.streams = streams;
    sopts.in_flight_chunks = in_flight;
    sopts.insecure_plaintext = plaintext;
    // Each side's QUIC endpoint presents that side's engine identity, which the
    // engine cross-checks against the Noise handshake.
    let (sender, receiver) = match transport {
        TransportArg::Tcp => loopback_pair(&TcpTransport::default(), &TcpTransport::default(), paths, &staging, &out, &sopts, ropts).await?,
        TransportArg::Quic => loopback_pair(&quic(&sopts.common.identity)?, &quic(&ropts.common.identity)?, paths, &staging, &out, &sopts, ropts).await?,
    };
    // Free the space before the next repetition.
    std::fs::remove_dir_all(&out)?;
    std::fs::remove_dir_all(&staging)?;
    Ok(LoopbackRun { sender, receiver })
}

async fn loopback_pair<S: Transport, R: Transport>(send_t: &S, recv_t: &R, paths: &[PathBuf], staging: &Path, out: &Path, sopts: &SendOptions, ropts: ReceiveOptions) -> Result<(TransferReport, TransferReport), BoxError>
where
    R::Listener: 'static,
{
    let mut l = recv_t.listen("127.0.0.1:0".parse()?).await?;
    let addr = l.local_addr()?;
    let (s2, o2) = (staging.to_path_buf(), out.to_path_buf());
    let rx = tokio::spawn(async move {
        let r = receive(&mut l, &s2, &o2, &ropts).await;
        drained("receiver", l.drain().await);
        r
    });
    let sender = send_files(send_t, addr, paths, sopts).await;
    drained("sender", send_t.drain().await);
    let receiver = rx.await??;
    Ok((sender?, receiver))
}

async fn recv_on<T: Transport>(t: &T, listen: SocketAddr, staging: &Path, out: &Path, opts: &ReceiveOptions) -> Result<TransferReport, BoxError> {
    let mut l = t.listen(listen).await?;
    eprintln!("listening on {} ({:?})", l.local_addr()?, t.kind());
    let r = receive(&mut l, staging, out, opts).await;
    drained("receiver", l.drain().await);
    Ok(r?)
}

async fn send_on<T: Transport>(t: &T, target: SocketAddr, files: &[PathBuf], opts: &SendOptions) -> Result<TransferReport, BoxError> {
    let r = send_files(t, target, files, opts).await;
    drained("sender", t.drain().await);
    Ok(r?)
}

/// The process is about to exit: let the transport deliver what it still owes
/// the peer (QUIC retransmits in userspace, see `Transport::drain`). The
/// transfer's own result is what this side reports; an undelivered tail is
/// surfaced on stderr, since the peer may then fail.
fn drained(side: &str, r: transport::Result<()>) {
    if let Err(e) = r {
        eprintln!("warning: {side} transport did not drain before exit: {e}; the peer may see the connection drop");
    }
}

/// QUIC endpoint whose TLS identity is the engine identity (manual §12.1).
fn quic(identity: &DeviceIdentity) -> Result<QuicTransport, BoxError> {
    Ok(QuicTransport::new(identity, QuicConfig::default())?)
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1G"), Ok(1 << 30));
        assert_eq!(parse_size("512MiB"), Ok(512 << 20));
        assert_eq!(parse_size("1.5k"), Ok(1536));
        assert_eq!(parse_size("42"), Ok(42));
        assert!(parse_size("1Q").is_err());
    }
}
