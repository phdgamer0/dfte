//! `netem-harness`: the §31 loss/latency/reorder matrix over `engine-bench`.
//!
//! Needs CAP_NET_ADMIN + CAP_SYS_ADMIN (root). In CI: `sudo netem-harness
//! --require-root ...`. Without root it skips with a message (exit 0) unless
//! `--require-root` is given. Unprivileged local runs work inside a user+net+mount
//! namespace with a private /run:
//!
//! ```text
//! unshare -rmn sh -c 'mount -t tmpfs tmpfs /run && mkdir /run/netns && exec netem-harness ...'
//! ```
//! (needs the `veth` and `sch_netem` modules already loaded on the host).

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use netem_harness::profile::{Profile, default_profiles};
use netem_harness::runner::{self, Caps, RunCtx, RunResult, Source, Status};
use netem_harness::{results, topology};

#[derive(Parser)]
#[command(name = "netem-harness", about = "netns + tc/netem loss/latency/reorder matrix over engine-bench (manual §31)", after_help = "Needs root (CAP_NET_ADMIN + CAP_SYS_ADMIN); in CI: sudo netem-harness --require-root.\n\nWithout sudo, run it inside a user + net + mount namespace with a private /run\n(the veth and sch_netem kernel modules must already be loaded on the host):\n\n  unshare -rmn sh -c 'mount -t tmpfs tmpfs /run && mkdir /run/netns && exec netem-harness --engine-bench \"$PWD/target/release/engine-bench\" ...'")]
struct Cli {
    /// The engine-bench binary (build with `cargo build --release -p bench`).
    #[arg(long, default_value = "target/release/engine-bench")]
    engine_bench: PathBuf,
    /// Only these profiles (repeatable); default: all. See --list.
    #[arg(long = "profile")]
    profiles: Vec<String>,
    #[arg(long, value_delimiter = ',', default_value = "1,4")]
    streams: Vec<usize>,
    /// Transports to exercise; one the binary rejects is skipped with the reason logged.
    #[arg(long, value_delimiter = ',', default_value = "tcp,quic")]
    transports: Vec<String>,
    /// Override every profile's transfer size, in MiB.
    #[arg(long)]
    size_mib: Option<u64>,
    /// Override every profile's hard per-run timeout, in seconds.
    #[arg(long)]
    timeout_secs: Option<u64>,
    /// Scratch space for source files, staging and output (default: a temp dir).
    #[arg(long)]
    work_dir: Option<PathBuf>,
    /// Where results.json, results.csv and summary.md go.
    #[arg(long, default_value = "netem-results")]
    out_dir: PathBuf,
    /// Also append the markdown summary here (e.g. "$GITHUB_STEP_SUMMARY").
    #[arg(long)]
    summary: Option<PathBuf>,
    /// Fail (exit 2) instead of skipping when not running as root.
    #[arg(long)]
    require_root: bool,
    /// Print the profiles and exit.
    #[arg(long)]
    list: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match real_main(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("netem-harness: error: {e}");
            ExitCode::from(2)
        }
    }
}

fn select_profiles(cli: &Cli) -> Result<Vec<Profile>, String> {
    let all = default_profiles();
    let mut ps: Vec<Profile> = if cli.profiles.is_empty() {
        all
    } else {
        let wanted: BTreeSet<&str> = cli.profiles.iter().map(String::as_str).collect();
        let known: BTreeSet<&str> = all.iter().map(|p| p.name.as_str()).collect();
        if let Some(bad) = wanted.difference(&known).next() {
            return Err(format!("unknown profile {bad:?}; known: {known:?}"));
        }
        all.into_iter().filter(|p| wanted.contains(p.name.as_str())).collect()
    };
    for p in &mut ps {
        if let Some(m) = cli.size_mib {
            p.size = m << 20;
        }
        if let Some(t) = cli.timeout_secs {
            p.timeout_secs = t;
        }
    }
    Ok(ps)
}

fn real_main(cli: &Cli) -> Result<ExitCode, String> {
    let profiles = select_profiles(cli)?;
    if cli.list {
        for p in &profiles {
            println!("{:<36} {:>4} MiB  timeout {:>3}s  netem: {}", p.name, p.size >> 20, p.timeout_secs, if p.netem.is_empty() { "-" } else { &p.netem });
        }
        return Ok(ExitCode::SUCCESS);
    }
    for t in &cli.transports {
        if !matches!(t.as_str(), "tcp" | "quic") {
            return Err(format!("unknown transport {t:?} (tcp, quic)"));
        }
    }
    if cli.streams.is_empty() || cli.streams.contains(&0) {
        return Err("--streams needs positive counts".into());
    }
    let specs = profiles.iter().map(|p| p.spec().map_err(|e| format!("profile {}: {e}", p.name))).collect::<Result<Vec<_>, _>>()?;

    let uid = topology::effective_uid()?;
    if uid != 0 {
        let msg = format!("netem-harness needs root (CAP_NET_ADMIN + CAP_SYS_ADMIN for ip netns / tc); running as uid {uid}");
        if cli.require_root {
            return Err(msg);
        }
        eprintln!("SKIP: {msg}. Run with sudo, or see `netem-harness --help` for an unprivileged unshare recipe.");
        return Ok(ExitCode::SUCCESS);
    }
    for tool in [["ip", "-V"], ["tc", "-V"]] {
        topology::run(&tool.map(str::to_owned))?;
    }
    if !cli.engine_bench.is_file() {
        return Err(format!("engine-bench not found at {} (cargo build --release -p bench)", cli.engine_bench.display()));
    }
    let bench = std::fs::canonicalize(&cli.engine_bench).map_err(|e| format!("{}: {e}", cli.engine_bench.display()))?;
    sweep_stale_namespaces()?;
    let help = topology::run(&[bench.display().to_string(), "recv".into(), "--help".into()])?;
    let caps = Caps { recv_transport_flag: help.contains("--transport") };

    let tmp = match &cli.work_dir {
        Some(_) => None,
        None => Some(tempfile::Builder::new().prefix("netem-harness-").tempdir().map_err(|e| format!("temp dir: {e}"))?),
    };
    let work: &Path = match (&cli.work_dir, &tmp) {
        (Some(d), _) => {
            std::fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
            d
        }
        (None, Some(t)) => t.path(),
        (None, None) => return Err("no work dir".into()),
    };

    let mut sources: Vec<Source> = Vec::new();
    let mut all: Vec<RunResult> = Vec::new();
    let mut idx = 0;
    for (p, spec) in profiles.iter().zip(&specs) {
        if !sources.iter().any(|s| s.size == p.size) {
            sources.push(runner::generate_source(work, p.size)?);
        }
        let src = sources.iter().find(|s| s.size == p.size).ok_or("source vanished")?;
        for t in &cli.transports {
            for &n in &cli.streams {
                let r = if t != "tcp" && !caps.recv_transport_flag {
                    RunResult::skip(p, t, n, format!("engine-bench recv has no --transport flag, so it cannot receive {t}"))
                } else {
                    eprintln!("[{}] {} / {t} x{n} ({} MiB, netem: {}) ...", idx + 1, p.name, p.size >> 20, if p.netem.is_empty() { "-" } else { &p.netem });
                    let r = runner::run_one(&RunCtx { bench: &bench, caps, work, run_index: idx }, p, spec, src, t, n);
                    idx += 1;
                    r
                };
                log_result(&r);
                all.push(r);
            }
        }
    }
    drop(sources);
    if let Some(t) = tmp {
        t.close().map_err(|e| format!("removing the work dir: {e}"))?;
    }

    write_outputs(cli, &all)?;
    let failed = all.iter().filter(|r| r.status == Status::Fail).count();
    if failed > 0 {
        eprintln!("netem-harness: {failed} run(s) failed");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn log_result(r: &RunResult) {
    let gp = r.goodput_bytes_per_sec.map(|g| format!("{:.1} MiB/s", g / (1024.0 * 1024.0))).unwrap_or_default();
    eprintln!("    {:?} {gp} in {:.1}s, tcp retrans {:?}, app resends {:?}", r.status, r.wall_secs, r.tcp_retrans_segs, r.app_retransmits);
    for why in &r.reasons {
        eprintln!("    {}: {why}", if r.status == Status::Skip { "skipped" } else { "failure" });
    }
    for n in &r.notes {
        eprintln!("    note: {n}");
    }
}

fn sweep_stale_namespaces() -> Result<(), String> {
    let list = topology::run(&["ip".into(), "netns".into(), "list".into()])?;
    for ns in topology::sweep_stale(&list, |pid| Path::new(&format!("/proc/{pid}")).exists()) {
        eprintln!("netem-harness: deleting stale namespace {ns}");
        topology::run(&["ip".into(), "netns".into(), "del".into(), ns])?;
    }
    Ok(())
}

fn write_outputs(cli: &Cli, all: &[RunResult]) -> Result<(), String> {
    let d = &cli.out_dir;
    std::fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
    let json = serde_json::to_string_pretty(all).map_err(|e| format!("serialize results: {e}"))?;
    let md = results::to_markdown(all).map_err(|e| format!("render summary: {e}"))?;
    for (name, body) in [("results.json", json), ("results.csv", results::to_csv(all)), ("summary.md", md.clone())] {
        let p = d.join(name);
        std::fs::write(&p, body).map_err(|e| format!("write {}: {e}", p.display()))?;
    }
    if let Some(s) = &cli.summary {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(s).map_err(|e| format!("open {}: {e}", s.display()))?;
        f.write_all(md.as_bytes()).map_err(|e| format!("write {}: {e}", s.display()))?;
    }
    print!("{md}");
    eprintln!("netem-harness: results in {}", d.display());
    Ok(())
}
