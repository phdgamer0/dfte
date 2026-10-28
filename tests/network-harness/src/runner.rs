//! One matrix cell: fresh topology → recv + send → verify → teardown.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::proc::Proc;
use crate::profile::{NetemSpec, Profile};
use crate::report::{self, Expect, Report};
use crate::topology::{self, Names, QdiscStats, TcpCounters, Topology};

pub const PORT: u16 = 47_031;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

/// What `engine-bench` supports, probed once from its `--help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// `recv` takes `--transport` (otherwise it is TCP-only).
    pub recv_transport_flag: bool,
}

/// One row of the results file.
#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub profile: String,
    pub netem: String,
    pub transport: String,
    pub streams: usize,
    pub size_bytes: u64,
    pub status: Status,
    /// Why it failed or was skipped.
    pub reasons: Vec<String>,
    /// Non-fatal observations (e.g. app-level resends under heavy loss).
    pub notes: Vec<String>,
    pub wall_secs: f64,
    pub hash_ok: Option<bool>,
    /// Sender data-phase goodput (`throughput_bytes_per_sec`).
    pub goodput_bytes_per_sec: Option<f64>,
    pub receiver_goodput_bytes_per_sec: Option<f64>,
    pub connect_secs: Option<f64>,
    pub handshake_secs: Option<f64>,
    /// Chunks the engine resent (ack timeout / integrity NACK, manual §9.3).
    pub app_retransmits: Option<u64>,
    /// Kernel TCP retransmitted segments (sender namespace); `None` for QUIC.
    pub tcp_retrans_segs: Option<u64>,
    pub tcp_out_segs: Option<u64>,
    pub netem_sender: Option<QdiscStats>,
    pub netem_receiver: Option<QdiscStats>,
}

impl RunResult {
    fn new(p: &Profile, transport: &str, streams: usize) -> Self {
        Self { profile: p.name.clone(), netem: p.netem.clone(), transport: transport.to_owned(), streams, size_bytes: p.size, status: Status::Fail, reasons: Vec::new(), notes: Vec::new(), wall_secs: 0.0, hash_ok: None, goodput_bytes_per_sec: None, receiver_goodput_bytes_per_sec: None, connect_secs: None, handshake_secs: None, app_retransmits: None, tcp_retrans_segs: None, tcp_out_segs: None, netem_sender: None, netem_receiver: None }
    }

    pub fn skip(p: &Profile, transport: &str, streams: usize, why: String) -> Self {
        let mut r = Self::new(p, transport, streams);
        r.status = Status::Skip;
        r.reasons.push(why);
        r
    }
}

/// A source file and its BLAKE3, generated once per size.
pub struct Source {
    pub path: PathBuf,
    pub size: u64,
    pub hash: blake3::Hash,
}

/// Writes `size` incompressible bytes (xorshift64) and hashes them on the way.
pub fn generate_source(dir: &Path, size: u64) -> Result<Source, String> {
    let path = dir.join(format!("src-{size}.bin"));
    let f = std::fs::File::create(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    let mut hasher = blake3::Hasher::new();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ size;
    let mut buf = vec![0u8; 1 << 20];
    let mut left = size;
    while left > 0 {
        for w8 in buf.as_chunks_mut::<8>().0 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *w8 = x.to_le_bytes();
        }
        let n = usize::try_from(left.min(buf.len() as u64)).map_err(|e| e.to_string())?;
        w.write_all(&buf[..n]).map_err(|e| format!("write {}: {e}", path.display()))?;
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    w.flush().map_err(|e| format!("flush {}: {e}", path.display()))?;
    Ok(Source { path, size, hash: hasher.finalize() })
}

pub fn hash_file(path: &Path) -> Result<blake3::Hash, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            return Ok(h.finalize());
        }
        h.update(&buf[..n]);
    }
}

/// `engine-bench` command lines. `--transport` goes to `recv` only when it has the flag;
/// without it, `recv` is the TCP-only build and `tcp` is its implicit transport.
pub fn recv_argv(bench: &Path, caps: Caps, transport: &str, staging: &Path, out: &Path) -> Vec<String> {
    let mut v = vec![bench.display().to_string(), "--json".into(), "recv".into(), "--listen".into(), format!("{}:{PORT}", topology::RECEIVER_ADDR), "--staging".into(), staging.display().to_string(), "--out".into(), out.display().to_string(), "--trust-any".into()];
    if caps.recv_transport_flag {
        v.extend(["--transport".into(), transport.to_owned()]);
    }
    v
}

pub fn send_argv(bench: &Path, transport: &str, file: &Path, streams: usize) -> Vec<String> {
    vec![bench.display().to_string(), "--json".into(), "send".into(), "--target".into(), format!("{}:{PORT}", topology::RECEIVER_ADDR), "--file".into(), file.display().to_string(), "--streams".into(), streams.to_string(), "--transport".into(), transport.to_owned(), "--trust-any".into()]
}

/// stderr patterns meaning "this build has no such transport" rather than a failure.
pub fn unsupported_transport(stderr: &str) -> Option<String> {
    const PATTERNS: [&str; 4] = ["not available in this build", "unexpected argument '--transport'", "invalid value 'quic'", "unsupported transport"];
    stderr.lines().find(|l| PATTERNS.iter().any(|p| l.contains(p))).map(|l| l.trim().to_owned())
}

/// Profile-specific checks on top of [`report::check_pair`].
pub fn check_profile(spec: &NetemSpec, r: &mut RunResult) {
    let tcp = r.transport == "tcp";
    let ns = r.netem_sender.unwrap_or_default();
    let nr = r.netem_receiver.unwrap_or_default();
    if spec.loss_pct > 0.0 && ns.dropped + nr.dropped == 0 {
        r.reasons.push(format!("netem configured {}% loss but dropped nothing: the impairment never engaged", spec.loss_pct));
    }
    if spec.duplicate_pct > 0.0 {
        match (ns.duplicated, nr.duplicated) {
            (Some(a), Some(b)) if a + b == 0 => r.reasons.push("netem configured duplication but duplicated nothing".into()),
            (Some(_), Some(_)) => {}
            _ => r.notes.push("this iproute2 does not print netem duplicate counters".into()),
        }
    }
    if spec.reorder_pct > 0.0 && matches!((ns.reordered, nr.reordered), (Some(0), Some(0))) {
        r.reasons.push("netem configured reordering but reordered nothing".into());
    }
    if spec.loss_pct > 0.0 && tcp && r.tcp_retrans_segs == Some(0) {
        r.reasons.push("packets were dropped but the sender's TCP retransmitted nothing".into());
    }
    // One MSS per packet proves gso_max_segs=1 took effect, so loss% is per packet.
    if ns.sent_pkts > 0 && ns.sent_bytes / ns.sent_pkts > 1600 {
        r.reasons.push(format!("netem saw {}-byte average packets: GSO super-packets were not split", ns.sent_bytes / ns.sent_pkts));
    }
    if let (Some(cap), Some(g)) = (spec.rate_bps, r.goodput_bytes_per_sec) {
        let frac = g * 8.0 / cap;
        // ≥ 50%: the pacer must not stall a capped link. ≤ 100% (+ timing slack):
        // goodput above the wire cap would mean the measurement itself is wrong.
        if !(0.5..=1.02).contains(&frac) {
            r.reasons.push(format!("goodput {:.1} Mbit/s is {:.0}% of the {:.0} Mbit/s cap (want 50-100%)", g * 8.0 / 1e6, frac * 100.0, cap / 1e6));
        } else {
            r.notes.push(format!("{:.0}% of rate cap", frac * 100.0));
        }
    }
    let clean = spec.loss_pct == 0.0 && spec.duplicate_pct == 0.0 && spec.reorder_pct == 0.0 && spec.jitter_ms == 0.0;
    match r.app_retransmits {
        Some(n) if n > 0 && clean => r.reasons.push(format!("{n} engine-level resends on a link without loss: ack timeouts or integrity NACKs where none can occur")),
        Some(n) if n > 0 => r.notes.push(format!("{n} engine-level chunk resends (ack timeout or integrity NACK)")),
        _ => {}
    }
}

pub struct RunCtx<'a> {
    pub bench: &'a Path,
    pub caps: Caps,
    pub work: &'a Path,
    pub run_index: usize,
}

pub fn run_one(ctx: &RunCtx<'_>, p: &Profile, spec: &NetemSpec, src: &Source, transport: &str, streams: usize) -> RunResult {
    let mut r = RunResult::new(p, transport, streams);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(p.timeout_secs);
    let dir = ctx.work.join(format!("run-{}", ctx.run_index));
    match execute(ctx, &dir, p, src, transport, streams, deadline, &mut r) {
        Ok(()) => {}
        Err(e) => match unsupported_transport(&e) {
            Some(why) if transport != "tcp" => {
                r.status = Status::Skip;
                r.reasons = vec![format!("engine-bench rejects --transport {transport}: {why}")];
            }
            _ => r.reasons.push(e),
        },
    }
    r.wall_secs = started.elapsed().as_secs_f64();
    if r.status != Status::Skip {
        // Profile checks need the counters of a run that got as far as verifying the file.
        if r.hash_ok.is_some() {
            check_profile(spec, &mut r);
        }
        r.status = if r.reasons.is_empty() { Status::Pass } else { Status::Fail };
    }
    if let Err(e) = std::fs::remove_dir_all(&dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        r.status = Status::Fail;
        r.reasons.push(format!("cleanup of {} failed: {e}", dir.display()));
    }
    r
}

#[allow(clippy::too_many_arguments)]
fn execute(ctx: &RunCtx<'_>, dir: &Path, p: &Profile, src: &Source, transport: &str, streams: usize, deadline: Instant, r: &mut RunResult) -> Result<(), String> {
    let (staging, out) = (dir.join("staging"), dir.join("out"));
    for d in [&staging, &out] {
        std::fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
    }
    let names = Names::for_run(std::process::id(), ctx.run_index);
    let topo = Topology::create(names.clone(), &p.netem)?;

    let mut recv = Proc::spawn("engine-bench recv", &topology::in_ns(&names.receiver_ns, &recv_argv(ctx.bench, ctx.caps, transport, &staging, &out)), Some("listening on"))?;
    recv.wait_ready(deadline)?;
    let send = Proc::spawn("engine-bench send", &topology::in_ns(&names.sender_ns, &send_argv(ctx.bench, transport, &src.path, streams)), None)?;
    let sent = send.wait(deadline);
    // Whatever the sender did, the receiver gets the rest of the deadline to finish (or is killed).
    let recvd = recv.wait(deadline);
    let sent = sent?;
    let recvd = recvd?;
    if !sent.status.success() || !recvd.status.success() {
        return Err(format!("engine-bench failed: send {} / recv {}\n--- send stderr:\n{}\n--- recv stderr:\n{}", sent.status, recvd.status, sent.stderr, recvd.stderr));
    }
    for (side, f) in [("send", &sent), ("recv", &recvd)] {
        // TCP and QUIC drop duplicates below the engine; a replay error means one leaked through (§12/§31).
        if f.stderr.to_ascii_lowercase().contains("replay") {
            r.reasons.push(format!("{side} logged a replay error:\n{}", f.stderr));
        }
    }

    r.netem_sender = stats(&names.sender_ns, topology::SENDER_IF, &p.netem)?;
    r.netem_receiver = stats(&names.receiver_ns, topology::RECEIVER_IF, &p.netem)?;
    if transport == "tcp" {
        let c: TcpCounters = topology::parse_snmp_tcp(&topology::run(&topology::snmp_command(&names.sender_ns))?)?;
        r.tcp_out_segs = Some(c.out_segs);
        r.tcp_retrans_segs = Some(c.retrans_segs);
    }
    topo.teardown()?;

    let s: Report = report::parse(sent.stdout.trim())?;
    let rv: Report = report::parse(recvd.stdout.trim())?;
    r.goodput_bytes_per_sec = Some(s.throughput_bytes_per_sec);
    r.receiver_goodput_bytes_per_sec = Some(rv.throughput_bytes_per_sec);
    r.connect_secs = Some(s.timings.connect_secs);
    r.handshake_secs = Some(s.timings.handshake_secs);
    r.app_retransmits = Some(s.retransmits);
    r.reasons.extend(report::check_pair(&s, &rv, &Expect { transport, streams, size: src.size }));

    let saved = rv.saved.first().ok_or("receiver saved nothing")?;
    if !saved.starts_with(&out) {
        r.reasons.push(format!("received file {} escaped the --out dir {}", saved.display(), out.display()));
    }
    let got = hash_file(saved)?;
    r.hash_ok = Some(got == src.hash);
    if got != src.hash {
        r.reasons.push(format!("BLAKE3 mismatch: sent {} received {}", src.hash.to_hex(), got.to_hex()));
    }
    Ok(())
}

fn stats(ns: &str, dev: &str, netem: &str) -> Result<Option<QdiscStats>, String> {
    if netem.trim().is_empty() {
        return Ok(None);
    }
    topology::parse_qdisc_stats(&topology::run(&topology::qdisc_stats_command(ns, dev))?).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse_netem;

    fn result(transport: &str) -> RunResult {
        RunResult::new(&Profile::new("p", "", 1, 1), transport, 1)
    }

    #[test]
    fn generated_source_hash_matches_file() {
        let d = tempfile::tempdir().unwrap();
        let s = generate_source(d.path(), (3 << 20) + 5).unwrap();
        assert_eq!(std::fs::metadata(&s.path).unwrap().len(), s.size);
        assert_eq!(hash_file(&s.path).unwrap(), s.hash);
        // Different sizes produce different content.
        let t = generate_source(d.path(), 1 << 20).unwrap();
        assert_ne!(t.hash, s.hash);
    }

    #[test]
    fn command_lines() {
        let b = Path::new("/bin/engine-bench");
        let caps = Caps { recv_transport_flag: false };
        let rv = recv_argv(b, caps, "tcp", Path::new("/w/s"), Path::new("/w/o")).join(" ");
        assert_eq!(rv, "/bin/engine-bench --json recv --listen 10.231.0.2:47031 --staging /w/s --out /w/o --trust-any");
        let rv = recv_argv(b, Caps { recv_transport_flag: true }, "quic", Path::new("/s"), Path::new("/o")).join(" ");
        assert!(rv.ends_with("--trust-any --transport quic"));
        let sv = send_argv(b, "quic", Path::new("/f.bin"), 4).join(" ");
        assert_eq!(sv, "/bin/engine-bench --json send --target 10.231.0.2:47031 --file /f.bin --streams 4 --transport quic --trust-any");
    }

    #[test]
    fn detects_unsupported_transport() {
        assert!(unsupported_transport("error: the QUIC backend is not available in this build yet").is_some());
        assert!(unsupported_transport("error: unexpected argument '--transport' found\n").is_some());
        assert!(unsupported_transport("error: connection refused").is_none());
    }

    #[test]
    fn loss_profile_needs_drops_and_tcp_retransmits() {
        let spec = parse_netem("loss 2%").unwrap();
        let mut r = result("tcp");
        r.netem_sender = Some(QdiscStats { sent_bytes: 1500, sent_pkts: 1, ..Default::default() });
        r.tcp_retrans_segs = Some(0);
        check_profile(&spec, &mut r);
        assert_eq!(r.reasons.len(), 2, "{:?}", r.reasons);

        let mut r = result("tcp");
        r.netem_sender = Some(QdiscStats { sent_bytes: 15000, sent_pkts: 10, dropped: 1, ..Default::default() });
        r.tcp_retrans_segs = Some(1);
        check_profile(&spec, &mut r);
        assert!(r.reasons.is_empty(), "{:?}", r.reasons);
    }

    #[test]
    fn gso_super_packets_are_flagged() {
        let mut r = result("tcp");
        r.netem_sender = Some(QdiscStats { sent_bytes: 64_000, sent_pkts: 1, ..Default::default() });
        check_profile(&parse_netem("delay 2ms").unwrap(), &mut r);
        assert!(r.reasons[0].contains("GSO"));
    }

    #[test]
    fn rate_cap_band() {
        let spec = parse_netem("rate 200mbit delay 3ms").unwrap();
        for (bytes_per_sec, ok) in [(20e6, true), (10e6, false), (26e6, false), (12.6e6, true)] {
            let mut r = result("tcp");
            r.goodput_bytes_per_sec = Some(bytes_per_sec);
            check_profile(&spec, &mut r);
            assert_eq!(r.reasons.is_empty(), ok, "{bytes_per_sec}: {:?}", r.reasons);
        }
    }

    #[test]
    fn app_resends_fail_only_on_clean_links() {
        let mut r = result("tcp");
        r.app_retransmits = Some(2);
        check_profile(&parse_netem("delay 2ms").unwrap(), &mut r);
        assert_eq!(r.reasons.len(), 1);
        let mut r = result("tcp");
        r.app_retransmits = Some(2);
        r.netem_sender = Some(QdiscStats { dropped: 5, sent_pkts: 1, sent_bytes: 1, ..Default::default() });
        r.tcp_retrans_segs = Some(5);
        check_profile(&parse_netem("loss 5% delay 10ms 5ms").unwrap(), &mut r);
        assert!(r.reasons.is_empty() && r.notes.len() == 1, "{:?} {:?}", r.reasons, r.notes);
    }

    #[test]
    fn missing_duplicate_counters_are_a_note_not_a_pass_or_fail() {
        let mut r = result("tcp");
        r.netem_sender = Some(QdiscStats { sent_pkts: 1, sent_bytes: 1, ..Default::default() });
        r.netem_receiver = r.netem_sender;
        check_profile(&parse_netem("duplicate 0.5%").unwrap(), &mut r);
        assert!(r.reasons.is_empty());
        assert_eq!(r.notes.len(), 1);
    }
}
