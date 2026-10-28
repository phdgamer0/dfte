//! The `engine-bench --json` report (`TransferReport`, crates/core/src/report.rs)
//! as seen from outside, and the sanity checks every run must pass.

use serde::{Deserialize, Serialize};

/// Chunk size fixed by manual §17.
pub const CHUNK: u64 = 4 << 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
pub struct Timings {
    pub hash_secs: f64,
    pub connect_secs: f64,
    pub handshake_secs: f64,
    pub manifest_secs: f64,
    pub transfer_secs: f64,
    pub finalize_secs: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Report {
    pub direction: String,
    pub transfer_id: String,
    pub peer_fingerprint: String,
    pub transport: String,
    pub cipher: String,
    pub streams: usize,
    pub files: usize,
    pub bytes_total: u64,
    pub bytes_transferred: u64,
    pub resumed_bytes: u64,
    pub chunks: u64,
    pub retransmits: u64,
    pub total_secs: f64,
    pub throughput_bytes_per_sec: f64,
    pub end_to_end_bytes_per_sec: f64,
    pub timings: Timings,
    pub saved: Vec<std::path::PathBuf>,
}

pub fn parse(json: &str) -> Result<Report, String> {
    serde_json::from_str(json).map_err(|e| format!("bad engine-bench JSON report ({e}): {json:?}"))
}

/// What one run asked for.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    pub transport: &'a str,
    pub streams: usize,
    pub size: u64,
}

/// Every way the pair of reports disagrees with the request or with itself.
pub fn check_pair(s: &Report, r: &Report, want: &Expect<'_>) -> Vec<String> {
    let mut bad = Vec::new();
    let mut check = |ok: bool, msg: String| {
        if !ok {
            bad.push(msg);
        }
    };
    check(s.direction == "send", format!("sender report direction {:?}", s.direction));
    check(r.direction == "receive", format!("receiver report direction {:?}", r.direction));
    check(!s.transfer_id.is_empty() && s.transfer_id == r.transfer_id, format!("transfer ids differ: {:?} vs {:?}", s.transfer_id, r.transfer_id));
    let chunks = want.size.div_ceil(CHUNK);
    for (side, rep) in [("sender", s), ("receiver", r)] {
        check(rep.transport == want.transport, format!("{side} transport {:?}, wanted {:?}", rep.transport, want.transport));
        check(rep.streams == want.streams, format!("{side} streams {}, wanted {}", rep.streams, want.streams));
        check(rep.cipher != "plaintext" && !rep.cipher.is_empty(), format!("{side} cipher {:?}: the harness must run encrypted", rep.cipher));
        check(!rep.peer_fingerprint.is_empty(), format!("{side} has no peer fingerprint"));
        check(rep.files == 1, format!("{side} files {}, wanted 1", rep.files));
        check(rep.bytes_total == want.size, format!("{side} bytes_total {}, wanted {}", rep.bytes_total, want.size));
        check(rep.bytes_transferred == want.size, format!("{side} bytes_transferred {}, wanted {} (fresh staging, nothing to resume)", rep.bytes_transferred, want.size));
        check(rep.resumed_bytes == 0, format!("{side} resumed {} bytes from a fresh staging dir", rep.resumed_bytes));
        check(rep.chunks == chunks, format!("{side} chunks {}, wanted {chunks}", rep.chunks));
        let t = &rep.timings;
        let all = [rep.total_secs, rep.throughput_bytes_per_sec, rep.end_to_end_bytes_per_sec, t.hash_secs, t.connect_secs, t.handshake_secs, t.manifest_secs, t.transfer_secs, t.finalize_secs];
        check(all.iter().all(|v| v.is_finite() && *v >= 0.0), format!("{side} has a negative or non-finite timing/rate: {rep:?}"));
        check(rep.throughput_bytes_per_sec > 0.0 && t.transfer_secs > 0.0, format!("{side} reports no data-phase time/throughput"));
        let phases = t.connect_secs + t.handshake_secs + t.manifest_secs + t.transfer_secs + t.finalize_secs;
        // Phases are sequential slices of the whole run (+ small slack for rounding).
        check(phases <= rep.total_secs + 0.05, format!("{side} phases sum to {phases:.3}s > total {:.3}s", rep.total_secs));
    }
    check(r.retransmits == 0, format!("receiver reports {} retransmits (only the sender resends)", r.retransmits));
    check(r.saved.len() == 1, format!("receiver saved {} entries, wanted 1", r.saved.len()));
    bad
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample(direction: &str) -> Report {
        Report { direction: direction.into(), transfer_id: "t-1".into(), peer_fingerprint: "abcd-ef01".into(), transport: "tcp".into(), cipher: "AES-256-GCM".into(), streams: 4, files: 1, bytes_total: 10 << 20, bytes_transferred: 10 << 20, resumed_bytes: 0, chunks: 3, retransmits: 0, total_secs: 2.0, throughput_bytes_per_sec: 1e7, end_to_end_bytes_per_sec: 9e6, timings: Timings { hash_secs: 0.1, connect_secs: 0.01, handshake_secs: 0.02, manifest_secs: 0.01, transfer_secs: 1.0, finalize_secs: 0.2 }, saved: if direction == "receive" { vec!["/x/file.bin".into()] } else { vec![] } }
    }

    type Mutate = dyn Fn(&mut Report, &mut Report);

    const WANT: Expect<'static> = Expect { transport: "tcp", streams: 4, size: 10 << 20 };

    #[test]
    fn parses_engine_bench_json() {
        // Shape printed by `engine-bench --json recv` (crates/core/src/report.rs).
        let json = r#"{"direction":"receive","transfer_id":"t","peer_fingerprint":"f","peer_name":"n","transport":"tcp","cipher":"AES-256-GCM","streams":2,"files":1,"bytes_total":5,"bytes_transferred":5,"resumed_bytes":0,"chunks":1,"retransmits":0,"total_secs":0.1,"throughput_bytes_per_sec":50.0,"end_to_end_bytes_per_sec":40.0,"timings":{"hash_secs":0.0,"connect_secs":0.0,"handshake_secs":0.01,"manifest_secs":0.0,"transfer_secs":0.1,"finalize_secs":0.0},"saved":["/tmp/out/a.bin"]}"#;
        let r = parse(json).unwrap();
        assert_eq!((r.direction.as_str(), r.streams, r.saved.len()), ("receive", 2, 1));
        assert!(parse("{\"direction\":1}").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn consistent_pair_passes() {
        assert_eq!(check_pair(&sample("send"), &sample("receive"), &WANT), Vec::<String>::new());
    }

    #[test]
    fn catches_each_inconsistency() {
        let s = sample("send");
        let cases: Vec<(&str, Box<Mutate>)> = vec![("transfer ids", Box::new(|_, r| r.transfer_id = "other".into())), ("transport", Box::new(|s, _| s.transport = "quic".into())), ("streams", Box::new(|_, r| r.streams = 1)), ("plaintext", Box::new(|s, _| s.cipher = "plaintext".into())), ("bytes_total", Box::new(|s, _| s.bytes_total += 1)), ("resumed", Box::new(|_, r| r.resumed_bytes = 4)), ("chunks", Box::new(|s, _| s.chunks = 2)), ("non-finite", Box::new(|s, _| s.throughput_bytes_per_sec = f64::NAN)), ("no data-phase", Box::new(|_, r| r.timings.transfer_secs = 0.0)), ("phases sum", Box::new(|s, _| s.timings.transfer_secs = 5.0)), ("receiver reports", Box::new(|_, r| r.retransmits = 1)), ("saved", Box::new(|_, r| r.saved.clear()))];
        for (needle, mutate) in cases {
            let (mut a, mut b) = (s.clone(), sample("receive"));
            mutate(&mut a, &mut b);
            let bad = check_pair(&a, &b, &WANT);
            assert!(bad.iter().any(|m| m.contains(needle)), "{needle}: {bad:?}");
        }
    }
}
