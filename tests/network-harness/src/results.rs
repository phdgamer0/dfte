//! Results file (JSON + CSV) and the markdown summary (CI step summary).

use std::fmt::Write;

use crate::runner::{RunResult, Status};

const MIB: f64 = 1024.0 * 1024.0;

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

fn mibs(v: Option<f64>) -> String {
    v.map(|v| format!("{:.1}", v / MIB)).unwrap_or_default()
}

fn ms(v: Option<f64>) -> String {
    v.map(|v| format!("{:.1}", v * 1e3)).unwrap_or_default()
}

fn status(s: Status) -> &'static str {
    match s {
        Status::Pass => "pass",
        Status::Fail => "FAIL",
        Status::Skip => "skip",
    }
}

fn retrans_pct(r: &RunResult) -> String {
    match (r.tcp_retrans_segs, r.tcp_out_segs) {
        (Some(re), Some(out)) if out > 0 => format!("{re} ({:.2}%)", re as f64 * 100.0 / out as f64),
        (Some(re), _) => re.to_string(),
        _ => String::new(),
    }
}

fn drops(r: &RunResult) -> String {
    match (r.netem_sender, r.netem_receiver) {
        (Some(s), Some(v)) => format!("{}/{}", s.dropped, v.dropped),
        _ => String::new(),
    }
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_owned() }
}

pub fn to_csv(rs: &[RunResult]) -> String {
    let mut out = String::from("profile,netem,transport,streams,size_bytes,status,wall_secs,hash_ok,goodput_bytes_per_sec,receiver_goodput_bytes_per_sec,connect_secs,handshake_secs,app_retransmits,tcp_retrans_segs,tcp_out_segs,netem_drops_sender,netem_drops_receiver,reasons,notes\n");
    for r in rs {
        let row = [csv_field(&r.profile), csv_field(&r.netem), r.transport.clone(), r.streams.to_string(), r.size_bytes.to_string(), status(r.status).to_owned(), format!("{:.3}", r.wall_secs), opt(r.hash_ok), opt(r.goodput_bytes_per_sec.map(|v| v.round())), opt(r.receiver_goodput_bytes_per_sec.map(|v| v.round())), opt(r.connect_secs), opt(r.handshake_secs), opt(r.app_retransmits), opt(r.tcp_retrans_segs), opt(r.tcp_out_segs), opt(r.netem_sender.map(|s| s.dropped)), opt(r.netem_receiver.map(|s| s.dropped)), csv_field(&r.reasons.join(" | ")), csv_field(&r.notes.join(" | "))];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

/// Multi-stream gain (manual §11 says it must be measured, not assumed):
/// goodput(max streams) / goodput(1 stream) for each passing profile×transport.
pub fn stream_gains(rs: &[RunResult]) -> Vec<(String, String, usize, f64, f64)> {
    let mut out = Vec::new();
    for one in rs.iter().filter(|r| r.streams == 1 && r.status == Status::Pass) {
        let best = rs.iter().filter(|r| r.profile == one.profile && r.transport == one.transport && r.streams > 1 && r.status == Status::Pass).max_by_key(|r| r.streams);
        if let (Some(m), Some(g1), Some(gm)) = (best, one.goodput_bytes_per_sec, best.and_then(|b| b.goodput_bytes_per_sec)) {
            out.push((one.profile.clone(), one.transport.clone(), m.streams, g1, gm));
        }
    }
    out
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn to_markdown(rs: &[RunResult]) -> Result<String, std::fmt::Error> {
    let mut md = String::new();
    let (pass, fail, skip) = rs.iter().fold((0, 0, 0), |(p, f, s), r| match r.status {
        Status::Pass => (p + 1, f, s),
        Status::Fail => (p, f + 1, s),
        Status::Skip => (p, f, s + 1),
    });
    writeln!(md, "### netem harness (manual §31): {pass} passed, {fail} failed, {skip} skipped\n")?;
    writeln!(md, "| profile | netem (both directions) | transport | streams | status | goodput MiB/s | handshake ms | app resends | TCP retrans segs | netem drops snd/rcv | wall s | notes |")?;
    writeln!(md, "|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---|")?;
    for r in rs {
        let mut notes = r.reasons.clone();
        notes.extend(r.notes.iter().cloned());
        // Long engine stderr belongs in the results file, not the table.
        let notes: Vec<String> = notes.iter().map(|n| n.lines().next().unwrap_or_default().chars().take(160).collect()).collect();
        writeln!(md, "| {} | `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {:.1} | {} |", r.profile, if r.netem.is_empty() { "-" } else { &r.netem }, r.transport, r.streams, status(r.status), mibs(r.goodput_bytes_per_sec), ms(r.handshake_secs), opt(r.app_retransmits), retrans_pct(r), drops(r), r.wall_secs, md_cell(&notes.join("; ")))?;
    }
    let gains = stream_gains(rs);
    if !gains.is_empty() {
        writeln!(md, "\n#### Multi-stream gain (manual §11)\n")?;
        writeln!(md, "| profile | transport | 1 stream MiB/s | N streams MiB/s | N | gain |")?;
        writeln!(md, "|---|---|---:|---:|---:|---:|")?;
        for (p, t, n, g1, gn) in gains {
            writeln!(md, "| {p} | {t} | {:.1} | {:.1} | {n} | {:.2}x |", g1 / MIB, gn / MIB, gn / g1)?;
        }
    }
    Ok(md)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use crate::topology::QdiscStats;

    fn row(profile: &str, streams: usize, status: Status, goodput: f64) -> RunResult {
        let mut r = RunResult::skip(&Profile::new(profile, "loss 2%", 64 << 20, 10), "tcp", streams, String::new());
        r.status = status;
        r.reasons.clear();
        r.goodput_bytes_per_sec = Some(goodput);
        r.tcp_retrans_segs = Some(10);
        r.tcp_out_segs = Some(1000);
        r.netem_sender = Some(QdiscStats { dropped: 7, ..Default::default() });
        r.netem_receiver = Some(QdiscStats { dropped: 3, ..Default::default() });
        r
    }

    #[test]
    fn gains_pair_one_stream_with_most_streams() {
        let rs = vec![row("a", 1, Status::Pass, 10.0), row("a", 4, Status::Pass, 30.0), row("a", 2, Status::Pass, 20.0), row("b", 1, Status::Pass, 5.0), row("b", 4, Status::Fail, 9.0)];
        let g = stream_gains(&rs);
        assert_eq!(g, vec![("a".into(), "tcp".into(), 4, 10.0, 30.0)]);
    }

    #[test]
    fn csv_quotes_and_counts() {
        let mut r = row("a", 1, Status::Fail, 1.0);
        r.reasons = vec!["bad, \"really\"".into()];
        let csv = to_csv(&[r]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].split(',').count(), 19);
        assert!(lines[1].contains("\"bad, \"\"really\"\"\""));
        assert!(lines[1].contains(",7,3,"));
    }

    #[test]
    fn markdown_has_summary_and_rows() {
        let mut f = row("a", 4, Status::Fail, 1.0);
        f.reasons = vec!["line one | pipe\nline two".into()];
        let md = to_markdown(&[row("a", 1, Status::Pass, 2.0 * MIB), f]).unwrap();
        assert!(md.contains("1 passed, 1 failed, 0 skipped"));
        assert!(md.contains("| a | `loss 2%` | tcp | 1 | pass | 2.0 |"));
        assert!(md.contains("10 (1.00%)"));
        assert!(md.contains("line one \\| pipe"));
        assert!(!md.contains("line two"));
    }
}
