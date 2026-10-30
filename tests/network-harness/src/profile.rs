// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! netem profiles (manual §31) and the parts of a netem spec the checks need.

use serde::Serialize;

const MIB: u64 = 1 << 20;

/// One link-impairment profile, applied symmetrically: the same netem qdisc sits
/// on the egress of both veth ends, so data and acks see the same impairment
/// (a lossy radio link loses frames in both directions).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Profile {
    pub name: String,
    /// Arguments after `tc qdisc add dev X root netem` (empty = no qdisc).
    pub netem: String,
    /// Bytes to transfer in one run.
    pub size: u64,
    /// Hard wall-clock limit for one run, seconds.
    pub timeout_secs: u64,
}

/// What a netem argument string asks for; drives the per-profile assertions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct NetemSpec {
    pub delay_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub duplicate_pct: f64,
    pub reorder_pct: f64,
    /// Bandwidth cap, bits per second.
    pub rate_bps: Option<f64>,
}

impl Profile {
    pub fn new(name: &str, netem: &str, size: u64, timeout_secs: u64) -> Self {
        Self { name: name.to_owned(), netem: netem.to_owned(), size, timeout_secs }
    }

    pub fn spec(&self) -> Result<NetemSpec, String> {
        parse_netem(&self.netem)
    }
}

/// The default §31 matrix. Sizes keep every run several 4 MiB chunks long while
/// fitting a CI job; the harsh profile is smaller because TCP over 5% loss at a
/// ~20 ms RTT is bounded to a few hundred KiB/s per flow (Mathis et al.).
pub fn default_profiles() -> Vec<Profile> {
    vec![Profile::new("clean", "", 128 * MIB, 120), Profile::new("delay-2ms", "delay 2ms", 128 * MIB, 180), Profile::new("delay-2ms-loss-0.5", "delay 2ms loss 0.5%", 64 * MIB, 240), Profile::new("loss-2", "loss 2%", 64 * MIB, 240), Profile::new("reorder-1-delay-2ms", "delay 2ms reorder 1%", 64 * MIB, 240), Profile::new("duplicate-0.5", "duplicate 0.5%", 64 * MIB, 180), Profile::new("rate-200mbit-delay-3ms", "rate 200mbit delay 3ms", 128 * MIB, 180), Profile::new("harsh-loss-5-delay-10ms-jitter-5ms", "loss 5% delay 10ms 5ms", 16 * MIB, 360)]
}

/// Parses the netem options this harness uses. Unknown keywords are rejected so
/// a typo cannot silently turn a lossy profile into a clean one.
pub fn parse_netem(s: &str) -> Result<NetemSpec, String> {
    let toks: Vec<&str> = s.split_whitespace().collect();
    let mut spec = NetemSpec::default();
    let mut i = 0;
    while i < toks.len() {
        let kw = toks[i];
        let arg = toks.get(i + 1).copied().ok_or_else(|| format!("netem {kw:?} needs a value"))?;
        i += 2;
        match kw {
            "delay" => {
                spec.delay_ms = parse_time_ms(arg)?;
                // Optional jitter (and correlation) follow as bare values.
                if let Some(j) = toks.get(i).and_then(|t| parse_time_ms(t).ok()) {
                    spec.jitter_ms = j;
                    i += 1;
                    if toks.get(i).is_some_and(|t| t.ends_with('%')) {
                        i += 1;
                    }
                }
            }
            "loss" => spec.loss_pct = parse_pct(arg)?,
            "duplicate" => spec.duplicate_pct = parse_pct(arg)?,
            "reorder" => spec.reorder_pct = parse_pct(arg)?,
            "rate" => spec.rate_bps = Some(parse_rate_bps(arg)?),
            "limit" => {
                arg.parse::<u64>().map_err(|e| format!("bad netem limit {arg:?}: {e}"))?;
            }
            _ => return Err(format!("unsupported netem keyword {kw:?} in {s:?}")),
        }
    }
    if spec.reorder_pct > 0.0 && spec.delay_ms <= 0.0 {
        return Err(format!("netem reorder needs a delay (got {s:?})"));
    }
    Ok(spec)
}

fn parse_pct(s: &str) -> Result<f64, String> {
    let n = s.strip_suffix('%').ok_or_else(|| format!("expected a percentage, got {s:?}"))?;
    let v: f64 = n.parse().map_err(|e| format!("bad percentage {s:?}: {e}"))?;
    if (0.0..=100.0).contains(&v) { Ok(v) } else { Err(format!("percentage out of range: {s:?}")) }
}

fn split_unit(s: &str) -> (&str, &str) {
    let at = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    s.split_at(at)
}

fn parse_time_ms(s: &str) -> Result<f64, String> {
    let (num, unit) = split_unit(s);
    let v: f64 = num.parse().map_err(|e| format!("bad time {s:?}: {e}"))?;
    let mult = match unit {
        "us" | "usec" => 1e-3,
        "ms" | "msec" => 1.0,
        "s" | "sec" => 1e3,
        _ => return Err(format!("bad time unit in {s:?}")),
    };
    Ok(v * mult)
}

/// tc rate units: `bit`/`kbit`/`mbit`/`gbit` are bits per second, while
/// `bps`/`kbps`/`mbps`/`gbps` are *bytes* per second (tc(8)).
pub fn parse_rate_bps(s: &str) -> Result<f64, String> {
    let (num, unit) = split_unit(s);
    let v: f64 = num.parse().map_err(|e| format!("bad rate {s:?}: {e}"))?;
    let mult = match unit.to_ascii_lowercase().as_str() {
        "bit" => 1.0,
        "kbit" => 1e3,
        "mbit" => 1e6,
        "gbit" => 1e9,
        "bps" => 8.0,
        "kbps" => 8e3,
        "mbps" => 8e6,
        "gbps" => 8e9,
        _ => return Err(format!("bad rate unit in {s:?}")),
    };
    Ok(v * mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profiles_parse_and_cover_section_31() {
        let ps = default_profiles();
        for p in &ps {
            p.spec().unwrap_or_else(|e| panic!("{}: {e}", p.name));
            assert!(p.size >= 4 * MIB, "{} must span several chunks", p.name);
        }
        let specs: Vec<NetemSpec> = ps.iter().map(|p| p.spec().unwrap()).collect();
        assert!(specs.iter().any(|s| s.loss_pct > 0.0));
        assert!(specs.iter().any(|s| s.reorder_pct > 0.0));
        assert!(specs.iter().any(|s| s.duplicate_pct > 0.0));
        assert!(specs.iter().any(|s| s.rate_bps.is_some()));
        let mut names: Vec<&str> = ps.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ps.len(), "profile names must be unique");
    }

    #[test]
    fn parses_each_keyword() {
        assert_eq!(parse_netem("").unwrap(), NetemSpec::default());
        let s = parse_netem("loss 5% delay 10ms 5ms").unwrap();
        assert_eq!((s.loss_pct, s.delay_ms, s.jitter_ms), (5.0, 10.0, 5.0));
        let s = parse_netem("delay 2ms 1ms 25% reorder 1%").unwrap();
        assert_eq!((s.delay_ms, s.jitter_ms, s.reorder_pct), (2.0, 1.0, 1.0));
        let s = parse_netem("rate 200mbit delay 3ms").unwrap();
        assert_eq!(s.rate_bps, Some(200e6));
        assert_eq!(s.delay_ms, 3.0);
        assert_eq!(parse_netem("duplicate 0.5%").unwrap().duplicate_pct, 0.5);
        assert_eq!(parse_netem("delay 500us").unwrap().delay_ms, 0.5);
    }

    #[test]
    fn rate_units_follow_tc() {
        assert_eq!(parse_rate_bps("1gbit").unwrap(), 1e9);
        assert_eq!(parse_rate_bps("10mbps").unwrap(), 80e6);
        assert!(parse_rate_bps("10furlongs").is_err());
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(parse_netem("reorder 1%").is_err(), "reorder without delay");
        assert!(parse_netem("loss").is_err());
        assert!(parse_netem("loss 5").is_err(), "percent sign required");
        assert!(parse_netem("loss 150%").is_err());
        assert!(parse_netem("corrupt 1%").is_err(), "unsupported keyword");
        assert!(parse_netem("delay 2parsecs").is_err());
    }
}
