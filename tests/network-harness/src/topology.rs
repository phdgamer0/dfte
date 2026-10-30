// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Two network namespaces joined by a veth pair, with netem on both ends
//! (manual §31). Building the command lines is pure (unit-tested); running them
//! needs CAP_NET_ADMIN + CAP_SYS_ADMIN.

use std::process::Command;

use serde::Serialize;

pub const SENDER_IF: &str = "veth-snd";
pub const RECEIVER_IF: &str = "veth-rcv";
/// Private /30: exactly the two endpoints.
pub const SENDER_ADDR: &str = "10.231.0.1";
pub const RECEIVER_ADDR: &str = "10.231.0.2";
pub const PREFIX_LEN: u8 = 30;
/// netem's default queue (1000 packets) overflows at multi-Gbit/s veth rates
/// once a delay is added, which would add tail drops the profile didn't ask for.
pub const NETEM_LIMIT: u32 = 20_000;
/// Namespace-name prefix; the stale-namespace sweep only touches these.
pub const NS_PREFIX: &str = "dfte-nh-";

/// Runs `argv` and returns stdout; any spawn failure or non-zero exit is an
/// error carrying the command line and its stderr.
pub fn run(argv: &[String]) -> Result<String, String> {
    let (prog, args) = argv.split_first().ok_or("empty command line")?;
    let out = Command::new(prog).args(args).output().map_err(|e| format!("cannot run {}: {e}", argv.join(" ")))?;
    if !out.status.success() {
        return Err(format!("`{}` failed ({}): {}", argv.join(" "), out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("`{}` printed non-UTF-8: {e}", argv.join(" ")))
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

/// `ip netns exec NS <cmd...>`.
pub fn in_ns(ns: &str, cmd: &[String]) -> Vec<String> {
    let mut v = argv(&["ip", "netns", "exec", ns]);
    v.extend_from_slice(cmd);
    v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Names {
    pub sender_ns: String,
    pub receiver_ns: String,
}

impl Names {
    pub fn for_run(pid: u32, run: usize) -> Self {
        Self { sender_ns: format!("{NS_PREFIX}{pid}-{run}-s"), receiver_ns: format!("{NS_PREFIX}{pid}-{run}-r") }
    }
}

/// Commands that build the topology, in order.
pub fn setup_commands(n: &Names, netem: &str) -> Vec<Vec<String>> {
    let (s, r) = (n.sender_ns.as_str(), n.receiver_ns.as_str());
    let s_cidr = format!("{SENDER_ADDR}/{PREFIX_LEN}");
    let r_cidr = format!("{RECEIVER_ADDR}/{PREFIX_LEN}");
    let mut cmds = vec![
        argv(&["ip", "netns", "add", s]),
        argv(&["ip", "netns", "add", r]),
        // Created directly inside the namespaces: nothing ever lands in the host netns.
        argv(&["ip", "link", "add", SENDER_IF, "netns", s, "type", "veth", "peer", "name", RECEIVER_IF, "netns", r]),
    ];
    for (ns, dev, cidr) in [(s, SENDER_IF, &s_cidr), (r, RECEIVER_IF, &r_cidr)] {
        cmds.push(argv(&["ip", "-n", ns, "link", "set", "lo", "up"]));
        // One MSS per skb, so netem drops/duplicates/reorders individual
        // packets as a radio would, not 64 KiB GSO super-packets.
        cmds.push(argv(&["ip", "-n", ns, "link", "set", dev, "gso_max_segs", "1"]));
        cmds.push(argv(&["ip", "-n", ns, "addr", "add", cidr, "dev", dev]));
        cmds.push(argv(&["ip", "-n", ns, "link", "set", dev, "up"]));
    }
    if !netem.trim().is_empty() {
        for (ns, dev) in [(s, SENDER_IF), (r, RECEIVER_IF)] {
            cmds.push(in_ns(ns, &netem_command(dev, netem)));
        }
    }
    cmds
}

pub fn netem_command(dev: &str, netem: &str) -> Vec<String> {
    let mut v = argv(&["tc", "qdisc", "add", "dev", dev, "root", "netem", "limit"]);
    v.push(NETEM_LIMIT.to_string());
    v.extend(netem.split_whitespace().map(str::to_owned));
    v
}

pub fn teardown_commands(n: &Names) -> Vec<Vec<String>> {
    // Deleting a namespace destroys its veth end, the peer end and the qdiscs.
    vec![argv(&["ip", "netns", "del", &n.sender_ns]), argv(&["ip", "netns", "del", &n.receiver_ns])]
}

/// A live topology; torn down on drop (the harness's `trap EXIT`), including
/// on early return and panic. Use [`Topology::teardown`] on the normal path to
/// see errors.
pub struct Topology {
    pub names: Names,
    live: bool,
}

impl Topology {
    pub fn create(names: Names, netem: &str) -> Result<Self, String> {
        // Constructed before the first command so a half-built topology is torn down too.
        let topo = Self { names, live: true };
        for cmd in setup_commands(&topo.names, netem) {
            run(&cmd)?;
        }
        Ok(topo)
    }

    pub fn teardown(mut self) -> Result<(), String> {
        self.live = false;
        teardown(&self.names)
    }
}

fn teardown(n: &Names) -> Result<(), String> {
    let mut errs = Vec::new();
    for cmd in teardown_commands(n) {
        if let Err(e) = run(&cmd) {
            errs.push(e);
        }
    }
    if errs.is_empty() { Ok(()) } else { Err(errs.join("; ")) }
}

impl Drop for Topology {
    fn drop(&mut self) {
        if self.live {
            // Drop cannot return the error; report it instead of losing it.
            if let Err(e) = teardown(&self.names) {
                eprintln!("netem-harness: teardown of {:?} failed: {e}", self.names);
            }
        }
    }
}

/// Deletes namespaces left behind by a harness process that no longer exists
/// (e.g. killed by SIGKILL, where no destructor runs).
pub fn sweep_stale(list_output: &str, is_alive: impl Fn(u32) -> bool) -> Vec<String> {
    list_output.lines().filter_map(|l| l.split_whitespace().next()).filter(|name| name.strip_prefix(NS_PREFIX).and_then(|rest| rest.split('-').next()).and_then(|pid| pid.parse::<u32>().ok()).is_some_and(|pid| !is_alive(pid))).map(str::to_owned).collect()
}

/// Per-qdisc counters from `tc -s qdisc show`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct QdiscStats {
    pub sent_bytes: u64,
    pub sent_pkts: u64,
    pub dropped: u64,
    /// Only printed by newer iproute2 (extended netem stats); `None` otherwise.
    pub duplicated: Option<u64>,
    pub reordered: Option<u64>,
}

pub fn parse_qdisc_stats(text: &str) -> Result<QdiscStats, String> {
    let toks: Vec<&str> = text.split(|c: char| c.is_whitespace() || c == '(' || c == ',' || c == ')').filter(|t| !t.is_empty()).collect();
    let after = |key: &str| -> Option<u64> { toks.windows(2).find(|w| w[0] == key).and_then(|w| w[1].parse().ok()) };
    let sent_at = toks.iter().position(|t| *t == "Sent").ok_or_else(|| format!("no `Sent` line in tc output: {text:?}"))?;
    let num = |i: usize| -> Result<u64, String> { toks.get(i).and_then(|t| t.parse().ok()).ok_or_else(|| format!("unexpected tc stats layout: {text:?}")) };
    Ok(QdiscStats { sent_bytes: num(sent_at + 1)?, sent_pkts: num(sent_at + 3)?, dropped: after("dropped").ok_or_else(|| format!("no drop counter in tc output: {text:?}"))?, duplicated: after("duplicated"), reordered: after("reordered") })
}

pub fn qdisc_stats_command(ns: &str, dev: &str) -> Vec<String> {
    in_ns(ns, &argv(&["tc", "-s", "qdisc", "show", "dev", dev]))
}

/// Kernel TCP counters of one namespace (`/proc/net/snmp` is per-netns).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TcpCounters {
    pub out_segs: u64,
    pub retrans_segs: u64,
}

pub fn snmp_command(ns: &str) -> Vec<String> {
    in_ns(ns, &argv(&["cat", "/proc/net/snmp"]))
}

pub fn parse_snmp_tcp(text: &str) -> Result<TcpCounters, String> {
    let mut rows = text.lines().filter(|l| l.starts_with("Tcp:"));
    let (head, vals) = rows.next().zip(rows.next()).ok_or("no Tcp: rows in /proc/net/snmp")?;
    let pairs: Vec<(&str, &str)> = head.split_whitespace().zip(vals.split_whitespace()).collect();
    let get = |k: &str| -> Result<u64, String> { pairs.iter().find(|(h, _)| *h == k).and_then(|(_, v)| v.parse().ok()).ok_or_else(|| format!("no Tcp {k} in /proc/net/snmp")) };
    Ok(TcpCounters { out_segs: get("OutSegs")?, retrans_segs: get("RetransSegs")? })
}

/// Effective UID from `/proc/self/status` (no libc / unsafe needed).
pub fn effective_uid() -> Result<u32, String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
    let line = status.lines().find(|l| l.starts_with("Uid:")).ok_or("no Uid: line in /proc/self/status")?;
    line.split_whitespace().nth(2).and_then(|v| v.parse().ok()).ok_or_else(|| format!("bad Uid line {line:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(cmds: &[Vec<String>]) -> Vec<String> {
        cmds.iter().map(|c| c.join(" ")).collect()
    }

    #[test]
    fn setup_builds_veth_pair_and_symmetric_netem() {
        let n = Names::for_run(42, 3);
        assert_eq!(n.sender_ns, "dfte-nh-42-3-s");
        let cmds = joined(&setup_commands(&n, "delay 2ms loss 0.5%"));
        assert_eq!(cmds[0], "ip netns add dfte-nh-42-3-s");
        assert_eq!(cmds[2], "ip link add veth-snd netns dfte-nh-42-3-s type veth peer name veth-rcv netns dfte-nh-42-3-r");
        assert!(cmds.contains(&"ip -n dfte-nh-42-3-r addr add 10.231.0.2/30 dev veth-rcv".to_owned()));
        assert!(cmds.contains(&"ip -n dfte-nh-42-3-s link set veth-snd gso_max_segs 1".to_owned()));
        let netem: Vec<&String> = cmds.iter().filter(|c| c.contains("netem")).collect();
        assert_eq!(netem.len(), 2, "one qdisc per direction");
        assert_eq!(netem[0], "ip netns exec dfte-nh-42-3-s tc qdisc add dev veth-snd root netem limit 20000 delay 2ms loss 0.5%");
        assert!(netem[1].contains("dev veth-rcv"));
    }

    #[test]
    fn clean_profile_adds_no_qdisc() {
        let cmds = joined(&setup_commands(&Names::for_run(1, 0), "  "));
        assert!(cmds.iter().all(|c| !c.contains("tc ")));
    }

    #[test]
    fn teardown_deletes_both_namespaces() {
        let cmds = joined(&teardown_commands(&Names::for_run(7, 1)));
        assert_eq!(cmds, vec!["ip netns del dfte-nh-7-1-s", "ip netns del dfte-nh-7-1-r"]);
    }

    #[test]
    fn sweep_only_removes_dead_harness_namespaces() {
        let list = "dfte-nh-100-0-s (id: 0)\ndfte-nh-100-0-r\ndfte-nh-200-4-s\nunrelated\ndfte-nh-x-1-s\n";
        let stale = sweep_stale(list, |pid| pid == 200);
        assert_eq!(stale, vec!["dfte-nh-100-0-s", "dfte-nh-100-0-r"]);
    }

    #[test]
    fn parses_tc_stats_old_and_new_layouts() {
        let new = "qdisc netem 8001: root refcnt 13 limit 1000 delay 2ms loss 1% seed 1252763556669021342\n Sent 512 bytes 6 pkt (dropped 3, overlimits 0 requeues 0) \n backlog 0b 0p requeues 0\n  delayed 6 dropped 0 corrupted 0 duplicated 2 reordered 1 ecn_marked 0\n";
        let s = parse_qdisc_stats(new).unwrap();
        assert_eq!(s, QdiscStats { sent_bytes: 512, sent_pkts: 6, dropped: 3, duplicated: Some(2), reordered: Some(1) });
        let old = "qdisc netem 8001: root refcnt 2 limit 1000 delay 2ms\n Sent 1000 bytes 10 pkt (dropped 0, overlimits 0 requeues 0)\n backlog 0b 0p requeues 0\n";
        let s = parse_qdisc_stats(old).unwrap();
        assert_eq!((s.sent_pkts, s.dropped, s.duplicated), (10, 0, None));
        assert!(parse_qdisc_stats("qdisc noqueue 0: root").is_err());
    }

    #[test]
    fn parses_snmp() {
        let text = "Ip: Forwarding DefaultTTL\nIp: 1 64\nTcp: RtoAlgorithm RtoMin OutSegs RetransSegs InErrs\nTcp: 1 200 5000 37 0\nUdp: InDatagrams\nUdp: 0\n";
        assert_eq!(parse_snmp_tcp(text).unwrap(), TcpCounters { out_segs: 5000, retrans_segs: 37 });
        assert!(parse_snmp_tcp("Ip: a\nIp: 1\n").is_err());
    }
}
