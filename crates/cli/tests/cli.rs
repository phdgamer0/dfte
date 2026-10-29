//! End-to-end tests: the real `dfte` binary, two processes over loopback, each
//! with its own isolated `XDG_DATA_HOME`/`HOME` in a temp dir and stdin piped.
//!
//! Every child is read by background threads (no pipe can fill up and stall
//! it) and waited on with a deadline (a hung child is killed and the test fails).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(180);

struct Device {
    root: tempfile::TempDir,
    name: &'static str,
}

impl Device {
    fn new(name: &'static str) -> Self {
        Self { root: tempfile::tempdir().unwrap(), name }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_dfte"));
        c.env("XDG_DATA_HOME", self.root.path().join("data")).env("HOME", self.root.path()).env("DFTE_DEVICE_NAME", self.name).env_remove("RUST_LOG").env_remove("DFTE_TEST_PROMPT_STDIN").env_remove("DFTE_TEST_CHUNK_DELAY_MS");
        c
    }

    fn data(&self) -> PathBuf {
        self.root.path().join("data").join("dfte")
    }

    fn fingerprint(&self) -> String {
        let out = self.cmd().args(["id", "--json"]).output().unwrap();
        assert!(out.status.success(), "{out:?}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["fingerprint"].as_str().unwrap().to_owned()
    }

    fn run_ok(&self, args: &[&str]) -> String {
        let out = self.cmd().args(args).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }
}

/// A running `dfte` with stderr lines streamed to the test.
struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr_all: Arc<Mutex<String>>,
    stdout: Option<JoinHandle<String>>,
    stderr: Option<JoinHandle<()>>,
}

impl Proc {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let stdout = std::thread::spawn(move || {
            let mut s = String::new();
            out.read_to_string(&mut s).unwrap();
            s
        });
        let (tx, lines) = channel();
        let stderr_all = Arc::new(Mutex::new(String::new()));
        let all = Arc::clone(&stderr_all);
        let stderr = std::thread::spawn(move || {
            for line in BufReader::new(err).lines() {
                let line = line.unwrap();
                all.lock().unwrap().push_str(&line);
                all.lock().unwrap().push('\n');
                // The test may have stopped listening; the text is still in `all`.
                tx.send(line).ok();
            }
        });
        let stdin = child.stdin.take();
        Self { child, stdin, lines, stderr_all, stdout: Some(stdout), stderr: Some(stderr) }
    }

    /// Waits for a stderr line containing `needle`; returns it.
    fn wait_for(&mut self, needle: &str) -> String {
        let end = Instant::now() + DEADLINE;
        loop {
            match self.lines.recv_timeout(end.saturating_duration_since(Instant::now())) {
                Ok(l) if l.contains(needle) => return l,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    self.child.kill().ok();
                    panic!("timed out waiting for {needle:?}; stderr:\n{}", self.stderr_all.lock().unwrap());
                }
                Err(RecvTimeoutError::Disconnected) => panic!("process ended before {needle:?}; stderr:\n{}", self.stderr_all.lock().unwrap()),
            }
        }
    }

    fn answer(&mut self, text: &str) {
        let s = self.stdin.as_mut().unwrap();
        s.write_all(text.as_bytes()).unwrap();
        s.flush().unwrap();
    }

    fn listen_port(&mut self) -> u16 {
        let line = self.wait_for("Listening on ");
        let addr = line.split_whitespace().nth(2).unwrap();
        addr.rsplit(':').next().unwrap().parse().unwrap()
    }

    #[cfg(unix)]
    fn interrupt(&self) {
        let st = Command::new("kill").args(["-INT", &self.child.id().to_string()]).status().unwrap();
        assert!(st.success());
    }

    /// (status, stdout, stderr), killing the child after the deadline.
    fn finish(mut self) -> (ExitStatus, String, String) {
        drop(self.stdin.take());
        let end = Instant::now() + DEADLINE;
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > end {
                self.child.kill().ok();
                panic!("process hung; stderr:\n{}", self.stderr_all.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = self.stdout.take().unwrap().join().unwrap();
        self.stderr.take().unwrap().join().unwrap();
        let err = self.stderr_all.lock().unwrap().clone();
        (status, out, err)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // Only reached with a live child when a test already failed.
        if self.stdout.is_some() {
            self.child.kill().ok();
        }
    }
}

const BEACON: [&str; 3] = ["--no-multicast", "--beacon-bind", "127.0.0.1:0"];

fn receiver(dev: &Device, out: &Path, transport: &str, extra: &[&str]) -> Proc {
    let mut c = dev.cmd();
    c.args(["--json", "receive", "--port", "0", "--bind", "127.0.0.1", "--transport", transport, "--dir"]).arg(out).args(BEACON).args(extra);
    Proc::spawn(c)
}

fn sender(dev: &Device, files: &[&Path], port: u16, transport: &str, extra: &[&str]) -> Proc {
    let mut c = dev.cmd();
    c.args(["--json", "send"]).args(files).args(["--to", &format!("127.0.0.1:{port}"), "--transport", transport]).args(BEACON).args(extra);
    Proc::spawn(c)
}

fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn report(stdout: &str) -> serde_json::Value {
    let line = stdout.lines().rev().find(|l| l.starts_with('{')).unwrap_or_else(|| panic!("no JSON report in {stdout:?}"));
    serde_json::from_str(line).unwrap()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn assert_code(s: ExitStatus, code: i32, err: &str) {
    assert_eq!(s.code(), Some(code), "stderr:\n{err}");
}

/// Pinned on both sides (`--accept-from` / `--expect`): no prompt, files arrive
/// intact, over both transports.
#[test]
fn pinned_send_receive_tcp_and_quic() {
    for transport in ["tcp", "quic"] {
        let (a, b) = (Device::new("alice"), Device::new("bob"));
        let (fa, fb) = (a.fingerprint(), b.fingerprint());
        let src = a.root.path().join("src");
        std::fs::create_dir_all(src.join("folder/sub")).unwrap();
        std::fs::write(src.join("folder/sub/x.bin"), data(5 << 20, 1)).unwrap();
        std::fs::write(src.join("folder/empty.txt"), b"").unwrap();
        std::fs::write(src.join("single.txt"), "héllo").unwrap();
        let out = b.root.path().join("out");

        let mut r = receiver(&b, &out, transport, &["--once", "--accept-from", &fa]);
        let port = r.listen_port();
        let s = sender(&a, &[&src.join("folder"), &src.join("single.txt")], port, transport, &["--expect", &fb]);
        let (ss, sout, serr) = s.finish();
        let (rs, rout, rerr) = r.finish();
        assert_code(ss, 0, &serr);
        assert_code(rs, 0, &rerr);
        assert!(rerr.contains("Incoming from \"alice\""), "{rerr}");
        assert!(rerr.contains("folder/"), "manifest shown before writing: {rerr}");
        let (sr, rr) = (report(&sout), report(&rout));
        assert_eq!(sr["transport"], transport);
        assert_eq!(rr["peer_fingerprint"], fa.as_str());
        assert_eq!(sr["peer_fingerprint"], fb.as_str());
        assert_eq!(std::fs::read(out.join("folder/sub/x.bin")).unwrap(), data(5 << 20, 1));
        assert_eq!(std::fs::read_to_string(out.join("single.txt")).unwrap(), "héllo");
        assert!(out.join("folder/empty.txt").exists());
    }
}

/// The default `--transport auto` receiver takes senders on either backend at
/// one port (each sender's backend follows its own kernel, manual §15).
#[test]
fn auto_receiver_serves_tcp_and_quic_senders() {
    let (a, b) = (Device::new("alice"), Device::new("bob"));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let out = b.root.path().join("out");
    let mut r = receiver(&b, &out, "auto", &["--accept-from", &fa]);
    let port = r.listen_port();
    for (i, transport) in ["tcp", "quic", "auto"].into_iter().enumerate() {
        let src = a.root.path().join(format!("f{i}.bin"));
        std::fs::write(&src, data(1 << 20, i as u64)).unwrap();
        let (ss, sout, serr) = sender(&a, &[&src], port, transport, &["--expect", &fb]).finish();
        assert_code(ss, 0, &serr);
        if transport != "auto" {
            assert_eq!(report(&sout)["transport"], transport);
        }
        assert_eq!(std::fs::read(out.join(format!("f{i}.bin"))).unwrap(), data(1 << 20, i as u64));
    }
    drop(r);
}

/// `trust add` on both sides, then `--to NAME` resolved through the trust store
/// and found by (unicast) LAN discovery: no prompt anywhere.
#[test]
fn trusted_peer_by_name_via_discovery() {
    let (a, b) = (Device::new("alice"), Device::new("bob"));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    a.run_ok(&["trust", "add", &fb, "bobs-box"]);
    b.run_ok(&["trust", "add", &fa, "alice"]);
    assert!(a.run_ok(&["trust", "list"]).contains(&fb));
    let f = a.root.path().join("f.bin");
    std::fs::write(&f, data(300_000, 2)).unwrap();
    let out = b.root.path().join("out");

    let q = free_udp_port();
    let mut rc = b.cmd();
    rc.args(["--json", "receive", "--once", "--port", "0", "--bind", "127.0.0.1", "--transport", "tcp", "--no-multicast", "--beacon-bind", "127.0.0.1:0", "--beacon-to", &format!("127.0.0.1:{q}"), "--dir"]).arg(&out);
    let mut r = Proc::spawn(rc);
    r.listen_port();
    let mut sc = a.cmd();
    sc.args(["--json", "send"]).arg(&f).args(["--to", "bobs-box", "--transport", "tcp", "--no-multicast", "--beacon-bind", &format!("127.0.0.1:{q}"), "--scan-timeout", "20"]);
    let (ss, _, serr) = Proc::spawn(sc).finish();
    let (rs, _, rerr) = r.finish();
    assert_code(ss, 0, &serr);
    assert_code(rs, 0, &rerr);
    assert!(rerr.contains("trusted device"), "{rerr}");
    assert_eq!(std::fs::read(out.join("f.bin")).unwrap(), data(300_000, 2));
}

/// Both users compare the code; it is the same on both screens; both say yes.
#[test]
fn sas_prompt_codes_match_and_yes_proceeds() {
    let (a, b) = (Device::new("alice"), Device::new("bob"));
    let f = a.root.path().join("f.txt");
    std::fs::write(&f, b"hi").unwrap();
    let out = b.root.path().join("out");
    let mut rc = b.cmd();
    rc.env("DFTE_TEST_PROMPT_STDIN", "1").args(["--json", "receive", "--once", "--port", "0", "--bind", "127.0.0.1", "--transport", "tcp", "--dir"]).arg(&out).args(BEACON);
    let mut r = Proc::spawn(rc);
    let port = r.listen_port();
    let mut sc = a.cmd();
    sc.env("DFTE_TEST_PROMPT_STDIN", "1").args(["--json", "send"]).arg(&f).args(["--to", &format!("127.0.0.1:{port}"), "--transport", "tcp"]).args(BEACON);
    let mut s = Proc::spawn(sc);
    let code_r = r.wait_for("security code").split_whitespace().last().unwrap().to_owned();
    let code_s = s.wait_for("security code").split_whitespace().last().unwrap().to_owned();
    assert_eq!(code_r.len(), 6);
    assert_eq!(code_r, code_s, "both screens show the same code");
    r.answer("y\n");
    s.answer("a\n"); // yes, and trust bob from now on
    let (ss, _, serr) = s.finish();
    let (rs, _, rerr) = r.finish();
    assert_code(ss, 0, &serr);
    assert_code(rs, 0, &rerr);
    assert_eq!(std::fs::read(out.join("f.txt")).unwrap(), b"hi");
    assert!(a.run_ok(&["trust", "list"]).contains(&b.fingerprint()), "\"always\" pinned the receiver");
}

/// The receiving user says the codes don't match: AuthenticationFailed, the
/// sender is told it was declined, and nothing is written anywhere.
#[test]
fn sas_rejection_blocks_and_writes_nothing() {
    let (a, b) = (Device::new("alice"), Device::new("bob"));
    let fb = b.fingerprint();
    let f = a.root.path().join("secret.txt");
    std::fs::write(&f, b"secret").unwrap();
    let out = b.root.path().join("out");
    let mut rc = b.cmd();
    rc.env("DFTE_TEST_PROMPT_STDIN", "1").args(["receive", "--once", "--port", "0", "--bind", "127.0.0.1", "--transport", "tcp", "--dir"]).arg(&out).args(BEACON);
    let mut r = Proc::spawn(rc);
    let port = r.listen_port();
    let s = sender(&a, &[&f], port, "tcp", &["--expect", &fb]);
    r.wait_for("security code");
    r.answer("n\n");
    let (rs, _, rerr) = r.finish();
    let (ss, _, serr) = s.finish();
    assert_code(rs, 4, &rerr);
    assert!(rerr.contains("Security check failed — this may not be the device you expect. Connection blocked."), "{rerr}");
    assert_code(ss, 5, &serr);
    assert!(serr.contains("declined the connection"), "{serr}");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0, "nothing in the destination");
    assert_eq!(std::fs::read_dir(b.data().join("staging")).unwrap().count(), 0, "nothing staged");
}

/// Without a terminal and without a pin there is nobody to ask: rejected.
#[test]
fn non_interactive_without_pin_rejects() {
    let (a, b) = (Device::new("alice"), Device::new("bob"));
    let fb = b.fingerprint();
    let f = a.root.path().join("f.txt");
    std::fs::write(&f, b"x").unwrap();
    let out = b.root.path().join("out");
    let mut r = receiver(&b, &out, "tcp", &["--once"]);
    let port = r.listen_port();
    let (ss, _, serr) = sender(&a, &[&f], port, "tcp", &["--expect", &fb]).finish();
    let (rs, rout, rerr) = r.finish();
    assert_code(rs, 4, &rerr);
    assert!(rerr.contains("not a terminal"), "{rerr}");
    assert_eq!(report(&rout)["exit_code"], 4);
    assert_code(ss, 5, &serr);
    assert!(!out.join("f.txt").exists());
}

/// Ctrl-C mid-transfer keeps the resume state and exits 130; running the same
/// command again resumes (resumed bytes > 0) and completes.
#[cfg(unix)]
#[test]
fn sigint_then_rerun_resumes() {
    let (a, b) = (Device::new("alice"), Device::new("bob"));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let f = a.root.path().join("big.bin");
    let len = 128 << 20;
    std::fs::write(&f, data(len, 3)).unwrap();
    let out = b.root.path().join("out");
    // One receiver serves both attempts (it keeps listening after a cancel).
    let mut r = receiver(&b, &out, "tcp", &["--accept-from", &fa]);
    let port = r.listen_port();
    // One stream and a small window so the first attempt is still running when interrupted.
    let args = ["--expect", fb.as_str(), "--streams", "1"];

    // Slow the first attempt down (debug-build hook, 50 ms per 4 MiB chunk, so at
    // least 1.6 s for 128 MiB). Otherwise a fast CI runner finishes the transfer
    // before the SIGINT lands and the sender exits 0 (seen on ubuntu-latest).
    let mut c = a.cmd();
    c.env("DFTE_TEST_CHUNK_DELAY_MS", "50").args(["--json", "send"]).arg(&f).args(["--to", &format!("127.0.0.1:{port}"), "--transport", "tcp"]).args(BEACON).args(args);
    let mut s = Proc::spawn(c);
    // Interrupt only once the receiver has confirmed a chunk: its first progress
    // line is printed on the first one. The sender's own first line can come
    // before any chunk lands, and then there is nothing to resume (seen on macOS).
    r.wait_for("Receiving ");
    s.interrupt();
    let (ss, _, serr) = s.finish();
    assert_code(ss, 130, &serr);
    assert!(serr.contains("Transfer interrupted; run the same command again to resume"), "{serr}");
    r.wait_for("Waiting for the next transfer");
    let resumable = b.run_ok(&["resumable", "--json"]);
    let list: serde_json::Value = serde_json::from_str(&resumable).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1, "{resumable}");

    let (ss, sout, serr) = sender(&a, &[&f], port, "tcp", &args).finish();
    assert_code(ss, 0, &serr);
    let rep = report(&sout);
    assert!(rep["resumed_bytes"].as_u64().unwrap() > 0, "{rep}");
    r.wait_for("Waiting for the next transfer");
    r.interrupt();
    let (rs, _, rerr) = r.finish();
    assert_code(rs, 130, &rerr);
    assert!(rerr.contains("Stopped."), "{rerr}");
    assert!(std::fs::read(out.join("big.bin")).unwrap() == data(len, 3));
    assert_eq!(b.run_ok(&["resumable", "--json"]).trim(), "[]");
}

#[cfg(unix)]
#[test]
fn identity_files_are_private_and_loose_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let a = Device::new("alice");
    let fp = a.fingerprint();
    assert_eq!(a.fingerprint(), fp, "stable across runs");
    let key = a.data().join("identity.key");
    assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(a.data()).unwrap().permissions().mode() & 0o777, 0o700);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = a.cmd().arg("id").output().unwrap();
    assert_eq!(out.status.code(), Some(11));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("chmod 600"), "{err}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&fp));
}

#[test]
fn qr_prints_parseable_payload() {
    let a = Device::new("alice");
    let fp = a.fingerprint();
    let out = a.run_ok(&["qr", "--ssid", "dfte-TEST", "--psk", "correct horse battery", "--port", "5000"]);
    let text = out.lines().find(|l| l.starts_with("dfte1:")).unwrap();
    let p = discovery::qr::QrPayload::parse(text).unwrap();
    assert_eq!(p.ssid, "dfte-TEST");
    assert_eq!(p.port, 5000);
    assert!(p.matches_fingerprint(&fp));
}
