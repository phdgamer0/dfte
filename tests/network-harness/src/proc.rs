// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Child processes with captured output, a readiness signal and a hard deadline.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct Proc {
    pub label: String,
    child: Child,
    stdout: Option<JoinHandle<std::io::Result<String>>>,
    stderr: Option<JoinHandle<std::io::Result<()>>>,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    ready: Receiver<()>,
    reaped: bool,
}

#[derive(Debug)]
pub struct Finished {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Proc {
    /// Spawns `argv`; `ready_marker` is a stderr line prefix that signals readiness.
    pub fn spawn(label: &str, argv: &[String], ready_marker: Option<&str>) -> Result<Self, String> {
        let (prog, args) = argv.split_first().ok_or("empty command line")?;
        let mut child = Command::new(prog).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{label}: cannot spawn {}: {e}", argv.join(" ")))?;
        let mut out = child.stdout.take().ok_or("stdout not piped")?;
        let err = child.stderr.take().ok_or("stderr not piped")?;
        let stdout = std::thread::spawn(move || {
            let mut s = String::new();
            out.read_to_string(&mut s).map(|_| s)
        });
        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let (tx, ready) = mpsc::channel();
        let lines = Arc::clone(&stderr_lines);
        let marker = ready_marker.map(str::to_owned);
        let stderr = std::thread::spawn(move || {
            for line in BufReader::new(err).lines() {
                let line = line?;
                if marker.as_deref().is_some_and(|m| line.starts_with(m)) {
                    // The receiver of `ready` may have given up already; nothing to report then.
                    let _sent = tx.send(());
                }
                lines.lock().map_err(|_| std::io::Error::other("stderr buffer poisoned"))?.push(line);
            }
            Ok(())
        });
        Ok(Self { label: label.to_owned(), child, stdout: Some(stdout), stderr: Some(stderr), stderr_lines, ready, reaped: false })
    }

    pub fn stderr_snapshot(&self) -> String {
        match self.stderr_lines.lock() {
            Ok(l) => l.join("\n"),
            Err(_) => "<stderr buffer poisoned>".to_owned(),
        }
    }

    /// Waits for the readiness marker; fails if the process exits first or the deadline passes.
    pub fn wait_ready(&mut self, deadline: Instant) -> Result<(), String> {
        loop {
            match self.ready.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => return Ok(()),
                Err(RecvTimeoutError::Disconnected) => return Err(format!("{} exited before becoming ready:\n{}", self.label, self.stderr_snapshot())),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if let Some(st) = self.child.try_wait().map_err(|e| format!("{}: wait failed: {e}", self.label))? {
                self.reaped = true;
                return Err(format!("{} exited ({st}) before becoming ready:\n{}", self.label, self.stderr_snapshot()));
            }
            if Instant::now() >= deadline {
                return Err(format!("{} not ready before the deadline:\n{}", self.label, self.stderr_snapshot()));
            }
        }
    }

    /// Waits for exit; kills the process when `deadline` passes.
    pub fn wait(mut self, deadline: Instant) -> Result<Finished, String> {
        let status = loop {
            if let Some(st) = self.child.try_wait().map_err(|e| format!("{}: wait failed: {e}", self.label))? {
                break st;
            }
            if Instant::now() >= deadline {
                self.kill();
                return Err(format!("{} timed out and was killed; stderr:\n{}", self.label, self.stderr_snapshot()));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        self.reaped = true;
        let stdout = join(self.stdout.take(), &self.label, "stdout")?.unwrap_or_default();
        join(self.stderr.take(), &self.label, "stderr")?;
        Ok(Finished { status, stdout, stderr: self.stderr_snapshot() })
    }

    fn kill(&mut self) {
        if self.reaped {
            return;
        }
        // An already-exited child makes kill fail; the wait below still reaps it.
        if let Err(e) = self.child.kill() {
            eprintln!("netem-harness: kill {} failed: {e}", self.label);
        }
        if let Err(e) = self.child.wait() {
            eprintln!("netem-harness: reaping {} failed: {e}", self.label);
        }
        self.reaped = true;
    }
}

fn join<T>(h: Option<JoinHandle<std::io::Result<T>>>, label: &str, what: &str) -> Result<Option<T>, String> {
    match h {
        None => Ok(None),
        Some(h) => h.join().map_err(|_| format!("{label}: {what} reader panicked"))?.map(Some).map_err(|e| format!("{label}: reading {what} failed: {e}")),
    }
}

impl Drop for Proc {
    /// Never leave an engine-bench running inside a namespace we are deleting.
    fn drop(&mut self) {
        self.kill();
    }
}

// The fixtures shell out to `sh`, which the Windows CI runner does not provide.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    #[test]
    fn captures_output_and_readiness() {
        let mut p = Proc::spawn("t", &sh("echo hello; echo 'listening on x' >&2; sleep 0.2; echo done >&2"), Some("listening on")).unwrap();
        p.wait_ready(Instant::now() + Duration::from_secs(5)).unwrap();
        let f = p.wait(Instant::now() + Duration::from_secs(5)).unwrap();
        assert!(f.status.success());
        assert_eq!(f.stdout, "hello\n");
        assert!(f.stderr.contains("done"));
    }

    #[test]
    fn early_exit_is_not_ready() {
        let mut p = Proc::spawn("t", &sh("echo boom >&2; exit 3"), Some("listening on")).unwrap();
        let e = p.wait_ready(Instant::now() + Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("boom"), "{e}");
    }

    #[test]
    fn deadline_kills() {
        let p = Proc::spawn("t", &sh("sleep 30"), None).unwrap();
        let t = Instant::now();
        let e = p.wait(Instant::now() + Duration::from_millis(200)).unwrap_err();
        assert!(e.contains("timed out"));
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}
