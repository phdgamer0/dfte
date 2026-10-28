//! Progress display and size formatting.
//!
//! The engine calls the progress callback once per confirmed chunk from its
//! event loop, so the callback only updates counters and draws when the
//! [`Throttle`] allows: at most 10 times a second on a terminal (one
//! carriage-return line), every few seconds as plain lines otherwise.

use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dfte_core::Progress;

const KIB: f64 = 1024.0;

pub fn human_bytes(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= KIB && u + 1 < units.len() {
        v /= KIB;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", units[u]) }
}

pub fn human_rate(bytes_per_sec: f64) -> String {
    format!("{:.1} MiB/s", bytes_per_sec / (KIB * KIB))
}

pub fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// Rate limiter for redraws. The final update (done == total) always passes,
/// exactly once.
#[derive(Debug)]
pub struct Throttle {
    min_interval: Duration,
    last: Option<Instant>,
    finished: bool,
}

impl Throttle {
    pub fn new(min_interval: Duration) -> Self {
        Self { min_interval, last: None, finished: false }
    }

    pub fn should_draw(&mut self, now: Instant, done: bool) -> bool {
        if self.finished {
            return false;
        }
        let due = done || self.last.is_none_or(|l| now.duration_since(l) >= self.min_interval);
        if due {
            self.last = Some(now);
            self.finished = done;
        }
        due
    }
}

/// Terminal: ≤ 10 Hz. Pipes/logs: a line every 5 s.
pub const TTY_INTERVAL: Duration = Duration::from_millis(100);
pub const PLAIN_INTERVAL: Duration = Duration::from_secs(5);

/// One rendered status line.
pub fn render(verb: &str, done: u64, total: u64, rate: f64, eta: Option<Duration>) -> String {
    let pct = if total == 0 { 100.0 } else { done as f64 * 100.0 / total as f64 };
    let eta = eta.map_or_else(|| "--".to_owned(), human_duration);
    format!("{verb} {} / {} ({pct:.0}%)  {}  ETA {eta}", human_bytes(done), human_bytes(total), human_rate(rate))
}

/// Simple text bar for terminals.
pub fn bar(done: u64, total: u64, width: usize) -> String {
    let filled = if total == 0 { width } else { ((done as f64 / total as f64) * width as f64).round() as usize }.min(width);
    format!("[{}{}]", "#".repeat(filled), "-".repeat(width - filled))
}

struct State {
    throttle: Throttle,
    /// (time, bytes) at the first callback: the rate excludes resumed bytes.
    start: Option<(Instant, u64)>,
    drew_tty_line: bool,
}

/// Progress sink handed to the engine.
pub struct Reporter {
    verb: &'static str,
    tty: bool,
    state: Mutex<State>,
}

impl Reporter {
    pub fn new(verb: &'static str, tty: bool) -> Self {
        Self { verb, tty, state: Mutex::new(State { throttle: Throttle::new(if tty { TTY_INTERVAL } else { PLAIN_INTERVAL }), start: None, drew_tty_line: false }) }
    }

    pub fn update(&self, p: &Progress) {
        let now = Instant::now();
        let mut s = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (t0, b0) = *s.start.get_or_insert((now, p.bytes_done));
        let done = p.bytes_done >= p.bytes_total;
        if !s.throttle.should_draw(now, done) {
            return;
        }
        let secs = now.duration_since(t0).as_secs_f64();
        let moved = p.bytes_done.saturating_sub(b0);
        let rate = if secs > 0.05 { moved as f64 / secs } else { 0.0 };
        let eta = (rate > 0.0).then(|| Duration::from_secs_f64(p.bytes_total.saturating_sub(p.bytes_done) as f64 / rate));
        let line = render(self.verb, p.bytes_done, p.bytes_total, rate, eta);
        let mut err = std::io::stderr().lock();
        // A failed progress write (closed terminal) must not fail the transfer;
        // the final summary reports the outcome anyway.
        let r = if self.tty {
            s.drew_tty_line = true;
            write!(err, "\r\x1b[2K{} {line}", bar(p.bytes_done, p.bytes_total, 24)).and_then(|()| err.flush())
        } else {
            writeln!(err, "{line}")
        };
        if let Err(e) = r {
            tracing::debug!(error = %e, "progress write failed");
        }
    }

    /// End the in-place line so following output starts on a fresh line.
    pub fn finish(&self) {
        let s = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.tty && s.drew_tty_line {
            eprintln!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(256 << 20), "256.0 MiB");
        assert_eq!(human_bytes(3 << 30), "3.0 GiB");
        assert_eq!(human_rate(100.0 * 1024.0 * 1024.0), "100.0 MiB/s");
        assert_eq!(human_duration(Duration::from_secs(42)), "42s");
        assert_eq!(human_duration(Duration::from_secs(125)), "2m05s");
        assert_eq!(human_duration(Duration::from_secs(3720)), "1h02m");
        assert_eq!(render("Sending", 512 << 20, 1 << 30, 100.0 * 1024.0 * 1024.0, Some(Duration::from_secs(5))), "Sending 512.0 MiB / 1.0 GiB (50%)  100.0 MiB/s  ETA 5s");
        assert_eq!(render("Receiving", 0, 0, 0.0, None), "Receiving 0 B / 0 B (100%)  0.0 MiB/s  ETA --");
        assert_eq!(bar(1, 2, 4), "[##--]");
        assert_eq!(bar(0, 0, 3), "[###]");
    }

    #[test]
    fn throttle_caps_rate_and_always_draws_final_once() {
        let t0 = Instant::now();
        let mut th = Throttle::new(TTY_INTERVAL);
        let ms = |n| t0 + Duration::from_millis(n);
        // 1000 updates over one second (a chunk every ms) draw at most ~10 times.
        let draws = (0..1000).filter(|&i| th.should_draw(ms(i), false)).count();
        assert!((10..=11).contains(&draws), "{draws}");
        assert!(th.should_draw(ms(1000), true), "final update always drawn");
        assert!(!th.should_draw(ms(5000), true), "and only once");
        assert!(!th.should_draw(ms(6000), false));

        let mut plain = Throttle::new(PLAIN_INTERVAL);
        assert!(plain.should_draw(t0, false), "first update is shown at once");
        assert!(!plain.should_draw(ms(4999), false));
        assert!(plain.should_draw(ms(5000), false));
    }
}
