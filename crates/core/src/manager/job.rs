// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! One job's live state. Counters the engine bumps per chunk are atomics; the
//! rest sits behind a short-lived std mutex that is never held across `.await`.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use transport::TransportKind;

use super::types::{SendTarget, Transfer, TransferId, TransferState};
use crate::options::CancelHandle;
use crate::report::Direction;

/// Throughput is averaged over this window (manual §39: rolling 1 s).
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(1);
/// A stall longer than this reads as 0 B/s (see `Inner::sample`).
const STALL_WINDOW: Duration = Duration::from_secs(8);

/// Why the current attempt is being stopped locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    Cancel,
    Pause,
    Shutdown,
}

/// Receiver's answer to an incoming offer: `Some(dest)` accepts, `None` declines.
pub(crate) type OfferReply = oneshot::Sender<Option<PathBuf>>;

pub(crate) struct Job {
    pub id: TransferId,
    /// Creation order, for listing.
    pub seq: u64,
    pub direction: Direction,
    pub transport: TransportKind,
    /// Sender only: what to (re)send.
    pub send: Option<(SendTarget, Vec<PathBuf>)>,
    pub bytes_done: AtomicU64,
    pub bytes_total: AtomicU64,
    /// A progress notice for this job is in the observer queue.
    pub progress_queued: AtomicBool,
    inner: Mutex<Inner>,
}

pub(crate) struct Inner {
    pub state: TransferState,
    pub resumed_bytes: u64,
    pub peer_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub cancel: CancelHandle,
    pub stop: Option<Stop>,
    /// Receiver: the pending offer's reply channel.
    pub offer: Option<OfferReply>,
    /// Receiver: the offer was declined because nobody answered in time.
    pub accept_timed_out: bool,
    samples: VecDeque<(Instant, u64)>,
    pub throughput: u64,
    /// What the observer last got (set by the dispatcher), to skip unchanged progress.
    pub reported_bytes: u64,
    pub reported_throughput: u64,
    /// A state change the observer has not been given yet (queue was full).
    pub state_dirty: bool,
}

impl Job {
    pub fn new(id: TransferId, seq: u64, direction: Direction, transport: TransportKind, send: Option<(SendTarget, Vec<PathBuf>)>, state: TransferState) -> Self {
        let inner = Inner { state, resumed_bytes: 0, peer_fingerprint: None, peer_name: None, cancel: CancelHandle::new(), stop: None, offer: None, accept_timed_out: false, samples: VecDeque::new(), throughput: 0, reported_bytes: 0, reported_throughput: 0, state_dirty: false };
        Self { id, seq, direction, transport, send, bytes_done: AtomicU64::new(0), bytes_total: AtomicU64::new(0), progress_queued: AtomicBool::new(false), inner: Mutex::new(inner) }
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        // Every critical section leaves `Inner` consistent, so a panic elsewhere
        // while holding the lock doesn't invalidate it.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn state(&self) -> TransferState {
        self.lock().state
    }

    pub fn snapshot(&self) -> Transfer {
        let g = self.lock();
        self.snapshot_locked(&g)
    }

    /// Snapshot for a progress callback: also records it as delivered.
    pub fn take_progress(&self) -> Transfer {
        self.progress_queued.store(false, Ordering::Release);
        let mut g = self.lock();
        let t = self.snapshot_locked(&g);
        g.reported_bytes = t.bytes_done;
        g.reported_throughput = t.throughput_bytes_per_sec;
        t
    }

    pub fn snapshot_locked(&self, g: &Inner) -> Transfer {
        Transfer { id: self.id.clone(), direction: self.direction, state: g.state, transport: self.transport, bytes_total: self.bytes_total.load(Ordering::Relaxed), bytes_done: self.bytes_done.load(Ordering::Relaxed), resumed_bytes: g.resumed_bytes, throughput_bytes_per_sec: g.throughput, peer_fingerprint: g.peer_fingerprint.clone(), peer_name: g.peer_name.clone() }
    }

    /// Asks the running attempt to stop. Returns `false` if the job isn't running.
    pub fn request_stop(&self, why: Stop) -> bool {
        let mut g = self.lock();
        if !g.state.is_active() {
            return false;
        }
        // The first reason wins: a pause racing a cancel stays a pause, so
        // that resume state is never claimed as gone when it isn't.
        g.stop.get_or_insert(why);
        g.cancel.cancel();
        if let Some(reply) = g.offer.take()
            && reply.send(None).is_err()
        {
            tracing::debug!(id = %self.id, "offer gate already gone");
        }
        true
    }
}

impl Inner {
    /// Starts a new attempt: fresh cancel handle, no stop request. Called under
    /// the same lock that moves the job into an active state, so a concurrent
    /// cancel either sees the old attempt finished or the new one running.
    pub fn reset_attempt(&mut self) -> CancelHandle {
        self.cancel = CancelHandle::new();
        self.stop = None;
        self.accept_timed_out = false;
        self.clear_rate();
        self.cancel.clone()
    }

    /// Records a throughput sample; returns the rolling rate in bytes/s.
    ///
    /// Progress moves in whole chunks, so only *growth* is kept, and the rate is
    /// measured between the moments data landed (about one window apart). A plain
    /// time window misreads chunky progress: on a 2.5 MiB/s link a 1 s window
    /// holds either no chunk (0 B/s, which the app showed as "—") or one (4 MiB/s).
    /// A silence longer than the measured span stretches it (the rate decays), and
    /// one longer than [`STALL_WINDOW`] reads as 0.
    pub fn sample(&mut self, now: Instant, bytes: u64) -> u64 {
        if self.samples.back().is_none_or(|&(_, b)| bytes > b) {
            self.samples.push_back((now, bytes));
        }
        while self.samples.len() > 1 && self.samples.front().is_some_and(|&(t, _)| now.duration_since(t) > STALL_WINDOW) {
            self.samples.pop_front();
        }
        if let Some(&(last, _)) = self.samples.back() {
            while self.samples.len() > 2 && self.samples.get(1).is_some_and(|&(t, _)| last.duration_since(t) >= THROUGHPUT_WINDOW) {
                self.samples.pop_front();
            }
        }
        self.throughput = match (self.samples.front(), self.samples.back()) {
            (Some(&(t0, b0)), Some(&(t1, b1))) if t1 > t0 => {
                let span = t1.duration_since(t0);
                let silence = now.saturating_duration_since(t1);
                let secs = if silence > span { now.duration_since(t0) } else { span }.as_secs_f64();
                (b1.saturating_sub(b0) as f64 / secs) as u64
            }
            _ => 0,
        };
        self.throughput
    }

    pub fn clear_rate(&mut self) {
        self.samples.clear();
        self.throughput = 0;
    }

    /// Entering Transferring: seed the window with the starting point, so the
    /// first tick already yields a rate. A short data phase may only ever see one
    /// tick, and a single sample can't produce a rate (seen on CI: 64 MiB
    /// "Transferring" at 0 B/s).
    pub fn start_rate(&mut self, now: Instant, bytes: u64) {
        self.samples.clear();
        self.samples.push_back((now, bytes));
        self.throughput = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_tick_after_start_reports_a_rate() {
        let job = Job::new("j".into(), 0, Direction::Send, TransportKind::Tcp, None, TransferState::Transferring);
        let mut g = job.lock();
        let t0 = Instant::now();
        // Without the seed, one sample yields 0; with it, the first tick has a rate.
        g.start_rate(t0, 0);
        assert_eq!(g.sample(t0 + Duration::from_millis(100), 50_000_000), 500_000_000);
    }

    #[test]
    fn rolling_rate_covers_about_one_second() {
        let job = Job::new("j".into(), 0, Direction::Send, TransportKind::Tcp, None, TransferState::Transferring);
        let mut g = job.lock();
        let t0 = Instant::now();
        assert_eq!(g.sample(t0, 0), 0);
        // 100 MB/s for 2 s, sampled every 100 ms.
        let mut rate = 0;
        for i in 1..=20u64 {
            rate = g.sample(t0 + Duration::from_millis(100 * i), i * 10_000_000);
        }
        assert!((95_000_000..=105_000_000).contains(&rate), "{rate}");
        // Window holds about 1 s of samples, not all 2 s.
        assert!(g.samples.len() <= 12, "{}", g.samples.len());
        // Stalled for 2 s: still a (lower) rate, since chunks land in bursts.
        for i in 21..=40u64 {
            rate = g.sample(t0 + Duration::from_millis(100 * i), 200_000_000);
        }
        assert!(rate > 0 && rate < 50_000_000, "{rate}");
        // Stalled longer than the stall window: 0.
        for i in 41..=130u64 {
            rate = g.sample(t0 + Duration::from_millis(100 * i), 200_000_000);
        }
        assert_eq!(rate, 0);
    }

    /// 4 MiB chunks landing every 1.6 s (2.5 MiB/s), ticks every 250 ms: the rate
    /// never drops to 0 between chunks (it did with a plain 1 s window: the app showed "—").
    #[test]
    fn slow_chunky_progress_keeps_a_rate() {
        let job = Job::new("j".into(), 0, Direction::Send, TransportKind::Tcp, None, TransferState::Transferring);
        let mut g = job.lock();
        let t0 = Instant::now();
        g.start_rate(t0, 0);
        const CHUNK: u64 = 4 << 20;
        for tick in 1..=80u64 {
            let ms = tick * 250;
            let rate = g.sample(t0 + Duration::from_millis(ms), (ms / 1600) * CHUNK);
            if ms >= 1600 {
                assert!(rate > 0, "0 B/s at {ms} ms");
            }
        }
        // True rate: 2.62 MB/s (4 MiB per 1.6 s); tick quantization allows a little slack.
        assert!((2_200_000..=3_200_000).contains(&g.throughput), "{}", g.throughput);
    }

    #[test]
    fn first_stop_reason_wins_and_only_while_active() {
        let job = Job::new("j".into(), 0, Direction::Send, TransportKind::Tcp, None, TransferState::Transferring);
        let c = job.lock().reset_attempt();
        assert!(job.request_stop(Stop::Pause));
        assert!(job.request_stop(Stop::Cancel));
        assert_eq!(job.lock().stop, Some(Stop::Pause));
        assert!(c.is_cancelled());
        job.lock().state = TransferState::Completed;
        assert!(!job.request_stop(Stop::Cancel));
    }
}
