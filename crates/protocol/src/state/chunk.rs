//! Sender-side per-chunk confirmation tracking (manual §9.3/§10). On both
//! backends the transport already guarantees delivery; this only drives
//! re-sends after an integrity NACK or a missing ChunkAck.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::Result;
use crate::error::ProtocolError;

pub const MAX_RETRIES: u8 = 8;
pub const DEFAULT_RTO: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkId {
    pub file_index: u32,
    pub chunk_index: u32,
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    sent_at: Instant,
    retries: u8,
}

#[derive(Debug)]
pub struct ChunkTracker {
    rto: Duration,
    in_flight: BTreeMap<ChunkId, InFlight>,
    confirmed: u64,
}

impl ChunkTracker {
    pub fn new(rto: Duration) -> Self {
        Self { rto, in_flight: BTreeMap::new(), confirmed: 0 }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    pub fn confirmed(&self) -> u64 {
        self.confirmed
    }

    pub fn on_sent(&mut self, id: ChunkId, now: Instant) {
        self.in_flight.entry(id).and_modify(|f| f.sent_at = now).or_insert(InFlight { sent_at: now, retries: 0 });
    }

    /// Returns false for an ack of a chunk that isn't outstanding (duplicate or bogus).
    pub fn on_ack(&mut self, id: ChunkId) -> bool {
        let known = self.in_flight.remove(&id).is_some();
        if known {
            self.confirmed += 1;
        }
        known
    }

    /// A NACK schedules an immediate resend; returns the chunk to resend.
    pub fn on_nack(&mut self, id: ChunkId) -> Result<ChunkId> {
        let f = self.in_flight.get_mut(&id).ok_or(ProtocolError::UnexpectedMessage)?;
        bump(f)?;
        Ok(id)
    }

    /// Chunks whose RTO elapsed, in deterministic order. Their retry counter is bumped;
    /// the caller resends them with the RETRANSMISSION flag and calls `on_sent` again.
    pub fn due(&mut self, now: Instant) -> Result<Vec<ChunkId>> {
        let mut out = Vec::new();
        for (id, f) in &mut self.in_flight {
            if now.saturating_duration_since(f.sent_at) >= self.rto {
                bump(f)?;
                out.push(*id);
            }
        }
        Ok(out)
    }
}

fn bump(f: &mut InFlight) -> Result<()> {
    f.retries += 1;
    if f.retries > MAX_RETRIES {
        // The link is gone, not lossy: stop instead of retrying forever.
        return Err(ProtocolError::TooManyRetries);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ChunkId = ChunkId { file_index: 0, chunk_index: 0 };

    #[test]
    fn ack_confirms_once() {
        let mut t = ChunkTracker::new(DEFAULT_RTO);
        t.on_sent(A, Instant::now());
        assert!(t.on_ack(A));
        assert!(!t.on_ack(A));
        assert_eq!(t.confirmed(), 1);
    }

    #[test]
    fn rto_then_retry_cap() {
        let rto = Duration::from_millis(5);
        let mut t = ChunkTracker::new(rto);
        let mut now = Instant::now();
        t.on_sent(A, now);
        assert!(t.due(now).unwrap().is_empty());
        for _ in 0..MAX_RETRIES {
            now += rto;
            assert_eq!(t.due(now).unwrap(), vec![A]);
            t.on_sent(A, now);
        }
        now += rto;
        assert_eq!(t.due(now), Err(ProtocolError::TooManyRetries));
    }

    #[test]
    fn nack_unknown_chunk_is_rejected() {
        let mut t = ChunkTracker::new(DEFAULT_RTO);
        assert!(t.on_nack(A).is_err());
        t.on_sent(A, Instant::now());
        assert_eq!(t.on_nack(A), Ok(A));
    }
}
