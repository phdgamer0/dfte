// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! What a finished transfer reports back (manual §30 metrics, §38 fields).

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Send,
    Receive,
}

/// Wall-clock time per phase, in seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct PhaseTimings {
    /// Sender: whole-file + per-chunk BLAKE3 before the manifest (manual §19).
    /// Receiver: re-hashing already-staged chunks of a resumed file.
    pub hash_secs: f64,
    /// Transport connect (sender) / accept (receiver).
    pub connect_secs: f64,
    /// Hello/HelloAck + Noise_XX + peer verification.
    pub handshake_secs: f64,
    /// Manifest exchange, staging setup and resume matching.
    pub manifest_secs: f64,
    /// First chunk out/in to last chunk acked/written.
    pub transfer_secs: f64,
    /// Receiver: fsync + whole-file verification + rename. Sender: waiting for it.
    pub finalize_secs: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TransferReport {
    pub direction: Direction,
    pub transfer_id: String,
    pub peer_fingerprint: String,
    pub peer_name: String,
    /// "tcp" or "quic".
    pub transport: String,
    /// Negotiated data-plane AEAD, or "plaintext" (bench-only builds).
    pub cipher: String,
    pub streams: usize,
    /// Manifest entries (files + empty-directory sentinels).
    pub files: usize,
    pub bytes_total: u64,
    /// Bytes moved in this session (excludes resumed bytes, includes no resends).
    pub bytes_transferred: u64,
    /// Bytes skipped because the receiver already held them (manual §19).
    pub resumed_bytes: u64,
    /// Sender: files whose hashes came from the hash cache instead of a read (§19).
    pub hash_cache_hits: u64,
    pub chunks: u64,
    /// Chunks resent after an integrity NACK or ack timeout (manual §9.3).
    pub retransmits: u64,
    pub total_secs: f64,
    /// `bytes_transferred / transfer_secs`: network + crypto + page-cache rate.
    pub throughput_bytes_per_sec: f64,
    /// `bytes_transferred / (transfer_secs + finalize_secs)`: includes the final
    /// fsync, so on a slow disk this is the number a user actually experiences.
    pub end_to_end_bytes_per_sec: f64,
    pub timings: PhaseTimings,
    /// Receiver: final locations of the received entries.
    pub saved: Vec<PathBuf>,
}

pub(crate) fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

pub(crate) fn rate(bytes: u64, secs: f64) -> f64 {
    if secs > 0.0 { bytes as f64 / secs } else { 0.0 }
}
