// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Persisted resume state (manual §19): the manifest essentials plus a bitmap of
//! confirmed chunks per file, stored as `<transfer_id>.resume.json` beside the
//! staged data, written atomically (tmp + fsync + rename).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::chunk::{CHUNK_SIZE, chunk_count, chunk_range};
use crate::error::{Result, StorageError};
use crate::fileio::sync_dir_blocking;
use crate::path::validate_relative_path;

/// Sidecar file suffix.
pub const RESUME_SUFFIX: &str = ".resume.json";
/// Default number of new confirmations between fsyncs (32 × 4 MiB = 128 MiB).
pub const DEFAULT_FLUSH_EVERY: u32 = 32;
/// On-disk format version of the sidecar.
pub const RESUME_FORMAT_VERSION: u32 = 1;

/// Fixed-length bitset over chunk indices, stored as `u64` words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkBitmap {
    len: u64,
    words: Vec<u64>,
}

impl ChunkBitmap {
    /// All-clear bitmap of `len` bits. Returns `None` if `len` can't be addressed in memory.
    pub fn new(len: u64) -> Option<Self> {
        let words = usize::try_from(len.div_ceil(64)).ok()?;
        Some(Self { len, words: vec![0; words] })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn locate(&self, idx: u64) -> Option<(usize, u64)> {
        if idx >= self.len {
            return None;
        }
        Some((usize::try_from(idx / 64).ok()?, 1u64 << (idx % 64)))
    }

    /// Whether bit `idx` is set (`false` when out of range).
    pub fn get(&self, idx: u64) -> bool {
        self.locate(idx).and_then(|(w, m)| self.words.get(w).map(|word| word & m != 0)).unwrap_or(false)
    }

    /// Set bit `idx`. Returns `Some(true)` if newly set, `Some(false)` if already
    /// set, `None` if out of range.
    pub fn set(&mut self, idx: u64) -> Option<bool> {
        let (w, m) = self.locate(idx)?;
        let word = self.words.get_mut(w)?;
        let was = *word & m != 0;
        *word |= m;
        Some(!was)
    }

    /// Number of set bits.
    pub fn count_ones(&self) -> u64 {
        self.words.iter().map(|w| u64::from(w.count_ones())).sum()
    }

    /// Number of leading set bits (indices `0..n` all set).
    pub fn contiguous_prefix(&self) -> u64 {
        let mut n = 0u64;
        for w in &self.words {
            if *w == u64::MAX {
                n += 64;
            } else {
                n += u64::from(w.trailing_ones());
                break;
            }
        }
        n.min(self.len)
    }

    pub fn is_complete(&self) -> bool {
        self.count_ones() == self.len
    }

    fn is_well_formed(&self) -> bool {
        let Ok(expected_words) = usize::try_from(self.len.div_ceil(64)) else {
            return false;
        };
        if self.words.len() != expected_words {
            return false;
        }
        let tail_bits = self.len % 64;
        match self.words.last() {
            Some(last) if tail_bits != 0 => last >> tail_bits == 0,
            _ => true,
        }
    }
}

/// Resume record for one file of a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeFile {
    /// Validated relative path from the manifest (wire form).
    pub relative_path: String,
    pub size: u64,
    #[serde(with = "hex32")]
    pub content_hash: [u8; 32],
    pub confirmed: ChunkBitmap,
}

impl ResumeFile {
    /// New record with nothing confirmed. Rejects invalid paths and sizes whose
    /// chunk bitmap can't be addressed.
    pub fn new(relative_path: &str, size: u64, content_hash: [u8; 32]) -> Result<Self> {
        let relative_path = validate_relative_path(relative_path)?.as_wire();
        let confirmed = ChunkBitmap::new(chunk_count(size)).ok_or(StorageError::ChunkOutOfRange { index: chunk_count(size), count: 0 })?;
        Ok(Self { relative_path, size, content_hash, confirmed })
    }

    /// Resume gate (§19): only resume onto this partial if size *and* whole-file
    /// hash match the incoming manifest entry.
    pub fn matches(&self, size: u64, content_hash: &[u8; 32]) -> bool {
        self.size == size && &self.content_hash == content_hash
    }

    /// Highest byte offset such that every byte before it is confirmed (§19).
    pub fn contiguous_offset(&self) -> u64 {
        self.confirmed.contiguous_prefix().saturating_mul(CHUNK_SIZE).min(self.size)
    }

    pub fn is_complete(&self) -> bool {
        self.confirmed.is_complete()
    }
}

/// Persisted resume state of a whole transfer job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeState {
    pub format_version: u32,
    pub transfer_id: String,
    pub files: Vec<ResumeFile>,
}

impl ResumeState {
    /// `transfer_id` becomes part of a file name, so it must be 1–128 chars of
    /// `[A-Za-z0-9_-]` (a UUID string qualifies).
    pub fn new(transfer_id: impl Into<String>, files: Vec<ResumeFile>) -> Result<Self> {
        let transfer_id = transfer_id.into();
        check_transfer_id(&transfer_id)?;
        Ok(Self { format_version: RESUME_FORMAT_VERSION, transfer_id, files })
    }

    fn file_mut(&mut self, file: usize) -> Result<&mut ResumeFile> {
        let count = self.files.len() as u64;
        self.files.get_mut(file).ok_or(StorageError::ChunkOutOfRange { index: file as u64, count })
    }

    /// Record chunk `chunk` of file `file` as integrity-confirmed.
    /// Returns whether it was newly confirmed.
    pub fn mark_confirmed(&mut self, file: usize, chunk: u64) -> Result<bool> {
        let f = self.file_mut(file)?;
        chunk_range(f.size, chunk)?;
        f.confirmed.set(chunk).ok_or(StorageError::ChunkOutOfRange { index: chunk, count: f.confirmed.len() })
    }

    /// [`ResumeFile::contiguous_offset`] for file `file`.
    pub fn contiguous_offset(&self, file: usize) -> Option<u64> {
        self.files.get(file).map(ResumeFile::contiguous_offset)
    }

    /// Index of the file with this path whose size and hash match, if any.
    pub fn matches(&self, relative_path: &str, size: u64, content_hash: &[u8; 32]) -> Option<usize> {
        self.files.iter().position(|f| f.relative_path == relative_path && f.matches(size, content_hash))
    }

    pub fn is_complete(&self) -> bool {
        self.files.iter().all(ResumeFile::is_complete)
    }

    /// Sidecar file name: `<transfer_id>.resume.json`.
    pub fn file_name(&self) -> String {
        format!("{}{RESUME_SUFFIX}", self.transfer_id)
    }

    /// Atomically persist into `dir` (write tmp, fsync, rename, fsync dir).
    pub fn save_blocking(&self, dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let final_path = dir.join(self.file_name());
        let tmp_path = dir.join(format!("{}.tmp", self.file_name()));
        let json = serde_json::to_vec(self).map_err(io::Error::other)?;
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;
        sync_dir_blocking(dir)?;
        Ok(final_path)
    }

    /// Load and validate a sidecar.
    pub fn load_blocking(path: &Path) -> Result<Self> {
        let corrupt = |reason: String| StorageError::CorruptResumeState { path: path.to_path_buf(), reason };
        let bytes = std::fs::read(path)?;
        let state: ResumeState = serde_json::from_slice(&bytes).map_err(|e| corrupt(e.to_string()))?;
        if state.format_version != RESUME_FORMAT_VERSION {
            return Err(corrupt(format!("unsupported format version {}", state.format_version)));
        }
        check_transfer_id(&state.transfer_id).map_err(|e| corrupt(e.to_string()))?;
        for f in &state.files {
            validate_relative_path(&f.relative_path).map_err(|e| corrupt(e.to_string()))?;
            if f.confirmed.len() != chunk_count(f.size) || !f.confirmed.is_well_formed() {
                return Err(corrupt(format!("bad bitmap for {}", f.relative_path)));
            }
        }
        Ok(state)
    }

    /// Load `<dir>/<transfer_id>.resume.json`.
    pub fn load_from_dir_blocking(dir: &Path, transfer_id: &str) -> Result<Self> {
        check_transfer_id(transfer_id)?;
        Self::load_blocking(&dir.join(format!("{transfer_id}{RESUME_SUFFIX}")))
    }

    /// Delete this transfer's sidecar (after successful completion). Missing is fine.
    pub fn remove_blocking(&self, dir: &Path) -> Result<()> {
        match std::fs::remove_file(dir.join(self.file_name())) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

fn check_transfer_id(id: &str) -> Result<()> {
    let ok = !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok { Ok(()) } else { Err(StorageError::InvalidPath { path: id.chars().take(256).collect(), reason: "invalid transfer id" }) }
}

/// Crash recovery (§19): every valid `*.resume.json` in `staging_dir`.
///
/// Unreadable/corrupt sidecars and leftover `.tmp` files are skipped (not
/// deleted) so a bad file never blocks recovery of the others. A missing
/// directory yields an empty list.
pub fn scan_orphans_blocking(staging_dir: &Path) -> Result<Vec<ResumeState>> {
    let entries = match std::fs::read_dir(staging_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.ends_with(RESUME_SUFFIX) || !entry.file_type()?.is_file() {
            continue;
        }
        if let Ok(state) = ResumeState::load_blocking(&entry.path()) {
            out.push(state);
        }
    }
    out.sort_by(|a, b| a.transfer_id.cmp(&b.transfer_id));
    Ok(out)
}

/// A [`ResumeState`] bound to its directory, fsyncing every `flush_every`
/// new confirmations instead of on every chunk (§19).
#[derive(Debug)]
pub struct ResumeStore {
    dir: PathBuf,
    state: ResumeState,
    unflushed: u32,
    flush_every: u32,
}

impl ResumeStore {
    /// Bind `state` to `dir` and persist it immediately.
    pub fn create_blocking(dir: impl Into<PathBuf>, state: ResumeState) -> Result<Self> {
        let store = Self { dir: dir.into(), state, unflushed: 0, flush_every: DEFAULT_FLUSH_EVERY };
        store.state.save_blocking(&store.dir)?;
        Ok(store)
    }

    /// Reopen a persisted state.
    pub fn open_blocking(dir: impl Into<PathBuf>, transfer_id: &str) -> Result<Self> {
        let dir = dir.into();
        let state = ResumeState::load_from_dir_blocking(&dir, transfer_id)?;
        Ok(Self { dir, state, unflushed: 0, flush_every: DEFAULT_FLUSH_EVERY })
    }

    /// Change the flush cadence (minimum 1).
    pub fn with_flush_every(mut self, n: u32) -> Self {
        self.flush_every = n.max(1);
        self
    }

    pub fn state(&self) -> &ResumeState {
        &self.state
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Confirmations recorded in memory but not yet persisted.
    pub fn unflushed(&self) -> u32 {
        self.unflushed
    }

    /// Mark a chunk confirmed; persists when the cadence threshold is reached.
    pub fn mark_confirmed_blocking(&mut self, file: usize, chunk: u64) -> Result<bool> {
        let newly = self.state.mark_confirmed(file, chunk)?;
        if newly {
            self.unflushed += 1;
            if self.unflushed >= self.flush_every {
                self.flush_blocking()?;
            }
        }
        Ok(newly)
    }

    /// Persist now, regardless of cadence (call on pause/interrupt).
    pub fn flush_blocking(&mut self) -> Result<()> {
        self.state.save_blocking(&self.dir)?;
        self.unflushed = 0;
        Ok(())
    }

    /// Remove the sidecar after a completed transfer.
    pub fn remove_blocking(self) -> Result<()> {
        self.state.remove_blocking(&self.dir)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::hash::to_hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        crate::hash::from_hex(&s).ok_or_else(|| D::Error::custom("expected 64 hex chars"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample(id: &str) -> ResumeState {
        ResumeState::new(id, vec![ResumeFile::new("dir/a.bin", 10 * CHUNK_SIZE + 5, [1; 32]).unwrap(), ResumeFile::new("b.txt", 100, [2; 32]).unwrap(), ResumeFile::new("empty", 0, [3; 32]).unwrap()]).unwrap()
    }

    #[test]
    fn bitmap_basics() {
        let mut b = ChunkBitmap::new(130).unwrap();
        assert_eq!(b.set(0), Some(true));
        assert_eq!(b.set(0), Some(false));
        assert_eq!(b.set(130), None);
        for i in 1..64 {
            b.set(i);
        }
        assert_eq!(b.contiguous_prefix(), 64);
        b.set(65);
        assert_eq!(b.contiguous_prefix(), 64);
        b.set(64);
        assert_eq!(b.contiguous_prefix(), 66);
        for i in 0..130 {
            b.set(i);
        }
        assert!(b.is_complete());
        assert_eq!(b.contiguous_prefix(), 130);
        assert!(b.get(129) && !b.get(130));
    }

    #[test]
    fn contiguous_offset_with_gaps() {
        let mut s = sample("t1");
        assert_eq!(s.contiguous_offset(0), Some(0));
        s.mark_confirmed(0, 0).unwrap();
        s.mark_confirmed(0, 1).unwrap();
        s.mark_confirmed(0, 3).unwrap(); // gap at 2
        assert_eq!(s.contiguous_offset(0), Some(2 * CHUNK_SIZE));
        s.mark_confirmed(0, 2).unwrap();
        assert_eq!(s.contiguous_offset(0), Some(4 * CHUNK_SIZE));
        for i in 0..11 {
            s.mark_confirmed(0, i).unwrap();
        }
        assert_eq!(s.contiguous_offset(0), Some(10 * CHUNK_SIZE + 5));
        assert!(s.files[0].is_complete());
        assert!(s.mark_confirmed(0, 11).is_err());
        assert!(s.mark_confirmed(9, 0).is_err());
        assert!(s.mark_confirmed(2, 0).is_err(), "empty file has no chunks");
        assert!(!s.is_complete());
        s.mark_confirmed(1, 0).unwrap();
        assert!(s.is_complete());
    }

    #[test]
    fn persist_reload_and_match_gate() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = sample("1b4e28ba-2fa1-11d2-883f-0016d3cca427");
        s.mark_confirmed(0, 4).unwrap();
        let path = s.save_blocking(dir.path()).unwrap();
        assert!(path.ends_with("1b4e28ba-2fa1-11d2-883f-0016d3cca427.resume.json"));
        let loaded = ResumeState::load_blocking(&path).unwrap();
        assert_eq!(loaded, s);
        assert_eq!(loaded.matches("dir/a.bin", 10 * CHUNK_SIZE + 5, &[1; 32]), Some(0));
        assert_eq!(loaded.matches("dir/a.bin", 10 * CHUNK_SIZE + 5, &[9; 32]), None);
        assert_eq!(loaded.matches("dir/a.bin", 1, &[1; 32]), None);
        assert_eq!(loaded.matches("other", 100, &[2; 32]), None);
        s.remove_blocking(dir.path()).unwrap();
        assert!(!path.exists());
        s.remove_blocking(dir.path()).unwrap();
    }

    #[test]
    fn rejects_bad_ids_and_corrupt_files() {
        assert!(ResumeState::new("../x", vec![]).is_err());
        assert!(ResumeState::new("", vec![]).is_err());
        assert!(ResumeFile::new("../x", 1, [0; 32]).is_err());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.resume.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(matches!(ResumeState::load_blocking(&p), Err(StorageError::CorruptResumeState { .. })));
        // Tampered bitmap length.
        let mut s = sample("t2");
        s.files[1].confirmed = ChunkBitmap::new(5).unwrap();
        let p = s.save_blocking(dir.path()).unwrap();
        assert!(matches!(ResumeState::load_blocking(&p), Err(StorageError::CorruptResumeState { .. })));
    }

    #[test]
    fn orphan_scan_finds_valid_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        assert!(scan_orphans_blocking(&dir.path().join("missing")).unwrap().is_empty());
        sample("job-b").save_blocking(dir.path()).unwrap();
        sample("job-a").save_blocking(dir.path()).unwrap();
        std::fs::write(dir.path().join("junk.resume.json"), b"garbage").unwrap();
        std::fs::write(dir.path().join("job-c.resume.json.tmp"), b"{}").unwrap();
        std::fs::write(dir.path().join("job-a.0.part"), b"data").unwrap();
        let found = scan_orphans_blocking(dir.path()).unwrap();
        let ids: Vec<_> = found.iter().map(|s| s.transfer_id.as_str()).collect();
        assert_eq!(ids, ["job-a", "job-b"]);
    }

    #[test]
    fn crash_simulation_respects_flush_cadence() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ResumeStore::create_blocking(dir.path(), sample("crash")).unwrap().with_flush_every(4);
        for i in 0..6 {
            store.mark_confirmed_blocking(0, i).unwrap();
        }
        // Duplicate confirmation doesn't count toward the cadence.
        assert!(!store.mark_confirmed_blocking(0, 5).unwrap());
        assert_eq!(store.unflushed(), 2);
        drop(store); // "crash": no explicit flush

        let reopened = ResumeStore::open_blocking(dir.path(), "crash").unwrap();
        assert_eq!(reopened.state().files[0].confirmed.count_ones(), 4);
        assert_eq!(reopened.state().contiguous_offset(0), Some(4 * CHUNK_SIZE));
        let mut reopened = reopened;
        reopened.mark_confirmed_blocking(0, 4).unwrap();
        reopened.flush_blocking().unwrap();
        let again = ResumeStore::open_blocking(dir.path(), "crash").unwrap();
        assert_eq!(again.state().contiguous_offset(0), Some(5 * CHUNK_SIZE));
        assert_eq!(scan_orphans_blocking(dir.path()).unwrap().len(), 1);
        again.remove_blocking().unwrap();
        assert!(scan_orphans_blocking(dir.path()).unwrap().is_empty());
    }
}
