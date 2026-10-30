// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Cache of whole-file BLAKE3 + per-chunk piece hashes, keyed by file identity.
//!
//! The sender must hash every file before offering the manifest (manual §19), so
//! without a cache each re-send or resume re-reads the whole file once before
//! sending it. Measured: about 17% of a 1 GiB loopback transfer, and a full
//! extra disk pass for files larger than RAM.
//!
//! An entry is used only if the file's current metadata matches what was stored:
//! size and mtime everywhere, plus ctime, inode and device on unix. ctime can't
//! be set by ordinary users, so an edit that restores mtime is still caught. A
//! stale or forged entry can't corrupt a transfer: the receiver checks every chunk
//! and the whole file against the bytes it actually received (manual §20), so a
//! wrong hash fails the transfer loudly.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hash::{from_hex, to_hex};

const FORMAT_VERSION: u32 = 1;

/// Hashes recovered from the cache for an unchanged file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedHashes {
    pub root: [u8; 32],
    pub pieces: Vec<[u8; 32]>,
}

#[derive(Debug)]
pub struct HashCache {
    dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    size: u64,
    mtime_ns: Option<u128>,
    ctime_ns: Option<i128>,
    ino: Option<u64>,
    dev: Option<u64>,
}

impl Stamp {
    fn of(meta: &Metadata) -> Self {
        // `modified()` is unsupported on a few platforms; size then guards alone.
        let mtime_ns = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self { size: meta.len(), mtime_ns, ctime_ns: Some(i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec())), ino: Some(meta.ino()), dev: Some(meta.dev()) }
        }
        #[cfg(not(unix))]
        {
            Self { size: meta.len(), mtime_ns, ctime_ns: None, ino: None, dev: None }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    version: u32,
    path: PathBuf,
    stamp: Stamp,
    root: String,
    pieces: Vec<String>,
}

impl HashCache {
    /// Opens (creating, mode 0700 on unix) the cache directory.
    pub fn open_blocking(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    fn entry_path(&self, canonical: &Path) -> PathBuf {
        let key = blake3::hash(canonical.as_os_str().as_encoded_bytes());
        self.dir.join(format!("{}.json", &key.to_hex()[..32]))
    }

    /// Cached hashes for `path` if its current metadata still matches. Any
    /// mismatch, missing entry or unreadable entry is a miss; the caller then
    /// hashes the file as usual, so a bad entry costs time, never correctness.
    pub fn get_blocking(&self, path: &Path, meta: &Metadata) -> Option<CachedHashes> {
        let canonical = match std::fs::canonicalize(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "hash cache: cannot canonicalize, treating as miss");
                return None;
            }
        };
        let file = self.entry_path(&canonical);
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(entry = %file.display(), error = %e, "hash cache: unreadable entry, treating as miss");
                return None;
            }
        };
        let entry: Entry = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(entry = %file.display(), error = %e, "hash cache: corrupt entry, treating as miss");
                return None;
            }
        };
        if entry.version != FORMAT_VERSION || entry.path != canonical || entry.stamp != Stamp::of(meta) {
            return None;
        }
        let root = from_hex(&entry.root)?;
        let pieces = entry.pieces.iter().map(|p| from_hex(p)).collect::<Option<Vec<_>>>()?;
        if pieces.len() as u64 != crate::chunk_count(meta.len()).max(1) {
            tracing::warn!(entry = %file.display(), "hash cache: piece count doesn't match file size, treating as miss");
            return None;
        }
        Some(CachedHashes { root, pieces })
    }

    /// Records hashes computed from `path` while it had metadata `meta`.
    /// Written atomically (temp file, rename) but not fsynced: after a crash an entry
    /// may be missing or torn, which [`get_blocking`](Self::get_blocking) treats as a
    /// miss. Two fsyncs per entry would cost more than hashing most files again.
    pub fn put_blocking(&self, path: &Path, meta: &Metadata, root: &[u8; 32], pieces: &[[u8; 32]]) -> Result<()> {
        let canonical = std::fs::canonicalize(path)?;
        let entry = Entry { version: FORMAT_VERSION, path: canonical.clone(), stamp: Stamp::of(meta), root: to_hex(root), pieces: pieces.iter().map(to_hex).collect() };
        let bytes = serde_json::to_vec(&entry).map_err(std::io::Error::other)?;
        let target = self.entry_path(&canonical);
        let tmp = target.with_extension(format!("json.tmp.{}", std::process::id()));
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f: File = opts.open(&tmp)?;
            f.write_all(&bytes)?;
        }
        std::fs::rename(&tmp, &target)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hash_file_parallel_blocking;

    fn setup(len: usize) -> (tempfile::TempDir, PathBuf, HashCache) {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f.bin");
        std::fs::write(&f, (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>()).unwrap();
        let c = HashCache::open_blocking(d.path().join("cache")).unwrap();
        (d, f, c)
    }

    #[test]
    fn hit_after_put_and_matches_fresh_hash() {
        let (_d, f, c) = setup(crate::CHUNK_SIZE as usize * 2 + 5);
        let meta = std::fs::metadata(&f).unwrap();
        assert!(c.get_blocking(&f, &meta).is_none());
        let (root, pieces) = hash_file_parallel_blocking(&f, 2).unwrap();
        c.put_blocking(&f, &meta, &root, &pieces).unwrap();
        assert_eq!(c.get_blocking(&f, &meta), Some(CachedHashes { root, pieces }));
    }

    #[test]
    fn content_change_is_a_miss() {
        let (_d, f, c) = setup(1000);
        let meta = std::fs::metadata(&f).unwrap();
        let (root, pieces) = hash_file_parallel_blocking(&f, 1).unwrap();
        c.put_blocking(&f, &meta, &root, &pieces).unwrap();
        // Same size, new content: mtime/ctime move on.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&f, vec![9u8; 1000]).unwrap();
        assert!(c.get_blocking(&f, &std::fs::metadata(&f).unwrap()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn restored_mtime_is_still_a_miss_via_ctime() {
        let (_d, f, c) = setup(1000);
        let meta = std::fs::metadata(&f).unwrap();
        let (root, pieces) = hash_file_parallel_blocking(&f, 1).unwrap();
        c.put_blocking(&f, &meta, &root, &pieces).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&f, vec![9u8; 1000]).unwrap();
        // Put the old mtime back, as `touch -r` or a sneaky tool would.
        let file = File::options().write(true).open(&f).unwrap();
        file.set_modified(meta.modified().unwrap()).unwrap();
        drop(file);
        assert!(c.get_blocking(&f, &std::fs::metadata(&f).unwrap()).is_none());
    }

    #[test]
    fn corrupt_entry_is_a_miss() {
        let (_d, f, c) = setup(1000);
        let meta = std::fs::metadata(&f).unwrap();
        let (root, pieces) = hash_file_parallel_blocking(&f, 1).unwrap();
        c.put_blocking(&f, &meta, &root, &pieces).unwrap();
        let entry = c.entry_path(&std::fs::canonicalize(&f).unwrap());
        std::fs::write(&entry, b"{not json").unwrap();
        assert!(c.get_blocking(&f, &meta).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (d, _f, _c) = setup(1);
        assert_eq!(std::fs::metadata(d.path().join("cache")).unwrap().permissions().mode() & 0o777, 0o700);
    }
}
