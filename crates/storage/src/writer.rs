// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Receiver-side staged file: pre-allocated in the app-private staging dir,
//! written chunk-by-chunk at random offsets, verified, then renamed into place
//! (manual §14/§18/§20).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::chunk::{chunk_count, chunk_range};
use crate::error::{Result, StorageError};
use crate::fileio::{available_space_blocking, preallocate_blocking, sync_dir_blocking, sync_files_blocking, write_all_at};
use crate::hash::hash_reader_blocking;

/// Below this size a staged file is not pre-allocated: it can't fragment in a way
/// that matters, and the caller checked free space for the whole transfer.
pub const PREALLOCATE_MIN: u64 = 1 << 20;

/// Suffix of in-progress staged files.
pub const STAGING_SUFFIX: &str = ".part";

/// Deterministic staging name for file `file_index` of transfer `transfer_id`,
/// so an interrupted transfer finds its partial data again (§19).
pub fn staging_name(transfer_id: &str, file_index: usize) -> String {
    format!("{transfer_id}.{file_index}")
}

/// A partially-received file in the staging directory.
#[derive(Debug)]
pub struct StagedFile {
    file: File,
    staging_path: PathBuf,
    destination: PathBuf,
    size: u64,
}

impl StagedFile {
    /// Create (truncating any previous content) `<staging_dir>/<name>.part`,
    /// check free space and pre-allocate `size` bytes.
    ///
    /// `destination` should come from [`crate::safe_join_blocking`].
    /// Insufficient space → [`StorageError::DiskFull`], before anything is allocated.
    pub fn create_blocking(staging_dir: &Path, name: &str, destination: PathBuf, size: u64) -> Result<Self> {
        let staging_path = staging_path(staging_dir, name)?;
        std::fs::create_dir_all(staging_dir)?;
        // Any stale staged file of the same name is about to be replaced, so its
        // allocated bytes count as reclaimable. A metadata error (missing file or
        // otherwise) counts as 0 reclaimable: the space check only gets stricter.
        let reclaimable = std::fs::symlink_metadata(&staging_path).ok().filter(|m| m.is_file()).map_or(0, |m| m.len());
        ensure_space(staging_dir, size.saturating_sub(reclaimable))?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&staging_path)?;
        preallocate_blocking(&file, size)?;
        Ok(Self { file, staging_path, destination, size })
    }

    /// Like [`create_blocking`](Self::create_blocking), for a caller that already
    /// created `staging_dir` and checked free space for every file it is about to
    /// stage (one `statvfs` per transfer instead of per file). Small files are not
    /// pre-allocated ([`PREALLOCATE_MIN`]).
    pub fn create_prechecked_blocking(staging_dir: &Path, name: &str, destination: PathBuf, size: u64) -> Result<Self> {
        let staging_path = staging_path(staging_dir, name)?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&staging_path)?;
        if size >= PREALLOCATE_MIN {
            preallocate_blocking(&file, size)?;
        } else {
            file.set_len(size)?;
        }
        Ok(Self { file, staging_path, destination, size })
    }

    /// Reopen an existing staged file for resumption without discarding its data.
    /// If its length differs from `size` it is re-allocated to `size`
    /// (free space is checked for any growth).
    pub fn open_existing_blocking(staging_dir: &Path, name: &str, destination: PathBuf, size: u64) -> Result<Self> {
        let staging_path = staging_path(staging_dir, name)?;
        let file = OpenOptions::new().read(true).write(true).open(&staging_path)?;
        let current = file.metadata()?.len();
        if current != size {
            ensure_space(staging_dir, size.saturating_sub(current))?;
            preallocate_blocking(&file, size)?;
        }
        Ok(Self { file, staging_path, destination, size })
    }

    /// Expected final size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Number of chunks expected.
    pub fn chunk_count(&self) -> u64 {
        chunk_count(self.size)
    }

    /// Where the partial data lives.
    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }

    /// Where [`Self::finalize_blocking`] will move the file.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Write chunk `index`; `data.len()` must equal its exact chunk length.
    /// Chunks may arrive in any order. Takes `&self` so it can be shared.
    pub fn write_chunk_blocking(&self, index: u64, data: &[u8]) -> Result<()> {
        let (offset, len) = chunk_range(self.size, index)?;
        if data.len() as u64 != len {
            return Err(StorageError::ChunkLengthMismatch { index, expected: len, actual: data.len() as u64 });
        }
        write_all_at(&self.file, data, offset)?;
        Ok(())
    }

    /// Flush file data to stable storage.
    pub fn sync_blocking(&self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    /// fsync, verify the whole-file BLAKE3 against `expected_hash`, then
    /// atomically rename into the destination and return it.
    ///
    /// On mismatch returns [`StorageError::HashMismatch`] and leaves the staged
    /// file in place so the transfer can be repaired/resumed (§20).
    pub fn finalize_blocking(self, expected_hash: &[u8; 32]) -> Result<PathBuf> {
        self.file.sync_all()?;
        let actual = hash_reader_blocking(File::open(&self.staging_path)?)?;
        self.commit_blocking(expected_hash, actual)
    }

    /// Like [`finalize_blocking`](Self::finalize_blocking) but derives the whole-file
    /// hash from the per-chunk [`crate::piece_hash`]es computed while receiving,
    /// instead of reading the file back (manual §20). Verifies what was written
    /// from memory; use `finalize_blocking` to also re-check what the OS returns.
    pub fn finalize_with_pieces_blocking(self, expected_hash: &[u8; 32], pieces: &[[u8; 32]]) -> Result<PathBuf> {
        let mut out = finalize_batch_blocking(vec![(self, *expected_hash, pieces.to_vec())])?;
        out.pop().ok_or(StorageError::PieceCountMismatch { expected: 1, actual: 0 })
    }

    fn commit_blocking(self, expected_hash: &[u8; 32], actual: [u8; 32]) -> Result<PathBuf> {
        let destination = self.verify_and_move_blocking(expected_hash, actual)?;
        if let Some(parent) = destination.parent() {
            sync_dir_blocking(parent)?;
        }
        Ok(destination)
    }

    /// Hash check, then rename into place. The caller made the data durable first and
    /// makes the destination directory durable after.
    fn verify_and_move_blocking(self, expected_hash: &[u8; 32], actual: [u8; 32]) -> Result<PathBuf> {
        if &actual != expected_hash {
            return Err(StorageError::HashMismatch { path: self.staging_path, expected: *expected_hash, actual });
        }
        let Self { file, staging_path, destination, .. } = self;
        // Windows cannot rename a file with an open handle.
        drop(file);
        move_file_blocking(&staging_path, &destination)?;
        Ok(destination)
    }
}

/// Makes the data of several staged files (one staging directory) durable with one
/// filesystem sync (see [`sync_files_blocking`]).
pub fn sync_staged_blocking(files: &[&StagedFile]) -> Result<()> {
    sync_files_blocking(&files.iter().map(|sf| &sf.file).collect::<Vec<_>>())?;
    Ok(())
}

/// Finalizes many staged files (all in one staging directory) with their expected
/// whole-file hashes and per-chunk piece hashes, like
/// [`StagedFile::finalize_with_pieces_blocking`] but with one filesystem sync for all
/// of them and one fsync per distinct destination directory, instead of a file sync and
/// a directory sync per file (manual §19/§20 durability order kept: data, rename, dir).
///
/// Returns the destinations in input order. On an error, files before the failing
/// one are already in place and the rest stay staged.
pub fn finalize_batch_blocking(items: Vec<(StagedFile, [u8; 32], Vec<[u8; 32]>)>) -> Result<Vec<PathBuf>> {
    let mut actual = Vec::with_capacity(items.len());
    for (sf, _, pieces) in &items {
        let Some(h) = crate::file_hash_from_pieces(sf.size, pieces) else {
            return Err(StorageError::PieceCountMismatch { expected: sf.chunk_count().max(1), actual: pieces.len() as u64 });
        };
        actual.push(h);
    }
    sync_files_blocking(&items.iter().map(|(sf, ..)| &sf.file).collect::<Vec<_>>())?;
    let mut out = Vec::with_capacity(items.len());
    for ((sf, expected, _), actual) in items.into_iter().zip(actual) {
        out.push(sf.verify_and_move_blocking(&expected, actual)?);
    }
    let mut dirs: Vec<&Path> = out.iter().filter_map(|p| p.parent()).collect();
    dirs.sort_unstable();
    dirs.dedup();
    for d in dirs {
        sync_dir_blocking(d)?;
    }
    Ok(out)
}

fn staging_path(staging_dir: &Path, name: &str) -> Result<PathBuf> {
    let ok = !name.is_empty() && name.len() <= 200 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) && !name.starts_with('.');
    if !ok {
        return Err(StorageError::InvalidPath { path: name.chars().take(256).collect(), reason: "invalid staging name" });
    }
    Ok(staging_dir.join(format!("{name}{STAGING_SUFFIX}")))
}

fn ensure_space(dir: &Path, needed: u64) -> Result<()> {
    if needed == 0 {
        return Ok(());
    }
    let available = available_space_blocking(dir)?;
    if available < needed {
        return Err(StorageError::DiskFull { needed, available });
    }
    Ok(())
}

/// Rename; if staging and destination are on different volumes, fall back to
/// copy + fsync + remove (no longer metadata-only, but still correct).
fn move_file_blocking(from: &Path, to: &Path) -> Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            std::fs::copy(from, to)?;
            File::open(to)?.sync_all()?;
            std::fs::remove_file(from)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chunk::{CHUNK_SIZE, chunk_len, chunk_offset};
    use crate::hash::hash_chunk;

    fn data(size: u64) -> Vec<u8> {
        (0..size).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn chunk(d: &[u8], i: u64) -> &[u8] {
        let off = chunk_offset(i).unwrap() as usize;
        let len = chunk_len(d.len() as u64, i).unwrap() as usize;
        &d[off..off + len]
    }

    #[test]
    fn out_of_order_writes_finalize() {
        let staging = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let size = 2 * CHUNK_SIZE + 12_345;
        let d = data(size);
        let dest = dest_dir.path().join("out.bin");
        let sf = StagedFile::create_blocking(staging.path(), "t1.0", dest.clone(), size).unwrap();
        assert_eq!(std::fs::metadata(sf.staging_path()).unwrap().len(), size);
        for i in [2, 0, 1] {
            sf.write_chunk_blocking(i, chunk(&d, i)).unwrap();
        }
        assert!(matches!(sf.write_chunk_blocking(3, b"x"), Err(StorageError::ChunkOutOfRange { .. })));
        assert!(matches!(sf.write_chunk_blocking(2, b"short"), Err(StorageError::ChunkLengthMismatch { .. })));
        let staged = sf.staging_path().to_path_buf();
        let out = sf.finalize_blocking(&hash_chunk(&d)).unwrap();
        assert_eq!(out, dest);
        assert_eq!(std::fs::read(&dest).unwrap(), d);
        assert!(!staged.exists());
    }

    #[test]
    fn hash_mismatch_keeps_staged_file_and_resumes() {
        let staging = tempfile::tempdir().unwrap();
        let size = CHUNK_SIZE + 10;
        let d = data(size);
        let dest = staging.path().join("final.bin");
        let sf = StagedFile::create_blocking(staging.path(), "t2.0", dest.clone(), size).unwrap();
        sf.write_chunk_blocking(0, chunk(&d, 0)).unwrap(); // chunk 1 never written
        let staged = sf.staging_path().to_path_buf();
        let err = sf.finalize_blocking(&hash_chunk(&d)).unwrap_err();
        assert!(matches!(err, StorageError::HashMismatch { .. }));
        assert!(staged.exists(), "staged file kept for resume");
        assert!(!dest.exists());

        let sf = StagedFile::open_existing_blocking(staging.path(), "t2.0", dest.clone(), size).unwrap();
        sf.write_chunk_blocking(1, chunk(&d, 1)).unwrap();
        sf.finalize_blocking(&hash_chunk(&d)).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), d);
    }

    #[test]
    fn finalize_with_pieces_skips_reread() {
        let staging = tempfile::tempdir().unwrap();
        let size = 2 * CHUNK_SIZE + 5;
        let d = data(size);
        let dest = staging.path().join("p.bin");
        let sf = StagedFile::create_blocking(staging.path(), "t4.0", dest.clone(), size).unwrap();
        let mut pieces = Vec::new();
        for i in 0..3 {
            sf.write_chunk_blocking(i, chunk(&d, i)).unwrap();
            pieces.push(crate::piece_hash(size, i, chunk(&d, i)));
        }
        assert!(matches!(StagedFile::open_existing_blocking(staging.path(), "t4.0", dest.clone(), size).unwrap().finalize_with_pieces_blocking(&hash_chunk(&d), &pieces[..2]), Err(StorageError::PieceCountMismatch { expected: 3, actual: 2 })));
        let mut bad = pieces.clone();
        bad[1][0] ^= 1;
        assert!(matches!(StagedFile::open_existing_blocking(staging.path(), "t4.0", dest.clone(), size).unwrap().finalize_with_pieces_blocking(&hash_chunk(&d), &bad), Err(StorageError::HashMismatch { .. })));
        sf.finalize_with_pieces_blocking(&hash_chunk(&d), &pieces).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), d);
    }

    #[test]
    fn zero_byte_file() {
        let staging = tempfile::tempdir().unwrap();
        let dest = staging.path().join("empty");
        let sf = StagedFile::create_blocking(staging.path(), "t3.0", dest.clone(), 0).unwrap();
        assert_eq!(sf.chunk_count(), 0);
        sf.finalize_blocking(&hash_chunk(b"")).unwrap();
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), 0);
    }

    #[test]
    fn disk_full_fails_fast() {
        let staging = tempfile::tempdir().unwrap();
        let err = StagedFile::create_blocking(staging.path(), "huge", staging.path().join("x"), u64::MAX / 2).unwrap_err();
        assert!(matches!(err, StorageError::DiskFull { .. }), "{err:?}");
        assert!(!staging.path().join("huge.part").exists());
    }

    #[test]
    fn rejects_bad_staging_names() {
        let staging = tempfile::tempdir().unwrap();
        for name in ["", "../x", "a/b", ".hidden", "a\\b"] {
            assert!(matches!(StagedFile::create_blocking(staging.path(), name, staging.path().join("x"), 1), Err(StorageError::InvalidPath { .. })));
        }
        assert_eq!(staging_name("abc", 3), "abc.3");
    }
}
