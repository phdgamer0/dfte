//! Chunk arithmetic and the sender-side chunk reader (manual §17/§18).
//!
//! All size/offset/count math is `u64` and checked, so nothing silently wraps
//! at 4 GiB / 8 GiB boundaries.

use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Result, StorageError};
use crate::fileio::read_exact_at;

/// Fixed v1 chunk size: 4 MiB (manual §17). Matches the buffer-pool buffer size.
pub const CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Number of chunks in a file of `size` bytes: `ceil(size / CHUNK_SIZE)`. Zero for empty files.
pub const fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE)
}

/// Byte offset of chunk `index`, or `None` if it would overflow `u64`.
pub const fn chunk_offset(index: u64) -> Option<u64> {
    index.checked_mul(CHUNK_SIZE)
}

/// Length of chunk `index` in a file of `size` bytes, or `None` if `index` is out of range.
/// Every chunk is `CHUNK_SIZE` except the last, which is `size - offset`.
pub const fn chunk_len(size: u64, index: u64) -> Option<u64> {
    match chunk_offset(index) {
        Some(off) if off < size => {
            let rest = size - off;
            Some(if rest < CHUNK_SIZE { rest } else { CHUNK_SIZE })
        }
        _ => None,
    }
}

/// `(offset, len)` for chunk `index`, or [`StorageError::ChunkOutOfRange`].
pub fn chunk_range(size: u64, index: u64) -> Result<(u64, u64)> {
    match (chunk_offset(index), chunk_len(size, index)) {
        (Some(off), Some(len)) => Ok((off, len)),
        _ => Err(StorageError::ChunkOutOfRange { index, count: chunk_count(size) }),
    }
}

/// Size + mtime snapshot used to detect a source file changing mid-send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    size: u64,
    modified: Option<SystemTime>,
}

impl Snapshot {
    fn of(meta: &Metadata) -> Self {
        Self { size: meta.len(), modified: meta.modified().ok() }
    }
}

/// Positional chunk reader over a source file.
///
/// Takes a size/mtime snapshot at open; every read re-checks it (one `fstat`
/// per 4 MiB chunk) and fails with [`StorageError::SourceFileChanged`] on drift.
/// Reads take `&self`, so one reader can be shared (e.g. in an `Arc`) across
/// blocking tasks.
#[derive(Debug)]
pub struct ChunkReader {
    file: File,
    path: PathBuf,
    snapshot: Snapshot,
}

impl ChunkReader {
    /// Open `path` for chunked reading. Missing file → [`StorageError::SourceFileMissing`].
    pub fn open_blocking(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = crate::fileio::open_source(&path).map_err(|e| missing_or_io(e, &path))?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(StorageError::Io(io::Error::new(io::ErrorKind::InvalidInput, "source is not a regular file")));
        }
        Ok(Self { file, snapshot: Snapshot::of(&meta), path })
    }

    /// File size at open time.
    pub fn size(&self) -> u64 {
        self.snapshot.size
    }

    /// Number of chunks at open time.
    pub fn chunk_count(&self) -> u64 {
        chunk_count(self.snapshot.size)
    }

    /// Path the reader was opened with.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read chunk `index` into the front of `buf`, returning the chunk length.
    ///
    /// `buf` must hold at least [`chunk_len`] bytes. Returns
    /// [`StorageError::SourceFileChanged`] if size/mtime differ from the open-time
    /// snapshot (checked before and after the read) or the file got truncated.
    pub fn read_chunk_blocking(&self, index: u64, buf: &mut [u8]) -> Result<usize> {
        let (offset, len) = chunk_range(self.snapshot.size, index)?;
        let len_usize = usize::try_from(len).map_err(|_| StorageError::BufferTooSmall { needed: len, capacity: buf.len() as u64 })?;
        let Some(dst) = buf.get_mut(..len_usize) else {
            return Err(StorageError::BufferTooSmall { needed: len, capacity: buf.len() as u64 });
        };
        self.check_unchanged()?;
        match read_exact_at(&self.file, dst, offset) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(self.changed());
            }
            Err(e) => return Err(e.into()),
        }
        self.check_unchanged()?;
        Ok(len_usize)
    }

    fn check_unchanged(&self) -> Result<()> {
        let meta = self.file.metadata()?;
        if Snapshot::of(&meta) == self.snapshot { Ok(()) } else { Err(self.changed()) }
    }

    fn changed(&self) -> StorageError {
        StorageError::SourceFileChanged { path: self.path.clone() }
    }
}

fn missing_or_io(e: io::Error, path: &Path) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound { StorageError::SourceFileMissing { path: path.to_path_buf() } } else { StorageError::Io(e) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Write;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn empty_file_has_no_chunks() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_len(0, 0), None);
    }

    #[test]
    fn exact_multiple_and_plus_one() {
        assert_eq!(chunk_count(CHUNK_SIZE), 1);
        assert_eq!(chunk_len(CHUNK_SIZE, 0), Some(CHUNK_SIZE));
        assert_eq!(chunk_len(CHUNK_SIZE, 1), None);
        assert_eq!(chunk_count(CHUNK_SIZE + 1), 2);
        assert_eq!(chunk_len(CHUNK_SIZE + 1, 1), Some(1));
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_len(1, 0), Some(1));
        assert_eq!(chunk_count(CHUNK_SIZE - 1), 1);
    }

    #[test]
    fn gib_boundaries() {
        for size in [4 * GIB - 1, 4 * GIB, 4 * GIB + 1, 8 * GIB - 1, 8 * GIB, 8 * GIB + 1] {
            let n = chunk_count(size);
            let last = n - 1;
            assert_eq!(chunk_offset(last).unwrap() + chunk_len(size, last).unwrap(), size);
            assert_eq!(chunk_len(size, n), None);
        }
        assert_eq!(chunk_count(4 * GIB), 1024);
        assert_eq!(chunk_offset(1024), Some(4 * GIB));
        // u32::MAX bytes would truncate if anything used u32 math.
        assert_eq!(chunk_count(u64::from(u32::MAX) + 1), 1024);
    }

    #[test]
    fn u64_extremes_do_not_overflow() {
        let n = chunk_count(u64::MAX);
        assert_eq!(n, u64::MAX / CHUNK_SIZE + 1);
        let last = n - 1;
        assert_eq!(chunk_len(u64::MAX, last), Some(u64::MAX - chunk_offset(last).unwrap()));
        assert_eq!(chunk_offset(u64::MAX), None);
        assert_eq!(chunk_len(u64::MAX, u64::MAX), None);
        assert!(matches!(chunk_range(u64::MAX, n), Err(StorageError::ChunkOutOfRange { .. })));
    }

    proptest! {
        #[test]
        fn chunk_lens_sum_to_size(size in 0u64..(64 * CHUNK_SIZE)) {
            let n = chunk_count(size);
            let mut sum = 0u64;
            for i in 0..n {
                let len = chunk_len(size, i).unwrap();
                prop_assert!(len > 0 && len <= CHUNK_SIZE);
                prop_assert_eq!(chunk_offset(i).unwrap(), sum);
                sum += len;
            }
            prop_assert_eq!(sum, size);
            prop_assert_eq!(chunk_len(size, n), None);
        }

        #[test]
        fn last_chunk_closes_file(size in 1u64..=u64::MAX) {
            let last = chunk_count(size) - 1;
            prop_assert_eq!(chunk_offset(last).unwrap() + chunk_len(size, last).unwrap(), size);
        }
    }

    fn write_file(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    #[test]
    fn reader_reads_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..CHUNK_SIZE + 100).map(|i| (i % 251) as u8).collect();
        let p = write_file(dir.path(), "src", &data);
        let r = ChunkReader::open_blocking(&p).unwrap();
        assert_eq!(r.chunk_count(), 2);
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        let n = r.read_chunk_blocking(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], &data[..CHUNK_SIZE as usize]);
        let n = r.read_chunk_blocking(1, &mut buf).unwrap();
        assert_eq!(n, 100);
        assert_eq!(&buf[..n], &data[CHUNK_SIZE as usize..]);
        assert!(matches!(r.read_chunk_blocking(2, &mut buf), Err(StorageError::ChunkOutOfRange { .. })));
        let mut small = [0u8; 10];
        assert!(matches!(r.read_chunk_blocking(1, &mut small), Err(StorageError::BufferTooSmall { .. })));
    }

    #[test]
    fn reader_detects_missing_and_changed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(ChunkReader::open_blocking(dir.path().join("nope")), Err(StorageError::SourceFileMissing { .. })));
        let p = write_file(dir.path(), "src", &[7u8; 1000]);
        let r = ChunkReader::open_blocking(&p).unwrap();
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"more").unwrap();
        let mut buf = vec![0u8; 2000];
        assert!(matches!(r.read_chunk_blocking(0, &mut buf), Err(StorageError::SourceFileChanged { .. })));
    }
}
