//! Cross-platform positional I/O, pre-allocation and free-space helpers (manual §14).
//!
//! Everything here is blocking; call from `spawn_blocking` in async code.

use std::fs::File;
use std::io;
use std::path::Path;

/// Opens a file chosen for sending. On Linux/Android a path that is (or links
/// to) `/proc/self/fd/N` duplicates that descriptor instead of reopening it
/// (see `procfd`); everything else is a plain open.
pub fn open_source(path: &Path) -> io::Result<File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(f) = crate::procfd::dup(path) {
        return f;
    }
    File::open(path)
}

/// `std::fs::metadata` for a file chosen for sending, through [`open_source`]
/// when the path is a descriptor link (stat on it would hit the same refusal).
pub fn source_metadata(path: &Path) -> io::Result<std::fs::Metadata> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(f) = crate::procfd::dup(path) {
        return f?.metadata();
    }
    std::fs::metadata(path)
}

/// Read exactly `buf.len()` bytes starting at `offset`, without moving any shared cursor.
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut buf = buf;
        let mut offset = offset;
        while !buf.is_empty() {
            match file.seek_read(buf, offset) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Write all of `buf` starting at `offset`, without moving any shared cursor.
pub fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut buf = buf;
        let mut offset = offset;
        while !buf.is_empty() {
            match file.seek_write(buf, offset) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer"));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Reserve `len` bytes for `file` and set its length to `len`.
///
/// Linux/Android use `fallocate(2)` so blocks are actually reserved; filesystems
/// that don't support it (and every other OS) fall back to `File::set_len`.
pub fn preallocate_blocking(file: &File, len: u64) -> io::Result<()> {
    if len == 0 {
        return file.set_len(0);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::fs::{FallocateFlags, fallocate};
        use rustix::io::Errno;
        match fallocate(file, FallocateFlags::empty(), 0, len) {
            Ok(()) => {
                // fallocate never shrinks; make the logical length exact.
                if file.metadata()?.len() != len {
                    file.set_len(len)?;
                }
                return Ok(());
            }
            Err(e) if e == Errno::OPNOTSUPP || e == Errno::NOSYS => {}
            Err(e) => return Err(e.into()),
        }
    }
    file.set_len(len)
}

/// Bytes available to an unprivileged user on the filesystem holding `path`.
pub fn available_space_blocking(path: &Path) -> io::Result<u64> {
    fs4::available_space(path)
}

/// Makes `files` durable. They must all live on one filesystem (the staging volume).
///
/// Per-file fsyncs each force their own journal commit, which on phone eMMC cost
/// ~3 ms apiece (2000 small files: 7 s). So on Linux/Android one `syncfs` writes
/// everything back in a single commit first; the per-file `fsync` after it has
/// nothing left to write and is cheap, and it still reports a writeback error for
/// that file (`syncfs` only reports them from Linux 5.8).
pub fn sync_files_blocking(files: &[&File]) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(first) = files.first() {
        rustix::fs::syncfs(first)?;
    }
    for f in files {
        f.sync_all()?;
    }
    Ok(())
}

/// fsync a directory so a preceding rename/create in it is durable.
/// No-op on Windows, where directories cannot be opened this way.
pub fn sync_dir_blocking(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn positional_round_trip_and_prealloc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        preallocate_blocking(&f, 10_000).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 10_000);
        write_all_at(&f, b"world", 5000).unwrap();
        write_all_at(&f, b"hello", 0).unwrap();
        let mut a = [0u8; 5];
        read_exact_at(&f, &mut a, 5000).unwrap();
        assert_eq!(&a, b"world");
        read_exact_at(&f, &mut a, 0).unwrap();
        assert_eq!(&a, b"hello");
        let mut big = [0u8; 16];
        assert_eq!(read_exact_at(&f, &mut big, 9_990).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(available_space_blocking(dir.path()).unwrap() > 0);
        sync_dir_blocking(dir.path()).unwrap();
    }
}
