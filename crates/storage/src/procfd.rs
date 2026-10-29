//! Source files the platform hands over as open descriptors.
//!
//! Android's file picker grants access to a file, not to its path: the app
//! gets an open descriptor, and on Android 11+ (scoped storage behind FUSE)
//! reopening `/proc/self/fd/N` is refused because the app has no permission
//! for the underlying path. The Android shim therefore passes a symlink named
//! after the file that points at `/proc/self/fd/N`, and keeps the descriptor
//! open for as long as the transfer may read it. Here such a path is turned
//! into a duplicate of descriptor N instead of a reopen.
//!
//! All source reads are positional (`read_exact_at`), so sharing a file offset
//! with the original descriptor is harmless.
#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::path::{Path, PathBuf};

const PREFIX: &str = "/proc/self/fd/";

/// `Some(dup of N)` when `path` is `/proc/self/fd/N` or a symlink to it; `None`
/// for every other path, which callers then open normally.
pub(crate) fn dup(path: &Path) -> Option<io::Result<File>> {
    let target: PathBuf = if path.starts_with(PREFIX) { path.to_path_buf() } else { std::fs::read_link(path).ok()? };
    let n: RawFd = target.to_str()?.strip_prefix(PREFIX)?.parse().ok()?;
    if n < 0 {
        return None;
    }
    // SAFETY: `borrow_raw` needs `n` to stay open while borrowed. The borrow
    // lives only for the `dup` below; if `n` is not open, `dup` fails with
    // EBADF and nothing else happens. The platform shim owns `n` and closes it
    // only after the transfer ends, and a reused number would be caught by the
    // size/mtime snapshot checks every reader does (it is never closed here).
    let fd = unsafe { BorrowedFd::borrow_raw(n) };
    Some(fd.try_clone_to_owned().map(File::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    #[test]
    fn symlink_to_proc_fd_dups_the_open_descriptor() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real.bin");
        std::fs::write(&real, b"hello").unwrap();
        let held = File::open(&real).unwrap();
        let link = d.path().join("picked.bin");
        std::os::unix::fs::symlink(format!("{PREFIX}{}", held.as_raw_fd()), &link).unwrap();
        // Even with the real path gone (like a FUSE path the app may not open), the dup reads.
        std::fs::remove_file(&real).unwrap();
        let mut s = String::new();
        dup(&link).unwrap().unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn ordinary_paths_and_bad_numbers_are_not_taken() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("plain.txt");
        std::fs::write(&f, b"x").unwrap();
        assert!(dup(&f).is_none());
        let link = d.path().join("other");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(dup(&link).is_none());
        assert!(dup(Path::new("/proc/self/fd/not-a-number")).is_none());
        assert!(dup(Path::new("/proc/self/fd/987654")).unwrap().is_err(), "closed descriptor → EBADF, not a panic");
    }
}
