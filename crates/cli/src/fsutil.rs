//! Private-file helpers: 0700 directories, atomic 0600 writes, permission checks.
//!
//! On non-Unix platforms the permission parts are no-ops (the per-user profile
//! directory is already private); the planned keystore integration (manual §6:
//! libsecret / DPAPI / Keychain) replaces the key file entirely.

use std::io::Write;
use std::path::Path;

use crate::error::CliError;

/// Create `dir` (and parents) if missing; a directory created here is 0700.
/// An existing directory readable by others is reported, not changed.
pub fn ensure_private_dir(dir: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match std::fs::metadata(dir) {
            Ok(m) if m.is_dir() => {
                if m.permissions().mode() & 0o077 != 0 {
                    tracing::warn!(dir = %dir.display(), mode = format_args!("{:o}", m.permissions().mode() & 0o777), "data directory is accessible by other users; consider chmod 700");
                }
                Ok(())
            }
            Ok(_) => Err(CliError::Config(format!("{} exists but is not a directory.", dir.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| CliError::io(format!("cannot create {}", dir.display()), e)),
            Err(e) => Err(CliError::io(format!("cannot access {}", dir.display()), e)),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| CliError::io(format!("cannot create {}", dir.display()), e))
    }
}

/// How [`write_private_atomic`] treats an existing file at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    Replace,
    /// Fail with `AlreadyExists` instead of replacing (first-run races).
    Keep,
}

/// Write `bytes` to `path` atomically: a 0600 temp file in the same directory,
/// fsynced, then renamed over (or linked to) the destination, then the
/// directory is fsynced so the rename survives a crash.
pub fn write_private_atomic(path: &Path, bytes: &[u8], existing: Existing) -> Result<(), CliError> {
    let dir = path.parent().ok_or_else(|| CliError::Config(format!("{} has no parent directory", path.display())))?;
    let ctx = |what: &str| format!("cannot {what} {}", path.display());
    // tempfile creates the file with mode 0600 on Unix.
    let mut tmp = tempfile::Builder::new().prefix(".dfte-").suffix(".tmp").tempfile_in(dir).map_err(|e| CliError::io(ctx("create a temporary file for"), e))?;
    tmp.write_all(bytes).map_err(|e| CliError::io(ctx("write"), e))?;
    tmp.as_file().sync_all().map_err(|e| CliError::io(ctx("sync"), e))?;
    match existing {
        Existing::Replace => tmp.persist(path).map(drop).map_err(|e| CliError::io(ctx("save"), e.error))?,
        Existing::Keep => tmp.persist_noclobber(path).map(drop).map_err(|e| CliError::io(ctx("save"), e.error))?,
    }
    sync_dir(dir)
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn sync_dir(dir: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| CliError::io(format!("cannot sync {}", dir.display()), e))
    }
    #[cfg(not(unix))]
    {
        // Windows has no directory fsync; NTFS journals the rename itself.
        Ok(())
    }
}

/// Unix permission bits of a regular, non-symlink file `path` owned by us.
/// `Ok(None)` if it doesn't exist.
#[cfg(unix)]
pub fn owned_file_mode(path: &Path) -> Result<Option<u32>, CliError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CliError::io(format!("cannot access {}", path.display()), e)),
    };
    if !m.file_type().is_file() {
        return Err(CliError::Config(format!("{} is not a regular file (symlinks are refused). Remove it and run the command again.", path.display())));
    }
    if m.uid() != rustix::process::getuid().as_raw() {
        return Err(CliError::Config(format!("{} is owned by another user. Remove it, or fix it with: chown $(id -u) '{}'", path.display(), path.display())));
    }
    Ok(Some(m.permissions().mode() & 0o7777))
}
