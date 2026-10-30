// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Persistent device identity (manual §6).
//!
//! The Ed25519 seed lives in `<data dir>/identity.key`: exactly 32 raw bytes,
//! mode 0600, in a 0700 directory, written atomically on first run. A key file
//! that other users could read is refused rather than used, since anyone who
//! read it could impersonate this device.
//!
//! Planned upgrade: store the seed in the desktop keyring via libsecret
//! (manual §6 "Linux `libsecret` or an encrypted file"); this file is the
//! fallback for headless machines.
//!
//! The secret is never printed or logged; buffers holding it are zeroized.

use std::path::{Path, PathBuf};

use dfte_core::DeviceIdentity;
use zeroize::Zeroizing;

use crate::error::CliError;
use crate::fsutil::{Existing, ensure_private_dir, write_private_atomic};

pub const KEY_FILE: &str = "identity.key";
const SEED_LEN: usize = 32;

pub fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_FILE)
}

/// Whether the identity was just created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Loaded,
    Created,
}

/// Load this device's identity, generating and saving one on first run.
pub fn load_or_create(data_dir: &Path) -> Result<(DeviceIdentity, Origin), CliError> {
    ensure_private_dir(data_dir)?;
    let path = key_path(data_dir);
    if let Some(id) = load(&path)? {
        return Ok((id, Origin::Loaded));
    }
    let id = DeviceIdentity::generate().map_err(|e| CliError::Config(format!("cannot generate a device identity: {e}")))?;
    let seed = id.secret_bytes();
    match write_private_atomic(&path, seed.as_ref(), Existing::Keep) {
        Ok(()) => {
            tracing::info!(fingerprint = %id.fingerprint(), "created new device identity");
            Ok((id, Origin::Created))
        }
        // Another dfte process created it first: use theirs so both agree.
        Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::AlreadyExists => match load(&path)? {
            Some(id) => Ok((id, Origin::Loaded)),
            None => Err(CliError::Config(format!("{} vanished while being created; run the command again.", path.display()))),
        },
        Err(e) => Err(e),
    }
}

/// `Ok(None)` if there is no key file yet.
fn load(path: &Path) -> Result<Option<DeviceIdentity>, CliError> {
    #[cfg(unix)]
    {
        match crate::fsutil::owned_file_mode(path)? {
            None => return Ok(None),
            Some(mode) if mode & 0o077 != 0 => {
                return Err(CliError::Config(format!("Refusing to use {}: it is readable by other users (mode {:o}), so the device identity may have been copied.\nFix it with: chmod 600 '{}'\nIf other people could have read it, delete it instead to create a new identity (devices that trusted this one must pair again).", path.display(), mode, path.display())));
            }
            Some(_) => {}
        }
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CliError::io(format!("cannot read {}", path.display()), e)),
    };
    let seed: Zeroizing<[u8; SEED_LEN]> = match <[u8; SEED_LEN]>::try_from(bytes.as_slice()) {
        Ok(s) => Zeroizing::new(s),
        Err(_) => return Err(CliError::Config(format!("{} is not a valid identity key ({} bytes, expected {SEED_LEN}). Move it away to create a new identity.", path.display(), bytes.len()))),
    };
    Ok(Some(DeviceIdentity::from_secret_bytes(&seed)))
}

/// This machine's name, shown to peers (unauthenticated, display only).
pub fn device_name() -> String {
    // A non-UTF-8 override/COMPUTERNAME is deliberately ignored (`.ok()`): the
    // name is cosmetic and the next source is tried instead.
    if let Some(n) = std::env::var_os("DFTE_DEVICE_NAME").and_then(|s| s.into_string().ok()).filter(|s| !s.trim().is_empty()) {
        return n.trim().to_owned();
    }
    #[cfg(unix)]
    {
        let uts = rustix::system::uname();
        let n = uts.nodename().to_string_lossy();
        if !n.is_empty() {
            return n.into_owned();
        }
    }
    #[cfg(windows)]
    if let Some(n) = std::env::var_os("COMPUTERNAME").and_then(|s| s.into_string().ok()).filter(|s| !s.is_empty()) {
        return n;
    }
    "dfte".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_once_then_loaded_with_same_fingerprint() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("dfte");
        let (a, o1) = load_or_create(&data).unwrap();
        let (b, o2) = load_or_create(&data).unwrap();
        assert_eq!((o1, o2), (Origin::Created, Origin::Loaded));
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(std::fs::read(key_path(&data)).unwrap().len(), 32);
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn modes_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("nested").join("dfte");
        load_or_create(&data).unwrap();
        assert_eq!(std::fs::metadata(&data).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(key_path(&data)).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn broader_permissions_are_refused_with_fix() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("dfte");
        load_or_create(&data).unwrap();
        let key = key_path(&data);
        for mode in [0o644, 0o640, 0o604, 0o660] {
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = load_or_create(&data).unwrap_err();
            let msg = err.user_message(None);
            assert!(matches!(err, CliError::Config(_)), "{err:?}");
            assert!(msg.contains("chmod 600"), "{msg}");
        }
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        load_or_create(&data).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_key_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("dfte");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(d.path().join("real"), [7u8; 32]).unwrap();
        std::os::unix::fs::symlink(d.path().join("real"), key_path(&data)).unwrap();
        assert!(matches!(load_or_create(&data), Err(CliError::Config(_))));
    }

    #[test]
    fn corrupt_key_is_reported_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("dfte");
        load_or_create(&data).unwrap();
        let key = key_path(&data);
        // Rewrite through the helper so permissions stay 0600.
        write_private_atomic(&key, b"short", Existing::Replace).unwrap();
        assert!(matches!(load_or_create(&data), Err(CliError::Config(_))));
        assert_eq!(std::fs::read(&key).unwrap(), b"short");
    }

    #[test]
    fn debug_output_has_no_secret() {
        let d = tempfile::tempdir().unwrap();
        let (id, _) = load_or_create(d.path()).unwrap();
        let seed = id.secret_bytes();
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!format!("{id:?}").contains(&hex));
    }
}
