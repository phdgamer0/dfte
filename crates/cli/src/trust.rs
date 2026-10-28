//! Pinned peers (`trusted.json`, 0600).
//!
//! A pinned fingerprint skips the SAS prompt on later connections (manual §9.1
//! "fingerprint-pin auto-accept for a previously trusted peer"). A peer only gets
//! here after the user verified it: by confirming the SAS and answering
//! "always", or by typing its fingerprint into `dfte trust add` after comparing
//! it out of band. There is no way to pin a peer without one of those (§35).
//!
//! Names are local labels chosen by the user (or copied from the peer's
//! self-reported name on "always", then editable); they are only used to pick a
//! peer with `--to NAME`, never to authorize one.

use std::path::{Path, PathBuf};

use discovery::fingerprint::{format_fingerprint, parse_fingerprint};
use serde::{Deserialize, Serialize};

use crate::error::CliError;
use crate::fsutil::{Existing, ensure_private_dir, write_private_atomic};

pub const TRUST_FILE: &str = "trusted.json";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPeer {
    /// Canonical `crypto::fingerprint_of` form.
    pub fingerprint: String,
    pub name: String,
    /// Unix seconds when pinned.
    pub added: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TrustFile {
    version: u32,
    peers: Vec<TrustedPeer>,
}

#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    peers: Vec<TrustedPeer>,
}

/// Canonical fingerprint for user input, or `None` if it isn't one.
pub fn normalize_fingerprint(text: &str) -> Option<String> {
    parse_fingerprint(text.trim()).map(|b| format_fingerprint(&b))
}

fn valid_name(name: &str) -> Result<&str, CliError> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
        return Err(CliError::Usage("A trusted device name must be 1–64 printable characters.".into()));
    }
    if normalize_fingerprint(n).is_some() || n.parse::<std::net::SocketAddr>().is_ok() {
        return Err(CliError::Usage(format!("{n:?} looks like a fingerprint or address; pick a name that doesn't, so --to stays unambiguous.")));
    }
    Ok(n)
}

fn now_secs() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            tracing::warn!(error = %e, "system clock is before 1970; recording pin time as 0");
            0
        }
    }
}

impl TrustStore {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(TRUST_FILE)
    }

    /// Load (an absent file is an empty store). A file other users can write is
    /// refused: whoever can edit it can make this device trust them.
    pub fn load(data_dir: &Path) -> Result<Self, CliError> {
        let path = Self::path(data_dir);
        #[cfg(unix)]
        if let Some(mode) = crate::fsutil::owned_file_mode(&path)?
            && mode & 0o022 != 0
        {
            return Err(CliError::Config(format!("Refusing to use {}: other users can modify it (mode {mode:o}), so it may list devices you never trusted.\nFix it with: chmod 600 '{}' (and check its contents with `dfte trust list`)", path.display(), path.display())));
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self { path, peers: Vec::new() }),
            Err(e) => return Err(CliError::io(format!("cannot read {}", path.display()), e)),
        };
        let file: TrustFile = serde_json::from_str(&text).map_err(|e| CliError::Config(format!("{} is not a valid trust store ({e}). Fix or remove it.", path.display())))?;
        if file.version != FORMAT_VERSION {
            return Err(CliError::Config(format!("{} has unsupported version {}; it was written by a newer dfte.", path.display(), file.version)));
        }
        let mut peers = Vec::with_capacity(file.peers.len());
        for p in file.peers {
            let fingerprint = normalize_fingerprint(&p.fingerprint).ok_or_else(|| CliError::Config(format!("{} contains an invalid fingerprint {:?}. Fix or remove it.", path.display(), p.fingerprint)))?;
            peers.push(TrustedPeer { fingerprint, ..p });
        }
        Ok(Self { path, peers })
    }

    pub fn save(&self) -> Result<(), CliError> {
        if let Some(dir) = self.path.parent() {
            ensure_private_dir(dir)?;
        }
        let file = TrustFile { version: FORMAT_VERSION, peers: self.peers.clone() };
        let json = serde_json::to_vec_pretty(&file).map_err(|e| CliError::Config(format!("cannot encode trust store: {e}")))?;
        write_private_atomic(&self.path, &json, Existing::Replace)
    }

    pub fn peers(&self) -> &[TrustedPeer] {
        &self.peers
    }

    pub fn get(&self, fingerprint: &str) -> Option<&TrustedPeer> {
        let fp = normalize_fingerprint(fingerprint)?;
        self.peers.iter().find(|p| p.fingerprint == fp)
    }

    /// Entries whose name matches (case-insensitively).
    pub fn by_name(&self, name: &str) -> Vec<&TrustedPeer> {
        let n = name.trim();
        self.peers.iter().filter(|p| p.name.eq_ignore_ascii_case(n) || p.name == n).collect()
    }

    /// Pin `fingerprint` as `name`, replacing an earlier entry for the same
    /// fingerprint (rename). Fails if another device already uses `name`.
    pub fn add(&mut self, fingerprint: &str, name: &str) -> Result<&TrustedPeer, CliError> {
        let fp = normalize_fingerprint(fingerprint).ok_or_else(|| CliError::Usage(format!("{fingerprint:?} is not a device fingerprint (expected 24 hex digits like a1b2-c3d4-e5f6-0718-293a-4b5c).")))?;
        let name = valid_name(name)?;
        if self.by_name(name).iter().any(|p| p.fingerprint != fp) {
            return Err(CliError::Usage(format!("Another trusted device is already called {name:?}; pick a different name.")));
        }
        self.peers.retain(|p| p.fingerprint != fp);
        self.peers.push(TrustedPeer { fingerprint: fp, name: name.to_owned(), added: now_secs() });
        self.peers.last().ok_or_else(|| CliError::Config("trust store update lost".into()))
    }

    /// Pin a peer the user just verified, deriving a free name from its
    /// self-reported one.
    pub fn add_verified(&mut self, fingerprint: &str, reported_name: &str) -> Result<&TrustedPeer, CliError> {
        let base: String = reported_name.chars().filter(|c| !c.is_control()).take(48).collect::<String>().trim().to_owned();
        let base = if valid_name(&base).is_ok() { base } else { "device".to_owned() };
        let short: String = normalize_fingerprint(fingerprint).unwrap_or_default().chars().take(4).collect();
        let mut name = base.clone();
        for n in 1.. {
            let free = self.by_name(&name).iter().all(|p| normalize_fingerprint(fingerprint).as_deref() == Some(p.fingerprint.as_str()));
            if free {
                break;
            }
            name = if n == 1 { format!("{base}-{short}") } else { format!("{base}-{short}-{n}") };
        }
        self.add(fingerprint, &name)
    }

    /// Remove by fingerprint or name; returns what was removed.
    pub fn remove(&mut self, who: &str) -> Result<TrustedPeer, CliError> {
        let idx = match normalize_fingerprint(who) {
            Some(fp) => self.peers.iter().position(|p| p.fingerprint == fp),
            None => {
                let hits: Vec<usize> = self.peers.iter().enumerate().filter(|(_, p)| p.name.eq_ignore_ascii_case(who.trim())).map(|(i, _)| i).collect();
                if hits.len() > 1 {
                    return Err(CliError::Usage(format!("Several trusted devices are called {who:?}; remove one by fingerprint.")));
                }
                hits.first().copied()
            }
        };
        match idx {
            Some(i) => Ok(self.peers.remove(i)),
            None => Err(CliError::NotFound(format!("No trusted device matches {who:?}. See `dfte trust list`."))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "a1b2-c3d4-e5f6-0718-293a-4b5c";
    const FP_B: &str = "0000-1111-2222-3333-4444-5555";

    #[test]
    fn add_list_remove_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let mut t = TrustStore::load(d.path()).unwrap();
        assert!(t.peers().is_empty());
        t.add("A1B2C3D4E5F60718293A4B5C", "laptop").unwrap();
        t.add(FP_B, "phone").unwrap();
        t.save().unwrap();

        let mut t = TrustStore::load(d.path()).unwrap();
        assert_eq!(t.peers().len(), 2);
        assert_eq!(t.get(FP_A).unwrap().name, "laptop");
        assert_eq!(t.by_name("LAPTOP").len(), 1);
        // Renaming keeps one entry per fingerprint.
        t.add(FP_A, "work laptop").unwrap();
        assert_eq!(t.peers().len(), 2);
        assert_eq!(t.remove("phone").unwrap().fingerprint, FP_B);
        assert_eq!(t.remove(FP_A).unwrap().name, "work laptop");
        assert!(matches!(t.remove("nobody"), Err(CliError::NotFound(_))));
    }

    #[test]
    fn rejects_bad_input() {
        let d = tempfile::tempdir().unwrap();
        let mut t = TrustStore::load(d.path()).unwrap();
        assert!(t.add("not-a-fingerprint", "x").is_err());
        assert!(t.add(FP_A, "").is_err());
        assert!(t.add(FP_A, FP_B).is_err(), "name that parses as a fingerprint");
        assert!(t.add(FP_A, "10.0.0.1:5000").is_err(), "name that parses as an address");
        t.add(FP_A, "laptop").unwrap();
        assert!(t.add(FP_B, "laptop").is_err(), "duplicate name for another device");
    }

    #[test]
    fn add_verified_picks_a_free_name() {
        let d = tempfile::tempdir().unwrap();
        let mut t = TrustStore::load(d.path()).unwrap();
        t.add(FP_A, "box").unwrap();
        let p = t.add_verified(FP_B, "box").unwrap().clone();
        assert_eq!(p.name, "box-0000");
        let p = t.add_verified(FP_A, "\u{7}").unwrap().clone();
        assert_eq!(p.name, "device");
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_store() {
        let d = tempfile::tempdir().unwrap();
        write_private_atomic(&TrustStore::path(d.path()), b"{nope", Existing::Replace).unwrap();
        assert!(matches!(TrustStore::load(d.path()), Err(CliError::Config(_))));
        write_private_atomic(&TrustStore::path(d.path()), br#"{"version":1,"peers":[{"fingerprint":"zz","name":"x","added":0}]}"#, Existing::Replace).unwrap();
        assert!(matches!(TrustStore::load(d.path()), Err(CliError::Config(_))));
    }

    #[cfg(unix)]
    #[test]
    fn file_is_0600_and_group_writable_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let mut t = TrustStore::load(d.path()).unwrap();
        t.add(FP_A, "laptop").unwrap();
        t.save().unwrap();
        let p = TrustStore::path(d.path());
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o620)).unwrap();
        let e = TrustStore::load(d.path()).unwrap_err();
        assert!(e.user_message(None).contains("chmod 600"));
    }
}
