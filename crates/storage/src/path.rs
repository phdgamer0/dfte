//! Validation of peer-supplied relative paths and safe joining under a root
//! (manual §17/§34/§35). Every path from a peer's manifest is untrusted input.

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Result, StorageError};

/// Maximum bytes in a single path component (common filesystem limit).
pub const MAX_COMPONENT_LEN: usize = 255;
/// Maximum bytes in a whole relative path.
pub const MAX_PATH_LEN: usize = 4096;

/// A validated, forward-slash separated relative path: non-empty, no `.`/`..`,
/// no empty components, no NUL/backslash, not absolute, no drive prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelPath {
    components: Vec<String>,
}

impl RelPath {
    /// The validated components, in order.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Last component (the file name).
    pub fn file_name(&self) -> &str {
        // Non-empty by construction.
        self.components.last().map_or("", String::as_str)
    }

    /// Canonical wire form (`a/b/c`).
    pub fn as_wire(&self) -> String {
        self.components.join("/")
    }

    /// Copy with every component passed through [`sanitize_component`].
    /// Compare with `self` to learn whether anything was renamed (for the completion log).
    pub fn sanitized(&self) -> RelPath {
        RelPath { components: self.components.iter().map(|c| sanitize_component(c).into_owned()).collect() }
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_wire())
    }
}

fn invalid(path: &str, reason: &'static str) -> StorageError {
    // Cap what we echo back so a hostile multi-KiB path doesn't bloat logs/errors.
    let shown: String = path.chars().take(256).collect();
    StorageError::InvalidPath { path: shown, reason }
}

/// Validate a peer-supplied relative path (manual §17/§35).
pub fn validate_relative_path(path: &str) -> Result<RelPath> {
    if path.is_empty() {
        return Err(invalid(path, "empty path"));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(invalid(path, "path too long"));
    }
    if path.contains('\0') {
        return Err(invalid(path, "contains NUL"));
    }
    if path.contains('\\') {
        return Err(invalid(path, "contains backslash"));
    }
    if path.starts_with('/') {
        return Err(invalid(path, "absolute path"));
    }
    let mut components = Vec::new();
    for (i, comp) in path.split('/').enumerate() {
        match comp {
            "" => return Err(invalid(path, "empty component")),
            "." => return Err(invalid(path, "'.' component")),
            ".." => return Err(invalid(path, "'..' component")),
            _ => {}
        }
        if comp.len() > MAX_COMPONENT_LEN {
            return Err(invalid(path, "component too long"));
        }
        if i == 0 && has_drive_prefix(comp) {
            return Err(invalid(path, "drive prefix"));
        }
        components.push(comp.to_owned());
    }
    Ok(RelPath { components })
}

fn has_drive_prefix(comp: &str) -> bool {
    let b = comp.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

const WINDOWS_RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³"];

fn is_reserved_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_uppercase();
    WINDOWS_RESERVED.contains(&upper.as_str())
}

fn is_forbidden_char(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\') || (c as u32) < 0x20
}

/// Make one component safe on Windows: replaces `<>:"|?*` and control chars
/// with `_`, replaces trailing dots/spaces with `_`, and prefixes reserved
/// device names (`CON`, `NUL`, `COM1`, … also with extensions) with `_`.
///
/// Returns `Cow::Borrowed` when unchanged, so callers can detect and log renames (§17).
pub fn sanitize_component(name: &str) -> Cow<'_, str> {
    let needs_char_fix = name.chars().any(is_forbidden_char);
    let needs_trail_fix = name.ends_with('.') || name.ends_with(' ');
    let reserved = is_reserved_name(name);
    if !needs_char_fix && !needs_trail_fix && !reserved && !name.is_empty() {
        return Cow::Borrowed(name);
    }
    let mut out: String = name.chars().map(|c| if is_forbidden_char(c) { '_' } else { c }).collect();
    let kept = out.trim_end_matches(['.', ' ']).len();
    let trailing = out.len() - kept;
    out.truncate(kept);
    out.extend(std::iter::repeat_n('_', trailing));
    if out.is_empty() {
        out.push('_');
    }
    if is_reserved_name(&out) {
        out.insert(0, '_');
    }
    Cow::Owned(out)
}

/// Join `rel` under `root`, creating missing parent directories.
///
/// Rejects ([`StorageError::SymlinkEscape`]) if any *existing* component under
/// `root` — including the final one — is a symlink (or Windows junction), which
/// catches links planted by an earlier transfer (§34). `root` itself is trusted
/// and created if missing. The final component is not created.
///
/// This is a check-then-use operation; it defends against content planted by
/// peers through this engine, not against a concurrent local attacker.
pub fn safe_join_blocking(root: &Path, rel: &RelPath) -> Result<PathBuf> {
    std::fs::create_dir_all(root)?;
    let mut current = root.to_path_buf();
    let n = rel.components.len();
    for (i, comp) in rel.components.iter().enumerate() {
        current.push(comp);
        let is_last = i + 1 == n;
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(StorageError::SymlinkEscape { path: current });
            }
            Ok(meta) if is_last => {
                if meta.is_dir() {
                    return Err(invalid(&rel.as_wire(), "target is an existing directory"));
                }
            }
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(invalid(&rel.as_wire(), "parent component is not a directory"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !is_last {
                    match std::fs::create_dir(&current) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            // Raced with someone else; re-check what's there now.
                            let meta = std::fs::symlink_metadata(&current)?;
                            if meta.file_type().is_symlink() {
                                return Err(StorageError::SymlinkEscape { path: current });
                            }
                            if !meta.is_dir() {
                                return Err(invalid(&rel.as_wire(), "parent component is not a directory"));
                            }
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(current)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_corpus() {
        let long_comp = "a".repeat(256);
        let long_path = vec!["a"; 2100].join("/");
        let bad = ["", "../x", "..", ".", "/etc/passwd", "a/../../b", "a/./b", "C:\\x", "C:x", "c:/windows", "a\0b", "a\\b", "a//b", "a/", "/", long_comp.as_str(), long_path.as_str()];
        for p in bad {
            assert!(matches!(validate_relative_path(p), Err(StorageError::InvalidPath { .. })), "should reject {p:?}");
        }
    }

    #[test]
    fn accepts_normal_and_unicode() {
        for p in ["a", ".hidden", "dir/file.txt", "фото/снимок.jpg", "日本語/ファイル名.png", "emoji 🎉/x..y", "ab:c", &"é".repeat(127)] {
            let r = validate_relative_path(p).unwrap();
            assert_eq!(r.as_wire(), p);
        }
        assert_eq!(validate_relative_path("a/b/c").unwrap().components(), &["a", "b", "c"]);
    }

    #[test]
    fn sanitizes_windows_names() {
        assert!(matches!(sanitize_component("normal.txt"), Cow::Borrowed(_)));
        assert_eq!(sanitize_component("CON"), "_CON");
        assert_eq!(sanitize_component("con.txt"), "_con.txt");
        assert_eq!(sanitize_component("Com1.tar.gz"), "_Com1.tar.gz");
        assert_eq!(sanitize_component("lpt9"), "_lpt9");
        assert_eq!(sanitize_component("COM10"), "COM10");
        assert_eq!(sanitize_component("a<b>c:d\"e|f?g*h"), "a_b_c_d_e_f_g_h");
        assert_eq!(sanitize_component("trail. "), "trail__");
        assert_eq!(sanitize_component("x\u{1}y"), "x_y");
        assert_eq!(sanitize_component("NUL."), "NUL_");
        let rel = validate_relative_path("ok/aux.c").unwrap();
        assert_eq!(rel.sanitized().as_wire(), "ok/_aux.c");
        assert_ne!(rel.sanitized(), rel);
    }

    #[test]
    fn safe_join_creates_parents() {
        let root = tempfile::tempdir().unwrap();
        let rel = validate_relative_path("a/b/c.txt").unwrap();
        let p = safe_join_blocking(root.path(), &rel).unwrap();
        assert_eq!(p, root.path().join("a").join("b").join("c.txt"));
        assert!(root.path().join("a/b").is_dir());
        assert!(!p.exists());
        // Existing directory as target is rejected.
        let rel = validate_relative_path("a/b").unwrap();
        assert!(safe_join_blocking(root.path(), &rel).is_err());
        // A file where a directory is needed is rejected.
        std::fs::write(root.path().join("f"), b"x").unwrap();
        let rel = validate_relative_path("f/x").unwrap();
        assert!(matches!(safe_join_blocking(root.path(), &rel), Err(StorageError::InvalidPath { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn safe_join_rejects_planted_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // An "earlier transfer" planted inbox/evil -> outside.
        std::fs::create_dir(root.path().join("inbox")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("inbox/evil")).unwrap();
        let rel = validate_relative_path("inbox/evil/payload.sh").unwrap();
        assert!(matches!(safe_join_blocking(root.path(), &rel), Err(StorageError::SymlinkEscape { .. })));
        // Symlink as the final component (pointing at a file outside) also rejected.
        let target = outside.path().join("victim");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("inbox/link")).unwrap();
        let rel = validate_relative_path("inbox/link").unwrap();
        assert!(matches!(safe_join_blocking(root.path(), &rel), Err(StorageError::SymlinkEscape { .. })));
        assert!(std::fs::read_dir(outside.path()).unwrap().count() == 1);
    }
}
