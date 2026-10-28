//! Where the app keeps its state (XDG base directories on Linux).
//!
//! - `$XDG_DATA_HOME/dfte` (default `~/.local/share/dfte`): `identity.key`,
//!   `trusted.json` and `staging/` (partial downloads + resume sidecars, §14/§19).
//! - Received files go to `$XDG_DOWNLOAD_DIR` (environment, then
//!   `~/.config/user-dirs.dirs`), falling back to `~/Downloads`.

use std::path::{Path, PathBuf};

use crate::error::CliError;

fn env_path(name: &str) -> Option<PathBuf> {
    // Unset, empty or relative values are ignored, as the XDG spec requires.
    std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute())
}

fn home() -> Result<PathBuf, CliError> {
    env_path("HOME").or_else(|| env_path("USERPROFILE")).ok_or_else(|| CliError::Config("cannot find your home directory: set HOME (or XDG_DATA_HOME)".into()))
}

/// `$XDG_DATA_HOME/dfte`, default `~/.local/share/dfte`.
pub fn data_dir() -> Result<PathBuf, CliError> {
    let base = match env_path("XDG_DATA_HOME") {
        Some(p) => p,
        None => home()?.join(".local").join("share"),
    };
    Ok(base.join("dfte"))
}

/// App-private staging directory (manual §14): partial files and resume sidecars.
pub fn staging_dir(data: &Path) -> PathBuf {
    data.join("staging")
}

/// Default destination for received files.
pub fn download_dir() -> Result<PathBuf, CliError> {
    if let Some(p) = env_path("XDG_DOWNLOAD_DIR") {
        return Ok(p);
    }
    let home = home()?;
    let config = env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let user_dirs = config.join("user-dirs.dirs");
    match std::fs::read_to_string(&user_dirs) {
        Ok(text) => {
            if let Some(p) = parse_user_dirs(&text, &home) {
                return Ok(p);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(path = %user_dirs.display(), error = %e, "cannot read user-dirs.dirs; using ~/Downloads"),
    }
    Ok(home.join("Downloads"))
}

/// Extracts `XDG_DOWNLOAD_DIR` from a `user-dirs.dirs` file (`XDG_DOWNLOAD_DIR="$HOME/Downloads"`).
pub fn parse_user_dirs(text: &str, home: &Path) -> Option<PathBuf> {
    let line = text.lines().map(str::trim).find(|l| l.starts_with("XDG_DOWNLOAD_DIR="))?;
    let value = line.trim_start_matches("XDG_DOWNLOAD_DIR=").trim_matches('"');
    let path = match value.strip_prefix("$HOME") {
        Some(rest) => home.join(rest.trim_start_matches('/')),
        None => PathBuf::from(value),
    };
    // `$HOME/` alone means "disabled" per xdg-user-dirs; treat as unset.
    (path.is_absolute() && path != home).then_some(path)
}

// XDG user-dirs is a Linux/BSD convention, and "/home/u" isn't an absolute
// path on Windows (no drive), so these tests only build on unix.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn user_dirs_parsing() {
        let home = Path::new("/home/u");
        let text = "# comment\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"$HOME/İndirilenler\"\n";
        assert_eq!(parse_user_dirs(text, home), Some(PathBuf::from("/home/u/İndirilenler")));
        assert_eq!(parse_user_dirs("XDG_DOWNLOAD_DIR=\"/data/dl\"", home), Some(PathBuf::from("/data/dl")));
        assert_eq!(parse_user_dirs("XDG_DOWNLOAD_DIR=\"$HOME/\"", home), None);
        assert_eq!(parse_user_dirs("XDG_MUSIC_DIR=\"$HOME/Music\"", home), None);
        assert_eq!(parse_user_dirs("XDG_DOWNLOAD_DIR=\"relative\"", home), None);
    }
}
