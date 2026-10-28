//! Sender side: turning user-selected paths into a manifest (manual §17) and
//! serving chunk reads from them.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use protocol::manifest::{FileEntry, Manifest, validate_relative_path};
use storage::{ChunkReader, hash_file_parallel_blocking};

use crate::error::{EngineError, Result};

/// One manifest entry's local source.
#[derive(Debug)]
pub(crate) struct SourceFile {
    /// `None` for an empty-directory sentinel.
    pub path: Option<PathBuf>,
    pub size: u64,
    modified: Option<SystemTime>,
    /// Per-chunk [`storage::piece_hash`]es, compared against the receiver's `ChunkAck`s.
    pub pieces: Vec<[u8; 32]>,
}

#[derive(Debug)]
pub(crate) struct Source {
    pub manifest: Manifest,
    pub files: Vec<SourceFile>,
}

struct Entry {
    rel: String,
    src: Option<PathBuf>,
}

fn utf8_name(p: &Path) -> Result<String> {
    let canonical;
    let name = match p.file_name() {
        Some(n) => n,
        None => {
            canonical = std::fs::canonicalize(p)?;
            canonical.file_name().ok_or_else(|| EngineError::InvalidInput(format!("{} has no file name", p.display())))?
        }
    };
    name.to_str().map(str::to_owned).ok_or_else(|| EngineError::InvalidInput(format!("{} is not valid UTF-8", p.display())))
}

/// Flattens a directory (manual §17): files in sorted order, symlinks skipped
/// (not followed, §35), an empty directory becomes a sentinel entry.
fn walk_blocking(dir: &Path, rel: &str, out: &mut Vec<Entry>) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    let mut any = false;
    for e in entries {
        let ft = e.file_type()?;
        let child = format!("{rel}/{}", utf8_name(&e.path())?);
        if ft.is_symlink() {
            tracing::warn!(path = %child, "skipping symlink");
        } else if ft.is_dir() {
            any = true;
            walk_blocking(&e.path(), &child, out)?;
        } else if ft.is_file() {
            any = true;
            out.push(Entry { rel: child, src: Some(e.path()) });
        }
    }
    if !any {
        out.push(Entry { rel: rel.to_owned(), src: None });
    }
    Ok(())
}

fn collect_blocking(paths: &[PathBuf]) -> Result<Vec<Entry>> {
    if paths.is_empty() {
        return Err(EngineError::InvalidInput("nothing to send".into()));
    }
    let mut out = Vec::new();
    for p in paths {
        // Top-level selections are followed if they are symlinks: the user picked them.
        let meta = std::fs::metadata(p).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { EngineError::SourceFileMissing { path: p.clone() } } else { e.into() })?;
        let name = utf8_name(p)?;
        if meta.is_dir() {
            walk_blocking(p, &name, &mut out)?;
        } else if meta.is_file() {
            out.push(Entry { rel: name, src: Some(p.clone()) });
        } else {
            return Err(EngineError::InvalidInput(format!("{} is not a file or directory", p.display())));
        }
    }
    for e in &out {
        validate_relative_path(&e.rel).map_err(|err| EngineError::InvalidInput(format!("{}: {err}", e.rel)))?;
    }
    Ok(out)
}

/// Walks `paths`, BLAKE3-hashes every file (keeping per-chunk hashes) and builds
/// the manifest. Runs before the manifest is offered, so a resume can be matched
/// on `content_hash` (manual §19).
pub(crate) fn build_source_blocking(paths: &[PathBuf], threads: usize) -> Result<Source> {
    let entries = collect_blocking(paths)?;
    let threads = if threads == 0 { std::thread::available_parallelism().map_or(1, usize::from) } else { threads };
    let mut files = Vec::with_capacity(entries.len());
    let mut sources = Vec::with_capacity(entries.len());
    for Entry { rel, src } in entries {
        let Some(path) = src else {
            files.push(FileEntry::dir(rel));
            sources.push(SourceFile { path: None, size: 0, modified: None, pieces: Vec::new() });
            continue;
        };
        let meta = std::fs::metadata(&path)?;
        let size = meta.len();
        let modified = meta.modified().ok();
        let (root, pieces) = hash_file_parallel_blocking(&path, threads)?;
        if pieces.len() as u64 != storage::chunk_count(size).max(1) {
            return Err(EngineError::SourceFileChanged { path });
        }
        let mut entry = FileEntry::file(rel, size, root).map_err(|e| EngineError::InvalidInput(e.to_string()))?;
        entry.modified_time = modified.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        files.push(entry);
        sources.push(SourceFile { path: Some(path), size, modified, pieces });
    }
    let manifest = Manifest::new(files).map_err(|e| EngineError::InvalidInput(format!("cannot build manifest: {e}")))?;
    Ok(Source { manifest, files: sources })
}

/// Lazily opened, shared chunk readers. A file is opened on its first chunk read
/// and closed after its last, so a 20k-file manifest never holds 20k descriptors.
pub(crate) struct Readers {
    files: Vec<SourceFile>,
    slots: Vec<Mutex<Option<Arc<ChunkReader>>>>,
    remaining: Vec<AtomicU64>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned slot only means another reader thread panicked mid-open; the
    // Option inside is still consistent.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Readers {
    /// `reads[i]` = chunks of file `i` that will be read.
    pub fn new(files: Vec<SourceFile>, reads: &[u64]) -> Self {
        let slots = files.iter().map(|_| Mutex::new(None)).collect();
        let remaining = reads.iter().map(|&n| AtomicU64::new(n)).collect();
        Self { files, slots, remaining }
    }

    pub fn file(&self, i: usize) -> Option<&SourceFile> {
        self.files.get(i)
    }

    /// Reader for file `i`, opening it if needed. Size/mtime drift since hashing
    /// is [`EngineError::SourceFileChanged`].
    pub fn get_blocking(&self, i: usize) -> Result<Arc<ChunkReader>> {
        let (Some(slot), Some(f)) = (self.slots.get(i), self.files.get(i)) else {
            return Err(EngineError::Internal(format!("no source file {i}")));
        };
        let mut slot = lock(slot);
        if let Some(r) = slot.as_ref() {
            return Ok(Arc::clone(r));
        }
        let path = f.path.as_ref().ok_or_else(|| EngineError::Internal("chunk read from a directory entry".into()))?;
        let reader = ChunkReader::open_blocking(path)?;
        let modified = std::fs::metadata(path)?.modified().ok();
        if reader.size() != f.size || modified != f.modified {
            return Err(EngineError::SourceFileChanged { path: path.clone() });
        }
        let reader = Arc::new(reader);
        *slot = Some(Arc::clone(&reader));
        Ok(reader)
    }

    /// One more read of file `i` is coming (a resend).
    pub fn expect_read(&self, i: usize) {
        if let Some(r) = self.remaining.get(i) {
            r.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// A read of file `i` finished; closes the file after its last expected read.
    pub fn read_done(&self, i: usize) {
        if let (Some(r), Some(slot)) = (self.remaining.get(i), self.slots.get(i))
            && r.fetch_sub(1, Ordering::AcqRel) == 1
        {
            lock(slot).take();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn walk_flattens_and_keeps_empty_dirs() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("top");
        std::fs::create_dir_all(root.join("sub/empty")).unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("sub/b.txt"), b"bb").unwrap();
        let src = build_source_blocking(&[root], 2).unwrap();
        let paths: Vec<_> = src.manifest.files.iter().map(|f| (f.relative_path.as_str(), f.is_dir)).collect();
        assert_eq!(paths, vec![("top/a.txt", false), ("top/sub/b.txt", false), ("top/sub/empty", true)]);
        assert_eq!(src.files[1].size, 2);
    }

    #[test]
    fn missing_source_is_reported() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(build_source_blocking(&[d.path().join("nope")], 1), Err(EngineError::SourceFileMissing { .. })));
    }
}
