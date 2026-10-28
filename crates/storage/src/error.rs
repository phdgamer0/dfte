//! Storage-layer error type. Converted into `EngineError` at the `core` boundary (manual §36).

use std::io;
use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T, E = StorageError> = std::result::Result<T, E>;

/// Every fallible storage operation returns this error.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Underlying OS I/O failure not covered by a more specific variant.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Free-space check before pre-allocation failed (manual §18).
    #[error("not enough free space: need {needed} bytes, {available} available")]
    DiskFull { needed: u64, available: u64 },

    /// Source file's size or mtime changed after it was opened for sending.
    #[error("source file changed while it was being read: {path}")]
    SourceFileChanged { path: PathBuf },

    /// Source file disappeared between selection and read.
    #[error("source file not found: {path}")]
    SourceFileMissing { path: PathBuf },

    /// Whole-file BLAKE3 did not match the manifest (manual §20). The staged
    /// file is kept on disk so the transfer can be resumed/repaired.
    #[error("content hash mismatch for {path}")]
    HashMismatch { path: PathBuf, expected: [u8; 32], actual: [u8; 32] },

    /// A peer-supplied relative path failed validation (manual §17/§35).
    #[error("invalid path {path:?}: {reason}")]
    InvalidPath { path: String, reason: &'static str },

    /// An existing path component under the root is a symlink (manual §34).
    #[error("refusing to traverse symlink at {path}")]
    SymlinkEscape { path: PathBuf },

    /// A persisted resume sidecar could not be parsed or failed validation.
    #[error("corrupt resume state {path}: {reason}")]
    CorruptResumeState { path: PathBuf, reason: String },

    /// Chunk index is not within `0..chunk_count`.
    #[error("chunk index {index} out of range (file has {count} chunks)")]
    ChunkOutOfRange { index: u64, count: u64 },

    /// Data length for a chunk does not equal the expected chunk length.
    #[error("chunk {index} length mismatch: expected {expected}, got {actual}")]
    ChunkLengthMismatch { index: u64, expected: u64, actual: u64 },

    /// A caller-supplied buffer is smaller than required.
    #[error("buffer too small: need {needed} bytes, capacity {capacity}")]
    BufferTooSmall { needed: u64, capacity: u64 },
}
