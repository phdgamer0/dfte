//! File I/O, chunking, pre-allocation and resume state (manual §14/§17-§20).
//!
//! Functions with a `_blocking` suffix perform synchronous filesystem I/O and
//! must be called via `tokio::task::spawn_blocking` from async code (§27/§50).
//! This crate deliberately does not depend on `protocol`; `core` glues the
//! wire-level manifest types to the storage types here.

pub mod chunk;
pub mod error;
pub mod fileio;
pub mod hash;
pub mod hash_cache;
pub mod path;
pub mod pool;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod procfd;
pub mod resume;
pub mod writer;

pub use chunk::{CHUNK_SIZE, ChunkReader, chunk_count, chunk_len, chunk_offset, chunk_range};
pub use error::{Result, StorageError};
pub use fileio::{open_source, source_metadata};
pub use hash::{FileHasher, file_hash_from_pieces, hash_chunk, hash_file_blocking, hash_file_parallel_blocking, piece_hash};
pub use hash_cache::{CachedHashes, HashCache};
pub use path::{RelPath, safe_join_blocking, sanitize_component, validate_relative_path};
pub use pool::{BufferPool, PoolBuffer};
pub use resume::{ChunkBitmap, ResumeFile, ResumeState, ResumeStore, scan_orphans_blocking};
pub use writer::{PREALLOCATE_MIN, StagedFile, finalize_batch_blocking, staging_name, sync_staged_blocking};
