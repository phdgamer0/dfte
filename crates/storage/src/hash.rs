//! BLAKE3 chunk and whole-file hashing (manual §19/§20).

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::error::{Result, StorageError};

/// Read size for streaming file hashes; large enough for BLAKE3's SIMD paths.
const HASH_READ_SIZE: usize = 1024 * 1024;

/// BLAKE3 of one chunk (compared via `ChunkAck`, manual §20).
pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Streaming whole-file BLAKE3. Missing file → [`StorageError::SourceFileMissing`].
pub fn hash_file_blocking(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|e| if e.kind() == io::ErrorKind::NotFound { StorageError::SourceFileMissing { path: path.to_path_buf() } } else { StorageError::Io(e) })?;
    hash_reader_blocking(file)
}

/// Streaming BLAKE3 of everything `reader` yields.
pub fn hash_reader_blocking(mut reader: impl Read) -> Result<[u8; 32]> {
    let mut hasher = FileHasher::new();
    let mut buf = vec![0u8; HASH_READ_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(hasher.finalize())
}

/// Lower-case hex rendering of a 32-byte hash, for logs and sidecar files.
pub fn to_hex(hash: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*hash).to_hex().to_string()
}

/// Parse a 64-char hex hash produced by [`to_hex`].
pub fn from_hex(s: &str) -> Option<[u8; 32]> {
    blake3::Hash::from_hex(s).ok().map(|h| *h.as_bytes())
}

/// Incremental whole-file hasher: feed bytes in file order (e.g. chunk by chunk).
#[derive(Debug, Clone, Default)]
pub struct FileHasher {
    hasher: blake3::Hasher,
    bytes: u64,
}

impl FileHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes += data.len() as u64;
    }

    /// Total bytes fed so far.
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn incremental_matches_one_shot_and_file() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
        let mut h = FileHasher::new();
        for part in data.chunks(777_777) {
            h.update(part);
        }
        assert_eq!(h.bytes_hashed(), data.len() as u64);
        assert_eq!(h.finalize(), hash_chunk(&data));

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, &data).unwrap();
        assert_eq!(hash_file_blocking(&p).unwrap(), hash_chunk(&data));
        assert!(matches!(hash_file_blocking(dir.path().join("missing")), Err(StorageError::SourceFileMissing { .. })));
    }

    #[test]
    fn known_vector_and_hex() {
        let empty = hash_chunk(b"");
        assert_eq!(to_hex(&empty), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        assert_eq!(from_hex(&to_hex(&empty)), Some(empty));
        assert_eq!(from_hex("zz"), None);
    }
}
