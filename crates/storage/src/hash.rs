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

/// Per-chunk digest that also composes into the whole-file hash (manual §20).
///
/// For a single-chunk file this is the plain BLAKE3 of the data, which *is* the
/// file hash. Otherwise it is the BLAKE3 chaining value of the 4 MiB subtree at
/// that offset; [`file_hash_from_pieces`] merges them into the root, so the
/// receiver can verify the whole file without reading it back from disk.
pub fn piece_hash(file_size: u64, index: u64, data: &[u8]) -> [u8; 32] {
    piece_hash_with(crate::CHUNK_SIZE, file_size, index, data)
}

/// Whole-file BLAKE3 from every chunk's [`piece_hash`], in order. Returns
/// `None` if the piece count doesn't match the file size.
pub fn file_hash_from_pieces(file_size: u64, pieces: &[[u8; 32]]) -> Option<[u8; 32]> {
    file_hash_from_pieces_with(crate::CHUNK_SIZE, file_size, pieces)
}

/// Whole-file BLAKE3 hashed on up to `threads` threads, one 4 MiB piece at a
/// time, merged with [`file_hash_from_pieces`]. Same result as
/// [`hash_file_blocking`]; used for the sender's pre-manifest hash (manual §19).
/// Also returns every piece hash so the sender can check `ChunkAck`s against them.
pub fn hash_file_parallel_blocking(path: impl AsRef<Path>, threads: usize) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    let reader = crate::ChunkReader::open_blocking(path)?;
    let size = reader.size();
    let count = reader.chunk_count();
    if count <= 1 {
        let mut buf = vec![0u8; size as usize];
        reader.read_chunk_blocking(0, &mut buf).or_else(|e| if size == 0 { Ok(0) } else { Err(e) })?;
        let h = piece_hash(size, 0, &buf);
        return Ok((h, vec![h]));
    }
    let threads = threads.clamp(1, count as usize);
    let next = std::sync::atomic::AtomicU64::new(0);
    let mut pieces = vec![[0u8; 32]; count as usize];
    let results: Vec<Result<Vec<IndexedPiece>>> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut buf = vec![0u8; crate::CHUNK_SIZE as usize];
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= count {
                            return Ok(out);
                        }
                        let n = reader.read_chunk_blocking(i, &mut buf)?;
                        out.push((i, piece_hash(size, i, &buf[..n])));
                    }
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap_or_else(|p| std::panic::resume_unwind(p))).collect()
    });
    for r in results {
        for (i, h) in r? {
            pieces[i as usize] = h;
        }
    }
    let root = file_hash_from_pieces(size, &pieces).ok_or(StorageError::PieceCountMismatch { expected: count, actual: pieces.len() as u64 })?;
    Ok((root, pieces))
}

type IndexedPiece = (u64, [u8; 32]);

// Piece size is a parameter so tests can cover many tree shapes cheaply. It
// must be a power of two and a multiple of blake3::CHUNK_LEN, so every piece
// is a complete, aligned BLAKE3 subtree (BLAKE3 paper §2.1).
fn piece_hash_with(piece: u64, file_size: u64, index: u64, data: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt;
    if file_size <= piece {
        return *blake3::hash(data).as_bytes();
    }
    let mut h = blake3::Hasher::new();
    h.set_input_offset(index * piece);
    h.update(data);
    h.finalize_non_root()
}

fn file_hash_from_pieces_with(piece: u64, file_size: u64, pieces: &[[u8; 32]]) -> Option<[u8; 32]> {
    use blake3::hazmat::{Mode, left_subtree_len, merge_subtrees_non_root, merge_subtrees_root};
    if pieces.len() as u64 != file_size.div_ceil(piece).max(1) {
        return None;
    }
    if file_size <= piece {
        return Some(pieces[0]);
    }
    // Same split rule BLAKE3 itself uses: the left subtree is the largest power
    // of two chunks strictly smaller than the input. With aligned power-of-two
    // pieces every split lands on a piece boundary.
    fn merge(piece: u64, len: u64, cvs: &[[u8; 32]]) -> [u8; 32] {
        if cvs.len() == 1 {
            return cvs[0];
        }
        let left = left_subtree_len(len);
        let n = (left / piece) as usize;
        merge_subtrees_non_root(&merge(piece, left, &cvs[..n]), &merge(piece, len - left, &cvs[n..]), Mode::Hash)
    }
    let left = left_subtree_len(file_size);
    let n = (left / piece) as usize;
    let root = merge_subtrees_root(&merge(piece, left, &pieces[..n]), &merge(piece, file_size - left, &pieces[n..]), Mode::Hash);
    Some(*root.as_bytes())
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

    fn pieces_of(piece: u64, data: &[u8]) -> Vec<[u8; 32]> {
        let size = data.len() as u64;
        if data.is_empty() {
            return vec![piece_hash_with(piece, 0, 0, data)];
        }
        data.chunks(piece as usize).enumerate().map(|(i, c)| piece_hash_with(piece, size, i as u64, c)).collect()
    }

    #[test]
    fn pieces_compose_to_file_hash_small_trees() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
        for piece in [1024u64, 2048, 4096] {
            for len in (0..=data.len()).step_by(97).chain([1023, 1024, 1025, 2048, 3072, 4096, 4097, 8192, 8193, 16384, 40_000]) {
                let d = &data[..len];
                let got = file_hash_from_pieces_with(piece, len as u64, &pieces_of(piece, d));
                assert_eq!(got, Some(*blake3::hash(d).as_bytes()), "piece {piece} len {len}");
            }
        }
    }

    #[test]
    fn pieces_compose_at_real_chunk_size() {
        let c = crate::CHUNK_SIZE as usize;
        let data: Vec<u8> = (0..3 * c + 12345).map(|i| (i % 251) as u8).collect();
        for len in [c, c + 1, 2 * c, 3 * c - 1, 3 * c + 12345] {
            let d = &data[..len];
            let pieces: Vec<_> = d.chunks(c).enumerate().map(|(i, x)| piece_hash(len as u64, i as u64, x)).collect();
            assert_eq!(file_hash_from_pieces(len as u64, &pieces), Some(hash_chunk(d)), "len {len}");
        }
    }

    #[test]
    fn parallel_file_hash_matches_sequential() {
        let dir = tempfile::tempdir().unwrap();
        let c = crate::CHUNK_SIZE as usize;
        for len in [0, 1, c, c + 1, 3 * c + 99] {
            let p = dir.path().join(format!("f{len}"));
            std::fs::write(&p, (0..len).map(|i| (i % 253) as u8).collect::<Vec<_>>()).unwrap();
            for threads in [1, 3, 8] {
                let (root, pieces) = hash_file_parallel_blocking(&p, threads).unwrap();
                assert_eq!(root, hash_file_blocking(&p).unwrap(), "len {len} threads {threads}");
                assert_eq!(file_hash_from_pieces(len as u64, &pieces), Some(root));
            }
        }
    }

    #[test]
    fn piece_count_mismatch_rejected() {
        assert_eq!(file_hash_from_pieces(crate::CHUNK_SIZE + 1, &[[0; 32]]), None);
        assert_eq!(file_hash_from_pieces(0, &[]), None);
    }

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
