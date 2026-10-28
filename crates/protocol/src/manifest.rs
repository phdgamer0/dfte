use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ProtocolError;
use crate::{Result, chunk_count};

/// Fixed chunk size (manual §17).
pub const CHUNK_SIZE: u64 = 4 * 1024 * 1024;
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_COMPONENT_LENGTH: usize = 255;
pub const MAX_MANIFEST_ENTRIES: usize = 20_000;
/// Serialized-size cap, checked before deserializing (manual §34 resource exhaustion).
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub transfer_id: Uuid,
    pub files: Vec<FileEntry>,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// UTF-8, forward-slash separated, relative. Untrusted on receipt (manual §35).
    pub relative_path: String,
    pub size: u64,
    pub modified_time: i64,
    pub permissions: Option<u32>,
    /// BLAKE3 of the whole file (manual §19/§20). Zero for directories.
    pub content_hash: [u8; 32],
    pub chunk_count: u32,
    /// Empty-directory sentinel (manual §17): size 0, no chunks.
    pub is_dir: bool,
}

impl FileEntry {
    pub fn file(relative_path: impl Into<String>, size: u64, content_hash: [u8; 32]) -> Result<Self> {
        let chunks = u32::try_from(chunk_count(size, CHUNK_SIZE)).map_err(|_| ProtocolError::FileTooLarge)?;
        Ok(Self { relative_path: relative_path.into(), size, modified_time: 0, permissions: None, content_hash, chunk_count: chunks, is_dir: false })
    }

    pub fn dir(relative_path: impl Into<String>) -> Self {
        Self { relative_path: relative_path.into(), size: 0, modified_time: 0, permissions: None, content_hash: [0; 32], chunk_count: 0, is_dir: true }
    }

    fn validate(&self) -> Result<()> {
        validate_relative_path(&self.relative_path)?;
        if self.is_dir {
            if self.size != 0 || self.chunk_count != 0 {
                return Err(ProtocolError::ChunkCountMismatch);
            }
            return Ok(());
        }
        let expected = chunk_count(self.size, CHUNK_SIZE);
        if u64::from(self.chunk_count) != expected {
            return Err(if expected > u64::from(u32::MAX) { ProtocolError::FileTooLarge } else { ProtocolError::ChunkCountMismatch });
        }
        Ok(())
    }
}

impl Manifest {
    pub fn new(files: Vec<FileEntry>) -> Result<Self> {
        let m = Self { transfer_id: Uuid::new_v4(), files };
        m.validate()?;
        Ok(m)
    }

    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn validate(&self) -> Result<()> {
        if self.files.len() > MAX_MANIFEST_ENTRIES {
            return Err(ProtocolError::TooManyEntries);
        }
        let mut seen = HashSet::with_capacity(self.files.len());
        for f in &self.files {
            f.validate()?;
            if !seen.insert(f.relative_path.as_str()) {
                return Err(ProtocolError::DuplicatePath);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = rmp_serde::to_vec_named(self).map_err(|_| ProtocolError::MessageEncode)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ProtocolError::ManifestTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes and fully validates an untrusted manifest.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ProtocolError::ManifestTooLarge);
        }
        let m: Self = rmp_serde::from_slice(bytes).map_err(|_| ProtocolError::ManifestDecode)?;
        m.validate()?;
        Ok(m)
    }
}

/// Parse-time path check (manual §17/§35). Storage repeats a filesystem-level
/// check (symlinks) at write time; this one only looks at the string.
pub fn validate_relative_path(path: &str) -> Result<()> {
    if path.len() > MAX_PATH_LENGTH {
        return Err(ProtocolError::PathTooLong);
    }
    if path.is_empty() || path.starts_with('/') || path.contains(['\0', '\\']) {
        return Err(ProtocolError::InvalidPath);
    }
    for component in path.split('/') {
        if component.len() > MAX_COMPONENT_LENGTH {
            return Err(ProtocolError::PathTooLong);
        }
        let drive_prefix = component.len() >= 2 && component.as_bytes()[1] == b':';
        if component.is_empty() || component == "." || component == ".." || drive_prefix {
            return Err(ProtocolError::InvalidPath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_corpus() {
        for bad in ["", "/etc/passwd", "../x", "a/../../b", "a/./b", "a//b", "a/", "C:\\x", "C:/x", "a\0b", "a\\b"] {
            assert_eq!(validate_relative_path(bad), Err(ProtocolError::InvalidPath), "{bad:?}");
        }
        for good in ["a", "dir/file.txt", ".hidden", "ünïcödé/日本.txt", "a..b"] {
            assert_eq!(validate_relative_path(good), Ok(()), "{good:?}");
        }
        assert_eq!(validate_relative_path(&"a".repeat(256)), Err(ProtocolError::PathTooLong));
    }

    #[test]
    fn roundtrip_and_validation() {
        let m = Manifest::new(vec![FileEntry::file("a.bin", CHUNK_SIZE + 1, [7; 32]).unwrap(), FileEntry::file("empty", 0, [0; 32]).unwrap(), FileEntry::dir("emptydir")]).unwrap();
        assert_eq!(m.files[0].chunk_count, 2);
        assert_eq!(Manifest::decode(&m.encode().unwrap()).unwrap(), m);

        let mut dup = m.clone();
        dup.files.push(dup.files[0].clone());
        assert_eq!(dup.validate(), Err(ProtocolError::DuplicatePath));

        let mut lie = m.clone();
        lie.files[0].chunk_count = 1;
        assert_eq!(Manifest::decode(&lie.encode().unwrap()), Err(ProtocolError::ChunkCountMismatch));

        let mut huge = m;
        huge.files[0].size = u64::MAX;
        assert_eq!(huge.validate(), Err(ProtocolError::FileTooLarge));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Manifest::decode(&[0xc1, 0x00]), Err(ProtocolError::ManifestDecode));
    }
}
