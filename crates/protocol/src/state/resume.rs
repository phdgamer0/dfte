// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Turning a receiver's `ManifestAccept` into a per-file starting chunk (manual §19).

use crate::Result;
use crate::error::ProtocolError;
use crate::manifest::{CHUNK_SIZE, Manifest};
use crate::message::ManifestAccept;

/// First chunk to send for each file, validated against the manifest. Offsets
/// come from the peer, so they must be chunk-aligned and within the file.
pub fn start_chunks(manifest: &Manifest, accept: &ManifestAccept) -> Result<Vec<u32>> {
    if accept.resume_offsets.len() != manifest.files.len() {
        return Err(ProtocolError::OutOfRange);
    }
    manifest
        .files
        .iter()
        .zip(&accept.resume_offsets)
        .map(|(f, &off)| {
            if off > f.size || (off % CHUNK_SIZE != 0 && off != f.size) {
                return Err(ProtocolError::OutOfRange);
            }
            u32::try_from(off.div_ceil(CHUNK_SIZE)).map_err(|_| ProtocolError::OutOfRange)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::FileEntry;

    #[test]
    fn offsets_map_to_chunks() {
        let m = Manifest::new(vec![FileEntry::file("a", 3 * CHUNK_SIZE, [0; 32]).unwrap(), FileEntry::file("b", 10, [0; 32]).unwrap()]).unwrap();
        let ok = |v: Vec<u64>| start_chunks(&m, &ManifestAccept { resume_offsets: v });
        assert_eq!(ok(vec![0, 0]), Ok(vec![0, 0]));
        assert_eq!(ok(vec![2 * CHUNK_SIZE, 10]), Ok(vec![2, 1]));
        assert_eq!(ok(vec![1, 0]), Err(ProtocolError::OutOfRange));
        assert_eq!(ok(vec![4 * CHUNK_SIZE, 0]), Err(ProtocolError::OutOfRange));
        assert_eq!(ok(vec![0]), Err(ProtocolError::OutOfRange));
    }
}
