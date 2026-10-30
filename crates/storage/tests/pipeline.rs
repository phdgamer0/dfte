// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! End-to-end through the public API: read source chunks into pooled buffers,
//! write them to a staged file, track resume state across a simulated crash,
//! then finalize and verify.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use storage::{BufferPool, CHUNK_SIZE, ChunkReader, ResumeFile, ResumeState, ResumeStore, StagedFile, hash_chunk, hash_file_blocking, safe_join_blocking, scan_orphans_blocking, staging_name, validate_relative_path};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfer_with_crash_and_resume() {
    let src_dir = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let dest_root = tempfile::tempdir().unwrap();

    let size = 5 * CHUNK_SIZE + 777;
    let data: Vec<u8> = (0..size).map(|i| (i * 7 % 256) as u8).collect();
    let src = src_dir.path().join("video.mp4");
    std::fs::write(&src, &data).unwrap();
    let content_hash = hash_file_blocking(&src).unwrap();

    let rel = validate_relative_path("movies/video.mp4").unwrap();
    let dest = safe_join_blocking(dest_root.path(), &rel).unwrap();
    let tid = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let name = staging_name(tid, 0);

    let reader = Arc::new(ChunkReader::open_blocking(&src).unwrap());
    let pool = BufferPool::for_chunks(2);

    // First attempt: 3 chunks confirmed, flush every 2 → only 2 survive the "crash".
    {
        let staged = StagedFile::create_blocking(staging.path(), &name, dest.clone(), size).unwrap();
        let state = ResumeState::new(tid, vec![ResumeFile::new(&rel.as_wire(), size, content_hash).unwrap()]).unwrap();
        let mut store = ResumeStore::create_blocking(staging.path(), state).unwrap().with_flush_every(2);
        for idx in 0..3 {
            let mut buf = pool.acquire().await;
            let r = Arc::clone(&reader);
            let buf_back = tokio::task::spawn_blocking(move || {
                let n = r.read_chunk_blocking(idx, buf.full_mut()).unwrap();
                buf.set_len(n).unwrap();
                buf
            })
            .await
            .unwrap();
            staged.write_chunk_blocking(idx, &buf_back).unwrap();
            assert_eq!(hash_chunk(&buf_back).len(), 32);
            store.mark_confirmed_blocking(0, idx).unwrap();
        }
    }

    // Relaunch: discover the orphan and resume from the persisted offset.
    let orphans = scan_orphans_blocking(staging.path()).unwrap();
    assert_eq!(orphans.len(), 1);
    let file_idx = orphans[0].matches(&rel.as_wire(), size, &content_hash).unwrap();
    let offset = orphans[0].contiguous_offset(file_idx).unwrap();
    assert_eq!(offset, 2 * CHUNK_SIZE);

    let staged = StagedFile::open_existing_blocking(staging.path(), &name, dest.clone(), size).unwrap();
    let mut store = ResumeStore::open_blocking(staging.path(), tid).unwrap();
    let first = offset / CHUNK_SIZE;
    for idx in first..reader.chunk_count() {
        let mut buf = pool.acquire().await;
        let n = reader.read_chunk_blocking(idx, buf.full_mut()).unwrap();
        buf.set_len(n).unwrap();
        staged.write_chunk_blocking(idx, &buf).unwrap();
        store.mark_confirmed_blocking(file_idx, idx).unwrap();
    }
    assert!(store.state().is_complete());
    let out = staged.finalize_blocking(&content_hash).unwrap();
    store.remove_blocking().unwrap();

    assert_eq!(out, dest);
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    assert!(scan_orphans_blocking(staging.path()).unwrap().is_empty());
    assert_eq!(pool.available(), 2);
}
