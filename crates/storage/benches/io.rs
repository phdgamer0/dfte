// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Storage micro-benchmarks (manual §13.1/§30): BLAKE3 over one 4 MiB chunk and
//! positional chunk reads from a (page-cached) temp file.
#![allow(clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use storage::{BufferPool, CHUNK_SIZE, ChunkReader, StagedFile, hash_chunk, hash_file_blocking, hash_file_parallel_blocking, piece_hash};

fn bench_hash(c: &mut Criterion) {
    let data: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
    let mut g = c.benchmark_group("blake3");
    g.throughput(Throughput::Bytes(CHUNK_SIZE));
    g.bench_function("hash_chunk_4MiB", |b| b.iter(|| hash_chunk(black_box(&data))));
    g.finish();
}

fn bench_read(c: &mut Criterion) {
    const CHUNKS: u64 = 16;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("src.bin");
    let data: Vec<u8> = (0..CHUNKS * CHUNK_SIZE).map(|i| (i % 253) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    drop(data);

    let reader = ChunkReader::open_blocking(&path).unwrap();
    let pool = BufferPool::for_chunks(1);
    let mut buf = pool.try_acquire().unwrap();
    let mut idx = 0u64;

    let mut g = c.benchmark_group("chunk_reader");
    g.throughput(Throughput::Bytes(CHUNK_SIZE));
    g.bench_function("read_chunk_4MiB_page_cached", |b| {
        b.iter(|| {
            let n = reader.read_chunk_blocking(idx, buf.full_mut()).unwrap();
            idx = (idx + 1) % CHUNKS;
            black_box(n)
        })
    });
    g.finish();
}

fn bench_finalize(c: &mut Criterion) {
    const CHUNKS: u64 = 64; // 256 MiB
    let size = CHUNKS * CHUNK_SIZE;
    let data: Vec<u8> = (0..size).map(|i| (i % 249) as u8).collect();
    let file_hash = hash_chunk(&data);
    let pieces: Vec<_> = data.chunks(CHUNK_SIZE as usize).enumerate().map(|(i, d)| piece_hash(size, i as u64, d)).collect();
    let dir = tempfile::tempdir().unwrap();
    let staged = StagedFile::create_blocking(dir.path(), "bench.0", dir.path().join("out"), size).unwrap();
    for (i, d) in data.chunks(CHUNK_SIZE as usize).enumerate() {
        staged.write_chunk_blocking(i as u64, d).unwrap();
    }
    staged.sync_blocking().unwrap();
    drop(staged);

    // Each iteration re-opens the staged file and finalizes it, then moves it back.
    let mut g = c.benchmark_group("finalize_256MiB");
    g.throughput(Throughput::Bytes(size));
    g.sample_size(10);
    let run = |b: &mut criterion::Bencher, with_pieces: bool| {
        b.iter(|| {
            let sf = StagedFile::open_existing_blocking(dir.path(), "bench.0", dir.path().join("out"), size).unwrap();
            let staged_path = sf.staging_path().to_path_buf();
            let out = if with_pieces { sf.finalize_with_pieces_blocking(&file_hash, &pieces) } else { sf.finalize_blocking(&file_hash) }.unwrap();
            std::fs::rename(out, staged_path).unwrap();
        })
    };
    g.bench_function("reread_file", |b| run(b, false));
    g.bench_function("merge_piece_hashes", |b| run(b, true));
    g.finish();
}

fn bench_file_hash(c: &mut Criterion) {
    let size = 64 * CHUNK_SIZE; // 256 MiB, page cached after the first pass
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("src.bin");
    std::fs::write(&path, (0..size).map(|i| (i % 241) as u8).collect::<Vec<_>>()).unwrap();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut g = c.benchmark_group("file_hash_256MiB");
    g.throughput(Throughput::Bytes(size));
    g.sample_size(10);
    g.bench_function("sequential", |b| b.iter(|| hash_file_blocking(&path).unwrap()));
    g.bench_function(format!("parallel_{threads}t"), |b| b.iter(|| hash_file_parallel_blocking(&path, threads).unwrap()));
    g.finish();
}

criterion_group!(benches, bench_hash, bench_read, bench_finalize, bench_file_hash);
criterion_main!(benches);
