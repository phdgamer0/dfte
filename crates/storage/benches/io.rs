//! Storage micro-benchmarks (manual §13.1/§30): BLAKE3 over one 4 MiB chunk and
//! positional chunk reads from a (page-cached) temp file.
#![allow(clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use storage::{BufferPool, CHUNK_SIZE, ChunkReader, hash_chunk};

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

criterion_group!(benches, bench_hash, bench_read);
criterion_main!(benches);
