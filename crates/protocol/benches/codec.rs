#![allow(clippy::unwrap_used)]
// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Protocol hot-path microbenchmarks (manual §30). Data-plane items must stay
//! allocation-free; manifest/control items are measured for regression only.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use protocol::codec::{encode_frame, parse_frame};
use protocol::header::{HEADER_LEN, Header};
use protocol::message::{ChunkAck, ChunkHeader, Message};
use protocol::{FileEntry, Manifest, MsgType};
use std::hint::black_box;

fn header(c: &mut Criterion) {
    let h = Header::new(MsgType::ChunkData, 0, 1, 42, 4 * 1024 * 1024);
    let bytes = h.to_bytes();
    c.bench_function("header/encode", |b| b.iter(|| black_box(black_box(&h).to_bytes())));
    c.bench_function("header/decode", |b| b.iter(|| Header::decode(black_box(&bytes)).unwrap()));
}

fn frame(c: &mut Criterion) {
    let body = vec![7u8; 4 * 1024 * 1024 + 8 + 16];
    let h = Header::new(MsgType::ChunkData, 0, 1, 42, body.len() as u32);
    let mut buf = Vec::new();
    encode_frame(&h, &body, &mut buf);
    let mut g = c.benchmark_group("frame");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("parse_4MiB", |b| b.iter(|| parse_frame(black_box(&buf)).unwrap().unwrap().len));
    g.bench_function("chunkdata_decode_4MiB", |b| b.iter(|| Message::decode(MsgType::ChunkData, black_box(&buf[HEADER_LEN..])).unwrap()));
    g.bench_function("chunk_header_encode", |b| {
        let mut out = [0u8; 8];
        b.iter(|| ChunkHeader { file_index: 1, chunk_index: black_box(9) }.encode(&mut out))
    });
    g.finish();
}

fn control(c: &mut Criterion) {
    let ack = Message::ChunkAck(ChunkAck { file_index: 1, chunk_index: 2, hash: [9; 32] });
    let mut body = Vec::new();
    ack.encode_body(&mut body).unwrap();
    c.bench_function("chunk_ack/encode", |b| {
        let mut out = Vec::with_capacity(128);
        b.iter(|| {
            out.clear();
            black_box(&ack).encode_body(&mut out).unwrap();
        })
    });
    c.bench_function("chunk_ack/decode", |b| b.iter(|| Message::decode(MsgType::ChunkAck, black_box(&body)).unwrap()));

    let mut g = c.benchmark_group("manifest");
    for n in [100usize, 20_000] {
        let files = (0..n).map(|i| FileEntry::file(format!("photos/2026/IMG_{i:06}.jpg"), 3_500_000 + i as u64, [i as u8; 32]).unwrap()).collect();
        let m = Manifest::new(files).unwrap();
        let bytes = m.encode().unwrap();
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::new("encode", n), &m, |b, m| b.iter(|| m.encode().unwrap()));
        g.bench_with_input(BenchmarkId::new("decode_validate", n), &bytes, |b, bytes| b.iter(|| Manifest::decode(bytes).unwrap()));
    }
    g.finish();
}

criterion_group!(benches, header, frame, control);
criterion_main!(benches);
