// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Discovery hot-ish paths: beacon sign/verify, QR encode/parse, peer-table ingest.
#![allow(clippy::unwrap_used)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use crypto::DeviceIdentity;
use discovery::lan::{BeaconSigner, BeaconView, PeerTable, TableConfig};
use discovery::qr::QrPayload;

const WALL: u64 = 1_700_000_000_000;

fn signer(seed: u8) -> BeaconSigner {
    BeaconSigner::new(&DeviceIdentity::from_secret_bytes(&[seed; 32]))
}

fn beacon(c: &mut Criterion) {
    let s = signer(1);
    let b = s.encode("Alice's laptop", 47_821, WALL, [7; 16]);
    c.bench_function("beacon/sign", |bench| bench.iter(|| s.encode(black_box("Alice's laptop"), 47_821, WALL, [7; 16])));
    c.bench_function("beacon/parse", |bench| bench.iter(|| BeaconView::parse(black_box(&b)).unwrap()));
    c.bench_function("beacon/parse+verify", |bench| bench.iter(|| BeaconView::parse(black_box(&b)).unwrap().verify().unwrap()));
}

fn qr(c: &mut Criterion) {
    let p = QrPayload::new("dfte-ABCD2345", "abcdefghjkmnpqrstuvwxyz2", [0xA5; 12], IpAddr::V4(Ipv4Addr::new(192, 168, 49, 1)), 47_821).unwrap();
    let text = p.encode().unwrap();
    c.bench_function("qr/encode", |bench| bench.iter(|| black_box(&p).encode().unwrap()));
    c.bench_function("qr/parse", |bench| bench.iter(|| QrPayload::parse(black_box(&text)).unwrap()));
}

/// Steady state: 64 known peers each re-announcing once (every beacon accepted).
fn table_steady(c: &mut Criterion) {
    let signers: Vec<_> = (0..64u8).map(signer).collect();
    let rounds: Vec<Vec<u8>> = (0..2u64).flat_map(|r| signers.iter().map(move |s| s.encode("peer", 4000, WALL + r, [0; 16]))).collect();
    let (first, second) = rounds.split_at(64);
    let mut group = c.benchmark_group("table");
    group.throughput(Throughput::Elements(64));
    group.bench_function("steady_64_refresh", |bench| {
        bench.iter_batched(
            || {
                let now = Instant::now();
                let mut t = PeerTable::new(TableConfig { verify_budget_per_sec: 100_000, ..TableConfig::default() }, now);
                for (i, b) in first.iter().enumerate() {
                    t.ingest(SocketAddr::from(([10, 0, 0, i as u8], 1)), b, now, WALL);
                }
                (t, now)
            },
            |(mut t, now)| {
                for (i, b) in second.iter().enumerate() {
                    black_box(t.ingest(SocketAddr::from(([10, 0, 0, i as u8], 1)), b, now, WALL));
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Hostile flood of 4096 datagrams mixed with one legitimate peer: garbage, replays of the
/// legitimate beacon from spoofed sources, multipath duplicates, and validly signed
/// beacons from 512 throwaway keys across 512 source addresses.
fn table_flood(c: &mut Criterion) {
    let legit = signer(200);
    let legit_beacons: Vec<Vec<u8>> = (0..256u64).map(|i| legit.encode("legit", 4000, WALL + i, [0; 16])).collect();
    let throwaway: Vec<Vec<u8>> = (0..512u32).map(|i| BeaconSigner::new(&DeviceIdentity::from_secret_bytes(&[(i % 251) as u8, (i / 251) as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30])).encode("x", 1, WALL, [0; 16])).collect();
    let mut flood: Vec<(SocketAddr, Vec<u8>)> = Vec::with_capacity(4096);
    for i in 0..4096usize {
        let spoof = SocketAddr::from(([10, 1, (i >> 8) as u8, i as u8], 1));
        let item = match i % 8 {
            0 => (SocketAddr::from(([10, 9, 9, 9], 1)), legit_beacons[(i / 8) % 256].clone()),
            1 => (spoof, legit_beacons[0].clone()),                                                                                 // replay
            2 | 3 => (spoof, vec![0x44, 0x46, 0x42, 0x31, 0, 0, 0, 1].into_iter().chain(std::iter::repeat_n(0xAA, 120)).collect()), // garbage w/ magic
            4 => (spoof, b"not a beacon at all".to_vec()),
            _ => (spoof, throwaway[i % 512].clone()),
        };
        flood.push(item);
    }
    let mut group = c.benchmark_group("table");
    group.throughput(Throughput::Elements(flood.len() as u64));
    group.bench_function("flood_4096", |bench| {
        bench.iter_batched(
            || {
                let now = Instant::now();
                (PeerTable::new(TableConfig::default(), now), now)
            },
            |(mut t, now)| {
                for (src, b) in &flood {
                    black_box(t.ingest(*src, b, now, WALL));
                }
                t
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, beacon, qr, table_steady, table_flood);
criterion_main!(benches);
