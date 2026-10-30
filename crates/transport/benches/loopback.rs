// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Loopback framed throughput per backend and stream count (manual §11/§30,
//! benchmark #6 on loopback). Measures the transport alone: no app-level
//! crypto, no disk. QUIC always encrypts (TLS 1.3 AEAD inside quinn) while TCP
//! here is plaintext, so QUIC numbers include an AEAD cost the TCP path only
//! pays later, above the transport.
#![allow(clippy::unwrap_used)]

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use crypto::DeviceIdentity;
use protocol::MsgType;
use protocol::header::Header;
use tokio::runtime::Runtime;
use transport::{CongestionControl, Connection, Listener, QuicConfig, QuicTransport, TcpConfig, TcpTransport, Transport};

const FRAME: usize = 4 * 1024 * 1024;
const FRAMES: usize = 32; // 128 MiB per iteration

async fn pair<T: Transport>(t: &T, streams: usize) -> (Connection, Connection) {
    let mut l = t.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let (a, b) = tokio::join!(t.connect(addr, streams), l.accept());
    (a.unwrap(), b.unwrap())
}

/// Every stream runs on its own task (so multiple cores are used, like the
/// real engine), and is handed back afterwards for the next iteration.
async fn blast(tx: &mut Connection, rx: &mut Connection, payload: &'static [u8]) {
    let n = tx.data.len();
    let senders: Vec<_> = std::mem::take(&mut tx.data)
        .into_iter()
        .enumerate()
        .map(|(i, mut s)| {
            tokio::spawn(async move {
                for f in (i..FRAMES).step_by(n) {
                    s.writer.write_frame(&Header::new(MsgType::ChunkData, 0, i as u32, f as u64, FRAME as u32), &[payload]).await.unwrap();
                }
                s.writer.flush().await.unwrap();
                s
            })
        })
        .collect();
    let receivers: Vec<_> = std::mem::take(&mut rx.data)
        .into_iter()
        .enumerate()
        .map(|(i, mut s)| {
            tokio::spawn(async move {
                let mut buf = vec![0u8; FRAME];
                for _ in (i..FRAMES).step_by(n) {
                    let h = s.reader.read_header().await.unwrap().unwrap();
                    s.reader.read_body_into(&h, &mut buf).await.unwrap();
                }
                s
            })
        })
        .collect();
    for t in senders {
        tx.data.push(t.await.unwrap());
    }
    for t in receivers {
        rx.data.push(t.await.unwrap());
    }
}

fn quic(cfg: QuicConfig) -> QuicTransport {
    QuicTransport::new(&DeviceIdentity::generate().unwrap(), cfg).unwrap()
}

fn bulk<T: Transport>(g: &mut BenchmarkGroup<'_, WallTime>, rt: &Runtime, label: &str, t: &T, payload: &'static [u8]) {
    for streams in [1usize, 2, 4] {
        let (mut a, mut b) = rt.block_on(pair(t, streams));
        g.bench_function(BenchmarkId::new(label, streams), |bch| {
            bch.iter_custom(|iters| {
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    rt.block_on(blast(&mut a, &mut b, payload));
                }
                start.elapsed()
            })
        });
    }
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let payload: &'static [u8] = Box::leak(vec![7u8; FRAME].into_boxed_slice());
    let mut g = c.benchmark_group("tcp_loopback_128MiB");
    g.throughput(Throughput::Bytes((FRAME * FRAMES) as u64));
    g.sample_size(10);
    for (label, cfg) in [("autotune", TcpConfig::default()), ("buf4MiB", TcpConfig { send_buffer: Some(4 << 20), recv_buffer: Some(4 << 20), ..TcpConfig::default() })] {
        bulk(&mut g, &rt, label, &TcpTransport::new(cfg), payload);
    }
    g.finish();

    let mut g = c.benchmark_group("quic_loopback_128MiB");
    g.throughput(Throughput::Bytes((FRAME * FRAMES) as u64));
    g.sample_size(10);
    for (label, cfg) in [("cubic", QuicConfig::default()), ("bbr", QuicConfig { congestion: CongestionControl::Bbr, ..QuicConfig::default() }), ("cubic_osbuf", QuicConfig { socket_send_buffer: None, socket_recv_buffer: None, ..QuicConfig::default() })] {
        bulk(&mut g, &rt, label, &quic(cfg), payload);
    }
    g.finish();
}

/// Control-path shape: many small frames (ChunkAck-sized) on one stream.
fn small<T: Transport>(c: &mut Criterion, group: &str, t: &T) {
    const N: usize = 20_000;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let (mut a, mut b) = rt.block_on(pair(t, 1));
    let body = [5u8; 64];
    let mut g = c.benchmark_group(group);
    g.throughput(Throughput::Elements(N as u64));
    g.sample_size(10);
    g.bench_function("64B_x20k_queued", |bch| {
        bch.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                rt.block_on(async {
                    let send = async {
                        for i in 0..N {
                            a.control.writer.queue_frame(&Header::new(MsgType::ChunkAck, 0, 0, i as u64, 64), &[&body]).await.unwrap();
                        }
                        a.control.writer.flush().await.unwrap();
                    };
                    let recv = async {
                        for _ in 0..N {
                            b.control.reader.read_frame().await.unwrap().unwrap();
                        }
                    };
                    tokio::join!(send, recv);
                });
            }
            start.elapsed()
        })
    });
    g.bench_function("64B_x20k_flush_each", |bch| {
        bch.iter_custom(|iters| {
            let start = std::time::Instant::now();
            for _ in 0..iters {
                rt.block_on(async {
                    let send = async {
                        for i in 0..N {
                            a.control.writer.write_frame(&Header::new(MsgType::ChunkAck, 0, 0, i as u64, 64), &[&body]).await.unwrap();
                        }
                    };
                    let recv = async {
                        for _ in 0..N {
                            b.control.reader.read_frame().await.unwrap().unwrap();
                        }
                    };
                    tokio::join!(send, recv);
                });
            }
            start.elapsed()
        })
    });
    g.finish();
}

fn small_frames(c: &mut Criterion) {
    small(c, "tcp_small_frames", &TcpTransport::default());
    small(c, "quic_small_frames", &quic(QuicConfig::default()));
}

criterion_group!(benches, bench, small_frames);
criterion_main!(benches);
