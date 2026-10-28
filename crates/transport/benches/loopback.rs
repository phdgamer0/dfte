//! Loopback framed throughput per backend and stream count (manual §11/§30).
//! Measures the transport alone: no crypto, no disk.
#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use protocol::MsgType;
use protocol::header::Header;
use transport::{Connection, Listener, TcpConfig, TcpTransport, Transport};

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

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let payload: &'static [u8] = Box::leak(vec![7u8; FRAME].into_boxed_slice());
    let mut g = c.benchmark_group("tcp_loopback_128MiB");
    g.throughput(Throughput::Bytes((FRAME * FRAMES) as u64));
    g.sample_size(10);
    for (label, cfg) in [("autotune", TcpConfig::default()), ("buf4MiB", TcpConfig { send_buffer: Some(4 << 20), recv_buffer: Some(4 << 20), ..TcpConfig::default() })] {
        for streams in [1usize, 2, 4] {
            let t = TcpTransport::new(cfg);
            let (mut a, mut b) = rt.block_on(pair(&t, streams));
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
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
