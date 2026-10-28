//! Seal throughput at the 4 MiB chunk size, both suites (manual §13.1, §17).
#![allow(clippy::unwrap_used)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use crypto::{CipherSuite, DeviceIdentity, Handshake, Session};

const CHUNK: usize = 4 * 1024 * 1024;

fn session(suite: CipherSuite) -> Session {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let mut init = Handshake::initiator(&a).unwrap();
    let mut resp = Handshake::responder(&b).unwrap();
    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    init.read_message(&m2).unwrap();
    let m3 = init.write_message(&[]).unwrap();
    resp.read_message(&m3).unwrap();
    init.into_session(suite).unwrap().0
}

fn seal_4mib(c: &mut Criterion) {
    let mut group = c.benchmark_group("seal_4MiB");
    group.throughput(Throughput::Bytes(CHUNK as u64));
    for suite in CipherSuite::ALL {
        let (mut sealer, _) = session(suite).split();
        let mut buf = vec![0xA5u8; CHUNK];
        let mut seq = 0u64;
        group.bench_function(format!("{suite:?}"), |bench| {
            bench.iter(|| {
                seq += 1;
                // Detached variant: encrypts the pool-sized buffer in place with no realloc.
                sealer.seal_in_place_detached(seq, b"header", &mut buf).unwrap()
            });
        });
    }
    group.finish();
}

/// Full Noise_XX exchange + key derivation: the per-connection startup cost (manual §30).
fn handshake(c: &mut Criterion) {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    c.bench_function("handshake/noise_xx_full", |bench| {
        bench.iter(|| {
            let mut init = Handshake::initiator(&a).unwrap();
            let mut resp = Handshake::responder(&b).unwrap();
            let m1 = init.write_message(&[]).unwrap();
            resp.read_message(&m1).unwrap();
            let m2 = resp.write_message(&[]).unwrap();
            init.read_message(&m2).unwrap();
            let m3 = init.write_message(&[]).unwrap();
            resp.read_message(&m3).unwrap();
            (init.into_session(CipherSuite::Aes256Gcm).unwrap(), resp.into_session(CipherSuite::Aes256Gcm).unwrap())
        })
    });
}

criterion_group!(benches, seal_4mib, handshake);
criterion_main!(benches);
