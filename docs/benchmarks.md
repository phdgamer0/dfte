# Benchmarks

Numbers on this page were recorded in the development log while the code was being built; the log itself isn't in the repository. They're single runs unless a median is mentioned, taken under whatever load the machine had at the time, so small differences don't mean much. Throughput is in MiB/s (1 MiB = 2^20 bytes), measured on the sending side unless noted.

## Hardware

- Phone: Samsung Galaxy A30 (SM-A305F), Exynos 7904 (Cortex-A73/A53), Android 11, Linux 4.4, eMMC storage. Its kernel has no UDP GSO, which matters for QUIC.
- Laptop: Arch Linux, Intel AX201 Wi-Fi (iwlwifi). The crypto micro-benchmarks ran on an Intel i7-10750H. Disk-mode runs on the laptop used a 5400 rpm HDD, since the NVMe drive wasn't mounted.

## engine-bench

`engine-bench` drives the real engine: the same `core`, `transport`, `crypto` and `storage` crates as the apps. It also has a plaintext mode for measuring encryption cost, which the apps can't do: the bench crate is the only one that enables the `bench-insecure-plaintext` feature, and CI checks that `dfte-core` and `platform-ffi` don't pick it up.

Build it:

```sh
cargo build --release -p bench
# binary: target/release/engine-bench
```

### loopback

Both sides in one process over 127.0.0.1, in a temporary directory.

```sh
engine-bench loopback --size 1G
engine-bench loopback --size 1G --transport quic --streams 4
engine-bench loopback --size 256M --files 2000 --in-memory   # many small files
engine-bench loopback --size 1G --plaintext                  # data streams unencrypted
```

| Option | Meaning |
|---|---|
| `--size SIZE` | Total bytes, e.g. `1G`, `512M`, `1048576`. Required. |
| `--files N` | Split the size across N files (default 1). |
| `--transport tcp\|quic` | Default `tcp`. |
| `--streams N` | Data streams (default 2). |
| `--plaintext` | Send data streams without AEAD. The control stream stays encrypted. |
| `--in-memory` | Source, staging and destination on tmpfs (`/dev/shm`). The full code path still runs (pread, pwrite, fallocate, fsync, rename), but no block device is involved. |
| `--dir DIR` | Base directory in disk mode (default `.`). The receiver's fsyncs hit the real disk here. |
| `--in-flight N` | Sender window in 4 MiB chunks. |
| `--recv-buffers N` | Receiver pool size in 4 MiB chunks. |
| `--repeat N` | Run the same transfer N times. |

In both modes the freshly generated source file is in the page cache, so the sender's reads aren't disk reads.

### send / recv across two machines

The receiver:

```sh
engine-bench recv --listen 0.0.0.0:9000 --staging /tmp/stage --out /tmp/out
```

The sender:

```sh
engine-bench send --target 192.168.49.1:9000 --file big.bin --transport quic --streams 2
```

Both sides show the security code and ask `[y/N]`. `--trust-any` skips that; only use it on links you control. `--transport` has to match on both sides, since `recv` listens on one backend only. `--plaintext` on the sender needs `--allow-plaintext` on the receiver.

### Global options

| Option | Meaning |
|---|---|
| `--json` | Machine-readable output instead of the summary. |
| `--hash-cache DIR` | Sender: cache whole-file and per-chunk hashes so unchanged files aren't hashed again. |
| `--quic-packet-threshold N` | QUIC reordering tolerance in packets (RFC 9002 default 3). |
| `--quic-time-threshold X` | QUIC loss time threshold as a multiple of RTT (default 1.125). |

`--in-flight` and `--recv-buffers` default to 8 chunks (32 MiB) in the current source; older builds used 16. `engine-bench <command> --help` shows what your build uses.

### Other benchmarks

- `cargo bench -p protocol` (likewise `storage`, `crypto`, `transport`, `discovery`) runs that crate's criterion micro-benchmarks. CI compares pull requests against `main` with these but never fails on them.
- `tests/network-harness` runs the engine through two network namespaces with netem delay, loss, reordering and duplication. It needs root, or a user namespace (`unshare -rmn`).

## Results

### Phone and laptop over the air

Phone's own hotspot: 5745 MHz, 80 MHz VHT, one spatial stream, −32 dBm, PHY 433 Mbit/s. 256 MiB, random data, hash-checked on arrival.

| Direction | Backend | Streams | Encrypted | Plaintext |
|---|---|---|---|---|
| phone → laptop | TCP | 2 | 25.9 | 28.8 |
| phone → laptop | TCP | 4 | 25.3 | 24.4 |
| phone → laptop | QUIC | 2 | 6.8 | 6.6 |
| phone → laptop | QUIC | 4 | 7.7 | 8.2 |
| laptop → phone | TCP | 2 | 25.2 | 30.0 |
| laptop → phone | TCP | 4 | 31.9 | 30.0 |
| laptop → phone | QUIC | 2 | 22.3 | 23.3 |
| laptop → phone | QUIC | 4 | 23.3 | 23.3 |

What this shows:

- TCP gets 210–270 Mbit/s out of the 433 Mbit/s PHY rate.
- Encryption makes no consistent difference over the air.
- 4 streams aren't consistently better than 2.
- QUIC is slow only when the phone sends, encrypted or not. UDP GSO arrived in Linux 4.18, and without it quinn makes one syscall and seals one packet per ~1.4 KB, and the phone's CPU runs out first. Socket buffers weren't the cause (`rmem_max`/`wmem_max` were 8 MiB). Since then, a sender whose kernel lacks GSO uses TCP by default.

Through a home router (5 GHz, phone link 200 Mbit/s), 128 MiB:

| Direction | TCP | QUIC |
|---|---|---|
| phone → laptop | 7.8–9.2 | 6.6–7.4 |
| laptop → phone | 7.8–9.1 | 8.3–9.1 |

The router path tops out around 9 MiB/s, about a third of the direct hotspot.

Wi-Fi Direct through NetworkManager (20 MHz group, PHY 72 Mbit/s): engine-bench 3.3 MiB/s, the apps 2.3–3.1 MiB/s. With the phone hosting a 5 GHz, 80 MHz group and the laptop joining it as a plain Wi-Fi client (PHY 433 Mbit/s, phone still connected to home Wi-Fi on 2.4 GHz channel 6): laptop → phone TCP 10.5, QUIC 9.7; phone → laptop TCP 11.6. That second mode was an experiment; the apps don't do it. Details in [wifi-direct.md](wifi-direct.md).

The first app transfer, phone to laptop through the router on a weak link (RSSI −73 dBm, 108 Mbit/s): 200 MiB at 3.8 MiB/s.

### Phone alone

Both ends on the phone, over loopback, disk-backed (eMMC).

| Test | Result |
|---|---|
| TCP, encrypted / plaintext, median of 5 | 48.9 / 62.0 |
| QUIC, encrypted or plaintext | 7.0 |
| Big file, after the small-file fixes, median | 55.2 |
| 2,000 files × 32 KiB, before / after batching fsyncs | 7.2 / 33.7 |

The small-file fix: fsync the filesystem once and each destination directory once instead of per file, skip pre-allocation under 1 MiB, check free space once per transfer, and hash small files in parallel on the sender. Finalizing went from 6.8 s to 0.7 s and building the manifest from 1.6 s to 0.7 s.

On the phone AEAD costs about 20% of loopback throughput (48.9 against 62.0). Real links so far ran at 3–32 MiB/s, where the gap doesn't show up, so encryption hasn't been optimized further.

Android app, release build on the same phone: APK 6.1 MB, PSS 52 MB, 0.4% CPU when idle. Cold start was 657–974 ms in the first release and about 370–450 ms after a later pass, with the engine ready after 210–230 ms.

### Laptop alone

| Test | Result |
|---|---|
| AES-256-GCM, one core, 4 MiB buffers (i7-10750H) | 4.12 GiB/s |
| ChaCha20-Poly1305, same | 1.97 GiB/s |
| Engine loopback, 1 GiB on tmpfs, encrypted, 1/2/4 streams (load 1.3) | 772–867 MiB/s |
| Same, plaintext | 1.14–1.24 GiB/s |
| Engine loopback, 512 MiB tmpfs, encrypted, TCP 1/2/4 streams (load ~5) | 428 / 766 / 933 |
| Same, QUIC 1/2/4 streams | 316–359 / 259 / 295–326 |
| `dfte` CLI against engine-bench, loopback | TCP 704 vs 646, QUIC 246 vs 250 |
| Sender window 16 vs 8 chunks, 1 GiB loopback | TCP 787 vs 889, QUIC 283 vs 278; peak RSS 241 vs 141 MB |

QUIC on one connection is limited by quinn's per-packet work. Turning off the engine's own encryption on top of QUIC's TLS gained only 1–4%, so the double encryption stays.

With the sender's hash cache, a repeat send of an unchanged file skipped 207–271 ms of hashing; total time went from about 1300 ms to 1075 ms.

### Under loss and reordering (netem)

Two network namespaces joined by a veth pair, netem on both directions. The full matrix (8 profiles × TCP/QUIC × 1/4 streams) passes. Two results matter here:

- At 2% loss, one flow: QUIC 203 MiB/s, TCP 21 MiB/s.
- Under reordering TCP is ahead of QUIC. Raising QUIC's packet threshold to 50 helped (from 14 to 24) but stayed below TCP. netem's reordering doesn't look much like Wi-Fi, so the RFC defaults were kept and the knobs exposed as `--quic-packet-threshold` / `--quic-time-threshold`.

### io_uring

A 2 GiB tmpfs loopback run spent 7.5 s in user and 10.8 s in kernel time. strace counted about 24,000 syscalls per GiB, around 25 ms and under 1% of CPU. The kernel time is copying, which io_uring doesn't remove, so it wasn't adopted. That's worth re-checking on fast NVMe or UFS storage.

## Not measured yet

- Anything on Windows or iOS, which don't exist yet.
- Any pair other than this one phone and one laptop.
- A comparison with LocalSend on the same hardware, which is in the test plan.
- Energy use.
