# Architecture

DFTE is one Rust engine with a thin native front end per platform. Everything from "there is a socket" upward (framing, handshake, encryption, chunking, hashing, resume) is shared Rust. The front ends handle the radio, the UI, and OS lifecycle chores like Android's foreground service. Most of what follows comes from that split.

## Layers

From the top:

1. The UI, native per platform: GTK4 + libadwaita on Linux, Jetpack Compose on Android. WinUI 3 and SwiftUI are planned.
2. The application API, `TransferManager` in `crates/core`. It's job-oriented: start a scan, send these paths to that peer, accept or reject an offer, cancel, pause, resume. The UI never sees packets or streams. It gets immutable `Transfer` snapshots through a `TransferObserver` callback interface.
3. The engine: sender and receiver pipelines, the secure session layer, manifests, resume (`crates/core`), on top of the pure protocol definitions (`crates/protocol`), crypto (`crates/crypto`) and file I/O (`crates/storage`).
4. Transport: a `Transport` trait with two backends, QUIC (`quinn`) and multi-stream TCP. Both hand the engine the same shape: one control stream plus N data streams.
5. The link, meaning how the two devices got onto the same IP network in the first place: a shared LAN, a Wi-Fi Direct group, or (planned) a hotspot an iPhone joins. This is `crates/discovery` on Linux and Kotlin code on Android.
6. The radio itself, which no app on any of these platforms can control.

## Crates

| Crate | What it does |
|---|---|
| `protocol` | The 24-byte frame header, message types, MessagePack control messages, the manifest and its validation, and the connection/transfer/chunk state machines. No I/O, no clocks, no async. That's deliberate: it can be fuzzed and unit-tested without a runtime. |
| `crypto` | Device identity (Ed25519), the Noise_XX handshake (via `snow`), SAS derivation, and the per-stream AEAD sessions (via `ring`). Also sans-I/O: bytes in, bytes out. |
| `storage` | Chunk reads, pre-allocated staging files, the buffer pool, BLAKE3 piece hashes, resume sidecars, path validation, and the sender's hash cache. Functions that block are named `*_blocking`. |
| `transport` | The `Transport`/`Listener`/`Connection` traits, the TCP and QUIC backends, framed I/O, and `DualListener` (TCP and QUIC on one port number). |
| `discovery` | The `PeerDiscovery` trait, the discovery state machine, signed LAN beacons, the QR payload format for iOS, and the Linux Wi-Fi Direct backends (NetworkManager, and an older `wpa_supplicant` one that's only tested against a mock bus). |
| `core` (`dfte-core`) | `TransferManager`, `send_files`/`receive`, the secure session (`secure.rs`), sender and receiver pipelines. |
| `platform-ffi` | uniffi bindings over `TransferManager`. Kotlin is in use; CI also generates Swift bindings, for which no app exists yet. No logic. |
| `cli` (`dfte-cli`) | The `dfte` command. Identity and trust-store files, the terminal code prompt, progress output, exit codes. |
| `bench` | `engine-bench` (see [benchmarks.md](benchmarks.md)) and criterion micro-benchmarks. Same crates as the apps, no separate implementation. |
| `platform/linux` (`dfte-gtk`) | The GTK app. Calls `dfte-core` directly, with no FFI, and reuses the CLI crate's identity, trust and path code. |
| `tests/network-harness` | netem tests: two network namespaces with loss, delay and reordering, each backend at 1 and 4 streams. |

Dependency direction: `core` depends on `protocol`, `transport`, `crypto`, `storage` and `discovery`; `transport` depends on `protocol`; `protocol` depends on none of the others. `storage` deliberately doesn't depend on `protocol` either; `core` converts between the wire manifest and the storage types.

`unsafe` is denied workspace-wide. The exceptions are the uniffi glue in `platform-ffi` and `storage/src/procfd.rs`, which duplicates Android picker file descriptors because Android 11's FUSE layer refuses to reopen them.

## Why a Rust core and native UIs

The hard, platform-specific part of this project is the radio code: Wi-Fi Direct on Android, NetworkManager on Linux, and later WinRT and `NEHotspotConfigurationManager`. No cross-platform UI toolkit covers those APIs, so Flutter, Qt or a WebView shell would still need native radio code underneath, plus a second FFI layer next to the Rust one. With native UIs there's exactly one boundary per platform (Kotlin to Rust here, through uniffi), and on Linux there's none: the GTK app is Rust.

Rust for the core, because the engine parses bytes from untrusted peers, and because the ecosystem already had what was needed (`tokio`, `quinn`, `rustls`, `ring`, `snow`, `uniffi`).

## The platform boundary

The line sits at "the two devices have IP addresses on a shared link". Below it, platform code finds the peer and forms the link. Above it, everything is shared.

- On Linux, discovery is Rust: LAN beacons (`discovery::lan`) and NetworkManager over D-Bus (`discovery::nm`).
- On Android, the Kotlin `WifiDirect` class only makes the phone discoverable and reports group changes. Once a group exists, the engine's own LAN beacons run over it so the two sides learn each other's port and fingerprint.
- No retry loops, byte parsing or crypto live in Kotlin. If a shim needs one of those, it belongs in the core behind a new FFI call.

Peer identity never comes from discovery. A beacon is signed, but the address it arrived from isn't, and the handshake still has to prove the key.

## Choosing TCP or QUIC

The sender picks the backend. The receiver listens on both, on the same port number (TCP and UDP sockets don't clash), so it doesn't need to know in advance (`transport/src/dual.rs`).

With `--transport auto` (the default), a sender uses `TransportKind::platform_default()`:

- TCP on Windows. QUIC through Windows' UDP offload has been reported unstable, and there's no Windows app yet anyway.
- TCP on Linux and Android kernels without UDP GSO (Linux older than 4.18). A probe at startup asks quinn whether the kernel segments UDP sends.
- QUIC everywhere else.

The GSO rule came out of testing on a real phone. On the Galaxy A30 (kernel 4.4), QUIC sends stayed at about 7 MiB/s on every path, encrypted or not, while TCP did 25–32 MiB/s on the same link. Without GSO quinn makes one syscall and seals one packet per ~1.4 KB, and the phone's cores can't keep up. Receiving QUIC on that phone was fine.

Neither backend wins everywhere. Under 2% netem loss QUIC did 203 MiB/s against TCP's 21 (single flow); under reordering TCP was ahead. Over loopback on the laptop TCP is faster (428–933 MiB/s against 259–359 for QUIC, depending on stream count). See [benchmarks.md](benchmarks.md).

Reliability comes from the transport in both cases. There is no retransmission layer on raw UDP. The application-level `ChunkAck` only confirms the receiver's hash of each chunk.

Data streams default to 2 per transfer (`dfte send --streams`, 1–16). On the real links measured so far, 4 streams did no better than 2.

## Threading

- `TransferManager` owns one multi-thread tokio runtime, one worker per core by default. Every async method runs its work there, so callers can await from any executor, such as Kotlin coroutines. The GTK app keeps a small one-thread tokio runtime of its own for the calls it makes and awaits their results from the GTK main loop.
- The job map sits behind a `tokio::sync::RwLock`. Per-chunk counters are atomics, so the data path doesn't take that lock.
- Observer callbacks run on one dedicated dispatcher thread, fed by a bounded queue. Progress and state updates merge when the queue is full, so a slow UI can't stall a transfer. Front ends hop to their UI thread themselves. The GTK app forwards events over a channel to the GTK main loop.
- Sender, per data stream: a producer task takes the next chunk from a shared queue (streams steal work from each other), reads it into a pool buffer on a blocking thread, and seals it in place; a writer task sends header, body and tag in one vectored write. Reading the next chunk overlaps with writing the previous one.
- Receiver, per data stream: a task reads each frame straight into a pool buffer and opens it in place. A blocking thread then computes the chunk's BLAKE3 piece hash and `pwrite`s it into the pre-allocated `.part` file. An event loop records the hash, marks the chunk in the resume bitmap and sends `ChunkAck`s in batches.
- Encryption runs inline on those tasks. There's no separate crypto pool, because AEAD hasn't shown up as a bottleneck on any real link.

## Memory and backpressure

Chunk buffers come from a fixed pool of 4 MiB buffers, allocated once per transfer. A sent buffer stays checked out until the receiver's `ChunkAck` arrives, so the pool size is the in-flight window, and waiting for a free buffer is the whole backpressure mechanism. The default is 8 chunks per side, 32 MiB. On a 1 GiB laptop loopback run, 16 chunks gave no more throughput than 8 at about twice the peak memory.

There are no unbounded queues: the observer queue, the LAN peer table, pending TCP connection groups (32) and concurrent incoming transfers (8) are all capped.

## Not in the code

- No Windows or iOS shim, so no WinRT, RIO sockets, AWDL or `NEHotspotConfigurationManager` code.
- No `io_uring`. It was measured on Linux and not adopted: kernel time went to copies, which `io_uring` doesn't remove, and syscall overhead was under 1% of CPU. Worth re-measuring on NVMe/UFS.
- No compression. The `COMPRESSED` flag and a capability bit are reserved for it.
- No Wi-Fi Aware, and no hotspot hosting for iPhones.
