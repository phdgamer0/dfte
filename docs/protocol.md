# DFTE wire protocol, version 1

This describes protocol version 1 as implemented in `crates/protocol`, `crates/crypto`, `crates/transport` and `crates/core/src/secure.rs`. All integers are big-endian.

## Terms

The sender offers files and always opens the connection, so it is the Noise initiator. The receiver listens and accepts. A connection is one control stream (stream 0) plus N data streams (1..=N), carried by TCP or QUIC.

## Transport bindings

### TCP

Each connection uses 1 + N TCP sockets to the same port. Right after connecting, every socket sends a 26-byte preamble so the listener can group them:

```
offset  size  field
0       8     magic "DFTE/tcp"
8       16    group token, random per connection
24      1     index (0 = control)
25      1     total socket count
```

The listener drops sockets with a bad preamble or one that doesn't arrive in time, and keeps at most 32 incomplete groups. `TCP_NODELAY` is set; buffer sizes are left to the OS.

### QUIC

One QUIC connection with 1 + N bidirectional streams. Since a QUIC peer only learns about a stream once data arrives on it, the opener writes a 4-byte preamble on each stream: `"DQ" | index: u8 | total: u8`. Index 0 is the control stream.

TLS 1.3 runs with self-signed certificates whose key is the device's Ed25519 identity key. Client authentication is mandatory. The verifier accepts any certificate with an Ed25519 key and ignores names, dates and the self-signature; what it does check is the TLS 1.3 `CertificateVerify` signature, which proves the peer holds that key. The authenticated key is handed up to the engine, which later requires it to equal the identity authenticated by Noise (below). A mismatch fails the connection with `AuthenticationFailed`.

So on QUIC the stack runs TLS 1.3, then Noise_XX inside it, then per-frame AEAD. The original design had TLS alone on QUIC. The code runs the same session setup on both backends instead, and the extra encryption layer measured at 1–4% of QUIC throughput on loopback, so it stayed.

Stream receive window: 1 MiB per stream (quinn's per-stream reassembly limit makes larger windows unsafe under loss); connection window: 64 MiB.

### Ports

The receiver listens for TCP and QUIC on the same port number, 47821 by default. LAN discovery beacons use UDP port 47820.

## Frame format

Every message on every stream is one frame: a fixed 24-byte header followed by `payload_length` bytes of body.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|         magic 0x5032          |          version              |
+---------------+---------------+-------------------------------+
|   msg type    |    flags      |       reserved (0x0000)       |
+---------------+---------------+-------------------------------+
|                          stream id                            |
+---------------------------------------------------------------+
|                                                               |
+                       sequence number                         +
|                                                               |
+---------------------------------------------------------------+
|                        payload length                         |
+---------------------------------------------------------------+
|                    body (payload length bytes)                |
```

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | magic | `0x5032` ("P2"). Anything else is rejected before the rest is read. |
| 2 | 2 | version | `0x0001`. The supported range is 1..=1. Outside it the frame is rejected. |
| 4 | 1 | msg type | See below. Unknown values are rejected. |
| 5 | 1 | flags | Bit 0 `COMPRESSED` (reserved, never set), bit 1 `RETRANSMISSION`. Unknown bits are ignored, not rejected. |
| 6 | 2 | reserved | Must be zero. Non-zero is rejected. |
| 8 | 4 | stream id | 0 for control, 1..=N for data. |
| 12 | 8 | sequence number | Per stream and direction, strictly increasing. Also the AEAD nonce input. |
| 20 | 4 | payload length | Bytes of body that follow, including the 16-byte AEAD tag. Capped at 16 MiB (`MAX_PAYLOAD`) before any buffer is sized from it. |

Before authentication only frames up to 64 KiB on stream 0 are accepted.

After the handshake, every body is `ciphertext || tag` (16 bytes). The associated data is the 24-byte header as sent, so the header is authenticated but not encrypted.

## Message types

| Value | Name | Stream | Body (plaintext) |
|---|---|---|---|
| `0x01` | Hello | control | MessagePack `Hello` |
| `0x02` | HelloAck | control | MessagePack `HelloAck` |
| `0x03` | Handshake | control | Raw Noise message |
| `0x10` | ChunkData | data | 8-byte chunk sub-header, then file bytes |
| `0x11` | ChunkAck | control | MessagePack `ChunkAck` |
| `0x12` | SelectiveNack | control | MessagePack `{ file_index: u32, chunks: [u32] }` |
| `0x20` | ManifestOffer | control | MessagePack `Manifest` |
| `0x21` | ManifestAccept | control | MessagePack `{ resume_offsets: [u64] }` |
| `0x30` | Cancel | control | Empty |
| `0xF0` | Ping | control | u64 |
| `0xF1` | Pong | control | u64 |
| `0xFF` | Close | control | MessagePack `CloseReason` |

`Handshake` (0x03) was added during implementation to carry the Noise messages.

The current engine never sends `SelectiveNack`, `Ping` or `Pong`. It parses them and ignores `Ping`/`Pong`, which reset the idle timer. Re-sends are driven by `ChunkAck` instead (see below).

`CloseReason` is one of `Done`, `Cancelled`, `UnsupportedVersion`, `ProtocolViolation`, `AuthenticationFailed`, `IntegrityFailure`, `InsufficientSpace`.

## Session setup

All of this happens on the control stream. The connection state machine is `Init → WaitHelloAck → Handshaking → Authenticated → Established`; any timeout, malformed frame or unexpected message type moves it to `Failed`.

1. Sender sends `Hello` in plaintext: `versions` (list of u16), `capabilities` (u64 bit set), `streams` (requested data streams), `device_name`, `ciphers` (AEAD suite ids in preference order).
2. Receiver answers `HelloAck`: the highest common `version`, the intersection of `capabilities`, the granted `streams` (the request clamped to its own maximum), its `device_name` and its own `ciphers` list.
3. Three `Handshake` frames carry `Noise_XX_25519_AESGCM_SHA256` (`-> e`, `<- e, ee, s, es`, `-> s, se`). The Noise prologue is the exact bytes of the Hello frame followed by the HelloAck frame, header included, so tampering with either breaks the handshake.

Capability bits: `0` TCP, `1` QUIC, `2` zstd compression (reserved, unused), `63` benchmark-only plaintext data streams. Bit 63 is only advertised by builds with the `bench-insecure-plaintext` feature, which the apps don't enable, and only takes effect if both peers set it. Even then the control stream stays encrypted.

`device_name` is unauthenticated and only for display.

### Identity binding

The Noise static key is X25519, derived from the device's Ed25519 identity key. Each side also sends its Ed25519 public key, encrypted, in the payload of the Noise message that carries its `s`, and the receiving side checks that it maps to the Noise static key. The identity users compare is therefore the key Noise actually authenticated.

Fingerprint: the first 12 bytes of SHA-256(Ed25519 public key), as six groups of four hex digits, for example `8bee-594a-310a-934b-0f81-3b14`. Comparison ignores case and separators.

### SAS

```
SAS = HKDF-SHA256(ikm = noise handshake hash, info = "dfte sas v1")[0..8]
      read as u64, mod 10^6, zero-padded to 6 digits
```

Both sides compute the same value only if they saw the same handshake. A relay in the middle runs two separate handshakes, so the two screens show different codes.

The peer is accepted when one of these holds:

- the user confirms the SAS on both devices;
- the peer's fingerprint is in the local trust store;
- the fingerprint was given out of band (`--to FINGERPRINT`, `--expect`, `--accept-from`, or a scanned QR code in future iOS pairing).

Otherwise the side closes with `Close(AuthenticationFailed)`.

### Data-plane keys

After the handshake, Noise's split yields one key per direction. For each stream id (0 for control, 1..=N for data) and direction:

```
prk   = HKDF-Extract(salt = handshake hash, ikm = split key for that direction)
key   = HKDF-Expand(prk, "dfte data key v1"   || suite_id || stream_id_be32)
salt  = HKDF-Expand(prk, "dfte nonce salt v1" || suite_id || stream_id_be32)   (12 bytes)
nonce = salt XOR (0^32 || sequence_number_be64)
```

Suite ids: `0x01` AES-256-GCM, `0x02` ChaCha20-Poly1305. Each side lists the suite its CPU accelerates first (AES-256-GCM when it has AES and carry-less multiply instructions); both run the same deterministic choice over the two lists, and a tie goes to ChaCha20-Poly1305.

A sealer refuses to reuse or go back in sequence numbers. An opener rejects a frame whose sequence number is not above the last authenticated one, and reports replay and tampering as different errors. Either ends the session. The replay window only advances after a frame authenticates.

## Transfer

The transfer state machine is `Ready → ManifestSent / ManifestReceived → Transferring → Complete`, with `Cancelled`, `Interrupted` (connection lost, resume state kept) and `Failed` as exits.

### Manifest

The sender hashes every file before the offer, then sends `ManifestOffer`:

```
Manifest  { transfer_id: UUID v4, files: [FileEntry] }
FileEntry { relative_path: string, size: u64, modified_time: i64,
            permissions: u32 | nil, content_hash: [u8; 32],
            chunk_count: u32, is_dir: bool }
```

- `relative_path` is UTF-8 with `/` separators. Receivers reject empty paths, absolute paths, `.` and `..` components, empty components, backslashes, NUL, drive prefixes like `C:`, paths over 4096 bytes and components over 255 bytes. Paths must be unique within a manifest.
- `content_hash` is BLAKE3 of the whole file, all zeros for directories.
- `chunk_count` must equal `ceil(size / 4 MiB)`.
- `is_dir` marks an empty-directory entry: size 0, no chunks.
- At most 20,000 entries and 8 MiB of encoded manifest. The size is checked before decoding.
- Symlinks on the sending side are skipped, not followed.

The receiver repeats the path checks against the real filesystem when it writes, so a symlink planted inside the destination by an earlier transfer can't redirect a write outside it.

### Accept and resume

The receiver answers `ManifestAccept { resume_offsets }`, one u64 per file: the number of bytes, counted from the start of the file, it already holds and has verified. Offsets must be a multiple of 4 MiB or equal to the file size; anything else is a protocol violation. The sender starts each file at `ceil(offset / 4 MiB)`.

The receiver resumes only if it finds a saved transfer whose file list has the same paths, sizes and `content_hash` values. `transfer_id` doesn't have to match, so a fresh `dfte send` of the same files picks up where the last one stopped. If the source file changed, the hashes differ and that file starts from zero.

Resume state is a bitmap of confirmed chunks per file, kept in `<staging>/<transfer_id>.resume.json` next to the `.part` files. Only the contiguous prefix of that bitmap goes on the wire. The receiver fsyncs the touched `.part` files and then rewrites the sidecar (temporary file, fsync, rename) every 32 confirmed chunks (128 MiB), so the sidecar never claims data that isn't on disk.

### Chunks

Chunk size is fixed at 4 MiB; the last chunk of a file is shorter. A `ChunkData` body starts with an 8-byte sub-header:

```
offset  size  field
0       4     file_index   (position in manifest.files)
4       4     chunk_index
8       n     file bytes, n = chunk length
```

The data plane doesn't use MessagePack. Chunks are spread over the data streams through a shared work queue, so chunks arrive out of order and the receiver writes each one at its offset.

For every chunk it stores, the receiver sends `ChunkAck { file_index, chunk_index, hash }`, where `hash` is the BLAKE3 hash of that 4 MiB piece as the receiver computed it from the bytes it wrote. The sender compares it with its own piece hash:

- match: the chunk is confirmed and its buffer goes back to the pool;
- mismatch, or no ack within the ack timeout (30 s): the sender re-reads the chunk from disk and sends it again under a new sequence number with the `RETRANSMISSION` flag set. It can't resend the old frame, because that frame's nonce is used up. After 8 retries the transfer fails.

The ack is an integrity check, not loss recovery; TCP or QUIC already guarantees delivery.

### Finishing

When every chunk is confirmed, the sender sends `Close(Done)`. The receiver fsyncs the staged files, checks each file's whole-file BLAKE3 against `content_hash` (combining the piece hashes it already has instead of reading the file again), renames each verified file from staging into the destination, deletes the sidecar, and replies `Close(Done)`. A file whose hash doesn't match is never moved and the transfer fails; files checked before it in the same batch may already be in place.

Either side can stop with `Cancel`. A dropped connection leaves the `.part` files and sidecar in place on the receiver.

## Things that are not part of version 1

Compression, SelectiveNack-driven re-sends, keepalive pings and any field beyond those listed above. Additive features go in as new capability bits or new optional MessagePack fields (`ciphers` was added this way and defaults to empty when absent). Anything incompatible bumps `version`.
