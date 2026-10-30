# docs

| File | Read it for |
|---|---|
| [architecture.md](architecture.md) | How the code is split into crates, which layer does what, how TCP or QUIC gets picked, and which threads run where. |
| [protocol.md](protocol.md) | The wire format: frame header, message types, handshake, key derivation, chunking, resume. Written for someone implementing or debugging a peer. |
| [security.md](security.md) | What DFTE protects against and what it doesn't, the code comparison, and what ends up in logs. |
| [wifi-direct.md](wifi-direct.md) | Connecting a Linux laptop and an Android phone without a router, its limits, and troubleshooting. |
| [benchmarks.md](benchmarks.md) | Running `engine-bench`, and every measured number so far with its hardware and conditions. |
| [man/dfte.1](man/dfte.1) | Man page for the command-line tool. View with `man -l docs/man/dfte.1`. |
| [man/dfte-gtk.1](man/dfte-gtk.1) | Man page for the desktop app. |

These pages describe the code as it is now. The project was planned from a longer design spec that isn't part of the repository; it also covers Windows and iOS, which don't exist yet, and a few of its details changed during implementation. Code comments that say "manual §N" refer to that spec.
