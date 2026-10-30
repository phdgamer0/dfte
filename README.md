# DFTE

DFTE sends files directly from one device to another over Wi-Fi, encrypted end to end. Nothing goes through a server or the internet, there are no accounts, and Bluetooth isn't used.

The engine is a Rust library. Each platform gets a native front end on top of it.

## Status

| Platform | State |
|---|---|
| Linux, command line (`dfte`) | Works. Shared network and Wi-Fi Direct (to an Android phone). |
| Linux, desktop app (`dfte-gtk`) | Works. GTK4 + libadwaita. Send, receive, Wi-Fi Direct, trusted devices. |
| Android | Works, arm64 only, Android 8.0 (API 26) and newer. Tested on one phone (Galaxy A30, Android 11). |
| Windows | Not started. Planned (WinUI 3). |
| iOS | Not started. Planned (SwiftUI, joins a hotspot the other device hosts after scanning a QR code). |

What works today:

- Transfers between any of the working front ends on the same local network. Devices find each other with signed UDP beacons, or you type an address.
- Wi-Fi Direct between a Linux laptop and an Android phone, with no router. The laptop has to start the connection, and it goes through NetworkManager, so no root is needed. See [docs/wifi-direct.md](docs/wifi-direct.md) for the details and the rough edges.
- Resuming an interrupted transfer, including after a crash or Ctrl-C.
- Folders, many small files, and files of any size (all offsets are 64-bit).

Not built yet: Android-to-Android over Wi-Fi Direct (two phones need a shared network for now), Wi-Fi Aware, hosting a hotspot for iPhones (`dfte qr` only prints the QR payload), compression, Windows, iOS, and any packaging (Flatpak, .deb, Play Store).

## Building from source

You need Rust 1.98.1. `rust-toolchain.toml` pins that version, so rustup picks it up on its own.

Command-line tool only:

```sh
cargo build --release -p dfte-cli
# binary: target/release/dfte
```

The desktop app needs the GTK 4 (4.12 or newer) and libadwaita (1.5 or newer) development packages. On Debian or Ubuntu 24.04 that's `libgtk-4-dev` and `libadwaita-1-dev`; on Arch, `gtk4` and `libadwaita`.

```sh
cargo build --release -p dfte-cli -p dfte-gtk
# binaries: target/release/dfte, target/release/dfte-gtk
```

A plain `cargo build --release` builds the whole workspace, including the GTK app and the benchmark tool, so it needs the GTK packages too.

Android (arm64 APK). You need JDK 21, the `aarch64-linux-android` Rust target, and an Android SDK with NDK 30.0.16248370, platform `android-37.0` and build-tools 36.0.0. Gradle runs the Rust cross-build and the uniffi binding generator for you.

```sh
rustup target add aarch64-linux-android
echo "sdk.dir=$HOME/Android/Sdk" > platform/android/local.properties
cd platform/android
./gradlew assembleRelease
# APK: app/build/outputs/apk/release/app-release.apk
```

`.github/workflows/android.yml` does the same thing in CI, if you want a reference.

## Quick start (same network)

On the machine that receives:

```console
$ dfte receive
Ready to receive as "archlinux" (8bee-594a-310a-934b-0f81-3b14).
Listening on 0.0.0.0:47821 (tcp+quic). Saving to /home/you/Downloads.
```

On the machine that sends:

```console
$ dfte send holiday.mp4 photos/
```

With no `--to`, `dfte send` looks for receivers for 5 seconds and shows a menu. You can also name the receiver directly: `--to archlinux`, `--to 8bee-594a-310a-934b-0f81-3b14`, or `--to 192.168.1.20:47821`.

Once connected, both terminals print the other device's fingerprint and a six-digit security code. The sender sees:

```
Receiving device "archlinux"
  fingerprint   8bee-594a-310a-934b-0f81-3b14
  security code 402917
Check that the other screen shows the same security code.
Send to this device? [y]es / [N]o / [a]lways trust this device:
```

The receiver gets the same block, ending in `Accept?`. Check that the two codes match before you answer `y`. That comparison is the only thing that stops someone else on the network from sitting in the middle of the connection: the encryption works either way, but without the comparison you don't know whose key you're encrypting to. If the codes differ, answer `n`. Answering `a` saves the device in your trust list, and the next connection to it skips the prompt as long as its key hasn't changed.

The desktop app and the Android app do the same thing through a dialog ("Compare this code").

If a transfer is interrupted, run the same `dfte send` command again. The receiver keeps the partial data and only the missing part is sent. `dfte resumable` lists what's waiting on the receiving side.

The full option list is in the man page, [docs/man/dfte.1](docs/man/dfte.1) (`man -l docs/man/dfte.1`).

## Quick start (Wi-Fi Direct, laptop and phone)

1. On the phone, open DFTE and go to Send or Receive. That keeps the phone discoverable. On Android 12 and older the Location switch has to be on (Android files Wi-Fi Direct under location; DFTE never reads where you are).
2. On the laptop, use the phone's Wi-Fi Direct name:

   ```sh
   dfte send --wifi-direct "Galaxy A30" holiday.mp4
   # or, to receive from the phone:
   dfte receive --wifi-direct "Galaxy A30"
   ```

   In the desktop app it's the Wi-Fi Direct box on the Receive page.
3. Accept the connection request on the phone if it asks, then compare the security code as usual.

If negotiation makes the laptop the group owner, NetworkManager needs `dnsmasq` installed to hand the phone an address. Without it the phone drops the group. [docs/wifi-direct.md](docs/wifi-direct.md) covers this and the other known problems.

## Where files go

| | Finished files | Partial data while a transfer runs |
|---|---|---|
| `dfte`, `dfte-gtk` | `$XDG_DOWNLOAD_DIR` (or the Downloads entry in `~/.config/user-dirs.dirs`, else `~/Downloads`). `dfte receive --dir` overrides it. | `$XDG_DATA_HOME/dfte/staging/` (`*.part` plus a `*.resume.json` per transfer) |
| Android | `Download/DFTE/` | App-private storage, moved once the transfer is verified |

A file only appears in the destination after its BLAKE3 hash has been checked against the sender's.

The CLI and the desktop app share one identity, trust list and staging directory in `$XDG_DATA_HOME/dfte` (default `~/.local/share/dfte`), so a machine looks like the same device whichever one you run.

## Security model

Every connection starts with a Noise_XX handshake (X25519, AES-256-GCM, SHA-256). On QUIC it runs inside TLS 1.3, which uses the same device key. Each device has an Ed25519 key, created on first run, and its fingerprint is the first 12 bytes of the key's SHA-256. After the handshake both sides derive the same six-digit code from the handshake transcript. If someone is relaying the connection, the two screens show different codes. File data is sealed per frame with AES-256-GCM, or ChaCha20-Poly1305 on CPUs without AES instructions, and every 4 MiB chunk is hash-checked on arrival. What this protects against and what it doesn't is spelled out in [docs/security.md](docs/security.md).

On Linux the identity key is a plain file (`identity.key`, mode 0600). Moving it into the desktop keyring is planned but not done. On Android it is wrapped with a Keystore key.

## Measured performance

All numbers are MiB/s, single runs unless stated, recorded during development. The phone is a Samsung Galaxy A30 (Exynos 7904, Android 11, kernel 4.4), the laptop an Arch Linux machine with an Intel AX201.

| Path | Result |
|---|---|
| Phone hotspot, 5 GHz 80 MHz, PHY 433 Mbit/s, TCP, encrypted, 256 MiB | 25.2–31.9 |
| Same link, QUIC, phone sending | 6.8–7.7 (CPU-bound, see below) |
| Through a home router (phone link 200 Mbit/s), 128 MiB, TCP | 7.8–9.2 |
| Wi-Fi Direct via NetworkManager (20 MHz group, PHY 72 Mbit/s), engine-bench | 3.3 |
| Same, through the apps | 2.3–3.1 |
| Phone loopback, TCP encrypted / plaintext, median of 5 | 48.9 / 62.0 |
| Laptop loopback, 1 GiB on tmpfs, encrypted, 1/2/4 streams | 772–867 |

Over the air, encryption costs nothing measurable; the radio is the limit. The phone's kernel has no UDP segmentation offload (it arrived in Linux 4.18), so QUIC sends top out around 7 MiB/s there. Senders without UDP GSO therefore use TCP automatically. The Wi-Fi Direct numbers are low because NetworkManager forms 20 MHz groups; an experiment with the phone hosting a 5 GHz, 80 MHz group reached 9.7–11.6 MiB/s, but that mode isn't in the apps yet.

More numbers, the test conditions and how to reproduce them: [docs/benchmarks.md](docs/benchmarks.md).

## Documentation

- [docs/architecture.md](docs/architecture.md): crates, layers, threading, transport choice
- [docs/protocol.md](docs/protocol.md): wire format and message flow
- [docs/security.md](docs/security.md): threat model, what users have to do, what gets logged
- [docs/wifi-direct.md](docs/wifi-direct.md): Wi-Fi Direct on Linux and Android, troubleshooting
- [docs/benchmarks.md](docs/benchmarks.md): engine-bench and measured results
- [docs/man/dfte.1](docs/man/dfte.1), [docs/man/dfte-gtk.1](docs/man/dfte-gtk.1): man pages

## License

PolyForm Shield 1.0.0, copyright Yazdan Samari. See [LICENSE](LICENSE). In short, you can use, change and share it, but not to compete with the project. The license text is what counts.
