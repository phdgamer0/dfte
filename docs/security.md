# Security

This page says what DFTE protects against, what it doesn't, and the one step users have to do themselves. The wire details are in [protocol.md](protocol.md).

## The short version

After a short setup exchange (which carries the device names in the clear), everything two devices send each other is encrypted and authenticated. That only helps if you're talking to the right device. The first time two devices connect, both show a six-digit security code. If the codes match, nobody is in the middle. If you accept without looking, you've skipped the only check that would catch someone who is.

## What you have to do

Compare the code on both screens before you accept. It's derived from the handshake itself, so an attacker relaying the connection can't make the two screens show the same number. If they differ, reject the connection and don't retry right away. Find out which device you were about to talk to first.

There is no option to skip the comparison on a first connection, in any of the front ends. A device can skip the prompt only when:

- you marked it as trusted after a previous comparison ("always trust" / "Trust this device"). It's then pinned by fingerprint. If its key ever changes, for example after a reinstall, the code is asked again;
- you gave its fingerprint yourself: `dfte send --to FINGERPRINT`, `--expect FINGERPRINT`, or `dfte receive --accept-from FINGERPRINT`. Get that fingerprint from the other device's own screen (`dfte id`, or the Settings page in the desktop and Android apps), not from a message someone sent you.

`dfte trust list` shows the pinned devices and `dfte trust remove` drops one. In the desktop app it's the Devices page.

## In scope

DFTE is designed to protect against:

- Someone on the same Wi-Fi or radio channel reading your files. Every frame after the handshake is sealed with AES-256-GCM or ChaCha20-Poly1305, with keys derived from an ephemeral X25519 exchange. A new connection always gets new keys.
- Someone tampering with or injecting traffic in an established session. The AEAD tag covers the frame header as well as the body, and sequence numbers must strictly increase per stream, so altered, replayed or reordered frames are rejected and the session ends.
- Impersonation during pairing, as long as the code comparison above actually happens.
- A malicious peer. Paths in an incoming manifest are untrusted: absolute paths, `..`, drive letters, backslashes, NUL bytes and overlong names are refused when the manifest is parsed, and the destination path is checked again against the real filesystem just before each write, so a symlink planted by an earlier transfer can't send data outside the destination. Manifests are capped at 20,000 entries and 8 MiB, frames at 16 MiB (64 KiB before authentication), and a receiver handles at most 8 incoming connections at once. The receiver checks free space in its staging directory before it pre-allocates the incoming files, so a too-large offer fails up front instead of filling the disk.
- Corruption somewhere between the sender's disk and the receiver's. Each 4 MiB chunk's BLAKE3 hash is compared between the two sides, and the whole file is checked against the manifest's hash before it leaves the staging directory.

Discovery beacons on the LAN are signed with the device key, so nobody can advertise your fingerprint at their own address and port. The source IP address can't be signed, but a connection to a forged address still fails the handshake.

## Out of scope

DFTE does not protect against:

- A compromised operating system or a malicious app with root on either device.
- Compromised Wi-Fi firmware or drivers.
- Someone with physical access to an unlocked device that already trusts the other one.
- Traffic analysis. Anyone in radio range can see that two devices are exchanging roughly this much data. Device names in LAN beacons and in the Hello message are sent in the clear. MAC address randomisation is up to the OS.
- Jamming and other radio-level denial of service.
- An attacker who learns your identity key. Session keys are ephemeral, but whoever holds the identity key can pose as your device.

## Known weak spots

- On Linux the identity key is a plain file, `$XDG_DATA_HOME/dfte/identity.key`, mode 0600. dfte refuses to use it if other users can read it. Anyone who can read your home directory as you can copy it. Moving it into the desktop keyring (libsecret) is planned. On Android the key is wrapped with an Android Keystore key and stored in app-private storage that is excluded from backups.
- `trusted.json` sits next to the key, also mode 0600. Anyone who can write to it can add a device that will then skip the code prompt.
- `dfte qr` prints a hotspot passphrase in the QR text. Only show it to the person you're pairing with. The command is a preview: dfte doesn't start a hotspot.
- Device names aren't authenticated. A nearby device can call itself anything. Pick devices by fingerprint or compare the code; don't rely on the name.

## Logging

By default the CLI logs only warnings and errors and the desktop app only warnings. With `-v` or `RUST_LOG` (CLI), or `DFTE_LOG` (desktop app), logs can include:

- the peer's fingerprint (the same string the user sees) and the transfer id;
- relative file paths in some warnings and info lines, such as a skipped symlink or a file renamed because its name isn't valid on this platform;
- connection and transfer events, the chosen cipher and stream count, timings, throughput, and error variants with OS error codes.

Never logged, at any level: file contents, session or identity keys, Noise handshake messages, and full public keys.

There's no automated check enforcing this. An allow-list of log field names was planned but isn't implemented, so it's down to code review. Logs go to stderr and stay on the machine; nothing is uploaded anywhere.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) at the top of the repository.
