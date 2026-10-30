# Security policy

DFTE moves files between devices over local Wi-Fi with no server in between, so a bug in it can expose someone's files or device to whoever is nearby. If you find one, please tell me privately first.

## Reporting a vulnerability

Use GitHub's private reporting form: https://github.com/phdgamer0/dfte/security/advisories/new

Only you and the maintainers can see what you send there. Please don't open a public issue for a security problem. If the form doesn't work for some reason, open an issue that only says you have something to report privately, without any details, and I'll set up another way to talk.

A useful report says which app and version or commit you tested, what the two devices were (platform, OS version, Wi-Fi Direct or a shared network), the steps to reproduce, and what an attacker gains. A proof of concept helps but isn't required.

## What happens next

DFTE is maintained by one person in their own time. I'll try to reply within a week to say I've seen the report, and to keep you updated while I work on a fix. Some fixes will take longer than others, and I'll tell you if that happens. Once a fix is released, I'll publish an advisory and credit you by name unless you'd rather not be named. There is no bug bounty.

Please give me a reasonable chance to release a fix before you publish anything. If we disagree about timing, let's talk about it in the advisory.

## Supported versions

DFTE hasn't had a stable release yet. Fixes go into the `main` branch and the next build of each app. Older builds don't get separate patches.

## Scope

These are in scope:

- Reading or changing transfer contents without the encryption keys, including replaying or tampering with packets on the local network.
- Getting a device to accept a connection or a transfer as a peer it didn't verify, or getting past the 6-digit code or fingerprint check.
- A peer making the receiver write outside its download or staging folder, for example with `..` in a file name, absolute paths or symlinks.
- A malformed packet, manifest or LAN announcement that crashes the app, hangs it, or makes it use unbounded memory or disk.
- Forging another device's announcement so that DFTE shows or connects to the wrong device.
- Keys, file contents or other secrets showing up in logs, or the device identity key stored with permissions others can read.
- An app connecting to anything on the internet. It isn't supposed to.

These are out of scope:

- Attacks that need root or administrator access, or malware already running as the user, on either device.
- Bugs in Wi-Fi firmware, drivers or the operating system's Wi-Fi Direct and hotspot code. Please report those to the vendor. If DFTE could reasonably work around one, a normal issue is welcome.
- Someone with physical access to an unlocked device that has already paired.
- Seeing that DFTE is running nearby, the device name, the public key, or how much data two devices exchange. Announcements are public on purpose, and radio traffic can't be hidden from someone nearby. The [privacy policy](docs/legal/privacy.md) describes what is visible.
- Jamming or flooding the Wi-Fi channel.
- A user who accepts a device without comparing the code.

If you aren't sure whether something counts, report it anyway.
