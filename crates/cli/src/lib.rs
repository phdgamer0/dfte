// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! `dfte`: the Linux command-line front end of the transfer engine.
//!
//! The binary is a thin shell over [`app`]; the modules below hold the
//! testable pieces (identity and trust storage, verification decisions, peer
//! selection, progress throttling, error copy). No protocol, crypto or
//! chunking logic lives here (manual §1.4): it all comes from `dfte_core`.
//!
//! # Files
//! `$XDG_DATA_HOME/dfte` (default `~/.local/share/dfte`, 0700) holds
//! `identity.key` (Ed25519 seed, 0600, refused if others can read it; the
//! planned upgrade is the desktop keyring via libsecret, manual §6),
//! `trusted.json` (pinned peers, 0600) and `staging/` (partial downloads and
//! resume sidecars, §14/§19).
//!
//! # Verification
//! A peer is accepted only if its fingerprint matches one the user gave
//! (`--to FP`, `--expect`, `--accept-from`), it is in the trust store, or the
//! user confirms the 6-digit code on a terminal. There is no skip flag (§35).
//!
//! # Wi-Fi Direct
//! `--wifi-direct DEVICE` joins a group the other device hosts through
//! NetworkManager (no root), then discovers it with beacons over that group.
//!
//! When this machine ends up owning the group, NetworkManager serves DHCP
//! through dnsmasq, which must be installed (no root needed at run time).
//!
//! # Not covered (needs root)
//! Hosting the iOS SoftAP: `dfte qr` only prints the payload.

pub mod app;
pub mod error;
pub mod fsutil;
pub mod identity;
pub mod offer;
pub mod paths;
pub mod progress;
pub mod select;
pub mod trust;
pub mod verify;
pub mod wifi_direct;
