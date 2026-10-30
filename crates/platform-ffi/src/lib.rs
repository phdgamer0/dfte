// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! uniffi bindings for iOS/Android/Windows (manual §2, §22).
//!
//! A thin, FFI-safe wrapper over [`dfte_core::TransferManager`]: strings for
//! paths and addresses, `Vec<u8>` for key material, a [`EngineError`] enum per
//! manual §36, and two callback interfaces implemented in Swift/Kotlin/C#:
//! [`TransferObserver`] (UI events) and [`PlatformDiscovery`] (radio discovery,
//! manual §5). No transfer logic lives here (manual §1.4).
//!
//! Bindings are generated in library mode from the compiled cdylib:
//! `cargo run -p platform-ffi --features bindgen --bin uniffi-bindgen -- generate --library target/debug/libplatform_ffi.so --language kotlin --out-dir target/bindings/kotlin`
//! (CI does this for Kotlin and Swift on every push, see `.github/workflows/ci.yml`).

// Manual §50: unsafe is denied workspace-wide. uniffi's proc macros
// (`setup_scaffolding!`, `#[uniffi::export]`, the derives) expand into
// `extern "C"` functions and raw-buffer handling that use `unsafe` inside every
// module they are applied to, so the allowance has to be crate-wide here. This
// crate contains no hand-written unsafe code; the invariants are uniffi's
// (handles and RustBuffers are only created and consumed by its generated
// foreign code).
#![allow(unsafe_code)]

mod discovery;
mod error;
mod manager;
mod types;

pub use discovery::{DiscoveryFailure, PeerSink, PlatformDiscovery};
pub use error::{EngineError, ErrorCode, ErrorInfo};
pub use manager::{ManagerConfig, TransferManager, TransferObserver, fingerprint_of_identity, generate_identity};
pub use types::{Direction, IncomingOffer, LinkInfo, LinkKind, LinkRole, OfferedFile, Peer, PeerAuth, Permission, Transfer, TransferState, TransportKind, VerifyRequest};

uniffi::setup_scaffolding!();

/// Copyright notice for the app's About screen (also embedded in the library).
#[uniffi::export]
pub fn notice() -> String {
    dfte_core::notice::NOTICE.to_owned()
}
