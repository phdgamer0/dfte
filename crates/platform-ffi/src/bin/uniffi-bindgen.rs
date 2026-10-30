// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! uniffi's binding generator, pinned to the same uniffi version as the
//! library. Usage (library mode):
//! `cargo run -p platform-ffi --features bindgen --bin uniffi-bindgen -- generate --library <libplatform_ffi.so> --language kotlin --out-dir <dir>`

fn main() {
    uniffi::uniffi_bindgen_main()
}
