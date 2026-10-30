// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! The copyright notice every DFTE binary carries.
//!
//! [`NOTICE`] is shown by `--version` and the apps' About views, and [`EMBEDDED`]
//! keeps the same text in the binary's read-only data even where nothing prints
//! it (the Android library), so it survives stripping and shows up in `strings`.

/// The copyright text as a literal, for `concat!` in other crates (clap's
/// `long_version` needs one string).
#[macro_export]
macro_rules! copyright {
    () => {
        "Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by the\nPolyForm Shield License 1.0.0: https://github.com/phdgamer0/dfte/blob/main/LICENSE"
    };
}

/// Product, version and copyright.
pub const NOTICE: &str = concat!("DFTE ", env!("CARGO_PKG_VERSION"), "\n", copyright!());

/// [`NOTICE`] as a kept static: `#[used]` stops the linker (and LTO) from dropping
/// it when no code path reads it.
#[used]
pub static EMBEDDED: &str = NOTICE;
