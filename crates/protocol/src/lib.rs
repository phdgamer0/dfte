// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Wire format, control messages and protocol state machines (manual §8-§11).
//! Pure and I/O-free so it can be fuzzed and tested without a runtime (manual §3).

pub mod codec;
pub mod error;
pub mod header;
pub mod manifest;
pub mod message;
pub mod msg_type;
pub mod state;

pub use error::ProtocolError;
pub use header::Header;
pub use manifest::{FileEntry, Manifest};
pub use message::Message;
pub use msg_type::MsgType;

pub type Result<T> = core::result::Result<T, ProtocolError>;

pub const fn chunk_count(file_size: u64, chunk_size: u64) -> u64 {
    debug_assert!(chunk_size != 0);
    file_size.div_ceil(chunk_size)
}

pub fn chunk_offset(index: u64, chunk_size: u64) -> Result<u64> {
    debug_assert!(chunk_size != 0);
    index.checked_mul(chunk_size).ok_or(ProtocolError::ArithmeticOverflow)
}

pub fn chunk_len(file_size: u64, index: u64, chunk_size: u64) -> Result<u64> {
    debug_assert!(chunk_size != 0);
    let offset = chunk_offset(index, chunk_size)?;
    if offset >= file_size {
        return Ok(0);
    }
    Ok((file_size - offset).min(chunk_size))
}
