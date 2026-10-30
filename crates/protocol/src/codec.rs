// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Frame = 24-byte header + body of `payload_length` bytes (manual §8.1).
//! Zero-allocation: these functions only slice the caller's buffer.

use crate::Result;
use crate::header::{HEADER_LEN, Header};

/// Writes header then body into `out`. `header.payload_length` must equal `body.len()`.
pub fn encode_frame(header: &Header, body: &[u8], out: &mut Vec<u8>) {
    debug_assert_eq!(header.payload_length as usize, body.len());
    out.reserve(HEADER_LEN + body.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(body);
}

/// A complete frame found at the front of a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRef<'a> {
    pub header: Header,
    pub body: &'a [u8],
    /// Total bytes this frame occupies in the buffer.
    pub len: usize,
}

/// Returns `Ok(None)` when more bytes are needed. The header (and its
/// `payload_length` cap) is validated before the body length is trusted.
pub fn parse_frame(buf: &[u8]) -> Result<Option<FrameRef<'_>>> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let header = Header::decode(buf)?;
    let len = HEADER_LEN + header.payload_length as usize;
    Ok(buf.get(HEADER_LEN..len).map(|body| FrameRef { header, body, len }))
}

/// Bytes still missing before `parse_frame` can return a frame, if the header
/// is already available. Lets a reader size exactly one `read_exact`.
pub fn frame_len(header_bytes: &[u8]) -> Result<Option<usize>> {
    if header_bytes.len() < HEADER_LEN {
        return Ok(None);
    }
    Ok(Some(HEADER_LEN + Header::decode(header_bytes)?.payload_length as usize))
}
