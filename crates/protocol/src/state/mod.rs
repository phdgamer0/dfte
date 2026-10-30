// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Pure, synchronous state machines (manual §9). No I/O, no clocks of their
//! own: time is passed in, so every transition is deterministic and testable.

pub mod chunk;
pub mod connection;
pub mod resume;
pub mod transfer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Connection initiator / file sender.
    Initiator,
    Responder,
}
