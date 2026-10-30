// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Internal hooks the [`TransferManager`](crate::TransferManager) uses to follow
//! a transfer through its phases and to ask the user about an incoming offer.
//! The public free functions run without them.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use protocol::Manifest;

use crate::error::Result;
use crate::options::PeerAuth;

/// A milestone in one transfer (manual §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Sender: sources hashed, manifest built; connecting next.
    Hashed { bytes_total: u64 },
    /// Both: `ManifestAccept` exchanged; chunks flow next. `resumed_bytes` is
    /// what the receiver already held (manual §19).
    Accepted { bytes_total: u64, resumed_bytes: u64 },
}

/// Called synchronously from the engine at each [`Phase`]; must not block.
pub(crate) type PhaseFn<'a> = &'a (dyn Fn(Phase) + Send + Sync);

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Decides where an offered manifest goes, or rejects it (an error is sent to
/// the peer as the matching `Close` reason).
pub(crate) type OfferGate<'a> = &'a (dyn Fn(&Manifest, &PeerAuth) -> BoxFuture<Result<PathBuf>> + Send + Sync);

pub(crate) fn emit(hook: Option<PhaseFn<'_>>, phase: Phase) {
    if let Some(h) = hook {
        h(phase);
    }
}
