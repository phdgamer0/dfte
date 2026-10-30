#![no_main]
// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Arbitrary sequences of valid-shaped messages in arbitrary order (manual §33).
//! Invariant: nothing panics, and data-plane frames are only admitted once the
//! connection is established and the manifest was accepted.

use libfuzzer_sys::fuzz_target;
use protocol::MsgType;
use protocol::state::Role;
use protocol::state::connection::{ConnEvent, Connection};
use protocol::state::transfer::{Transfer, TransferEvent, TransferState};

fuzz_target!(|data: &[u8]| {
    let role = if data.first().is_some_and(|b| b & 1 == 1) { Role::Initiator } else { Role::Responder };
    let mut conn = Connection::new(role);
    let mut xfer = Transfer::new(role);
    for &b in data.iter().skip(1) {
        let Ok(t) = MsgType::try_from(b | 0x01).or_else(|_| MsgType::try_from(b)) else { continue };
        if !conn.is_established() {
            if conn.check_incoming(t).is_err() {
                continue;
            }
            let ev = match (t, b >> 4) {
                (MsgType::Hello, _) => ConnEvent::HelloReceived,
                (MsgType::HelloAck, _) => ConnEvent::HelloAckReceived,
                (_, 0) => ConnEvent::HelloSent,
                (_, 1) => ConnEvent::HandshakeComplete,
                (_, 2) => ConnEvent::PeerVerified,
                _ => ConnEvent::CloseReceived,
            };
            let _ = conn.on_event(ev);
            continue;
        }
        let admitted = xfer.check_incoming(t).is_ok();
        if t == MsgType::ChunkData && admitted {
            assert_eq!(xfer.state(), TransferState::Transferring);
            assert_eq!(role, Role::Responder);
        }
        let ev = match t {
            MsgType::ManifestOffer => TransferEvent::OfferReceived,
            MsgType::ManifestAccept => TransferEvent::AcceptReceived,
            MsgType::Cancel => TransferEvent::Cancel,
            MsgType::Close => TransferEvent::ConnectionLost,
            MsgType::Ping => TransferEvent::OfferSent,
            MsgType::Pong => TransferEvent::AcceptSent,
            MsgType::ChunkAck => TransferEvent::AllChunksConfirmed,
            _ => TransferEvent::Reconnected,
        };
        if admitted || matches!(t, MsgType::Ping | MsgType::Pong) {
            let _ = xfer.on_event(ev);
        }
    }
});
