// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

use crate::error::ProtocolError;

/// Message type byte of the fixed header (manual §8.1).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum MsgType {
    Hello = 0x01,
    HelloAck = 0x02,
    /// Noise_XX handshake message on the control stream (manual §12.1, TCP backend).
    Handshake = 0x03,
    ChunkData = 0x10,
    ChunkAck = 0x11,
    SelectiveNack = 0x12,
    ManifestOffer = 0x20,
    ManifestAccept = 0x21,
    Cancel = 0x30,
    Ping = 0xF0,
    Pong = 0xF1,
    Close = 0xFF,
}

impl MsgType {
    pub const ALL: [MsgType; 12] = [MsgType::Hello, MsgType::HelloAck, MsgType::Handshake, MsgType::ChunkData, MsgType::ChunkAck, MsgType::SelectiveNack, MsgType::ManifestOffer, MsgType::ManifestAccept, MsgType::Cancel, MsgType::Ping, MsgType::Pong, MsgType::Close];
}

impl TryFrom<u8> for MsgType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => MsgType::Hello,
            0x02 => MsgType::HelloAck,
            0x03 => MsgType::Handshake,
            0x10 => MsgType::ChunkData,
            0x11 => MsgType::ChunkAck,
            0x12 => MsgType::SelectiveNack,
            0x20 => MsgType::ManifestOffer,
            0x21 => MsgType::ManifestAccept,
            0x30 => MsgType::Cancel,
            0xF0 => MsgType::Ping,
            0xF1 => MsgType::Pong,
            0xFF => MsgType::Close,
            _ => return Err(ProtocolError::UnknownMsgType),
        })
    }
}

impl From<MsgType> for u8 {
    fn from(value: MsgType) -> Self {
        value as u8
    }
}
