// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

use crate::Result;
use crate::error::ProtocolError;
use crate::msg_type::MsgType;

pub const MAGIC: u16 = 0x5032;
pub const PROTOCOL_VERSION: u16 = 0x0001;
/// Oldest version this build still speaks (manual §37: N and N-1).
pub const MIN_PROTOCOL_VERSION: u16 = 0x0001;
/// Encoded size of the fixed header. Not `size_of::<Header>()`: the in-memory
/// struct is padded, the wire layout is not.
pub const HEADER_LEN: usize = 24;
/// AEAD tag appended to every sealed body (manual §8.1).
pub const TAG_LEN: usize = 16;
/// Largest data-plane payload: one 4 MiB chunk plus its chunk sub-header.
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
/// Hard cap on `payload_length`, enforced before any buffer is sized from it.
/// Control messages (manifests) may be larger than a chunk, see manifest limits.
pub const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Header flag bits (manual §8.1). Unknown bits are ignored, never rejected.
pub mod flags {
    pub const COMPRESSED: u8 = 0b0000_0001;
    pub const RETRANSMISSION: u8 = 0b0000_0010;
    pub const KNOWN: u8 = COMPRESSED | RETRANSMISSION;
}

/// Fixed 24-byte frame header (manual §8.1). `payload_length` counts the whole
/// sealed body that follows the header, i.e. ciphertext plus AEAD tag.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: u16,
    pub msg_type: MsgType,
    pub flags: u8,
    pub stream_id: u32,
    pub sequence_number: u64,
    pub payload_length: u32,
}

impl Header {
    pub fn new(msg_type: MsgType, flags: u8, stream_id: u32, sequence_number: u64, payload_length: u32) -> Self {
        Self { version: PROTOCOL_VERSION, msg_type, flags, stream_id, sequence_number, payload_length }
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn encode(&self, buf: &mut [u8; HEADER_LEN]) {
        buf[0..2].copy_from_slice(&MAGIC.to_be_bytes());
        buf[2..4].copy_from_slice(&self.version.to_be_bytes());
        buf[4] = self.msg_type.into();
        buf[5] = self.flags;
        buf[6..8].copy_from_slice(&0u16.to_be_bytes());
        buf[8..12].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[12..20].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[20..24].copy_from_slice(&self.payload_length.to_be_bytes());
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        self.encode(&mut buf);
        buf
    }

    /// Parses a header from the front of `buf`. Checks run cheapest-first so
    /// garbage traffic is rejected on the magic alone (manual §8.1).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let buf: &[u8; HEADER_LEN] = buf.get(..HEADER_LEN).and_then(|b| b.try_into().ok()).ok_or(ProtocolError::Truncated)?;
        if u16::from_be_bytes([buf[0], buf[1]]) != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let version = u16::from_be_bytes([buf[2], buf[3]]);
        if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version) {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let msg_type = MsgType::try_from(buf[4])?;
        let flags = buf[5] & flags::KNOWN;
        if buf[6] != 0 || buf[7] != 0 {
            return Err(ProtocolError::ReservedBitsSet);
        }
        let payload_length = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        if payload_length > MAX_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge { len: payload_length, max: MAX_PAYLOAD });
        }
        Ok(Self { version, msg_type, flags, stream_id: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), sequence_number: u64::from_be_bytes([buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]]), payload_length })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_good_bytes() {
        let h = Header::new(MsgType::ChunkData, flags::RETRANSMISSION, 3, 0x0102, 0x10);
        assert_eq!(h.to_bytes(), [0x50, 0x32, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x10,]);
    }

    #[test]
    fn rejects_malformed() {
        let good = Header::new(MsgType::Ping, 0, 0, 0, 0).to_bytes();
        assert!(matches!(Header::decode(&good[..23]), Err(ProtocolError::Truncated)));

        let mut b = good;
        b[0] = 0;
        assert!(matches!(Header::decode(&b), Err(ProtocolError::BadMagic)));

        let mut b = good;
        b[3] = 9;
        assert!(matches!(Header::decode(&b), Err(ProtocolError::UnsupportedVersion(9))));

        let mut b = good;
        b[4] = 0x77;
        assert!(matches!(Header::decode(&b), Err(ProtocolError::UnknownMsgType)));

        let mut b = good;
        b[7] = 1;
        assert!(matches!(Header::decode(&b), Err(ProtocolError::ReservedBitsSet)));

        let mut b = good;
        b[20] = 0xFF;
        assert!(matches!(Header::decode(&b), Err(ProtocolError::PayloadTooLarge { .. })));
    }

    #[test]
    fn unknown_flag_bits_are_ignored() {
        let mut b = Header::new(MsgType::Ping, 0, 0, 0, 0).to_bytes();
        b[5] = 0b1111_0001;
        let h = Header::decode(&b).expect("unknown flag bits must not reject");
        assert_eq!(h.flags, flags::COMPRESSED);
    }
}
