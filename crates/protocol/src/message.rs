use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::Result;
use crate::error::ProtocolError;
use crate::header::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::manifest::Manifest;
use crate::msg_type::MsgType;

/// Additive capability bits exchanged in Hello/HelloAck (manual §37). Breaking
/// changes bump the header version instead.
pub mod caps {
    pub const TRANSPORT_TCP: u64 = 1 << 0;
    pub const TRANSPORT_QUIC: u64 = 1 << 1;
    pub const COMPRESSION_ZSTD: u64 = 1 << 2;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub versions: Vec<u16>,
    pub capabilities: u64,
    /// Parallel streams the sender would like to use (manual §11: 1-4).
    pub streams: u8,
    pub device_name: String,
}

impl Hello {
    pub fn new(capabilities: u64, streams: u8, device_name: impl Into<String>) -> Self {
        Self { versions: (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).collect(), capabilities, streams, device_name: device_name.into() }
    }

    /// Responder side: picks the highest common version and intersects capabilities.
    pub fn accept(&self, local_caps: u64, max_streams: u8, device_name: &str) -> Result<HelloAck> {
        let version = self.versions.iter().copied().filter(|v| (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(v)).max().ok_or(ProtocolError::NoCommonVersion)?;
        Ok(HelloAck { version, capabilities: self.capabilities & local_caps, streams: self.streams.clamp(1, max_streams.max(1)), device_name: device_name.to_owned() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    pub version: u16,
    pub capabilities: u64,
    pub streams: u8,
    pub device_name: String,
}

/// Integrity confirmation for one reassembled chunk (manual §10/§20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkAck {
    pub file_index: u32,
    pub chunk_index: u32,
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveNack {
    pub file_index: u32,
    pub chunks: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAccept {
    /// Per file, the contiguous byte offset already held by the receiver (manual §19).
    pub resume_offsets: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    Done,
    Cancelled,
    UnsupportedVersion,
    ProtocolViolation,
    AuthenticationFailed,
    IntegrityFailure,
}

/// Fixed sub-header at the front of every ChunkData body, so the data plane
/// never goes through MessagePack (manual §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub file_index: u32,
    pub chunk_index: u32,
}

pub const CHUNK_HEADER_LEN: usize = 8;

impl ChunkHeader {
    pub fn encode(&self, buf: &mut [u8; CHUNK_HEADER_LEN]) {
        buf[0..4].copy_from_slice(&self.file_index.to_be_bytes());
        buf[4..8].copy_from_slice(&self.chunk_index.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let b = buf.get(..CHUNK_HEADER_LEN).ok_or(ProtocolError::Truncated)?;
        Ok(Self { file_index: u32::from_be_bytes([b[0], b[1], b[2], b[3]]), chunk_index: u32::from_be_bytes([b[4], b[5], b[6], b[7]]) })
    }
}

/// A decoded frame body. `ChunkData` borrows from the receive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message<'a> {
    Hello(Hello),
    HelloAck(HelloAck),
    ChunkData { chunk: ChunkHeader, data: &'a [u8] },
    ChunkAck(ChunkAck),
    SelectiveNack(SelectiveNack),
    ManifestOffer(Manifest),
    ManifestAccept(ManifestAccept),
    Cancel,
    Ping(u64),
    Pong(u64),
    Close(CloseReason),
}

impl Message<'_> {
    pub fn msg_type(&self) -> MsgType {
        match self {
            Message::Hello(_) => MsgType::Hello,
            Message::HelloAck(_) => MsgType::HelloAck,
            Message::ChunkData { .. } => MsgType::ChunkData,
            Message::ChunkAck(_) => MsgType::ChunkAck,
            Message::SelectiveNack(_) => MsgType::SelectiveNack,
            Message::ManifestOffer(_) => MsgType::ManifestOffer,
            Message::ManifestAccept(_) => MsgType::ManifestAccept,
            Message::Cancel => MsgType::Cancel,
            Message::Ping(_) => MsgType::Ping,
            Message::Pong(_) => MsgType::Pong,
            Message::Close(_) => MsgType::Close,
        }
    }

    /// Appends the plaintext body to `out`. For ChunkData this copies `data`;
    /// the hot path writes [`ChunkHeader`] straight into its pool buffer instead.
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Message::Hello(m) => encode_rmp(m, out),
            Message::HelloAck(m) => encode_rmp(m, out),
            Message::ChunkData { chunk, data } => {
                let mut h = [0u8; CHUNK_HEADER_LEN];
                chunk.encode(&mut h);
                out.extend_from_slice(&h);
                out.extend_from_slice(data);
                Ok(())
            }
            Message::ChunkAck(m) => encode_rmp(m, out),
            Message::SelectiveNack(m) => encode_rmp(m, out),
            Message::ManifestOffer(m) => {
                out.extend_from_slice(&m.encode()?);
                Ok(())
            }
            Message::ManifestAccept(m) => encode_rmp(m, out),
            Message::Cancel => Ok(()),
            Message::Ping(n) | Message::Pong(n) => {
                out.extend_from_slice(&n.to_be_bytes());
                Ok(())
            }
            Message::Close(r) => encode_rmp(r, out),
        }
    }
}

impl<'a> Message<'a> {
    /// Decodes an (already decrypted) body. All input is untrusted.
    pub fn decode(msg_type: MsgType, body: &'a [u8]) -> Result<Self> {
        Ok(match msg_type {
            MsgType::Hello => Message::Hello(decode_rmp(body)?),
            MsgType::HelloAck => Message::HelloAck(decode_rmp(body)?),
            MsgType::ChunkData => Message::ChunkData { chunk: ChunkHeader::decode(body)?, data: &body[CHUNK_HEADER_LEN..] },
            MsgType::ChunkAck => Message::ChunkAck(decode_rmp(body)?),
            MsgType::SelectiveNack => Message::SelectiveNack(decode_rmp(body)?),
            MsgType::ManifestOffer => Message::ManifestOffer(Manifest::decode(body)?),
            MsgType::ManifestAccept => Message::ManifestAccept(decode_rmp(body)?),
            MsgType::Cancel => {
                if !body.is_empty() {
                    return Err(ProtocolError::TrailingBytes);
                }
                Message::Cancel
            }
            MsgType::Ping | MsgType::Pong => {
                let n: [u8; 8] = body.try_into().map_err(|_| ProtocolError::Truncated)?;
                let n = u64::from_be_bytes(n);
                if msg_type == MsgType::Ping { Message::Ping(n) } else { Message::Pong(n) }
            }
            MsgType::Close => Message::Close(decode_rmp(body)?),
        })
    }
}

fn encode_rmp<T: Serialize>(value: &T, out: &mut Vec<u8>) -> Result<()> {
    rmp_serde::encode::write_named(out, value).map_err(|_| ProtocolError::MessageEncode)
}

fn decode_rmp<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(body));
    let value = T::deserialize(&mut de).map_err(|_| ProtocolError::MessageDecode)?;
    if de.position() != body.len() as u64 {
        return Err(ProtocolError::TrailingBytes);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_negotiation() {
        let hello = Hello::new(caps::TRANSPORT_TCP | caps::TRANSPORT_QUIC, 4, "a");
        let ack = hello.accept(caps::TRANSPORT_TCP, 2, "b").unwrap();
        assert_eq!(ack.version, PROTOCOL_VERSION);
        assert_eq!(ack.capabilities, caps::TRANSPORT_TCP);
        assert_eq!(ack.streams, 2);

        let future = Hello { versions: vec![99], ..hello };
        assert_eq!(future.accept(0, 1, "b"), Err(ProtocolError::NoCommonVersion));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut body = Vec::new();
        Message::Close(CloseReason::Done).encode_body(&mut body).unwrap();
        body.push(0);
        assert_eq!(Message::decode(MsgType::Close, &body), Err(ProtocolError::TrailingBytes));
    }
}
