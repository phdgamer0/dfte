#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MsgType {
    Hello = 0x01,
    HelloAck = 0x02,
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
