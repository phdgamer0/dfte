mod msg_type;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Header {
    magic: u16,
    version: u16,
    msg_type: msg_type::MsgType,
    flags: u8,
    reserved: u16,
    stream_id: u32,
    sequance_number: u64,
    payload_length: u32,
}

impl Header {
    pub fn new(msg_type: msg_type::MsgType, flags: u8, stream_id: u32, sequance_number: u64, payload_length: u32) -> Self {
        Self { magic: MAGIC, version: PROTOCOL_VERSION, msg_type, flags, reserved: 0x0000, stream_id, sequance_number, payload_length }
    }
}

const MAGIC: u16 = 0x5032;
const HEADER_SIZE: usize = size_of::<Header>();
const PROTOCOL_VERSION: u16 = 0x0001;
