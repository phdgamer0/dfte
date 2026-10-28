#![no_main]
//! Arbitrary bytes into the frame parser and every message decoder (manual §33).

use libfuzzer_sys::fuzz_target;
use protocol::codec::parse_frame;
use protocol::{Message, MsgType};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(frame)) = parse_frame(data) {
        assert!(frame.len <= data.len());
        let _ = Message::decode(frame.header.msg_type, frame.body);
    }
    for t in MsgType::ALL {
        let _ = Message::decode(t, data);
    }
});
