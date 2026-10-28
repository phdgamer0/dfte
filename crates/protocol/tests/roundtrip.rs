#![allow(clippy::unwrap_used)]
use proptest::prelude::*;
use protocol::codec::{encode_frame, parse_frame};
use protocol::header::{HEADER_LEN, Header, MAX_PAYLOAD, flags};
use protocol::message::{CHUNK_HEADER_LEN, ChunkAck, ChunkHeader, CloseReason, Hello, ManifestAccept, Message, SelectiveNack};
use protocol::{FileEntry, Manifest, MsgType, chunk_count, chunk_len};

fn arb_msg_type() -> impl Strategy<Value = MsgType> {
    prop::sample::select(MsgType::ALL.to_vec())
}

proptest! {
    #[test]
    fn header_roundtrip(t in arb_msg_type(), f in 0u8..=flags::KNOWN, stream in any::<u32>(), seq in any::<u64>(), len in 0..=MAX_PAYLOAD) {
        let h = Header::new(t, f, stream, seq, len);
        prop_assert_eq!(Header::decode(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn header_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = Header::decode(&bytes);
        let _ = parse_frame(&bytes);
    }

    #[test]
    fn frame_roundtrip_and_partial(seq in any::<u64>(), body in prop::collection::vec(any::<u8>(), 0..512), cut in 0usize..600) {
        let h = Header::new(MsgType::ChunkData, 0, 1, seq, body.len() as u32);
        let mut buf = Vec::new();
        encode_frame(&h, &body, &mut buf);
        let f = parse_frame(&buf).unwrap().unwrap();
        prop_assert_eq!(f.header, h);
        prop_assert_eq!(f.body, &body[..]);
        prop_assert_eq!(f.len, HEADER_LEN + body.len());
        if cut < buf.len() {
            prop_assert!(parse_frame(&buf[..cut]).unwrap().is_none());
        }
    }

    #[test]
    fn chunk_data_roundtrip(file_index in any::<u32>(), chunk_index in any::<u32>(), data in prop::collection::vec(any::<u8>(), 0..256)) {
        let m = Message::ChunkData { chunk: ChunkHeader { file_index, chunk_index }, data: &data };
        let mut body = Vec::new();
        m.encode_body(&mut body).unwrap();
        prop_assert_eq!(body.len(), CHUNK_HEADER_LEN + data.len());
        prop_assert_eq!(Message::decode(MsgType::ChunkData, &body).unwrap(), m);
    }

    #[test]
    fn control_roundtrip(n in any::<u64>(), file_index in any::<u32>(), chunk_index in any::<u32>(), hash in any::<[u8; 32]>(), offsets in prop::collection::vec(any::<u64>(), 0..8), name in "\\PC{0,32}") {
        let msgs = [
            Message::Hello(Hello::new(n, 4, name)),
            Message::ChunkAck(ChunkAck { file_index, chunk_index, hash }),
            Message::SelectiveNack(SelectiveNack { file_index, chunks: vec![chunk_index] }),
            Message::ManifestAccept(ManifestAccept { resume_offsets: offsets }),
            Message::Ping(n),
            Message::Pong(n),
            Message::Cancel,
            Message::Close(CloseReason::Cancelled),
        ];
        for m in msgs {
            let mut body = Vec::new();
            m.encode_body(&mut body).unwrap();
            prop_assert_eq!(Message::decode(m.msg_type(), &body).unwrap(), m);
        }
    }

    #[test]
    fn message_decode_never_panics(t in arb_msg_type(), bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Message::decode(t, &bytes);
    }

    #[test]
    fn manifest_roundtrip(sizes in prop::collection::vec(0u64..(1 << 40), 1..20)) {
        let files = sizes.iter().enumerate().map(|(i, &s)| FileEntry::file(format!("dir/f{i}.bin"), s, [i as u8; 32]).unwrap()).collect();
        let m = Manifest::new(files).unwrap();
        prop_assert_eq!(Manifest::decode(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn chunk_lens_sum_to_size(size in 0u64..(1 << 44), chunk in 1u64..(1 << 24)) {
        let n = chunk_count(size, chunk);
        // Only the last two chunks matter for the invariant; avoids iterating millions.
        let last = if n == 0 { 0 } else { chunk_len(size, n - 1, chunk).unwrap() };
        prop_assert_eq!(n.saturating_sub(1) * chunk + last, size);
        prop_assert_eq!(chunk_len(size, n, chunk).unwrap(), 0);
    }
}

#[test]
fn chunk_math_boundaries() {
    const C: u64 = 4 * 1024 * 1024;
    for (size, n) in [(0, 0), (1, 1), (C, 1), (C + 1, 2), (4 << 30, 1024), ((4 << 30) + 1, 1025), (8 << 30, 2048)] {
        assert_eq!(chunk_count(size, C), n, "size {size}");
    }
    assert!(protocol::chunk_offset(u64::MAX, C).is_err());
}
