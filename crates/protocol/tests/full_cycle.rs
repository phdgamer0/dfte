#![allow(clippy::unwrap_used)]
//! Phase 1 definition of done (manual §40): two in-process peers, driven only by
//! byte buffers, walk connect -> manifest -> transfer -> complete.

use protocol::codec::{encode_frame, parse_frame};
use protocol::manifest::CHUNK_SIZE;
use protocol::message::{ChunkAck, ChunkHeader, CloseReason, Hello, ManifestAccept, Message, caps};
use protocol::state::Role;
use protocol::state::chunk::{ChunkId, ChunkTracker, DEFAULT_RTO};
use protocol::state::connection::{ConnEvent, Connection};
use protocol::state::resume::start_chunks;
use protocol::state::transfer::{Transfer, TransferEvent, TransferState};
use protocol::{FileEntry, Header, Manifest, chunk_len};
use std::time::Instant;

struct Wire(Vec<u8>);

impl Wire {
    fn send(&mut self, seq: &mut u64, m: &Message<'_>) {
        let mut body = Vec::new();
        m.encode_body(&mut body).unwrap();
        let h = Header::new(m.msg_type(), 0, 0, *seq, body.len() as u32);
        *seq += 1;
        encode_frame(&h, &body, &mut self.0);
    }

    fn recv(&mut self) -> (Header, Vec<u8>) {
        let f = parse_frame(&self.0).unwrap().expect("frame pending");
        let out = (f.header, f.body.to_vec());
        let n = f.len;
        self.0.drain(..n);
        out
    }
}

#[test]
fn connect_manifest_transfer_complete() {
    let file: Vec<u8> = (0..(CHUNK_SIZE as usize * 2 + 123)).map(|i| (i * 31) as u8).collect();
    let (mut a_to_b, mut b_to_a) = (Wire(Vec::new()), Wire(Vec::new()));
    let (mut seq_a, mut seq_b) = (0u64, 0u64);
    let mut a = Connection::new(Role::Initiator);
    let mut b = Connection::new(Role::Responder);

    // §9.1 establishment
    a_to_b.send(&mut seq_a, &Message::Hello(Hello::new(caps::TRANSPORT_TCP, 2, "a")));
    a.on_event(ConnEvent::HelloSent).unwrap();
    let (h, body) = a_to_b.recv();
    b.check_incoming(h.msg_type).unwrap();
    let Message::Hello(hello) = Message::decode(h.msg_type, &body).unwrap() else { panic!() };
    b.on_event(ConnEvent::HelloReceived).unwrap();
    b_to_a.send(&mut seq_b, &Message::HelloAck(hello.accept(caps::TRANSPORT_TCP, 4, "b").unwrap()));
    let (h, _) = b_to_a.recv();
    a.check_incoming(h.msg_type).unwrap();
    a.on_event(ConnEvent::HelloAckReceived).unwrap();
    for c in [&mut a, &mut b] {
        c.on_event(ConnEvent::HandshakeComplete).unwrap();
        c.on_event(ConnEvent::PeerVerified).unwrap();
        assert!(c.is_established());
    }

    // §9.2 manifest exchange
    let manifest = Manifest::new(vec![FileEntry::file("f.bin", file.len() as u64, [9; 32]).unwrap()]).unwrap();
    let mut tx = Transfer::new(Role::Initiator);
    let mut rx = Transfer::new(Role::Responder);
    a_to_b.send(&mut seq_a, &Message::ManifestOffer(manifest.clone()));
    tx.on_event(TransferEvent::OfferSent).unwrap();
    let (h, body) = a_to_b.recv();
    rx.check_incoming(h.msg_type).unwrap();
    let Message::ManifestOffer(offer) = Message::decode(h.msg_type, &body).unwrap() else { panic!() };
    assert_eq!(offer, manifest);
    rx.on_event(TransferEvent::OfferReceived).unwrap();
    b_to_a.send(&mut seq_b, &Message::ManifestAccept(ManifestAccept { resume_offsets: vec![0] }));
    rx.on_event(TransferEvent::AcceptSent).unwrap();
    let (h, body) = b_to_a.recv();
    tx.check_incoming(h.msg_type).unwrap();
    let Message::ManifestAccept(accept) = Message::decode(h.msg_type, &body).unwrap() else { panic!() };
    assert_eq!(start_chunks(&offer, &accept).unwrap(), vec![0]);
    tx.on_event(TransferEvent::AcceptReceived).unwrap();

    // §9.3 chunks + acks
    let mut tracker = ChunkTracker::new(DEFAULT_RTO);
    let mut received = Vec::new();
    for idx in 0..manifest.files[0].chunk_count {
        let off = idx as usize * CHUNK_SIZE as usize;
        let len = chunk_len(file.len() as u64, idx as u64, CHUNK_SIZE).unwrap() as usize;
        let chunk = ChunkHeader { file_index: 0, chunk_index: idx };
        a_to_b.send(&mut seq_a, &Message::ChunkData { chunk, data: &file[off..off + len] });
        tracker.on_sent(ChunkId { file_index: 0, chunk_index: idx }, Instant::now());

        let (h, body) = a_to_b.recv();
        rx.check_incoming(h.msg_type).unwrap();
        let Message::ChunkData { chunk, data } = Message::decode(h.msg_type, &body).unwrap() else { panic!() };
        received.extend_from_slice(data);
        b_to_a.send(&mut seq_b, &Message::ChunkAck(ChunkAck { file_index: chunk.file_index, chunk_index: chunk.chunk_index, hash: [0; 32] }));

        let (h, body) = b_to_a.recv();
        tx.check_incoming(h.msg_type).unwrap();
        let Message::ChunkAck(ack) = Message::decode(h.msg_type, &body).unwrap() else { panic!() };
        assert!(tracker.on_ack(ChunkId { file_index: ack.file_index, chunk_index: ack.chunk_index }));
    }
    assert_eq!(tracker.in_flight(), 0);
    assert_eq!(received, file);
    assert_eq!(tx.on_event(TransferEvent::AllChunksConfirmed), Ok(TransferState::Complete));
    assert_eq!(rx.on_event(TransferEvent::AllChunksConfirmed), Ok(TransferState::Complete));
    a_to_b.send(&mut seq_a, &Message::Close(CloseReason::Done));
    assert_eq!(a_to_b.recv().0.sequence_number, seq_a - 1);
}
