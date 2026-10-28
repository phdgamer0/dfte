//! Shared conformance suite (manual §32): every backend must pass the same
//! tests. QUIC plugs in by adding one more `#[tokio::test]` calling `suite`.
#![allow(clippy::unwrap_used)]

use protocol::MsgType;
use protocol::header::Header;
use tokio::io::AsyncWriteExt;
use transport::{Listener, TcpTransport, Transport, TransportError};

fn hdr(t: MsgType, stream: u32, seq: u64, len: usize) -> Header {
    Header::new(t, 0, stream, seq, len as u32)
}

async fn suite<T: Transport + Clone + 'static>(t: T) {
    let mut l = t.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move { l.accept().await.unwrap() });
    let mut a = t.connect(addr, 3).await.unwrap();
    let mut b = server.await.unwrap();
    assert_eq!(a.kind, t.kind());
    assert_eq!(a.data.len(), 3);
    assert_eq!(b.data.len(), 3);

    // Control both ways, multi-part body is reassembled.
    a.control.writer.write_frame(&hdr(MsgType::Ping, 0, 1, 5), &[b"he", b"", b"llo"]).await.unwrap();
    a.control.writer.flush().await.unwrap();
    let (h, body) = b.control.reader.read_frame().await.unwrap().unwrap();
    assert_eq!((h.msg_type, h.sequence_number, &body[..]), (MsgType::Ping, 1, &b"hello"[..]));
    b.control.writer.write_frame(&hdr(MsgType::Pong, 0, 1, 0), &[]).await.unwrap();
    b.control.writer.flush().await.unwrap();
    assert_eq!(a.control.reader.read_frame().await.unwrap().unwrap().0.msg_type, MsgType::Pong);

    // Header/body length mismatch is refused locally.
    assert!(matches!(a.control.writer.write_frame(&hdr(MsgType::Ping, 0, 2, 4), &[b"abc"]).await, Err(TransportError::LengthMismatch { .. })));

    // Each data stream carries its own frames; 4 MiB bodies land in a caller buffer.
    let big: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    for (i, (tx, rx)) in a.data.iter_mut().zip(b.data.iter_mut()).enumerate() {
        // Write and read concurrently: 4 MiB exceeds socket buffers.
        let send = async {
            tx.writer.write_frame(&hdr(MsgType::ChunkData, i as u32, 0, big.len()), &[&big]).await.unwrap();
            tx.writer.flush().await.unwrap();
        };
        let recv = async {
            let mut dst = vec![0u8; big.len()];
            let h = rx.reader.read_header().await.unwrap().unwrap();
            assert_eq!(h.stream_id, i as u32);
            let got = rx.reader.read_body_into(&h, &mut dst).await.unwrap();
            assert!(got[..] == big[..]);
        };
        tokio::join!(send, recv);
    }
    let mut small = [0u8; 3];
    a.data[0].writer.write_frame(&hdr(MsgType::ChunkData, 0, 1, 4), &[b"abcd"]).await.unwrap();
    a.data[0].writer.flush().await.unwrap();
    let h = b.data[0].reader.read_header().await.unwrap().unwrap();
    assert!(matches!(b.data[0].reader.read_body_into(&h, &mut small).await, Err(TransportError::BufferTooSmall { .. })));

    // Clean shutdown at a frame boundary reads as None.
    a.data[1].writer.shutdown().await.unwrap();
    assert!(b.data[1].reader.read_header().await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_conformance() {
    suite(TcpTransport::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_garbage_socket_does_not_break_listener() {
    let t = TcpTransport::default();
    let mut l = t.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move { l.accept().await.unwrap() });
    let mut junk = tokio::net::TcpStream::connect(addr).await.unwrap();
    junk.write_all(&[0xAB; 26]).await.unwrap();
    let c = t.connect(addr, 1).await.unwrap();
    let s = server.await.unwrap();
    assert_eq!((c.data.len(), s.data.len()), (1, 1));
}

#[tokio::test]
async fn invalid_stream_counts() {
    let t = TcpTransport::default();
    assert!(matches!(t.connect("127.0.0.1:9".parse().unwrap(), 0).await, Err(TransportError::InvalidStreamCount(0))));
    assert!(matches!(t.connect("127.0.0.1:9".parse().unwrap(), 17).await, Err(TransportError::InvalidStreamCount(17))));
}
