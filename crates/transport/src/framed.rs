//! Frame I/O over any byte stream (TCP socket or QUIC stream), manual §8.1.
//! Crypto-agnostic: bodies are passed through sealed; `core` opens/seals them.

use std::io::IoSlice;

use protocol::header::{HEADER_LEN, Header};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};

use crate::{Result, TransportError};

pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Body parts per frame: chunk sub-header, data, detached AEAD tag, plus one spare.
pub const MAX_PARTS: usize = 4;

/// Read-side buffer. Small control frames (acks) then cost ~one syscall per
/// batch instead of two per frame; body reads larger than this bypass the
/// buffer, so 4 MiB chunks still land directly in the caller's buffer.
const READ_BUFFER: usize = 64 * 1024;

pub struct FrameReader<R = BoxRead> {
    inner: BufReader<R>,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner: BufReader::with_capacity(READ_BUFFER, inner), buf: Vec::new() }
    }

    /// Reads the next header. `Ok(None)` on a clean EOF at a frame boundary;
    /// EOF inside a header is an error. The caller must then read exactly
    /// `payload_length` bytes with [`read_body`](Self::read_body) or
    /// [`read_body_into`](Self::read_body_into).
    pub async fn read_header(&mut self) -> Result<Option<Header>> {
        let mut h = [0u8; HEADER_LEN];
        let mut filled = 0;
        while filled < HEADER_LEN {
            let n = self.inner.read(&mut h[filled..]).await?;
            if n == 0 {
                return if filled == 0 { Ok(None) } else { Err(TransportError::UnexpectedEof) };
            }
            filled += n;
        }
        Ok(Some(Header::decode(&h)?))
    }

    /// Reads the body into the reader's own reusable buffer (control path).
    pub async fn read_body(&mut self, header: &Header) -> Result<&mut [u8]> {
        let len = header.payload_length as usize;
        self.buf.resize(len, 0);
        self.inner.read_exact(&mut self.buf[..len]).await.map_err(eof)?;
        Ok(&mut self.buf[..len])
    }

    /// Reads the body straight into a caller buffer, e.g. a pool buffer (manual §14).
    pub async fn read_body_into<'a>(&mut self, header: &Header, dst: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let len = header.payload_length as usize;
        let dst = dst.get_mut(..len).ok_or(TransportError::BufferTooSmall { needed: len })?;
        self.inner.read_exact(dst).await.map_err(eof)?;
        Ok(dst)
    }

    /// Header + body into the internal buffer.
    pub async fn read_frame(&mut self) -> Result<Option<(Header, &mut [u8])>> {
        let Some(h) = self.read_header().await? else { return Ok(None) };
        let body = self.read_body(&h).await?;
        Ok(Some((h, body)))
    }
}

/// Small frames are coalesced here between flushes; writes larger than this
/// (chunk bodies) bypass it.
const WRITE_BUFFER: usize = 64 * 1024;

pub struct FrameWriter<W = BoxWrite> {
    inner: BufWriter<W>,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner: BufWriter::with_capacity(WRITE_BUFFER, inner) }
    }

    /// Writes one frame and flushes it to the stream.
    ///
    /// Header + body parts go out with vectored I/O, so a chunk sub-header,
    /// the chunk data and a detached AEAD tag are never concatenated
    /// (manual §14). The parts' total length must equal `header.payload_length`.
    pub async fn write_frame(&mut self, header: &Header, parts: &[&[u8]]) -> Result<()> {
        self.queue_frame(header, parts).await?;
        self.flush().await
    }

    /// Like [`write_frame`](Self::write_frame) but leaves small frames in the
    /// write buffer until [`flush`](Self::flush). Batching acks this way is
    /// ~40x cheaper than one syscall + TCP segment per ack. Forgetting to
    /// flush stalls the peer, so only use this inside a batch that ends in a flush.
    pub async fn queue_frame(&mut self, header: &Header, parts: &[&[u8]]) -> Result<()> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        if total != header.payload_length as usize {
            return Err(TransportError::LengthMismatch { header: header.payload_length, actual: total });
        }
        if parts.len() > MAX_PARTS {
            return Err(TransportError::TooManyParts(parts.len()));
        }
        let h = header.to_bytes();
        // Fixed stack arrays: no allocation per frame on the data path.
        let mut slices: [&[u8]; MAX_PARTS + 1] = [&[]; MAX_PARTS + 1];
        slices[0] = &h;
        slices[1..=parts.len()].copy_from_slice(parts);
        write_all_vectored(&mut self.inner, &mut slices[..=parts.len()]).await
    }

    pub async fn flush(&mut self) -> Result<()> {
        Ok(self.inner.flush().await?)
    }

    /// Flushes and half-closes the write side.
    pub async fn shutdown(&mut self) -> Result<()> {
        Ok(self.inner.shutdown().await?)
    }
}

async fn write_all_vectored<W: AsyncWrite + Unpin>(w: &mut W, parts: &mut [&[u8]]) -> Result<()> {
    let mut first = 0;
    while first < parts.len() {
        if parts[first].is_empty() {
            first += 1;
            continue;
        }
        let mut io = [IoSlice::new(&[]); MAX_PARTS + 1];
        let live = &parts[first..];
        for (dst, src) in io.iter_mut().zip(live) {
            *dst = IoSlice::new(src);
        }
        let mut n = w.write_vectored(&io[..live.len()]).await?;
        if n == 0 {
            return Err(TransportError::Io(std::io::ErrorKind::WriteZero.into()));
        }
        while first < parts.len() && n >= parts[first].len() {
            n -= parts[first].len();
            first += 1;
        }
        if n > 0 {
            parts[first] = &parts[first][n..];
        }
    }
    Ok(())
}

fn eof(e: std::io::Error) -> TransportError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof { TransportError::UnexpectedEof } else { TransportError::Io(e) }
}

/// One bidirectional framed stream.
pub struct FramedStream {
    pub reader: FrameReader,
    pub writer: FrameWriter,
}

impl FramedStream {
    pub fn new(read: BoxRead, write: BoxWrite) -> Self {
        Self { reader: FrameReader::new(read), writer: FrameWriter::new(write) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::MsgType;

    #[tokio::test]
    async fn eof_handling() {
        let h = Header::new(MsgType::Ping, 0, 0, 0, 10);
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let mut r = FrameReader::new(&bytes[..]);
        assert!(matches!(r.read_frame().await, Err(TransportError::UnexpectedEof)));

        let mut r = FrameReader::new(&bytes[..10]);
        assert!(matches!(r.read_header().await, Err(TransportError::UnexpectedEof)));

        let mut r = FrameReader::new(&[][..]);
        assert!(r.read_header().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn vectored_write_handles_partial_writes() {
        // A 7-byte sink buffer forces many short vectored writes.
        let (a, mut b) = tokio::io::duplex(7);
        let mut w = FrameWriter::new(a);
        let h = Header::new(MsgType::Ping, 0, 0, 1, 26);
        let t = tokio::spawn(async move {
            w.write_frame(&h, &[b"abcdefghij", b"", b"klmnopqrstuvwxyz"]).await.unwrap();
        });
        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut b, &mut out).await.unwrap();
        t.await.unwrap();
        assert_eq!(&out[..HEADER_LEN], &h.to_bytes());
        assert_eq!(&out[HEADER_LEN..], b"abcdefghijklmnopqrstuvwxyz");
    }
}
