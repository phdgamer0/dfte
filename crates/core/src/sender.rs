//! Sender (manual §9.2/§9.3/§10/§14).
//!
//! Pipeline per data stream: a *producer* task takes the next chunk from the
//! shared work queue (work stealing across streams), reads it into a pool buffer
//! on a blocking thread, writes the chunk sub-header in front, seals header +
//! data in place with a detached tag, and hands it to the stream's *writer* task,
//! which sends header, body and tag with one vectored write. Reading/sealing the
//! next chunk overlaps with the socket write of the previous one.
//!
//! A sent buffer is held until the receiver's `ChunkAck` confirms the chunk's
//! BLAKE3 piece hash; the pool size therefore *is* the in-flight window and the
//! whole backpressure mechanism (manual §14/§28). A mismatching ack or an ack
//! timeout re-reads the chunk from disk and resends it under a fresh sequence
//! number with the RETRANSMISSION flag (the sealed buffer can't be resent: its
//! nonce is spent).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crypto::{Sealer, TAG_LEN};
use protocol::header::{Header, flags};
use protocol::message::{CHUNK_HEADER_LEN, ChunkAck, ChunkHeader, CloseReason, Message};
use protocol::state::Role;
use protocol::state::chunk::{ChunkId, ChunkTracker};
use protocol::state::resume::start_chunks;
use protocol::state::transfer::{Transfer, TransferEvent};
use protocol::{Manifest, MsgType};
use storage::{BufferPool, CHUNK_SIZE, ChunkBitmap, PoolBuffer};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;
use tracing::Instrument;
use transport::{FrameWriter, Transport, TransportKind};

use crate::error::{EngineError, Result};
use crate::options::{CancelHandle, Progress, SendOptions};
use crate::report::{Direction, PhaseTimings, TransferReport, rate, secs};
use crate::secure::{Control, ControlRx, DataStream, SecureConnection, establish_initiator};
use crate::source::{Readers, Source, build_source_blocking};

/// Pool buffers hold a whole sealed chunk body: sub-header + data + tag.
pub(crate) const BODY_CAPACITY: usize = CHUNK_HEADER_LEN + CHUNK_SIZE as usize + TAG_LEN;

/// Hash the files at `paths`, connect to `addr` over `transport`, authenticate the
/// peer and send everything (manual §9.2). Returns once the receiver confirmed it
/// verified and stored every file.
///
/// Cancellation: dropping the future aborts the transfer and closes the
/// connection (the receiver keeps its resume state); [`CancelHandle`] does the
/// same but tells the peer first.
pub async fn send_files<T: Transport>(transport: &T, addr: SocketAddr, paths: &[PathBuf], opts: &SendOptions) -> Result<TransferReport> {
    if opts.streams == 0 || opts.streams > transport::MAX_DATA_STREAMS {
        return Err(EngineError::InvalidInput(format!("streams must be 1..={}", transport::MAX_DATA_STREAMS)));
    }
    let started = Instant::now();
    let mut timings = PhaseTimings::default();

    let owned = paths.to_vec();
    let threads = opts.hash_threads;
    let source = tokio::task::spawn_blocking(move || build_source_blocking(&owned, threads)).await??;
    timings.hash_secs = secs(started.elapsed());
    tracing::debug!(files = source.manifest.files.len(), bytes = source.manifest.total_bytes(), "hashed sources");

    let t = Instant::now();
    let conn = transport.connect(addr, opts.streams).await?;
    timings.connect_secs = secs(t.elapsed());

    #[cfg(feature = "bench-insecure-plaintext")]
    let want_plaintext = opts.insecure_plaintext;
    #[cfg(not(feature = "bench-insecure-plaintext"))]
    let want_plaintext = false;
    let sc = establish_initiator(conn, &opts.common, want_plaintext).await?;
    timings.handshake_secs = secs(sc.handshake_time);

    let span = tracing::info_span!("send", transfer_id = %source.manifest.transfer_id, peer = %sc.peer.fingerprint);
    run(sc, source, opts, timings, started).instrument(span).await
}

#[derive(Debug, Clone, Copy)]
struct Work {
    id: ChunkId,
    retransmit: bool,
}

/// Chunks still to send, in file order, plus resends (which go first).
struct WorkQueue {
    state: Mutex<QueueState>,
    notify: Notify,
}

struct QueueState {
    /// (file index, next chunk, end chunk)
    ranges: Vec<(u32, u32, u32)>,
    pos: usize,
    retx: VecDeque<ChunkId>,
    closed: bool,
}

impl WorkQueue {
    fn new(ranges: Vec<(u32, u32, u32)>) -> Self {
        Self { state: Mutex::new(QueueState { ranges, pos: 0, retx: VecDeque::new(), closed: false }), notify: Notify::new() }
    }

    fn with<R>(&self, f: impl FnOnce(&mut QueueState) -> R) -> R {
        let mut g = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Next chunk to send; waits while everything is out but unconfirmed, `None`
    /// once [`close`](Self::close)d.
    async fn next(&self) -> Option<Work> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let found = self.with(|s| {
                if let Some(id) = s.retx.pop_front() {
                    return Some(Some(Work { id, retransmit: true }));
                }
                while let Some(r) = s.ranges.get_mut(s.pos) {
                    if r.1 < r.2 {
                        let id = ChunkId { file_index: r.0, chunk_index: r.1 };
                        r.1 += 1;
                        return Some(Some(Work { id, retransmit: false }));
                    }
                    s.pos += 1;
                }
                if s.closed { Some(None) } else { None }
            });
            if let Some(w) = found {
                return w;
            }
            notified.await;
        }
    }

    fn push_retx(&self, id: ChunkId) {
        self.with(|s| s.retx.push_back(id));
        self.notify.notify_waiters();
    }

    fn close(&self) {
        self.with(|s| s.closed = true);
        self.notify.notify_waiters();
    }
}

struct Prepared {
    id: ChunkId,
    header: Header,
    buf: PoolBuffer,
    tag: Option<[u8; TAG_LEN]>,
}

enum Event {
    Control(Control),
    ControlEof,
    Sending(ChunkId),
    Written(ChunkId, PoolBuffer),
    Failed(EngineError),
}

pub(crate) async fn cancelled(c: &Option<CancelHandle>) {
    match c {
        Some(c) => c.cancelled().await,
        None => std::future::pending().await,
    }
}

async fn producer(stream_id: u32, mut sealer: Option<Sealer>, queue: Arc<WorkQueue>, readers: Arc<Readers>, pool: BufferPool, tx: mpsc::Sender<Prepared>) -> Result<()> {
    let mut seq = 0u64;
    while let Some(work) = queue.next().await {
        let buf = pool.acquire().await;
        let file = work.id.file_index as usize;
        let index = u64::from(work.id.chunk_index);
        let r = Arc::clone(&readers);
        let (mut buf, n) = tokio::task::spawn_blocking(move || -> Result<(PoolBuffer, usize)> {
            let mut buf = buf;
            let n = r.get_blocking(file)?.read_chunk_blocking(index, &mut buf.full_mut()[CHUNK_HEADER_LEN..])?;
            r.read_done(file);
            Ok((buf, n))
        })
        .await??;
        let body_len = CHUNK_HEADER_LEN + n;
        let mut ch = [0u8; CHUNK_HEADER_LEN];
        ChunkHeader { file_index: work.id.file_index, chunk_index: work.id.chunk_index }.encode(&mut ch);
        buf.full_mut()[..CHUNK_HEADER_LEN].copy_from_slice(&ch);
        seq += 1;
        let wire_len = body_len + if sealer.is_some() { TAG_LEN } else { 0 };
        let flag = if work.retransmit { flags::RETRANSMISSION } else { 0 };
        let header = Header::new(MsgType::ChunkData, flag, stream_id, seq, u32::try_from(wire_len).map_err(|_| EngineError::Internal("chunk too large".into()))?);
        let tag = match sealer.as_mut() {
            Some(s) => Some(s.seal_in_place_detached(seq, &header.to_bytes(), &mut buf.full_mut()[..body_len])?),
            None => None,
        };
        buf.set_len(body_len)?;
        if tx.send(Prepared { id: work.id, header, buf, tag }).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn writer(mut w: FrameWriter, mut rx: mpsc::Receiver<Prepared>, events: mpsc::UnboundedSender<Event>) -> Result<()> {
    while let Some(p) = rx.recv().await {
        let _ = events.send(Event::Sending(p.id));
        match &p.tag {
            Some(tag) => w.write_frame(&p.header, &[&p.buf, tag]).await?,
            None => w.write_frame(&p.header, &[&p.buf]).await?,
        }
        let _ = events.send(Event::Written(p.id, p.buf));
    }
    w.shutdown().await?;
    Ok(())
}

async fn control_reader(mut rx: ControlRx, events: mpsc::UnboundedSender<Event>) {
    loop {
        let ev = match rx.recv().await {
            Ok(Some(c)) => Event::Control(c),
            Ok(None) => Event::ControlEof,
            Err(e) => Event::Failed(e),
        };
        let stop = !matches!(ev, Event::Control(_));
        if events.send(ev).is_err() || stop {
            return;
        }
    }
}

/// Spawns `fut`; its error (if any) is forwarded as an event.
fn spawn_reporting(set: &mut JoinSet<()>, events: &mpsc::UnboundedSender<Event>, fut: impl std::future::Future<Output = Result<()>> + Send + 'static) {
    let events = events.clone();
    set.spawn(
        async move {
            if let Err(e) = fut.await {
                let _ = events.send(Event::Failed(e));
            }
        }
        .in_current_span(),
    );
}

async fn wait_accept(sc: &mut SecureConnection, opts: &SendOptions) -> Result<protocol::message::ManifestAccept> {
    loop {
        let msg = tokio::select! {
            r = tokio::time::timeout(opts.common.idle_timeout, sc.control_rx.recv()) => r.map_err(|_| EngineError::Timeout)??,
            () = cancelled(&opts.common.cancel) => return Err(EngineError::Cancelled),
        };
        match msg {
            Some(Control::ManifestAccept(a)) => return Ok(a),
            Some(Control::Close(r)) => return Err(EngineError::from_peer_close(r)),
            Some(Control::Cancel) => return Err(EngineError::Cancelled),
            Some(Control::Ping(_) | Control::Pong(_)) => {}
            Some(other) => return Err(EngineError::violation(format!("expected ManifestAccept, got {other:?}"))),
            None => return Err(EngineError::PeerLost),
        }
    }
}

struct Plan {
    manifest: Manifest,
    /// First chunk to send per file.
    starts: Vec<u32>,
    chunk_counts: Vec<u32>,
    total_chunks: u64,
    resumed_bytes: u64,
}

fn plan(manifest: Manifest, starts: Vec<u32>) -> Plan {
    let chunk_counts: Vec<u32> = manifest.files.iter().map(|f| f.chunk_count).collect();
    let total_chunks = chunk_counts.iter().zip(&starts).map(|(&c, &s)| u64::from(c.saturating_sub(s))).sum();
    let resumed_bytes = manifest.files.iter().zip(&starts).map(|(f, &s)| (u64::from(s) * CHUNK_SIZE).min(f.size)).sum();
    Plan { manifest, starts, chunk_counts, total_chunks, resumed_bytes }
}

async fn run(mut sc: SecureConnection, source: Source, opts: &SendOptions, mut timings: PhaseTimings, started: Instant) -> Result<TransferReport> {
    let mut xfer = Transfer::new(Role::Initiator);
    let t = Instant::now();
    let Source { manifest, files } = source;
    let result = async {
        sc.control_tx.send(&Message::ManifestOffer(manifest.clone())).await?;
        xfer.on_event(TransferEvent::OfferSent)?;
        let accept = wait_accept(&mut sc, opts).await?;
        xfer.check_incoming(MsgType::ManifestAccept)?;
        let starts = start_chunks(&manifest, &accept)?;
        xfer.on_event(TransferEvent::AcceptReceived)?;
        Ok(starts)
    }
    .await;
    let starts = match result {
        Ok(s) => s,
        Err(e) => {
            if !matches!(e, EngineError::PeerLost | EngineError::ConnectionRejected) {
                sc.control_tx.close(e.close_reason()).await;
            }
            return Err(e);
        }
    };
    timings.manifest_secs = secs(t.elapsed());
    let plan = plan(manifest, starts);
    tracing::info!(chunks = plan.total_chunks, resumed_bytes = plan.resumed_bytes, "transfer accepted");

    let streams = sc.data.len();
    let cipher = sc.cipher_name();
    let kind = sc.kind;
    let peer = sc.peer.clone();
    let transfer_id = plan.manifest.transfer_id.to_string();
    let file_count = plan.manifest.files.len();
    let bytes_total = plan.manifest.total_bytes();

    let t = Instant::now();
    let outcome = transfer(sc, files, &plan, opts, &mut xfer).await;
    let (retransmits, finalize_secs) = match outcome {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "send failed");
            return Err(e);
        }
    };
    timings.finalize_secs = finalize_secs;
    timings.transfer_secs = secs(t.elapsed()) - finalize_secs;
    let bytes_transferred = bytes_total - plan.resumed_bytes;
    let report = TransferReport { direction: Direction::Send, transfer_id, peer_fingerprint: peer.fingerprint, peer_name: peer.device_name, transport: kind_name(kind), cipher, streams, files: file_count, bytes_total, bytes_transferred, resumed_bytes: plan.resumed_bytes, chunks: plan.total_chunks, retransmits, total_secs: secs(started.elapsed()), throughput_bytes_per_sec: rate(bytes_transferred, timings.transfer_secs), timings, saved: Vec::new() };
    tracing::info!(bytes = report.bytes_transferred, secs = report.timings.transfer_secs, retransmits, "send complete");
    Ok(report)
}

pub(crate) fn kind_name(kind: TransportKind) -> String {
    match kind {
        TransportKind::Tcp => "tcp".into(),
        TransportKind::Quic => "quic".into(),
    }
}

/// Runs the data phase; returns (retransmits, finalize wait seconds).
async fn transfer(sc: SecureConnection, files: Vec<crate::source::SourceFile>, plan: &Plan, opts: &SendOptions, xfer: &mut Transfer) -> Result<(u64, f64)> {
    let SecureConnection { mut control_tx, control_rx, data, .. } = sc;
    let mut set = JoinSet::new();
    let res = drive(&mut control_tx, control_rx, data, files, plan, opts, xfer, &mut set).await;
    match res {
        Ok(v) => Ok(v),
        Err(e) => {
            if xfer.on_event(if matches!(e, EngineError::Cancelled) { TransferEvent::Cancel } else { TransferEvent::ConnectionLost }).is_err() {
                tracing::debug!("transfer state machine already terminal");
            }
            set.abort_all();
            if matches!(e, EngineError::Cancelled) {
                let _ = control_tx.send(&Message::Cancel).await;
            }
            if !matches!(e, EngineError::PeerLost | EngineError::ConnectionRejected | EngineError::PeerDiskFull) {
                control_tx.close(e.close_reason()).await;
            }
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive(control_tx: &mut crate::secure::ControlTx, control_rx: ControlRx, data: Vec<DataStream>, files: Vec<crate::source::SourceFile>, plan: &Plan, opts: &SendOptions, xfer: &mut Transfer, set: &mut JoinSet<()>) -> Result<(u64, f64)> {
    let reads: Vec<u64> = plan.chunk_counts.iter().zip(&plan.starts).map(|(&c, &s)| u64::from(c.saturating_sub(s))).collect();
    let sizes: Vec<u64> = plan.manifest.files.iter().map(|f| f.size).collect();
    let readers = Arc::new(Readers::new(files, &reads));
    let ranges = plan.chunk_counts.iter().zip(&plan.starts).enumerate().filter(|(_, (c, s))| s < c).map(|(i, (&c, &s))| (i as u32, s, c)).collect();
    let queue = Arc::new(WorkQueue::new(ranges));
    // Each stream's pipeline also holds up to two unsent buffers (reading, queued).
    let pool = BufferPool::new(opts.in_flight_chunks.max(2 * data.len() + 1), BODY_CAPACITY);

    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    for ds in data {
        let DataStream { stream_id, writer: w, sealer, .. } = ds;
        let (ptx, prx) = mpsc::channel(1);
        spawn_reporting(set, &ev_tx, producer(stream_id, sealer, Arc::clone(&queue), Arc::clone(&readers), pool.clone(), ptx));
        spawn_reporting(set, &ev_tx, writer(w, prx, ev_tx.clone()));
    }
    set.spawn(control_reader(control_rx, ev_tx.clone()).in_current_span());
    drop(ev_tx);

    let mut tracker = ChunkTracker::new(opts.ack_timeout);
    let mut confirmed: Vec<ChunkBitmap> = plan.chunk_counts.iter().map(|&c| ChunkBitmap::new(u64::from(c)).ok_or_else(|| EngineError::Internal("chunk bitmap".into()))).collect::<Result<_>>()?;
    let mut held: HashMap<ChunkId, PoolBuffer> = HashMap::new();
    let mut pending_retx: HashSet<ChunkId> = HashSet::new();
    let mut done_chunks = 0u64;
    let mut bytes_done = plan.resumed_bytes;
    let mut retransmits = 0u64;
    let mut last_heard = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let bytes_total = plan.manifest.total_bytes();
    let transfer_id = plan.manifest.transfer_id.to_string();

    let schedule_resend = |id: ChunkId, tracker: &mut ChunkTracker, held: &mut HashMap<ChunkId, PoolBuffer>, pending: &mut HashSet<ChunkId>, retransmits: &mut u64| {
        if pending.insert(id) {
            held.remove(&id);
            tracker.on_sent(id, Instant::now());
            readers.expect_read(id.file_index as usize);
            queue.push_retx(id);
            *retransmits += 1;
        }
    };

    while done_chunks < plan.total_chunks {
        let ev = tokio::select! {
            biased;
            () = cancelled(&opts.common.cancel) => return Err(EngineError::Cancelled),
            ev = ev_rx.recv() => ev.ok_or_else(|| EngineError::Internal("sender tasks vanished".into()))?,
            _ = tick.tick() => {
                if last_heard.elapsed() > opts.common.idle_timeout {
                    return Err(EngineError::Timeout);
                }
                for id in tracker.due(Instant::now())? {
                    tracing::debug!(file = id.file_index, chunk = id.chunk_index, "ack timeout, resending");
                    schedule_resend(id, &mut tracker, &mut held, &mut pending_retx, &mut retransmits);
                }
                continue;
            }
        };
        match ev {
            Event::Sending(id) => {
                pending_retx.remove(&id);
                if !confirmed.get(id.file_index as usize).is_some_and(|b| b.get(u64::from(id.chunk_index))) {
                    tracker.on_sent(id, Instant::now());
                }
            }
            Event::Written(id, buf) => {
                if !confirmed.get(id.file_index as usize).is_some_and(|b| b.get(u64::from(id.chunk_index))) && !pending_retx.contains(&id) {
                    held.insert(id, buf);
                }
            }
            Event::Control(Control::ChunkAck(ChunkAck { file_index, chunk_index, hash })) => {
                last_heard = Instant::now();
                let id = ChunkId { file_index, chunk_index };
                let f = file_index as usize;
                let expected = readers.file(f).and_then(|s| s.pieces.get(chunk_index as usize)).filter(|_| chunk_index < plan.chunk_counts[f]).copied();
                let Some(expected) = expected else {
                    return Err(EngineError::violation("ChunkAck for a chunk that does not exist"));
                };
                if hash == expected {
                    if tracker.on_ack(id) {
                        held.remove(&id);
                        pending_retx.remove(&id);
                        confirmed[f].set(u64::from(chunk_index));
                        done_chunks += 1;
                        bytes_done += storage::chunk_len(sizes[f], u64::from(chunk_index)).unwrap_or(0);
                        if let Some(cb) = &opts.common.progress {
                            cb(&Progress { transfer_id: transfer_id.clone(), bytes_done, bytes_total, chunks_done: done_chunks, chunks_total: plan.total_chunks });
                        }
                    }
                } else {
                    match tracker.on_nack(id) {
                        Ok(_) => {
                            tracing::warn!(file = file_index, chunk = chunk_index, "chunk hash mismatch, resending");
                            schedule_resend(id, &mut tracker, &mut held, &mut pending_retx, &mut retransmits);
                        }
                        Err(protocol::ProtocolError::TooManyRetries) => return Err(EngineError::CorruptedData),
                        Err(_) => {} // stale ack for a chunk already resent/confirmed
                    }
                }
            }
            Event::Control(Control::Close(r)) => return Err(EngineError::from_peer_close(r)),
            Event::Control(Control::Cancel) => return Err(EngineError::Cancelled),
            Event::Control(Control::Ping(_) | Control::Pong(_)) => last_heard = Instant::now(),
            Event::Control(other) => return Err(EngineError::violation(format!("unexpected {other:?} during transfer"))),
            Event::ControlEof => return Err(EngineError::PeerLost),
            Event::Failed(e) => return Err(e),
        }
    }
    xfer.on_event(TransferEvent::AllChunksConfirmed)?;
    queue.close();
    drop(held);

    // Every chunk is confirmed: tell the receiver, then wait for its verdict on
    // the whole-file hashes and renames (manual §20).
    let t = Instant::now();
    control_tx.send(&Message::Close(CloseReason::Done)).await?;
    let deadline = tokio::time::sleep(opts.finalize_timeout);
    tokio::pin!(deadline);
    loop {
        let ev = tokio::select! {
            () = &mut deadline => return Err(EngineError::Timeout),
            ev = ev_rx.recv() => ev.ok_or(EngineError::PeerLost)?,
        };
        match ev {
            Event::Control(Control::Close(CloseReason::Done)) => break,
            Event::Control(Control::Close(r)) => return Err(EngineError::from_peer_close(r)),
            Event::ControlEof => return Err(EngineError::PeerLost),
            Event::Failed(e) => return Err(e),
            _ => {}
        }
    }
    let finalize = secs(t.elapsed());
    let _ = control_tx.shutdown().await;
    set.abort_all();
    Ok((retransmits, finalize))
}
