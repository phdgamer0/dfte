//! Receiver (manual §9.2/§14/§17–§20).
//!
//! Each data stream has a task that reads a frame body straight into a pool
//! buffer, opens it in place (AEAD, replay check), validates the chunk against
//! the manifest and hands the buffer to a blocking thread that computes the
//! chunk's BLAKE3 piece hash and `pwrite`s it into the pre-allocated staging file.
//! The event loop records the piece hash, marks the chunk in the resume bitmap and
//! sends a `ChunkAck` (batched: flushed whenever no further events are ready).
//!
//! Every `flush_every` confirmed chunks the touched staging files are fsynced and
//! then the resume sidecar is saved, so the sidecar never claims data that isn't
//! durable (manual §19). On `Close(Done)` every file is verified from its piece
//! hashes (no re-read, manual §20) and renamed into the destination; the sidecar
//! is removed. Connection loss or cancel leaves `.part` files and sidecar in place.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto::{Opener, TAG_LEN};
use protocol::Manifest;
use protocol::message::{CHUNK_HEADER_LEN, ChunkAck, ChunkHeader, CloseReason, ManifestAccept, Message};
use protocol::state::Role;
use protocol::state::transfer::{Transfer, TransferEvent};
use protocol::{MsgType, header::Header};
use storage::fileio::available_space_blocking;
use storage::{BufferPool, CHUNK_SIZE, ChunkReader, PoolBuffer, RelPath, ResumeFile, ResumeState, StagedFile, StorageError, piece_hash, safe_join_blocking, scan_orphans_blocking, staging_name};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::Instrument;
use transport::{Connection, Listener};

use crate::error::{EngineError, Result};
use crate::hooks::{self, OfferGate, Phase, PhaseFn};
use crate::options::{Progress, ReceiveOptions};
use crate::report::{Direction, PhaseTimings, TransferReport, rate, secs};
use crate::secure::{Control, ControlTx, DataStream, SecureConnection, establish_responder};
use crate::sender::{BODY_CAPACITY, cancelled, kind_name};
use crate::tasks::{CLOSE_LINGER, ControlReader, EventSink, abort_all, forward_bounded, spawn_control_reader};

/// Accept one connection on `listener`, authenticate the peer, and receive its
/// transfer: partial data and the resume sidecar live in `staging_dir`
/// (app-private, manual §14), finished files are renamed under `dest_dir`.
///
/// If a sidecar in `staging_dir` matches the offered manifest (same paths, sizes
/// and whole-file hashes) the transfer resumes from it (manual §19).
///
/// Cancellation: dropping the future aborts the transfer; staged data and the
/// last flushed sidecar remain usable for a later resume.
pub async fn receive<L: Listener>(listener: &mut L, staging_dir: &Path, dest_dir: &Path, opts: &ReceiveOptions) -> Result<TransferReport> {
    let started = Instant::now();
    let conn = listener.accept().await?;
    receive_connection(conn, started, staging_dir, Dest::Fixed(dest_dir), opts, None).await
}

/// Where accepted files go.
pub(crate) enum Dest<'a> {
    Fixed(&'a Path),
    /// Ask once the offer is in; `Err` rejects it.
    Ask(OfferGate<'a>),
}

/// [`receive`] on an already accepted connection; `started` is when accepting began.
pub(crate) async fn receive_connection(conn: Connection, started: Instant, staging_dir: &Path, dest: Dest<'_>, opts: &ReceiveOptions, phase: Option<PhaseFn<'_>>) -> Result<TransferReport> {
    let mut timings = PhaseTimings { connect_secs: secs(started.elapsed()), ..PhaseTimings::default() };

    #[cfg(feature = "bench-insecure-plaintext")]
    let allow_plaintext = opts.allow_insecure_plaintext;
    #[cfg(not(feature = "bench-insecure-plaintext"))]
    let allow_plaintext = false;
    let sc = establish_responder(conn, &opts.common, opts.max_streams.max(1), allow_plaintext).await?;
    timings.handshake_secs = secs(sc.handshake_time);

    let span = tracing::info_span!("receive", transfer_id = tracing::field::Empty, peer = %sc.peer.fingerprint);
    run(sc, staging_dir.to_path_buf(), dest, opts, timings, started, phase).instrument(span).await
}

/// Everything prepared for an accepted manifest.
struct Incoming {
    /// Id the staging files and sidecar are named after (the resumed transfer's id
    /// if this is a resume, else the manifest's).
    staging_id: String,
    state: ResumeState,
    staged: Vec<Option<Arc<StagedFile>>>,
    rels: Vec<RelPath>,
    dests: Vec<PathBuf>,
    pieces: Vec<Vec<Option<[u8; 32]>>>,
    offsets: Vec<u64>,
    resumed_bytes: u64,
    rehash_secs: f64,
}

/// For a directory entry: same checks as `safe_join_blocking`, but an existing
/// directory at the target is fine.
fn dir_target_blocking(root: &Path, rel: &RelPath) -> Result<PathBuf> {
    match safe_join_blocking(root, rel) {
        Ok(p) => Ok(p),
        Err(StorageError::InvalidPath { reason: "target is an existing directory", .. }) => Ok(rel.components().iter().fold(root.to_path_buf(), |p, c| p.join(c))),
        Err(e) => Err(e.into()),
    }
}

fn manifest_matches(state: &ResumeState, m: &Manifest) -> bool {
    state.files.len() == m.files.len() && state.files.iter().zip(&m.files).all(|(r, f)| r.relative_path == f.relative_path && r.matches(f.size, &f.content_hash))
}

fn prepare_blocking(m: &Manifest, staging: &Path, dest: &Path) -> Result<Incoming> {
    // Filesystem-level path checks on top of the protocol's string checks (§35).
    let mut rels = Vec::with_capacity(m.files.len());
    let mut dests = Vec::with_capacity(m.files.len());
    for f in &m.files {
        let rel = storage::validate_relative_path(&f.relative_path)?;
        let rel = if cfg!(windows) { rel.sanitized() } else { rel };
        let target = if f.is_dir { dir_target_blocking(dest, &rel)? } else { safe_join_blocking(dest, &rel)? };
        if rel.as_wire() != f.relative_path {
            tracing::info!(from = %f.relative_path, to = %rel, "renamed for this platform");
        }
        rels.push(rel);
        dests.push(target);
    }

    std::fs::create_dir_all(staging)?;
    let best = scan_orphans_blocking(staging)?.into_iter().filter(|s| manifest_matches(s, m)).max_by_key(|s| s.files.iter().map(ResumeFile::contiguous_offset).sum::<u64>());
    let (mut state, resumed) = match best {
        Some(s) => (s, true),
        None => {
            let files = m.files.iter().map(|f| ResumeFile::new(&f.relative_path, f.size, f.content_hash)).collect::<storage::Result<Vec<_>>>()?;
            (ResumeState::new(m.transfer_id.to_string(), files)?, false)
        }
    };

    let offsets: Vec<u64> = m.files.iter().enumerate().map(|(i, f)| if resumed && !f.is_dir { state.files[i].contiguous_offset() } else { 0 }).collect();
    let needed: u64 = m.files.iter().zip(&offsets).filter(|(_, o)| **o == 0).map(|(f, _)| f.size).sum();
    if needed > 0 {
        let available = available_space_blocking(staging)?;
        if available < needed {
            return Err(EngineError::DiskFull { needed, available });
        }
    }

    let t = Instant::now();
    let mut staged = Vec::with_capacity(m.files.len());
    let mut pieces = Vec::with_capacity(m.files.len());
    let mut final_offsets = Vec::with_capacity(m.files.len());
    let mut resumed_bytes = 0;
    for (i, f) in m.files.iter().enumerate() {
        if f.is_dir {
            staged.push(None);
            pieces.push(Vec::new());
            final_offsets.push(0);
            continue;
        }
        let name = staging_name(&state.transfer_id, i);
        let count = storage::chunk_count(f.size);
        let mut p: Vec<Option<[u8; 32]>> = vec![None; usize::try_from(count.max(1)).map_err(|_| EngineError::Internal("file too large".into()))?];
        if f.size == 0 {
            p[0] = Some(piece_hash(0, 0, &[]));
        }
        let mut offset = offsets[i];
        let sf = if offset > 0 {
            match StagedFile::open_existing_blocking(staging, &name, dests[i].clone(), f.size) {
                Ok(sf) => match rehash_prefix_blocking(&sf, offset, &mut p) {
                    Ok(()) => Some(sf),
                    Err(e) => {
                        tracing::warn!(file = i, error = %e, "cannot re-read staged data, starting file over");
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(file = i, error = %e, "staged data missing, starting file over");
                    None
                }
            }
        } else {
            None
        };
        let sf = match sf {
            Some(sf) => sf,
            None => {
                offset = 0;
                p.iter_mut().skip(usize::from(f.size == 0)).for_each(|x| *x = None);
                state.files[i] = ResumeFile::new(&f.relative_path, f.size, f.content_hash)?;
                StagedFile::create_blocking(staging, &name, dests[i].clone(), f.size)?
            }
        };
        resumed_bytes += offset;
        final_offsets.push(offset);
        staged.push(Some(Arc::new(sf)));
        pieces.push(p);
    }
    state.save_blocking(staging)?;
    Ok(Incoming { staging_id: state.transfer_id.clone(), state, staged, rels, dests, pieces, offsets: final_offsets, resumed_bytes, rehash_secs: if resumed { secs(t.elapsed()) } else { 0.0 } })
}

/// Piece hashes for the already-held prefix of a resumed file, read back from the
/// staging file, so the final verification can still be done from pieces.
fn rehash_prefix_blocking(sf: &StagedFile, offset: u64, pieces: &mut [Option<[u8; 32]>]) -> Result<()> {
    let reader = ChunkReader::open_blocking(sf.staging_path())?;
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    for c in 0..offset.div_ceil(CHUNK_SIZE) {
        let n = reader.read_chunk_blocking(c, &mut buf)?;
        let slot = pieces.get_mut(c as usize).ok_or_else(|| EngineError::Internal("piece index".into()))?;
        *slot = Some(piece_hash(sf.size(), c, &buf[..n]));
    }
    Ok(())
}

enum Event {
    ChunkDone {
        file: u32,
        chunk: u32,
        hash: [u8; 32],
    },
    Control(Control),
    ControlEof,
    Failed(EngineError),
    /// A data stream broke; the control stream may still carry the reason.
    StreamFailed(EngineError),
}

/// How long a data-stream failure waits for the peer's reason on the control stream.
const STREAM_FAILURE_GRACE: Duration = Duration::from_millis(500);

/// A sender that cancels or shuts down resets its data streams, and on QUIC
/// the reset can overtake the `Cancel` sent on the control stream just before
/// it. Briefly look for that reason so a cancel isn't reported as a lost peer;
/// `e` stands if none arrives (mirrors the sender's `explain_stream_failure`).
async fn explain_stream_failure(ev_rx: &mut mpsc::Receiver<Event>, e: EngineError) -> EngineError {
    let reason = async {
        while let Some(ev) = ev_rx.recv().await {
            match ev {
                Event::Control(Control::Cancel) => return Some(EngineError::Cancelled),
                Event::Control(Control::Close(r)) => return Some(EngineError::from_peer_close(r)),
                Event::ControlEof | Event::Failed(_) => return None,
                _ => {}
            }
        }
        None
    };
    match tokio::time::timeout(STREAM_FAILURE_GRACE, reason).await {
        Ok(Some(reason)) => {
            tracing::debug!(error = %e, reason = %reason, "data stream failed because the peer stopped the transfer");
            reason
        }
        Ok(None) | Err(_) => e,
    }
}

fn control_event(r: Result<Option<Control>>) -> Event {
    match r {
        Ok(Some(c)) => Event::Control(c),
        Ok(None) => Event::ControlEof,
        Err(e) => Event::Failed(e),
    }
}

/// Per-file facts a data-stream task needs to validate a chunk.
struct FileInfo {
    size: u64,
    chunks: u64,
    staged: Option<Arc<StagedFile>>,
}

/// One data stream, as two pipelined stages so socket reads overlap AEAD work:
/// this task reads frame bodies straight into pool buffers; [`open_and_store`]
/// (its own task, so it runs on another worker) opens them in order and hands
/// them to hash+pwrite jobs.
async fn data_reader(ds: DataStream, pool: BufferPool, files: Arc<Vec<FileInfo>>, events: mpsc::Sender<Event>) -> Result<()> {
    let DataStream { stream_id, mut reader, opener, .. } = ds;
    let overhead = CHUNK_HEADER_LEN + if opener.is_some() { TAG_LEN } else { 0 };
    let (tx, rx) = mpsc::channel::<(Header, PoolBuffer)>(2);
    let mut stage: JoinSet<Result<()>> = JoinSet::new();
    stage.spawn(open_and_store(opener, rx, files, events).in_current_span());

    let net = async move {
        let tx = tx;
        while let Some(h) = reader.read_header().await? {
            let body_len = h.payload_length as usize;
            if h.msg_type != MsgType::ChunkData || h.stream_id != stream_id || body_len < overhead || body_len > BODY_CAPACITY {
                return Err(EngineError::violation(format!("bad frame on data stream {stream_id}: {:?}", h.msg_type)));
            }
            let mut buf = pool.acquire().await;
            reader.read_body_into(&h, buf.full_mut()).await?;
            if tx.send((h, buf)).await.is_err() {
                // The open stage stopped; its own result is collected below.
                break;
            }
        }
        Ok(())
    };
    tokio::pin!(net);
    tokio::select! {
        r = &mut net => {
            r?;
            // `net` finished and dropped its sender: the stage drains and ends.
            join_stage(&mut stage).await
        }
        r = stage.join_next() => match r {
            Some(r) => r?,
            None => Err(EngineError::Internal("open stage missing".into())),
        },
    }
}

async fn join_stage(stage: &mut JoinSet<Result<()>>) -> Result<()> {
    match stage.join_next().await {
        Some(r) => r?,
        None => Err(EngineError::Internal("open stage missing".into())),
    }
}

/// Opens (verifies + decrypts, replay-checked) each body in place, validates the
/// chunk against the manifest and spawns its hash+pwrite job.
async fn open_and_store(mut opener: Option<Opener>, mut rx: mpsc::Receiver<(Header, PoolBuffer)>, files: Arc<Vec<FileInfo>>, events: mpsc::Sender<Event>) -> Result<()> {
    // Hash+pwrite jobs; reaped as they finish so a panicking write surfaces as
    // an error instead of a chunk that silently never gets acked.
    let mut writes: JoinSet<()> = JoinSet::new();
    while let Some((h, mut buf)) = rx.recv().await {
        while let Some(r) = writes.try_join_next() {
            r?;
        }
        let body_len = h.payload_length as usize;
        let plain_len = match opener.as_mut() {
            Some(o) => o.open_in_place(h.sequence_number, &h.to_bytes(), &mut buf.full_mut()[..body_len])?.len(),
            None => body_len,
        };
        let ch = ChunkHeader::decode(&buf.full_mut()[..CHUNK_HEADER_LEN])?;
        let info = files.get(ch.file_index as usize).ok_or_else(|| EngineError::violation("chunk for unknown file"))?;
        let index = u64::from(ch.chunk_index);
        let data_len = (plain_len - CHUNK_HEADER_LEN) as u64;
        if info.staged.is_none() || index >= info.chunks || storage::chunk_len(info.size, index) != Some(data_len) {
            return Err(EngineError::violation("chunk does not match the manifest"));
        }
        buf.set_len(plain_len)?;
        let files = Arc::clone(&files);
        let events = events.clone();
        writes.spawn_blocking(move || {
            let info = &files[ch.file_index as usize];
            let data = &buf[CHUNK_HEADER_LEN..];
            let hash = piece_hash(info.size, index, data);
            let written = match &info.staged {
                Some(sf) => sf.write_chunk_blocking(index, data),
                None => Ok(()),
            };
            // Release the staging file and buffer *before* reporting, so the event
            // loop can take sole ownership of the files once every chunk is in.
            drop(buf);
            drop(files);
            let ev = match written {
                Ok(()) => Event::ChunkDone { file: ch.file_index, chunk: ch.chunk_index, hash },
                Err(e) => Event::Failed(e.into()),
            };
            if events.blocking_send(ev).is_err() {
                // The event loop already ended (with its own error); this chunk is
                // simply not recorded and will be resent on resume.
                tracing::trace!("event loop gone, dropping chunk result");
            }
        });
    }
    while let Some(r) = writes.join_next().await {
        r?;
    }
    Ok(())
}

async fn wait_offer(sc: &mut SecureConnection, opts: &ReceiveOptions) -> Result<Manifest> {
    loop {
        let msg = tokio::select! {
            r = tokio::time::timeout(opts.common.idle_timeout, sc.control_rx.recv()) => r.map_err(|_| EngineError::Timeout)??,
            () = cancelled(&opts.common.cancel) => return Err(EngineError::Cancelled),
        };
        match msg {
            Some(Control::ManifestOffer(m)) => return Ok(m),
            Some(Control::Close(r)) => return Err(EngineError::from_peer_close(r)),
            Some(Control::Cancel) => return Err(EngineError::Cancelled),
            Some(Control::Ping(_) | Control::Pong(_)) => {}
            Some(other) => return Err(EngineError::violation(format!("expected ManifestOffer, got {other:?}"))),
            None => return Err(EngineError::PeerLost),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(mut sc: SecureConnection, staging: PathBuf, dest: Dest<'_>, opts: &ReceiveOptions, mut timings: PhaseTimings, started: Instant, phase: Option<PhaseFn<'_>>) -> Result<TransferReport> {
    let mut xfer = Transfer::new(Role::Responder);
    let t = Instant::now();
    let prepared = async {
        let manifest = wait_offer(&mut sc, opts).await?;
        xfer.check_incoming(MsgType::ManifestOffer)?;
        xfer.on_event(TransferEvent::OfferReceived)?;
        tracing::Span::current().record("transfer_id", tracing::field::display(manifest.transfer_id));
        if let Some(hook) = &opts.on_manifest {
            // Before prepare_blocking: a declined offer leaves no trace on disk.
            let (hook, m) = (hook.clone(), manifest.clone());
            if !tokio::task::spawn_blocking(move || (hook.0)(&m)).await? {
                return Err(EngineError::Cancelled);
            }
        }
        let m = manifest.clone();
        let dest = match dest {
            Dest::Fixed(d) => d.to_path_buf(),
            // The gate bounds its own wait (accept timeout). A peer that gives up
            // meanwhile is noticed on the first read after the decision.
            Dest::Ask(gate) => {
                let decision = gate(&manifest, &sc.peer);
                tokio::select! {
                    d = decision => d?,
                    () = cancelled(&opts.common.cancel) => return Err(EngineError::Cancelled),
                }
            }
        };
        let (s, d) = (staging.clone(), dest.clone());
        let inc = tokio::task::spawn_blocking(move || prepare_blocking(&m, &s, &d)).await??;
        Ok((manifest, inc, dest))
    }
    .await;
    let (manifest, mut inc, dest) = match prepared {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "rejecting transfer");
            if !matches!(e, EngineError::PeerLost | EngineError::ConnectionRejected) {
                sc.control_tx.close(e.close_reason()).await;
            }
            return Err(e);
        }
    };
    sc.control_tx.send(&Message::ManifestAccept(ManifestAccept { resume_offsets: inc.offsets.clone() })).await?;
    xfer.on_event(TransferEvent::AcceptSent)?;
    timings.manifest_secs = secs(t.elapsed()) - inc.rehash_secs;
    timings.hash_secs = inc.rehash_secs;
    tracing::info!(files = manifest.files.len(), resumed_bytes = inc.resumed_bytes, staging_id = %inc.staging_id, "transfer accepted");
    hooks::emit(phase, Phase::Accepted { bytes_total: manifest.total_bytes(), resumed_bytes: inc.resumed_bytes });

    let streams = sc.data.len();
    let cipher = sc.cipher_name();
    let kind = sc.kind;
    let peer = sc.peer.clone();
    let SecureConnection { mut control_tx, control_rx, data, .. } = sc;

    let t = Instant::now();
    let mut set = JoinSet::new();
    let mut reader = None;
    let res = drive(&mut control_tx, control_rx, data, &manifest, &mut inc, opts, &staging, &mut set, &mut reader).await;
    let local_cancel = matches!(res, Err(EngineError::Cancelled)) && opts.common.cancel.as_ref().is_some_and(super::options::CancelHandle::is_cancelled);
    if local_cancel {
        // Tell the peer *before* the stream tasks go away: on QUIC, dropping a
        // receive stream sends STOP_SENDING, and a sender that sees its data
        // stream stopped first reports a lost peer instead of a cancel.
        // Best effort on a failing path: the local error is what we report.
        if let Err(ce) = control_tx.send(&Message::Cancel).await {
            tracing::debug!(error = %ce, "could not tell peer about cancel");
        }
    }
    // Stop the stream tasks (they may be parked on a read) and let them drop
    // their handles on the staging files.
    let reaped = abort_all(&mut set).await;
    let res = match (res, reaped) {
        (Ok(()), r) => r,
        (Err(e), Err(te)) => {
            tracing::error!(error = %te, "task failure while tearing down after: {e}");
            Err(e)
        }
        (Err(e), Ok(())) => Err(e),
    };

    if let Err(e) = res {
        let event = if matches!(e, EngineError::Cancelled) { TransferEvent::Cancel } else { TransferEvent::ConnectionLost };
        if let Err(se) = xfer.on_event(event) {
            tracing::debug!(error = %se, "transfer state machine already terminal");
        }
        tracing::warn!(error = %e, "receive interrupted, keeping resume state");
        if !matches!(e, EngineError::PeerLost | EngineError::Cancelled) {
            control_tx.close(e.close_reason()).await;
        } else if let Err(se) = control_tx.shutdown().await {
            tracing::debug!(error = %se, "control half-close on a failing path failed");
        }
        if let Err(pe) = persist_on_interrupt(&inc, &staging).await {
            // The interruption is the error to report; failing to persist only
            // means the next attempt starts further back.
            tracing::error!(error = %pe, "could not persist resume state");
        }
        linger_close(reader, &e).await;
        return Err(e);
    }
    let transfer_secs = secs(t.elapsed());

    let t = Instant::now();
    let finalized = finalize(&mut inc, &manifest, &dest, &staging).await;
    match finalized {
        Ok(saved) => {
            xfer.on_event(TransferEvent::AllChunksConfirmed)?;
            control_tx.send(&Message::Close(CloseReason::Done)).await?;
            // Files are committed and the sender has its Done; a failing half-close
            // (peer already hung up) doesn't change the outcome.
            if let Err(e) = control_tx.shutdown().await {
                tracing::debug!(error = %e, "control half-close after completion failed");
            }
            // Graceful close: wait for the sender's EOF so neither side resets.
            if let Some(r) = reader {
                r.finish(CLOSE_LINGER).await?;
            }
            timings.finalize_secs = secs(t.elapsed());
            timings.transfer_secs = transfer_secs;
            let bytes_total = manifest.total_bytes();
            let bytes_transferred = bytes_total - inc.resumed_bytes;
            let chunks = manifest.files.iter().map(|f| u64::from(f.chunk_count)).sum::<u64>();
            tracing::info!(bytes = bytes_transferred, secs = transfer_secs, "receive complete");
            Ok(TransferReport { direction: Direction::Receive, transfer_id: manifest.transfer_id.to_string(), peer_fingerprint: peer.fingerprint, peer_name: peer.device_name, transport: kind_name(kind), cipher, streams, files: manifest.files.len(), bytes_total, bytes_transferred, resumed_bytes: inc.resumed_bytes, chunks, retransmits: 0, total_secs: secs(started.elapsed()), throughput_bytes_per_sec: rate(bytes_transferred, transfer_secs), end_to_end_bytes_per_sec: rate(bytes_transferred, transfer_secs + timings.finalize_secs), timings, saved })
        }
        Err(e) => {
            if let Err(se) = xfer.on_event(TransferEvent::IntegrityFailure) {
                tracing::debug!(error = %se, "transfer state machine already terminal");
            }
            tracing::error!(error = %e, "finalize failed");
            control_tx.close(e.close_reason()).await;
            linger_close(reader, &e).await;
            Err(e)
        }
    }
}

/// On a failing path: keep reading until the peer closes so our Close/Cancel is
/// delivered (see `tasks::ControlReader`); `e` is the error being reported.
async fn linger_close(reader: Option<ControlReader>, e: &EngineError) {
    if let Some(r) = reader
        && let Err(re) = r.finish(CLOSE_LINGER).await
    {
        tracing::error!(error = %re, "control reader failed while closing after: {e}");
    }
}

/// Make staged data durable and persist the bitmap so a later transfer of the
/// same files resumes (manual §19).
async fn persist_on_interrupt(inc: &Incoming, staging: &Path) -> Result<()> {
    let staged: Vec<Arc<StagedFile>> = inc.staged.iter().flatten().cloned().collect();
    let state = inc.state.clone();
    let staging = staging.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        for sf in staged {
            sf.sync_blocking()?;
        }
        state.save_blocking(&staging)?;
        Ok(())
    })
    .await?
}

#[allow(clippy::too_many_arguments)]
async fn drive(control_tx: &mut ControlTx, control_rx: crate::secure::ControlRx, data: Vec<DataStream>, manifest: &Manifest, inc: &mut Incoming, opts: &ReceiveOptions, staging: &Path, set: &mut JoinSet<()>, reader: &mut Option<ControlReader>) -> Result<()> {
    let (ev_tx, mut ev_rx) = mpsc::channel::<Event>(1024);
    let infos: Vec<FileInfo> = manifest.files.iter().zip(&inc.staged).map(|(f, s)| FileInfo { size: f.size, chunks: u64::from(f.chunk_count), staged: s.clone() }).collect();
    let infos = Arc::new(infos);
    let pool = BufferPool::new(opts.pool_buffers.max(4 * data.len()), BODY_CAPACITY);
    for ds in data {
        let events = ev_tx.clone();
        let fut = data_reader(ds, pool.clone(), Arc::clone(&infos), ev_tx.clone());
        set.spawn(
            async move {
                if let Err(e) = fut.await {
                    forward_bounded(&events, Event::StreamFailed(e)).await;
                }
            }
            .in_current_span(),
        );
    }
    drop(infos);
    *reader = Some(spawn_control_reader(control_rx, EventSink::Bounded(ev_tx.clone()), control_event));

    let mut missing: u64 = inc.pieces.iter().map(|p| p.iter().filter(|h| h.is_none()).count() as u64).sum();
    let bytes_total = manifest.total_bytes();
    let chunks_total: u64 = manifest.files.iter().map(|f| u64::from(f.chunk_count)).sum();
    let mut chunks_done = chunks_total - missing;
    let mut bytes_done = inc.resumed_bytes;
    let mut dirty: BTreeSet<usize> = BTreeSet::new();
    let mut unflushed = 0u32;
    // At most one sidecar flush runs at a time; its result is awaited, never dropped.
    let mut flush_task: Option<tokio::task::JoinHandle<Result<()>>> = None;
    let mut acks_pending = false;
    let mut last_heard = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let transfer_id = manifest.transfer_id.to_string();

    let result = loop {
        let ev = tokio::select! {
            biased;
            () = cancelled(&opts.common.cancel) => break Err(EngineError::Cancelled),
            ev = ev_rx.recv() => match ev { Some(ev) => ev, None => break Err(EngineError::Internal("receiver tasks vanished".into())) },
            r = join_flush(&mut flush_task) => {
                flush_task = None;
                match r {
                    Ok(Ok(())) => continue,
                    Ok(Err(e)) => break Err(e),
                    Err(e) => break Err(e.into()),
                }
            }
            _ = tick.tick() => {
                if last_heard.elapsed() > opts.common.idle_timeout {
                    break Err(EngineError::Timeout);
                }
                continue;
            }
        };
        match ev {
            Event::ChunkDone { file, chunk, hash } => {
                last_heard = Instant::now();
                let (f, c) = (file as usize, chunk as usize);
                let slot = &mut inc.pieces[f][c];
                if slot.is_none() {
                    missing -= 1;
                    chunks_done += 1;
                    bytes_done += storage::chunk_len(manifest.files[f].size, u64::from(chunk)).ok_or_else(|| EngineError::Internal("chunk out of range".into()))?;
                }
                *slot = Some(hash);
                if inc.state.mark_confirmed(f, u64::from(chunk))? {
                    unflushed += 1;
                }
                dirty.insert(f);
                if let Err(e) = control_tx.queue(&Message::ChunkAck(ChunkAck { file_index: file, chunk_index: chunk, hash })).await {
                    break Err(e);
                }
                acks_pending = true;
                if let Some(cb) = &opts.common.progress {
                    cb(&Progress { transfer_id: transfer_id.clone(), bytes_done, bytes_total, chunks_done, chunks_total });
                }
            }
            Event::Control(Control::Close(CloseReason::Done)) => {
                if missing != 0 {
                    break Err(EngineError::violation(format!("sender finished with {missing} chunks missing")));
                }
                break Ok(());
            }
            Event::Control(Control::Close(r)) => break Err(EngineError::from_peer_close(r)),
            Event::Control(Control::Cancel) => break Err(EngineError::Cancelled),
            Event::Control(Control::Ping(_) | Control::Pong(_)) => last_heard = Instant::now(),
            Event::Control(other) => break Err(EngineError::violation(format!("unexpected {other:?} during transfer"))),
            Event::ControlEof => break Err(EngineError::PeerLost),
            Event::Failed(e) => break Err(e),
            Event::StreamFailed(e) => break Err(explain_stream_failure(&mut ev_rx, e).await),
        }
        if unflushed >= opts.flush_every.max(1) && flush_task.is_none() {
            unflushed = 0;
            let files: Vec<Arc<StagedFile>> = std::mem::take(&mut dirty).into_iter().filter_map(|i| inc.staged[i].clone()).collect();
            let state = inc.state.clone();
            let dir = staging.to_path_buf();
            flush_task = Some(tokio::task::spawn_blocking(move || -> Result<()> {
                // Data first, then the sidecar that claims it (manual §19).
                for sf in files {
                    sf.sync_blocking()?;
                }
                state.save_blocking(&dir)?;
                Ok(())
            }));
        }
        // Batch acks: one flush per burst of ready events (transport queue_frame).
        if acks_pending && ev_rx.is_empty() {
            acks_pending = false;
            if let Err(e) = control_tx.flush().await {
                break Err(e);
            }
        }
    };
    // Let an in-flight sidecar flush finish so it can't race the final save/removal.
    if let Some(h) = flush_task {
        let flushed = h.await.map_err(EngineError::from).and_then(|r| r);
        match (&result, flushed) {
            (Ok(()), Err(e)) => return Err(e),
            (Err(e), Err(fe)) => tracing::error!(error = %fe, "sidecar flush failed while tearing down after: {e}"),
            (_, Ok(())) => {}
        }
    }
    result
}

/// Resolves with the running flush's result; never resolves when none is running.
async fn join_flush(task: &mut Option<tokio::task::JoinHandle<Result<()>>>) -> std::result::Result<Result<()>, tokio::task::JoinError> {
    match task {
        Some(h) => h.await,
        None => std::future::pending().await,
    }
}

/// Takes sole ownership of a staged file, waiting for straggling blocking writes
/// (e.g. a duplicate resend still being written) to release their handle.
async fn take_owned(sf: Arc<StagedFile>) -> Result<StagedFile> {
    let mut sf = sf;
    for _ in 0..2000 {
        match Arc::try_unwrap(sf) {
            Ok(owned) => return Ok(owned),
            Err(shared) => sf = shared,
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err(EngineError::Internal("staging file still in use".into()))
}

async fn finalize(inc: &mut Incoming, manifest: &Manifest, dest: &Path, staging: &Path) -> Result<Vec<PathBuf>> {
    let mut owned = Vec::with_capacity(inc.staged.len());
    for s in std::mem::take(&mut inc.staged) {
        owned.push(match s {
            Some(sf) => Some(take_owned(sf).await?),
            None => None,
        });
    }
    let files = manifest.files.clone();
    let rels = inc.rels.clone();
    let dests = inc.dests.clone();
    let pieces: Vec<Vec<[u8; 32]>> = inc.pieces.iter().map(|p| p.iter().map(|h| h.ok_or_else(|| EngineError::Internal("finalizing with a missing piece hash".into()))).collect::<Result<_>>()).collect::<Result<_>>()?;
    let dest = dest.to_path_buf();
    let staging = staging.to_path_buf();
    let state = inc.state.clone();
    tokio::task::spawn_blocking(move || -> Result<Vec<PathBuf>> {
        let mut saved = Vec::with_capacity(files.len());
        for (i, (f, sf)) in files.iter().zip(owned).enumerate() {
            // Re-check at write time: a symlink may have been planted since the
            // manifest was accepted (manual §34).
            let target = if f.is_dir { dir_target_blocking(&dest, &rels[i])? } else { safe_join_blocking(&dest, &rels[i])? };
            if target != dests[i] {
                return Err(EngineError::UnsafePath(f.relative_path.clone()));
            }
            match sf {
                Some(sf) => saved.push(sf.finalize_with_pieces_blocking(&f.content_hash, &pieces[i])?),
                None => {
                    match std::fs::create_dir(&target) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && target.is_dir() => {}
                        Err(e) => return Err(e.into()),
                    }
                    saved.push(target);
                }
            }
        }
        state.remove_blocking(&staging)?;
        Ok(saved)
    })
    .await?
}
