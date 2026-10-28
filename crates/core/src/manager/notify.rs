//! Delivers observer callbacks on one dedicated thread, so a slow or blocking
//! observer can never stall a runtime worker or a transfer.
//!
//! Everything goes through one bounded queue (manual §28: no unbounded queue).
//! "Latest value" notices (progress, state) are offered with `try_send`; when the
//! queue is full the job is marked dirty and the manager's ticker re-offers the
//! *current* value later, so intermediate values merge instead of piling up.
//! One-off notices (incoming offer, verification request, errors, peers) wait
//! for room, which only ever blocks the job's control path, never the data path.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, PoisonError, RwLock};

use discovery::{Peer, PeerHandle};
use tokio::sync::{mpsc, oneshot};

use super::job::Job;
use super::types::{IncomingOffer, TransferId, TransferObserver, TransferState, VerifyRequest};
use crate::error::EngineError;

/// Queue capacity between the runtime and the dispatcher thread.
pub(crate) const NOTICE_CAPACITY: usize = 256;

pub(crate) enum Notice {
    /// Snapshotted at delivery time ([`Job::take_progress`]).
    Progress(Arc<Job>),
    State(TransferId, TransferState),
    PeerFound(Peer),
    PeerLost(PeerHandle),
    Error(Option<TransferId>, EngineError),
    Incoming(IncomingOffer),
    Verify(VerifyRequest),
    /// Deliver everything queued before this, then exit; acknowledges on the sender.
    Stop(Option<oneshot::Sender<()>>),
}

pub(crate) type ObserverSlot = Arc<RwLock<Option<Arc<dyn TransferObserver>>>>;

pub(crate) fn current(slot: &ObserverSlot) -> Option<Arc<dyn TransferObserver>> {
    // A poisoned lock only means a panic elsewhere while swapping the Arc; the
    // stored value is still a whole Arc.
    slot.read().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Starts the dispatcher thread.
pub(crate) fn spawn_dispatcher(mut rx: mpsc::Receiver<Notice>, slot: ObserverSlot) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new().name("dfte-observer".into()).spawn(move || {
        while let Some(n) = rx.blocking_recv() {
            if let Notice::Stop(ack) = n {
                if let Some(ack) = ack
                    && ack.send(()).is_err()
                {
                    tracing::debug!("shutdown stopped waiting for the dispatcher");
                }
                return;
            }
            let Some(obs) = current(&slot) else {
                if let Notice::Progress(job) = &n {
                    job.progress_queued.store(false, std::sync::atomic::Ordering::Release);
                }
                // No observer registered: there is nobody to tell. Verification
                // requests then time out as rejections (manual §35).
                continue;
            };
            let delivered = catch_unwind(AssertUnwindSafe(|| deliver(obs.as_ref(), n)));
            if delivered.is_err() {
                tracing::error!("transfer observer panicked; continuing with the next callback");
            }
        }
    })
}

fn deliver(obs: &dyn TransferObserver, n: Notice) {
    match n {
        Notice::Progress(job) => obs.on_progress(job.take_progress()),
        Notice::State(id, s) => obs.on_state_changed(id, s),
        Notice::PeerFound(p) => obs.on_peer_found(p),
        Notice::PeerLost(h) => obs.on_peer_lost(h),
        Notice::Error(id, e) => obs.on_error(id, e),
        Notice::Incoming(o) => obs.on_incoming(o),
        Notice::Verify(r) => obs.on_verify_peer(r),
        Notice::Stop(_) => {}
    }
}
