//! Background-task bookkeeping shared by sender and receiver: no task result and
//! no task panic is dropped silently.

use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::error::{EngineError, Result};

/// Reaps every task in `set`. A panic becomes an error; a cancellation is only
/// expected (and ignored) for tasks this side aborted itself.
pub(crate) async fn join_all(set: &mut JoinSet<()>) -> Result<()> {
    let mut first = Ok(());
    while let Some(r) = set.join_next().await {
        if let Err(e) = r
            && !e.is_cancelled()
        {
            tracing::error!(error = %e, "engine task panicked");
            if first.is_ok() {
                first = Err(EngineError::from(e));
            }
        }
    }
    first
}

/// Aborts every task in `set` and reaps them (see [`join_all`]).
pub(crate) async fn abort_all(set: &mut JoinSet<()>) -> Result<()> {
    set.abort_all();
    join_all(set).await
}

/// Sends an event to the engine's event loop. If the loop is gone the transfer is
/// already being torn down (with its own error), so the event is dropped on
/// purpose; it is logged rather than silently lost.
pub(crate) fn forward<T>(tx: &mpsc::UnboundedSender<T>, ev: T) {
    if tx.send(ev).is_err() {
        tracing::trace!("event loop gone, dropping event");
    }
}

/// Bounded-channel variant of [`forward`] for async senders.
pub(crate) async fn forward_bounded<T>(tx: &mpsc::Sender<T>, ev: T) {
    if tx.send(ev).await.is_err() {
        tracing::trace!("event loop gone, dropping event");
    }
}
