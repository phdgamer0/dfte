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

/// How long a closing side waits for the peer to close its end of the control
/// stream after our own `Close`/`Cancel` + half-close.
pub(crate) const CLOSE_LINGER: std::time::Duration = std::time::Duration::from_secs(2);

/// Where the control reader delivers events: the sender's loop is unbounded,
/// the receiver's is bounded.
pub(crate) enum EventSink<E> {
    Unbounded(mpsc::UnboundedSender<E>),
    Bounded(mpsc::Sender<E>),
}

impl<E> EventSink<E> {
    fn is_closed(&self) -> bool {
        match self {
            Self::Unbounded(t) => t.is_closed(),
            Self::Bounded(t) => t.is_closed(),
        }
    }

    async fn deliver(&self, ev: E) {
        match self {
            Self::Unbounded(t) => forward(t, ev),
            Self::Bounded(t) => forward_bounded(t, ev).await,
        }
    }
}

/// Control-stream reader that lives outside the abortable task set.
///
/// After the event loop stops listening it keeps reading (and discarding) until
/// the peer closes, so our socket never closes with unread data in its receive
/// buffer. Closing with unread data makes the OS send RST instead of FIN, and
/// on Windows that RST can destroy a `Cancel`/`Close` the peer has not read yet
/// (seen in CI as the peer reporting PeerLost instead of Cancelled).
pub(crate) struct ControlReader(Option<tokio::task::JoinHandle<()>>);

pub(crate) fn spawn_control_reader<E: Send + 'static>(mut rx: crate::secure::ControlRx, sink: EventSink<E>, to_event: fn(Result<Option<crate::secure::Control>>) -> E) -> ControlReader {
    use tracing::Instrument;
    let task = async move {
        let mut delivering = true;
        loop {
            let r = rx.recv().await;
            let last = !matches!(r, Ok(Some(_)));
            if delivering && sink.is_closed() {
                delivering = false;
            }
            if delivering {
                sink.deliver(to_event(r)).await;
            } else if let Err(e) = &r {
                tracing::debug!(error = %e, "control stream ended with an error while draining");
            }
            if last {
                return;
            }
        }
    };
    ControlReader(Some(tokio::spawn(task.in_current_span())))
}

impl ControlReader {
    /// Waits up to `linger` for the peer to close its side, then stops reading.
    /// Call after this side's own half-close. A reader panic is an error; a peer
    /// that never closes is not (it only costs the linger).
    pub(crate) async fn finish(mut self, linger: std::time::Duration) -> Result<()> {
        let Some(mut handle) = self.0.take() else { return Ok(()) };
        match tokio::time::timeout(linger, &mut handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) if e.is_cancelled() => Ok(()),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "control reader panicked");
                Err(EngineError::from(e))
            }
            Err(_) => {
                tracing::debug!(?linger, "peer did not close the control stream in time");
                handle.abort();
                Ok(())
            }
        }
    }
}

impl Drop for ControlReader {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}
