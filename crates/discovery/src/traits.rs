//! The `PeerDiscovery` abstraction (manual §5) and its object-safe twin.

use std::future::Future;
use std::pin::Pin;

use crypto::DeviceIdentity;
use tokio::sync::mpsc;

use crate::{DiscoveryError, DiscoveryEvent, LinkInfo, Peer, Result};

/// Stream of discovery events returned by [`PeerDiscovery::start_scanning`].
///
/// A thin wrapper over a bounded channel: if the consumer stops polling, the backend's
/// producer task blocks (or drops events, for lossy radio callbacks) instead of growing an
/// unbounded queue (manual §28). The stream ends (`None`) when the backend stops.
#[derive(Debug)]
pub struct PeerStream {
    rx: mpsc::Receiver<DiscoveryEvent>,
}

/// Default capacity of a [`PeerStream`]'s channel.
pub const PEER_STREAM_CAPACITY: usize = 64;

impl PeerStream {
    /// Create a stream plus the sender a backend feeds it from.
    pub fn channel() -> (mpsc::Sender<DiscoveryEvent>, Self) {
        let (tx, rx) = mpsc::channel(PEER_STREAM_CAPACITY);
        (tx, Self { rx })
    }

    /// Next event, or `None` once the backend has stopped.
    ///
    /// Cancel-safe: dropping the future loses no event.
    pub async fn next(&mut self) -> Option<DiscoveryEvent> {
        self.rx.recv().await
    }

    /// Non-blocking poll, for UI-tick style consumers: `Ok(None)` when nothing is queued,
    /// `Err(DiscoveryError::Stopped)` once the backend has stopped.
    pub fn try_next(&mut self) -> Result<Option<DiscoveryEvent>> {
        match self.rx.try_recv() {
            Ok(ev) => Ok(Some(ev)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(DiscoveryError::Stopped),
        }
    }
}

/// Radio-level discovery and link establishment (manual §5).
///
/// The abstraction boundary is "an addressable link exists": everything below it (radio
/// negotiation, platform APIs) is backend-specific, everything above it (sockets, the
/// handshake, transfers) is the shared core. Implemented in Rust for Linux
/// (`wpa_supplicant`, see [`crate::wpa`]) and LAN development ([`crate::lan`]); implemented
/// natively in Swift/Kotlin/C# on iOS/Android/Windows and called back into Rust through a
/// uniffi callback interface (via [`DynPeerDiscovery`]).
///
/// Uses `impl Future + Send` in trait position (native async-fn-in-trait, like the
/// `transport::Transport` trait) so static dispatch costs nothing. Such a trait is not
/// object-safe; [`DynPeerDiscovery`] is the boxed-future twin, blanket-implemented for
/// every `PeerDiscovery`, for the FFI boundary and `Box<dyn ...>` storage in `core`.
///
/// Cancellation (manual §50): dropping any returned future before completion leaves the
/// backend in a consistent state. A dropped `connect` may leave a half-formed radio group,
/// which the next `stop` tears down.
pub trait PeerDiscovery: Send + Sync {
    /// Make this device discoverable as `identity`.
    fn start_advertising(&self, identity: &DeviceIdentity) -> impl Future<Output = Result<()>> + Send;

    /// Start looking for peers. Each call returns a fresh stream; earlier streams end.
    fn start_scanning(&self) -> impl Future<Output = Result<PeerStream>> + Send;

    /// Establish a radio-level link to `peer` and return how to reach it. The engine then
    /// opens its own transport socket (see [`LinkInfo`] for why this deviates from §5).
    fn connect(&self, peer: &Peer) -> impl Future<Output = Result<LinkInfo>> + Send;

    /// Stop advertising and scanning and tear down any link this backend formed.
    fn stop(&self) -> impl Future<Output = Result<()>> + Send;
}

/// A pinned, boxed, `Send` future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe version of [`PeerDiscovery`]. `core` stores `Box<dyn DynPeerDiscovery>`,
/// and uniffi callback interfaces (which need dynamic dispatch) target this shape.
pub trait DynPeerDiscovery: Send + Sync {
    fn start_advertising<'a>(&'a self, identity: &'a DeviceIdentity) -> BoxFuture<'a, Result<()>>;
    fn start_scanning(&self) -> BoxFuture<'_, Result<PeerStream>>;
    fn connect<'a>(&'a self, peer: &'a Peer) -> BoxFuture<'a, Result<LinkInfo>>;
    fn stop(&self) -> BoxFuture<'_, Result<()>>;
}

impl<T: PeerDiscovery> DynPeerDiscovery for T {
    fn start_advertising<'a>(&'a self, identity: &'a DeviceIdentity) -> BoxFuture<'a, Result<()>> {
        Box::pin(PeerDiscovery::start_advertising(self, identity))
    }

    fn start_scanning(&self) -> BoxFuture<'_, Result<PeerStream>> {
        Box::pin(PeerDiscovery::start_scanning(self))
    }

    fn connect<'a>(&'a self, peer: &'a Peer) -> BoxFuture<'a, Result<LinkInfo>> {
        Box::pin(PeerDiscovery::connect(self, peer))
    }

    fn stop(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(PeerDiscovery::stop(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerHandle;

    #[test]
    fn try_next_distinguishes_empty_from_stopped() {
        let (tx, mut stream) = PeerStream::channel();
        assert!(matches!(stream.try_next(), Ok(None)));
        tx.try_send(DiscoveryEvent::PeerLost(PeerHandle::new("p"))).unwrap();
        assert!(matches!(stream.try_next(), Ok(Some(DiscoveryEvent::PeerLost(_)))));
        drop(tx);
        assert!(matches!(stream.try_next(), Err(DiscoveryError::Stopped)));
    }

    /// The object-safe twin is usable as `Box<dyn DynPeerDiscovery>`.
    #[tokio::test]
    async fn dyn_wrapper_dispatches() {
        let lan = crate::lan::LanDiscovery::new(crate::lan::LanConfig { bind: "127.0.0.1:0".parse().unwrap(), multicast_group: None, ..crate::lan::LanConfig::new("x", 1) }).unwrap();
        let d: Box<dyn DynPeerDiscovery> = Box::new(lan);
        let _stream = d.start_scanning().await.unwrap();
        d.stop().await.unwrap();
    }
}
