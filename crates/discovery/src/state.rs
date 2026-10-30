// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Discovery state machine (manual §6 diagram).
//!
//! Pure and synchronous like `protocol`'s state machines: no I/O, no clock reads. The
//! caller passes `now` into every call (an injected clock, manual §5 `Clock`), so every
//! timeout is deterministic under test. Unrecognized inputs in a state are no-ops, never
//! panics: radio callbacks arrive late and out of order in practice.

use std::time::{Duration, Instant};

use crate::PeerHandle;

/// Timeouts for the states that wait on something external.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// SCANNING with no peer found → IDLE + QR fallback prompt (manual §6: 15 s).
    pub scan: Duration,
    /// NEGOTIATING (WFD group formation / SoftAP join / AWDL link) → FAILED.
    pub negotiate: Duration,
    /// AUTHENTICATING (user comparing the SAS / scanning the QR) → FAILED.
    pub authenticate: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { scan: Duration::from_secs(15), negotiate: Duration::from_secs(30), authenticate: Duration::from_secs(120) }
    }
}

/// Why the machine entered [`State::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    NegotiationFailed,
    NegotiationTimeout,
    /// The radio link dropped before the session was handed off.
    PeerLost,
    /// The peer (or the local user) declined the pairing prompt.
    Rejected,
    VerificationTimeout,
    /// SAS / QR fingerprint mismatch. Flag a possible MITM; never retry silently (manual §6).
    PossibleMitm,
}

impl FailureReason {
    /// Whether an automatic retry is acceptable. False for anything involving the
    /// user's trust decision.
    pub fn auto_retry_allowed(self) -> bool {
        matches!(self, Self::NegotiationFailed | Self::NegotiationTimeout | Self::PeerLost)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Idle,
    Scanning {
        since: Instant,
    },
    PeerFound {
        peers: usize,
    },
    Negotiating {
        peer: PeerHandle,
        since: Instant,
    },
    LinkEstablished {
        peer: PeerHandle,
    },
    Authenticating {
        peer: PeerHandle,
        since: Instant,
    },
    Connected {
        peer: PeerHandle,
    },
    /// The protocol engine owns the connection; discovery's job is done.
    Ready {
        peer: PeerHandle,
    },
    /// Terminal until the user explicitly acknowledges ([`Input::Acknowledge`]).
    Failed {
        peer: Option<PeerHandle>,
        reason: FailureReason,
    },
}

/// Things that happen to the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// User tapped Send/Receive.
    StartScan,
    PeerFound,
    PeerLost(PeerHandle),
    /// User picked a peer from the list.
    SelectPeer(PeerHandle),
    /// Radio-level connect succeeded.
    LinkUp,
    /// Radio-level connect failed.
    LinkFailed,
    /// The link dropped (any post-negotiation state before READY).
    LinkLost,
    /// The engine started the crypto handshake over the link.
    HandshakeStarted,
    /// SAS confirmed by the user, QR fingerprint matched, or a pinned peer auto-accepted.
    VerificationConfirmed,
    /// SAS / QR fingerprint mismatch.
    VerificationMismatch,
    /// Peer or user declined.
    Rejected,
    /// The protocol engine took over the connection.
    HandOff,
    /// User cancelled; back to IDLE from any non-failed state.
    Cancel,
    /// User dismissed a failure.
    Acknowledge,
}

/// Side effects the driver should perform after a transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Scan found nobody: show "no peers found" plus the QR fallback (manual §6).
    ShowQrFallback,
    /// Start radio negotiation with this peer (`PeerDiscovery::connect`).
    BeginNegotiation(PeerHandle),
    /// Surface this failure to the user (manual §36). Never auto-retried for
    /// [`FailureReason::PossibleMitm`].
    Surface(FailureReason),
}

/// The discovery state machine.
#[derive(Debug, Clone)]
pub struct DiscoveryMachine {
    state: State,
    timeouts: Timeouts,
}

impl Default for DiscoveryMachine {
    fn default() -> Self {
        Self::new(Timeouts::default())
    }
}

impl DiscoveryMachine {
    pub fn new(timeouts: Timeouts) -> Self {
        Self { state: State::Idle, timeouts }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// When the current state times out, if it can. Drivers sleep until this instant and
    /// then call [`tick`](Self::tick).
    pub fn deadline(&self) -> Option<Instant> {
        match &self.state {
            State::Scanning { since } => Some(*since + self.timeouts.scan),
            State::Negotiating { since, .. } => Some(*since + self.timeouts.negotiate),
            State::Authenticating { since, .. } => Some(*since + self.timeouts.authenticate),
            _ => None,
        }
    }

    /// Advance timers. Call whenever the clock moves; cheap and idempotent.
    pub fn tick(&mut self, now: Instant) -> Option<Output> {
        let deadline = self.deadline()?;
        if now < deadline {
            return None;
        }
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Scanning { .. } => Some(Output::ShowQrFallback),
            State::Negotiating { peer, .. } => Some(self.fail(Some(peer), FailureReason::NegotiationTimeout)),
            State::Authenticating { peer, .. } => Some(self.fail(Some(peer), FailureReason::VerificationTimeout)),
            other => {
                self.state = other;
                None
            }
        }
    }

    /// Apply an input. Inputs that make no sense in the current state are ignored.
    pub fn handle(&mut self, input: Input, now: Instant) -> Option<Output> {
        // Expire first, so a stale state cannot accept a late success.
        if let Some(out) = self.tick(now) {
            return Some(out);
        }
        let state = std::mem::replace(&mut self.state, State::Idle);
        let (next, out) = Self::transition(state, input, now);
        self.state = next;
        out
    }

    fn fail(&mut self, peer: Option<PeerHandle>, reason: FailureReason) -> Output {
        self.state = State::Failed { peer, reason };
        Output::Surface(reason)
    }

    fn transition(state: State, input: Input, now: Instant) -> (State, Option<Output>) {
        use FailureReason as R;
        use State as S;
        let failed = |peer: PeerHandle, reason: R| (S::Failed { peer: Some(peer), reason }, Some(Output::Surface(reason)));
        match (state, input) {
            // Failed only leaves on an explicit user acknowledgement: this is what makes
            // "never auto-retry after a MITM flag" structural rather than a convention.
            (S::Failed { .. }, Input::Acknowledge) => (S::Idle, None),
            (s @ S::Failed { .. }, _) => (s, None),

            (S::Idle, Input::StartScan) => (S::Scanning { since: now }, None),
            (S::Scanning { .. }, Input::PeerFound) => (S::PeerFound { peers: 1 }, None),
            (S::PeerFound { peers }, Input::PeerFound) => (S::PeerFound { peers: peers.saturating_add(1) }, None),
            (S::PeerFound { peers }, Input::PeerLost(_)) => match peers.saturating_sub(1) {
                0 => (S::Scanning { since: now }, None),
                n => (S::PeerFound { peers: n }, None),
            },
            (S::PeerFound { .. }, Input::SelectPeer(peer)) => (S::Negotiating { peer: peer.clone(), since: now }, Some(Output::BeginNegotiation(peer))),

            (S::Negotiating { peer, .. }, Input::LinkUp) => (S::LinkEstablished { peer }, None),
            (S::Negotiating { peer, .. }, Input::LinkFailed) => failed(peer, R::NegotiationFailed),
            (S::Negotiating { peer, .. }, Input::Rejected) => failed(peer, R::Rejected),

            (S::LinkEstablished { peer }, Input::HandshakeStarted) => (S::Authenticating { peer, since: now }, None),

            (S::Authenticating { peer, .. }, Input::VerificationConfirmed) => (S::Connected { peer }, None),
            (S::Authenticating { peer, .. }, Input::VerificationMismatch) => failed(peer, R::PossibleMitm),
            (S::Authenticating { peer, .. }, Input::Rejected) => failed(peer, R::Rejected),

            (S::Connected { peer }, Input::HandOff) => (S::Ready { peer }, None),

            (S::Negotiating { peer, .. } | S::LinkEstablished { peer } | S::Authenticating { peer, .. } | S::Connected { peer }, Input::LinkLost) => failed(peer, R::PeerLost),

            (S::Ready { .. }, Input::Cancel | Input::Acknowledge) => (S::Idle, None),
            (S::Ready { peer }, _) => (S::Ready { peer }, None),
            (_, Input::Cancel) => (S::Idle, None),
            (s, _) => (s, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> PeerHandle {
        PeerHandle::new(s)
    }

    fn to_authenticating(m: &mut DiscoveryMachine, t0: Instant) {
        m.handle(Input::StartScan, t0);
        m.handle(Input::PeerFound, t0);
        assert_eq!(m.handle(Input::SelectPeer(h("p")), t0), Some(Output::BeginNegotiation(h("p"))));
        m.handle(Input::LinkUp, t0);
        m.handle(Input::HandshakeStarted, t0);
        assert!(matches!(m.state(), State::Authenticating { .. }));
    }

    #[test]
    fn happy_path_reaches_ready() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        to_authenticating(&mut m, t0);
        m.handle(Input::VerificationConfirmed, t0);
        assert_eq!(m.state(), &State::Connected { peer: h("p") });
        m.handle(Input::HandOff, t0);
        assert_eq!(m.state(), &State::Ready { peer: h("p") });
        assert_eq!(m.deadline(), None);
    }

    #[test]
    fn scan_times_out_after_15s_to_idle_with_qr_prompt() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        m.handle(Input::StartScan, t0);
        assert_eq!(m.deadline(), Some(t0 + Duration::from_secs(15)));
        assert_eq!(m.tick(t0 + Duration::from_millis(14_999)), None);
        assert_eq!(m.tick(t0 + Duration::from_secs(15)), Some(Output::ShowQrFallback));
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.tick(t0 + Duration::from_secs(99)), None);
    }

    #[test]
    fn found_peer_stops_scan_timer_and_losing_all_peers_restarts_it() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        m.handle(Input::StartScan, t0);
        m.handle(Input::PeerFound, t0);
        m.handle(Input::PeerFound, t0);
        assert_eq!(m.tick(t0 + Duration::from_secs(60)), None);
        let t1 = t0 + Duration::from_secs(60);
        m.handle(Input::PeerLost(h("a")), t1);
        assert_eq!(m.state(), &State::PeerFound { peers: 1 });
        m.handle(Input::PeerLost(h("b")), t1);
        assert_eq!(m.state(), &State::Scanning { since: t1 });
    }

    #[test]
    fn negotiation_failure_and_timeout() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        m.handle(Input::StartScan, t0);
        m.handle(Input::PeerFound, t0);
        m.handle(Input::SelectPeer(h("p")), t0);
        assert_eq!(m.handle(Input::LinkFailed, t0), Some(Output::Surface(FailureReason::NegotiationFailed)));

        let mut m = DiscoveryMachine::default();
        m.handle(Input::StartScan, t0);
        m.handle(Input::PeerFound, t0);
        m.handle(Input::SelectPeer(h("p")), t0);
        // A late LinkUp after the deadline must not succeed.
        let late = t0 + Duration::from_secs(31);
        assert_eq!(m.handle(Input::LinkUp, late), Some(Output::Surface(FailureReason::NegotiationTimeout)));
        assert!(matches!(m.state(), State::Failed { reason: FailureReason::NegotiationTimeout, .. }));
    }

    #[test]
    fn mitm_mismatch_fails_and_never_auto_retries() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        to_authenticating(&mut m, t0);
        assert_eq!(m.handle(Input::VerificationMismatch, t0), Some(Output::Surface(FailureReason::PossibleMitm)));
        assert!(!FailureReason::PossibleMitm.auto_retry_allowed());
        // Nothing but an explicit Acknowledge leaves Failed: no StartScan/SelectPeer/LinkUp
        // can sneak back into a connection attempt.
        for input in [Input::StartScan, Input::SelectPeer(h("p")), Input::LinkUp, Input::VerificationConfirmed, Input::HandOff, Input::Cancel] {
            assert_eq!(m.handle(input, t0), None);
            assert!(matches!(m.state(), State::Failed { reason: FailureReason::PossibleMitm, .. }));
        }
        assert_eq!(m.tick(t0 + Duration::from_secs(3600)), None);
        m.handle(Input::Acknowledge, t0);
        assert_eq!(m.state(), &State::Idle);
    }

    #[test]
    fn verification_timeout_and_rejection() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        to_authenticating(&mut m, t0);
        assert_eq!(m.tick(t0 + Duration::from_secs(120)), Some(Output::Surface(FailureReason::VerificationTimeout)));

        let mut m = DiscoveryMachine::default();
        to_authenticating(&mut m, t0);
        assert_eq!(m.handle(Input::Rejected, t0), Some(Output::Surface(FailureReason::Rejected)));
        assert!(!FailureReason::Rejected.auto_retry_allowed());
    }

    #[test]
    fn link_loss_before_ready_fails_with_peer_lost() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        to_authenticating(&mut m, t0);
        assert_eq!(m.handle(Input::LinkLost, t0), Some(Output::Surface(FailureReason::PeerLost)));
        assert!(FailureReason::PeerLost.auto_retry_allowed());
    }

    #[test]
    fn out_of_order_inputs_are_ignored() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        for input in [Input::LinkUp, Input::HandshakeStarted, Input::VerificationConfirmed, Input::HandOff, Input::SelectPeer(h("x")), Input::PeerLost(h("x"))] {
            assert_eq!(m.handle(input, t0), None);
            assert_eq!(m.state(), &State::Idle);
        }
        // Verification before a handshake started does nothing.
        m.handle(Input::StartScan, t0);
        m.handle(Input::PeerFound, t0);
        m.handle(Input::SelectPeer(h("p")), t0);
        m.handle(Input::LinkUp, t0);
        assert_eq!(m.handle(Input::VerificationConfirmed, t0), None);
        assert_eq!(m.state(), &State::LinkEstablished { peer: h("p") });
    }

    #[test]
    fn cancel_returns_to_idle_from_active_states() {
        let t0 = Instant::now();
        let mut m = DiscoveryMachine::default();
        to_authenticating(&mut m, t0);
        m.handle(Input::Cancel, t0);
        assert_eq!(m.state(), &State::Idle);
    }

    proptest::proptest! {
        /// Arbitrary input sequences never panic, and a MITM flag is sticky until Acknowledge.
        #[test]
        fn arbitrary_sequences_keep_mitm_sticky(seq in proptest::collection::vec((0u8..15, 0u64..200), 0..64)) {
            let t0 = Instant::now();
            let mut m = DiscoveryMachine::default();
            for (code, secs) in seq {
                let input = match code {
                    0 => Input::StartScan, 1 => Input::PeerFound, 2 => Input::PeerLost(h("p")), 3 => Input::SelectPeer(h("p")),
                    4 => Input::LinkUp, 5 => Input::LinkFailed, 6 => Input::LinkLost, 7 => Input::HandshakeStarted,
                    8 => Input::VerificationConfirmed, 9 => Input::VerificationMismatch, 10 => Input::Rejected,
                    11 => Input::HandOff, 12 => Input::Cancel, 13 => Input::Acknowledge, _ => Input::PeerFound,
                };
                let was_mitm = matches!(m.state(), State::Failed { reason: FailureReason::PossibleMitm, .. });
                let ack = input == Input::Acknowledge;
                m.handle(input, t0 + Duration::from_secs(secs));
                if was_mitm && !ack {
                    let still_mitm = matches!(m.state(), State::Failed { reason: FailureReason::PossibleMitm, .. });
                    proptest::prop_assert!(still_mitm, "MITM failure left without Acknowledge");
                }
            }
        }
    }
}
