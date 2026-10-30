// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

use crate::Result;
use crate::error::ProtocolError;
use crate::msg_type::MsgType;
use crate::state::Role;

/// Connection establishment (manual §9.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Init,
    WaitHelloAck,
    Handshaking,
    Authenticated,
    Established,
    Closed,
    Failed(ProtocolError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnEvent {
    HelloSent,
    HelloReceived,
    HelloAckReceived,
    HandshakeComplete,
    /// SAS confirmed by the user, QR fingerprint matched, or a pinned peer (manual §12.1).
    PeerVerified,
    PeerRejected,
    CloseReceived,
    Timeout,
    Malformed(ProtocolError),
}

#[derive(Debug, Clone)]
pub struct Connection {
    role: Role,
    state: ConnState,
}

impl Connection {
    pub fn new(role: Role) -> Self {
        Self { role, state: ConnState::Init }
    }

    pub fn state(&self) -> &ConnState {
        &self.state
    }

    pub fn is_established(&self) -> bool {
        self.state == ConnState::Established
    }

    /// Applies an event. Anything out of order fails the connection: a peer
    /// sending messages in the wrong order is treated as hostile (manual §33/§35).
    pub fn on_event(&mut self, event: ConnEvent) -> Result<&ConnState> {
        use ConnEvent as E;
        use ConnState as S;
        let next = match (&self.state, self.role, event) {
            (S::Failed(_) | S::Closed, _, _) => return Err(ProtocolError::UnexpectedMessage),
            (_, _, E::Timeout) => S::Failed(ProtocolError::Timeout),
            (_, _, E::Malformed(e)) => S::Failed(e),
            (_, _, E::CloseReceived) => S::Closed,
            (S::Init, Role::Initiator, E::HelloSent) => S::WaitHelloAck,
            (S::WaitHelloAck, Role::Initiator, E::HelloAckReceived) => S::Handshaking,
            // Responder answers Hello with HelloAck in the same step.
            (S::Init, Role::Responder, E::HelloReceived) => S::Handshaking,
            (S::Handshaking, _, E::HandshakeComplete) => S::Authenticated,
            (S::Authenticated, _, E::PeerVerified) => S::Established,
            (S::Authenticated, _, E::PeerRejected) => S::Failed(ProtocolError::UnexpectedMessage),
            _ => S::Failed(ProtocolError::UnexpectedMessage),
        };
        self.state = next;
        if let S::Failed(e) = &self.state {
            return Err(e.clone());
        }
        Ok(&self.state)
    }

    /// Which inbound frame types are legal before the transfer layer takes over.
    pub fn check_incoming(&self, msg: MsgType) -> Result<()> {
        let ok = match (&self.state, self.role) {
            (ConnState::Init, Role::Responder) => msg == MsgType::Hello,
            (ConnState::WaitHelloAck, Role::Initiator) => msg == MsgType::HelloAck,
            (ConnState::Handshaking, _) => matches!(msg, MsgType::Handshake | MsgType::Close),
            (ConnState::Established, _) => !matches!(msg, MsgType::Hello | MsgType::HelloAck | MsgType::Handshake),
            _ => msg == MsgType::Close,
        };
        if ok { Ok(()) } else { Err(ProtocolError::UnexpectedMessage) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish(role: Role) -> Connection {
        let mut c = Connection::new(role);
        match role {
            Role::Initiator => {
                c.on_event(ConnEvent::HelloSent).unwrap();
                c.on_event(ConnEvent::HelloAckReceived).unwrap();
            }
            Role::Responder => {
                c.on_event(ConnEvent::HelloReceived).unwrap();
            }
        }
        c.on_event(ConnEvent::HandshakeComplete).unwrap();
        c.on_event(ConnEvent::PeerVerified).unwrap();
        c
    }

    #[test]
    fn happy_paths() {
        assert!(establish(Role::Initiator).is_established());
        assert!(establish(Role::Responder).is_established());
    }

    #[test]
    fn out_of_order_fails() {
        let mut c = Connection::new(Role::Initiator);
        assert!(c.on_event(ConnEvent::HandshakeComplete).is_err());
        assert!(matches!(c.state(), ConnState::Failed(_)));
        // Terminal: nothing revives it.
        assert!(c.on_event(ConnEvent::HelloSent).is_err());
    }

    #[test]
    fn verification_cannot_be_skipped() {
        let mut c = Connection::new(Role::Responder);
        c.on_event(ConnEvent::HelloReceived).unwrap();
        assert!(c.on_event(ConnEvent::PeerVerified).is_err());
    }

    #[test]
    fn timeout_and_rejection_fail() {
        let mut c = Connection::new(Role::Initiator);
        c.on_event(ConnEvent::HelloSent).unwrap();
        assert_eq!(c.on_event(ConnEvent::Timeout), Err(ProtocolError::Timeout));

        let mut c = establish(Role::Responder);
        c.on_event(ConnEvent::CloseReceived).unwrap();
        assert_eq!(c.state(), &ConnState::Closed);
    }

    #[test]
    fn incoming_filter() {
        let c = Connection::new(Role::Responder);
        assert!(c.check_incoming(MsgType::Hello).is_ok());
        assert!(c.check_incoming(MsgType::ChunkData).is_err());
        assert!(c.check_incoming(MsgType::Handshake).is_err());
        let mut c = Connection::new(Role::Responder);
        c.on_event(ConnEvent::HelloReceived).unwrap();
        assert!(c.check_incoming(MsgType::Handshake).is_ok());
        assert!(c.check_incoming(MsgType::ManifestOffer).is_err());
        let c = establish(Role::Initiator);
        assert!(c.check_incoming(MsgType::Hello).is_err());
        assert!(c.check_incoming(MsgType::Handshake).is_err());
        assert!(c.check_incoming(MsgType::ChunkAck).is_ok());
    }
}
