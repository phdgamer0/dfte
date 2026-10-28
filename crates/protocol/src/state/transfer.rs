use crate::Result;
use crate::error::ProtocolError;
use crate::msg_type::MsgType;
use crate::state::Role;

/// File transfer lifecycle (manual §9.2). `Initiator` = sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Connection established, no manifest exchanged yet.
    Ready,
    ManifestSent,
    /// Receiver holds an offer and is waiting for the user to accept.
    ManifestReceived,
    Transferring,
    Complete,
    Cancelled,
    /// Connection dropped; resume state is kept on both sides (manual §19).
    Interrupted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEvent {
    OfferSent,
    OfferReceived,
    AcceptSent,
    AcceptReceived,
    AllChunksConfirmed,
    Cancel,
    ConnectionLost,
    /// Reconnected and the offer hashes matched; goes back through the manifest exchange.
    Reconnected,
    IntegrityFailure,
}

#[derive(Debug, Clone)]
pub struct Transfer {
    role: Role,
    state: TransferState,
}

impl Transfer {
    pub fn new(role: Role) -> Self {
        Self { role, state: TransferState::Ready }
    }

    pub fn state(&self) -> TransferState {
        self.state
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, TransferState::Complete | TransferState::Cancelled | TransferState::Failed)
    }

    pub fn on_event(&mut self, event: TransferEvent) -> Result<TransferState> {
        use TransferEvent as E;
        use TransferState as S;
        if self.is_terminal() {
            return Err(ProtocolError::UnexpectedMessage);
        }
        let next = match (self.state, self.role, event) {
            (_, _, E::Cancel) => S::Cancelled,
            (_, _, E::IntegrityFailure) => S::Failed,
            (S::ManifestSent | S::ManifestReceived | S::Transferring, _, E::ConnectionLost) => S::Interrupted,
            (S::Ready, _, E::ConnectionLost) => S::Failed,
            (S::Interrupted, _, E::Reconnected) => S::Ready,
            (S::Ready, Role::Initiator, E::OfferSent) => S::ManifestSent,
            (S::ManifestSent, Role::Initiator, E::AcceptReceived) => S::Transferring,
            (S::Ready, Role::Responder, E::OfferReceived) => S::ManifestReceived,
            (S::ManifestReceived, Role::Responder, E::AcceptSent) => S::Transferring,
            (S::Transferring, _, E::AllChunksConfirmed) => S::Complete,
            _ => {
                self.state = S::Failed;
                return Err(ProtocolError::UnexpectedMessage);
            }
        };
        self.state = next;
        Ok(next)
    }

    /// Inbound frame filter for an established connection (manual §33 fuzz_state_machine).
    pub fn check_incoming(&self, msg: MsgType) -> Result<()> {
        use TransferState as S;
        let ok = match msg {
            MsgType::Ping | MsgType::Pong | MsgType::Close | MsgType::Cancel => true,
            MsgType::ManifestOffer => self.role == Role::Responder && self.state == S::Ready,
            MsgType::ManifestAccept => self.role == Role::Initiator && self.state == S::ManifestSent,
            MsgType::ChunkData => self.role == Role::Responder && self.state == S::Transferring,
            MsgType::ChunkAck | MsgType::SelectiveNack => self.role == Role::Initiator && self.state == S::Transferring,
            _ => false,
        };
        if ok { Ok(()) } else { Err(ProtocolError::UnexpectedMessage) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TransferEvent as E;
    use TransferState as S;

    #[test]
    fn sender_and_receiver_happy_path() {
        let mut tx = Transfer::new(Role::Initiator);
        let mut rx = Transfer::new(Role::Responder);
        assert_eq!(tx.on_event(E::OfferSent), Ok(S::ManifestSent));
        assert_eq!(rx.on_event(E::OfferReceived), Ok(S::ManifestReceived));
        assert_eq!(rx.on_event(E::AcceptSent), Ok(S::Transferring));
        assert_eq!(tx.on_event(E::AcceptReceived), Ok(S::Transferring));
        assert_eq!(tx.on_event(E::AllChunksConfirmed), Ok(S::Complete));
        assert!(tx.is_terminal());
    }

    #[test]
    fn interrupt_and_resume() {
        let mut tx = Transfer::new(Role::Initiator);
        tx.on_event(E::OfferSent).unwrap();
        tx.on_event(E::AcceptReceived).unwrap();
        assert_eq!(tx.on_event(E::ConnectionLost), Ok(S::Interrupted));
        assert_eq!(tx.on_event(E::Reconnected), Ok(S::Ready));
        assert_eq!(tx.on_event(E::OfferSent), Ok(S::ManifestSent));
    }

    #[test]
    fn chunk_before_accept_is_rejected() {
        let mut rx = Transfer::new(Role::Responder);
        assert!(rx.check_incoming(MsgType::ChunkData).is_err());
        rx.on_event(E::OfferReceived).unwrap();
        assert!(rx.check_incoming(MsgType::ChunkData).is_err());
        rx.on_event(E::AcceptSent).unwrap();
        assert!(rx.check_incoming(MsgType::ChunkData).is_ok());
        assert!(rx.check_incoming(MsgType::ChunkAck).is_err());
    }

    #[test]
    fn wrong_role_event_fails() {
        let mut rx = Transfer::new(Role::Responder);
        assert!(rx.on_event(E::OfferSent).is_err());
        assert_eq!(rx.state(), S::Failed);
        assert!(rx.on_event(E::Cancel).is_err());
    }
}
