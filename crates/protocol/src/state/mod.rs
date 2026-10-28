//! Pure, synchronous state machines (manual §9). No I/O, no clocks of their
//! own: time is passed in, so every transition is deterministic and testable.

pub mod chunk;
pub mod connection;
pub mod resume;
pub mod transfer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Connection initiator / file sender.
    Initiator,
    Responder,
}
