//! The session layer: byte sequences, replay buffers and resume (docs/DESIGN.md section 4).
//!
//! Each direction of a terminal channel is a byte stream numbered from 0 when the session
//! starts. The sender keeps what it sent in a [`ReplayBuffer`] until the peer acknowledges it;
//! the receiver keeps a [`Inbound`] position. When a connection breaks, the next one starts
//! with both ends saying how far they received, and both resend from there: not a byte is lost
//! unless more than the replay buffer's capacity went unacknowledged, and then the receiver
//! sees a gap (and the server has the program redraw its screen).

mod replay;

pub use replay::ReplayBuffer;

/// Output the server keeps for a client that comes back: 8 MiB.
pub const OUTPUT_REPLAY: usize = 8 << 20;

/// Error output (stderr of a pipe session) the server keeps: 1 MiB.
pub const ERROR_REPLAY: usize = 1 << 20;

/// Input the client keeps until the server acknowledges it: 1 MiB.
pub const INPUT_REPLAY: usize = 1 << 20;

/// The receiving side of one direction: how far the stream was received.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Inbound {
    received: u64,
}

/// What [`Inbound::accept`] made of a chunk.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted<'a> {
    /// New bytes, to deliver in order.
    New(&'a [u8]),
    /// New bytes after a gap of `missing` bytes the sender no longer had (they fell out of its
    /// replay buffer and will never come).
    AfterGap {
        /// How many bytes were skipped.
        missing: u64,
        /// The bytes to deliver.
        bytes: &'a [u8],
    },
    /// Everything in the chunk was received before: a resend after a reconnect.
    Duplicate,
}

impl Inbound {
    /// A stream received up to `received`, e.g. restored from saved credentials.
    pub fn at(received: u64) -> Inbound {
        Inbound { received }
    }

    /// The offset of the next byte expected: everything before it was received.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Take a chunk of the stream that starts at offset `seq`, keeping only what is new.
    ///
    /// A chunk after a gap is taken whole: the sender only skips bytes that fell out of its
    /// replay buffer, and waiting for them would freeze the terminal for good.
    pub fn accept<'a>(&mut self, seq: u64, bytes: &'a [u8]) -> Accepted<'a> {
        let Some(end) = seq.checked_add(bytes.len() as u64) else {
            // A chunk running past 2^64 cannot be real
            return Accepted::Duplicate;
        };
        if end <= self.received || bytes.is_empty() {
            return Accepted::Duplicate;
        }
        if seq > self.received {
            let missing = seq - self.received;
            self.received = end;
            return Accepted::AfterGap { missing, bytes };
        }
        let skip = (self.received - seq) as usize;
        self.received = end;
        Accepted::New(&bytes[skip..])
    }
}

#[cfg(test)]
mod tests;
