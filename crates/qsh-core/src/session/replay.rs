//! The replay buffer: bytes sent and not yet acknowledged.

use std::collections::VecDeque;

/// Bytes sent on one direction of a channel and not yet acknowledged, kept to resend them
/// after a reconnect.
///
/// Offsets are positions in the whole stream since the session started. When more than the
/// capacity is unacknowledged the oldest bytes are dropped: a peer that missed them gets the
/// rest after a gap.
#[derive(Debug, Clone)]
pub struct ReplayBuffer {
    buf: VecDeque<u8>,
    /// Stream offset of `buf[0]`.
    base: u64,
    capacity: usize,
}

impl ReplayBuffer {
    /// An empty buffer for a stream at offset 0 keeping at most `capacity` bytes.
    pub fn new(capacity: usize) -> ReplayBuffer {
        ReplayBuffer {
            buf: VecDeque::new(),
            base: 0,
            capacity,
        }
    }

    /// An empty buffer for a stream that continues at `offset`.
    pub fn starting_at(capacity: usize, offset: u64) -> ReplayBuffer {
        ReplayBuffer {
            buf: VecDeque::new(),
            base: offset,
            capacity,
        }
    }

    /// The offset after the last byte pushed: where the next byte goes.
    pub fn end(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    /// The offset of the oldest byte still held.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Bytes held.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when nothing is held.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Append bytes to the stream; drops the oldest beyond the capacity.
    pub fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= self.capacity {
            // Only the tail survives: skip copying what would be dropped at once
            let dropped = self.buf.len() as u64 + (bytes.len() - self.capacity) as u64;
            self.buf.clear();
            self.buf.extend(&bytes[bytes.len() - self.capacity..]);
            self.base += dropped;
            return;
        }
        self.buf.extend(bytes);
        if self.buf.len() > self.capacity {
            let drop = self.buf.len() - self.capacity;
            self.buf.drain(..drop);
            self.base += drop as u64;
        }
    }

    /// The peer has everything before `offset`: forget it. Offsets beyond the end are clamped.
    pub fn ack(&mut self, offset: u64) {
        if offset > self.base {
            let n = (offset - self.base).min(self.buf.len() as u64) as usize;
            self.buf.drain(..n);
            self.base += n as u64;
        }
    }

    /// Up to `max` bytes from `offset`, clamped to what is still held, with the offset they
    /// start at (greater than `offset` when bytes fell out of the buffer).
    pub fn read_from(&self, offset: u64, max: usize) -> (u64, Vec<u8>) {
        let start = offset.clamp(self.base, self.end());
        let skip = (start - self.base) as usize;
        let (a, b) = self.buf.as_slices();
        let mut out = Vec::with_capacity(max.min(self.buf.len() - skip));
        if skip < a.len() {
            let take = (a.len() - skip).min(max);
            out.extend_from_slice(&a[skip..skip + take]);
            let rest = max - take;
            out.extend_from_slice(&b[..rest.min(b.len())]);
        } else {
            let skip = skip - a.len();
            out.extend_from_slice(&b[skip..(skip + max).min(b.len())]);
        }
        (start, out)
    }
}
