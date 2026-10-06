//! Screen models for smart catch-up (m2.md section 6, protocol.md 7.8).
//!
//! For every tty session the daemon keeps a terminal emulator state, fed with exactly the bytes
//! that enter the session's output replay buffer, so that the state at offset `E` is there
//! whenever the buffer ends at `E`. From it a snapshot is encoded: terminal bytes that redraw
//! the screen in any terminal, following the content profile of protocol.md 7.8.4.
//!
//! - [`Model`]: the boundary around the emulator, so that it can be replaced; [`Vt100Model`]
//!   implements it with the `vt100` crate and a scanner of our own for what `vt100` does not
//!   keep (`scan.rs`, `model.rs`).
//! - [`snapshot`]: the [`Capture`] of a model, its encoding ([`snapshot::encode`]) and an
//!   independent check of the content profile ([`snapshot::check_profile`]).
//! - [`Live`]: one session's model as the daemon keeps it: the size caps, the offsets it has
//!   seen, how many lines scrolled since a given offset (for the tail of a skip snapshot).

mod model;
mod scan;
pub mod snapshot;
#[cfg(test)]
mod tests;

use std::collections::VecDeque;

pub use model::Vt100Model;
pub use snapshot::Capture;

use crate::proto::message::MAX_SNAPSHOT;

/// The widest terminal that gets a model.
pub const MODEL_MAX_COLS: u16 = 1024;
/// The tallest terminal that gets a model.
pub const MODEL_MAX_ROWS: u16 = 512;
/// The most cells of a terminal that gets a model (`MODEL_MAX_CELLS`, m2.md 6.2).
pub const MODEL_MAX_CELLS: usize = 262_144;
/// Lines of scrollback a model keeps, and the most a skip snapshot pushes into the client's
/// scrollback (`SNAPSHOT_TAIL_LINES`).
pub const SNAPSHOT_TAIL_LINES: usize = 100;

/// The smallest terminal that gets a model: `vt100` underflows (and panics) wrapping a wide
/// character in one column, or a line on a screen of one row.
pub const MODEL_MIN: u16 = 2;

/// Whether a `cols` × `rows` terminal gets a model.
pub fn fits(cols: u16, rows: u16) -> bool {
    (MODEL_MIN..=MODEL_MAX_COLS).contains(&cols)
        && (MODEL_MIN..=MODEL_MAX_ROWS).contains(&rows)
        && usize::from(cols) * usize::from(rows) <= MODEL_MAX_CELLS
}

/// A terminal emulator state that snapshots are taken from.
pub trait Model: Send {
    /// The next bytes of output; the line feeds among them that ran on the normal screen.
    fn feed(&mut self, bytes: &[u8]) -> u64;
    /// Bytes fed but not processed yet (the start of a character): the model's state is that
    /// of the output up to `fed − held`.
    fn held(&self) -> usize;
    /// The terminal's new size.
    fn resize(&mut self, cols: u16, rows: u16);
    /// (columns, rows).
    fn size(&self) -> (u16, u16);
    /// The alternate screen is active.
    fn alternate(&self) -> bool;
    /// Everything a snapshot reproduces, with up to `tail` lines of scrollback.
    fn capture(&mut self, tail: usize) -> Capture;
}

/// Chunks remembered for [`Live::lines_since`].
const CHECKPOINTS: usize = 4096;

/// A snapshot as the daemon sends it.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The output offset it was taken at.
    pub offset: u64,
    /// `Columns`, `Rows`.
    pub cols: u16,
    /// `Rows`.
    pub rows: u16,
    /// The data (protocol.md 7.8.4), at most `MAX_SNAPSHOT` bytes.
    pub data: Vec<u8>,
    /// The program should redraw as well (it used what a snapshot cannot express).
    pub redraw: bool,
}

/// One session's model in the daemon.
pub struct Live {
    /// None: the terminal is beyond the caps (or was): no snapshots for this session.
    model: Option<Box<dyn Model>>,
    /// The output offset fed up to; None before the first output.
    end: Option<u64>,
    /// Line feeds on the normal screen so far.
    line_feeds: u64,
    /// (end offset, line feeds) after each chunk.
    checkpoints: VecDeque<(u64, u64)>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("model", &self.model.as_ref().map(|m| m.size()))
            .field("end", &self.end)
            .finish()
    }
}

impl Live {
    /// A model for a new `cols` × `rows` session (none beyond the caps).
    pub fn new(cols: u16, rows: u16) -> Live {
        Live {
            model: fits(cols, rows).then(|| Box::new(Vt100Model::new(cols, rows)) as Box<dyn Model>),
            end: None,
            line_feeds: 0,
            checkpoints: VecDeque::new(),
        }
    }

    /// The model handed over by the previous image of the daemon (m2.md 6.8): a fresh model
    /// fed the resync snapshot it sent, standing at output offset `end`.
    pub fn resumed(cols: u16, rows: u16, snapshot: &[u8], end: u64) -> Live {
        let mut live = Live::new(cols, rows);
        if let Some(model) = live.model.as_mut() {
            model.feed(snapshot);
            live.end = Some(end);
            live.checkpoints.push_back((end, 0));
        }
        live
    }

    /// Output entered the buffer at `offset`. Bytes before what was fed already are skipped
    /// (installing the sink replays the buffer).
    pub fn feed(&mut self, offset: u64, bytes: &[u8]) {
        let Some(model) = self.model.as_mut() else { return };
        let skip = self.end.map_or(0, |end| end.saturating_sub(offset));
        let Some(bytes) = usize::try_from(skip).ok().and_then(|s| bytes.get(s..)) else {
            return;
        };
        if bytes.is_empty() {
            return;
        }
        if self.end.is_none() {
            self.checkpoints.push_back((offset, 0));
        }
        self.line_feeds += model.feed(bytes);
        let end = offset + skip + bytes.len() as u64;
        self.end = Some(end);
        if self.checkpoints.len() == CHECKPOINTS {
            self.checkpoints.pop_front();
        }
        self.checkpoints.push_back((end, self.line_feeds));
    }

    /// The terminal's new size. Beyond the caps the model is dropped for good: its state
    /// could not be trusted again.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        if !fits(cols, rows) {
            self.model = None;
        } else if let Some(model) = self.model.as_mut() {
            model.resize(cols, rows);
        }
    }

    /// The session has a model.
    pub fn usable(&self) -> bool {
        self.model.is_some()
    }

    /// The alternate screen is active.
    pub fn alternate(&self) -> bool {
        self.model.as_ref().is_some_and(|m| m.alternate())
    }

    /// Lines that scrolled on the normal screen since output offset `offset`, at least (the
    /// count of the first chunk ending at or after it).
    pub fn lines_since(&self, offset: u64) -> u64 {
        let at = self
            .checkpoints
            .iter()
            .find(|c| c.0 >= offset)
            .map_or(self.line_feeds, |c| c.1);
        self.line_feeds - at
    }

    /// A snapshot at the current end (before a character not complete yet, which then follows
    /// it as output): a skip snapshot when `skip_from` (the offset the client
    /// expects) is given, with the tail of the lines that scrolled off since then; a resync
    /// snapshot otherwise. None without a model or when it would exceed `MAX_SNAPSHOT`.
    pub fn snapshot(&mut self, skip_from: Option<u64>) -> Option<Snapshot> {
        let held = self.model.as_ref().map_or(0, |m| m.held()) as u64;
        let offset = self.end.unwrap_or(0) - held;
        let tail = match skip_from {
            Some(from) => {
                let rows = self.model.as_ref()?.size().1;
                // The cursor may have been anywhere: the first rows of line feeds may not have
                // scrolled; fewer lines rather than lines the client already has
                let scrolled = self.lines_since(from).saturating_sub(u64::from(rows) - 1);
                scrolled.min(SNAPSHOT_TAIL_LINES as u64) as usize
            }
            None => 0,
        };
        let model = self.model.as_mut()?;
        let capture = model.capture(tail);
        let data = snapshot::encode(&capture, skip_from.is_some());
        (data.len() <= MAX_SNAPSHOT).then_some(Snapshot {
            offset,
            cols: capture.cols,
            rows: capture.rows,
            data,
            redraw: capture.redraw,
        })
    }

    /// The model's state for an upgrade in place: (columns, rows, a resync snapshot).
    pub fn handoff(&mut self) -> Option<(u16, u16, Vec<u8>)> {
        let snapshot = self.snapshot(None)?;
        Some((snapshot.cols, snapshot.rows, snapshot.data))
    }
}
