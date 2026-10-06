//! A scanner in front of the `vt100` model: it follows the escape-sequence state machine of
//! `vte` (the parser inside `vt100`) byte for byte, so that it agrees with the model on where
//! every sequence begins and ends, and it keeps what `vt100` does not (m2.md 6.2):
//!
//! - focus reporting (mode 1004) and the urxvt mouse encoding (mode 1015);
//! - the cursor style (DECSCUSR);
//! - the window title and icon name (OSC 0, 1, 2);
//! - whether origin mode or a non-ASCII character set was used since the screen was last
//!   cleared (protocol.md 7.8.4: the snapshot cannot express them; the program should redraw).
//!
//! It also tells the model where it must act between two slices of input ([`Action`]), and
//! whether a chunk is "simple" (text, harmless controls, SGR, OSC and character set
//! designations only): simple output on the normal screen may be fed to `vt100` lazily (see
//! `model.rs`), which is what keeps the model's cost far below a byte-for-byte emulation on
//! floods.
//!
//! **It is a filter** (protocol.md 7.8.7, the program's output is hostile input): `vt100` gets
//! the scanner's output ([`Scanned::bytes`]), never the program's bytes directly, and that output
//! has the same effect on `vt100`'s screen with bounded cost:
//!
//! - **Strings** (OSC, DCS, SOS, PM, APC) never reach `vt100`. It keeps nothing of them that a
//!   snapshot uses (titles are the scanner's), but `vte` buffers an OSC without limit: one
//!   unterminated OSC would grow the daemon's memory with the program's output. A CAN takes
//!   their place, which returns `vt100` to the ground state from wherever it was (as the ESC of
//!   the string would have).
//! - **Control sequences** are held back until they are complete, so that a sequence split
//!   across chunks reaches `vt100` in one piece and can be rewritten. A complete one is passed
//!   on as written, except that the counts `vt100` loops on without a bound (insert and delete
//!   characters and lines, scroll, erase characters) are clamped to the screen's size, which
//!   is exact: `vt100` repeats such an operation `n` times, and every repetition beyond the
//!   screen's size changes nothing more. A sequence too long to hold is passed on in a
//!   canonical form of what `vte` parsed of it.
//! - **Cost.** Every chunk is given the work it asks of `vt100` beyond the ordinary (clearing
//!   screens, inserting cells and lines), [`Scanned::cost`], in cells; the model refuses a
//!   chunk that exceeds its budget (`model.rs`).

/// The most bytes of an OSC string kept (a title is at most 256 bytes of it).
const MAX_OSC: usize = 4096;
/// The most bytes of an unfinished escape or control sequence held back as written; a longer
/// one is passed on in canonical form.
const MAX_HELD: usize = 64;
/// A string unfinished at the end of a chunk counts as not processed yet (`held`) while it is at
/// most this long.
const MAX_HELD_STRING: usize = 4096;
/// `vte`'s limits.
const MAX_PARAMS: usize = 32;
const MAX_INTERMEDIATES: usize = 2;
/// Lines of scrollback `vt100` keeps (`SNAPSHOT_TAIL_LINES`), for the cost of clearing it or
/// of a full reset.
const SCROLLBACK: u64 = super::SNAPSHOT_TAIL_LINES as u64;

/// The C0 controls `vte` executes inside a sequence (all but CAN, SUB and ESC, which end it).
fn executes(b: u8) -> bool {
    matches!(b, 0x00..=0x17 | 0x19 | 0x1c..=0x1f)
}

/// The parser states of `vte` 0.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Ground,
    Escape,
    EscapeIntermediate,
    CsiEntry,
    CsiParam,
    CsiIntermediate,
    CsiIgnore,
    Osc,
    DcsEntry,
    DcsParam,
    DcsIntermediate,
    DcsPassthrough,
    DcsIgnore,
    SosPmApc,
}

/// Something the model must do at a point of the input, after `vt100` has processed the bytes
/// before it (the model's state at that point matters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    /// `CSI ! p`, a soft reset, which `vt100` does not implement.
    SoftReset,
    /// `CSI Pt ; Pb r` with its raw parameters (0: absent).
    ScrollRegion(u16, u16),
    /// `CSI ? 1049 h`: the alternate screen is cleared, its scroll region with it.
    EnterAlternate,
    /// Another switch between the screens (47, 1049 l): line feeds after it count for the
    /// screen then active.
    Switch,
    /// `ESC c`, a full reset.
    FullReset,
}

/// What one chunk contained. Byte indexes are into [`Scanned::bytes`].
#[derive(Debug, Default)]
pub(super) struct Scanned {
    /// What `vt100` gets for the chunk (module documentation).
    pub bytes: Vec<u8>,
    /// Only text, controls `vt100` treats as cursor motion within a line or as line feeds,
    /// SGR, OSC, strings `vt100` ignores, and character set designations.
    pub simple: bool,
    /// Points (byte index after the sequence) where the model must act, with the line feeds
    /// counted before them.
    pub actions: Vec<(usize, Action, u64)>,
    /// Line feeds (LF, VT, FF) executed.
    pub line_feeds: u64,
    /// Byte indexes just after each CR LF pair seen in the ground state.
    pub cuts: Vec<usize>,
    /// Byte ranges of the complete SGR sequences.
    pub sgr: Vec<(usize, usize)>,
    /// The work the chunk asks of `vt100` beyond the ordinary, in cells (module documentation).
    pub cost: u64,
}

/// The scanner's state and what it follows.
#[derive(Debug, Clone, Default)]
pub(super) struct Scanner {
    state: State,
    /// UTF-8 continuation bytes still expected in the ground state.
    utf8: u8,
    /// The previous byte was a CR executed in the ground state.
    cr: bool,
    params: [u16; MAX_PARAMS],
    /// Whether each parameter ends its group (`;`) or is followed by a sub-parameter (`:`).
    ends: [bool; MAX_PARAMS],
    count: usize,
    param: u16,
    intermediates: [u8; MAX_INTERMEDIATES],
    n_intermediates: usize,
    /// The control sequence's first intermediate is a private marker (`<=>?`, before its
    /// parameters).
    marker: bool,
    /// The unfinished escape or control sequence, from its ESC, as written: not passed on yet.
    seq: Vec<u8>,
    /// The sequence outgrew [`MAX_HELD`]: what it executed was passed on, the rest is known
    /// only as parsed.
    long: bool,
    /// Bytes of the current string so far, from its ESC (`usize::MAX`: not held).
    string: usize,
    /// The screen's size, for the clamps and the cost.
    cols: u16,
    rows: u16,
    osc: Vec<u8>,
    /// Mode 1004.
    pub focus: bool,
    /// Mode 1015.
    pub urxvt: bool,
    /// DECSCUSR, 0 to 6.
    pub cursor_style: u8,
    /// OSC 2 (or 0).
    pub title: String,
    /// OSC 1 (or 0).
    pub icon: String,
    /// Origin mode or a non-ASCII character set was used since the screen was last cleared.
    pub redraw: bool,
}

impl Scanner {
    /// A scanner for a `cols` × `rows` screen.
    pub fn new(cols: u16, rows: u16) -> Scanner {
        let mut scanner = Scanner::default();
        scanner.set_size(cols, rows);
        scanner
    }

    /// The screen's new size.
    pub fn set_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols.max(1);
        self.rows = rows.max(1);
    }

    /// `vt100`'s parser is between two sequences, after what the scanner passed on (it can be
    /// inside one only after an escape sequence with intermediates, or a partial UTF-8
    /// character).
    pub fn at_rest(&self) -> bool {
        self.state != State::EscapeIntermediate && self.utf8 == 0
    }

    /// Bytes at the end of what was scanned that were not passed on yet: an unfinished
    /// sequence (or string) that `vt100` has not seen. The model's state is that of the output
    /// before them.
    pub fn held(&self) -> usize {
        match self.state {
            State::Escape | State::CsiEntry | State::CsiParam | State::CsiIntermediate | State::CsiIgnore => {
                if self.long {
                    0
                } else {
                    self.seq.len()
                }
            }
            State::Osc
            | State::DcsEntry
            | State::DcsParam
            | State::DcsIntermediate
            | State::DcsPassthrough
            | State::DcsIgnore
            | State::SosPmApc => {
                if self.string <= MAX_HELD_STRING {
                    self.string
                } else {
                    0
                }
            }
            State::Ground | State::EscapeIntermediate => 0,
        }
    }

    /// Scan `bytes`, updating what the scanner follows; `out` gets what `vt100` is to process.
    pub fn scan(&mut self, bytes: &[u8], out: &mut Scanned) {
        out.bytes.clear();
        out.simple = true;
        out.actions.clear();
        out.line_feeds = 0;
        out.cuts.clear();
        out.sgr.clear();
        out.cost = 0;
        for &b in bytes {
            self.byte(b, out);
        }
    }

    fn reset_params(&mut self) {
        self.count = 0;
        self.param = 0;
        self.n_intermediates = 0;
        self.marker = false;
    }

    /// An ESC: a new sequence starts, held back.
    fn begin_escape(&mut self) {
        self.seq.clear();
        self.seq.push(0x1b);
        self.long = false;
        self.reset_params();
        self.state = State::Escape;
    }

    /// One more byte of the held sequence.
    fn hold(&mut self, b: u8, out: &mut Scanned) {
        if self.long {
            if executes(b) {
                out.bytes.push(b);
            }
            return;
        }
        self.seq.push(b);
        if self.seq.len() > MAX_HELD {
            self.pass_controls(out);
            self.long = true;
        }
    }

    /// Pass on the controls the held sequence executed (`vte` executes them as they come),
    /// and forget the rest of it.
    fn pass_controls(&mut self, out: &mut Scanned) {
        if !self.long {
            out.bytes.extend(self.seq.iter().copied().filter(|&b| executes(b)));
        }
        self.seq.clear();
    }

    /// Pass on the held escape sequence as written (only its ESC when it was too long: what it
    /// executed went on already, and `vte` ignored the rest).
    fn pass_held(&mut self, out: &mut Scanned) {
        if self.long {
            out.bytes.push(0x1b);
        } else {
            out.bytes.extend_from_slice(&self.seq);
        }
        self.seq.clear();
        self.long = false;
    }

    /// A string starts after the held ESC: swallowed (module documentation).
    fn begin_string(&mut self, state: State, out: &mut Scanned) {
        self.string = if !self.long && self.seq.len() == 1 {
            2
        } else {
            usize::MAX
        };
        self.pass_controls(out);
        self.long = false;
        out.bytes.push(0x18);
        self.state = state;
    }

    /// A C0 control executed (in the ground state or inside a sequence).
    fn execute(&mut self, b: u8, ground: bool, out: &mut Scanned) {
        match b {
            0x0a..=0x0c => {
                out.line_feeds += 1;
                if b == 0x0a && ground && self.cr {
                    out.cuts.push(out.bytes.len());
                }
            }
            0x0e | 0x0f => self.redraw = true,
            _ => {}
        }
        self.cr = ground && b == 0x0d;
    }

    fn collect(&mut self, b: u8) {
        if self.n_intermediates < MAX_INTERMEDIATES {
            self.intermediates[self.n_intermediates] = b;
            self.n_intermediates += 1;
        }
    }

    fn param_digit(&mut self, b: u8) {
        if self.count < MAX_PARAMS {
            self.param = self.param.saturating_mul(10).saturating_add(u16::from(b - b'0'));
        }
    }

    fn param_end(&mut self, ends_group: bool) {
        if self.count < MAX_PARAMS {
            self.params[self.count] = self.param;
            self.ends[self.count] = ends_group;
            self.count += 1;
            self.param = 0;
        }
    }

    /// The first value of each parameter group, and whether the group has sub-parameters.
    fn groups(&self) -> impl Iterator<Item = (u16, bool)> + '_ {
        let mut start = 0;
        let mut i = 0;
        std::iter::from_fn(move || {
            while i < self.count {
                let end = self.ends[i];
                i += 1;
                if end {
                    let group = (self.params[start], i - start > 1);
                    start = i;
                    return Some(group);
                }
            }
            if start < self.count {
                let group = (self.params[start], true);
                start = self.count;
                return Some(group);
            }
            None
        })
    }

    /// The bytes of a string (swallowed).
    fn string_byte(&mut self, b: u8, out: &mut Scanned) {
        self.string = self.string.saturating_add(1);
        match (self.state, b) {
            (State::Osc, 0x07) => {
                self.osc_end();
                self.state = State::Ground;
            }
            (_, 0x18 | 0x1a) => {
                if self.state == State::Osc {
                    self.osc_end();
                }
                out.bytes.push(b);
                self.execute(b, false, out);
                self.state = State::Ground;
            }
            (_, 0x1b) => {
                if self.state == State::Osc {
                    self.osc_end();
                }
                self.begin_escape();
            }
            (State::Osc, _) if b < 0x20 => {}
            (State::Osc, _) => {
                if self.osc.len() < MAX_OSC {
                    self.osc.push(b);
                }
            }
            (State::DcsEntry, 0x20..=0x2f) | (State::DcsParam, 0x20..=0x2f) => self.state = State::DcsIntermediate,
            (State::DcsEntry, 0x30..=0x3f) => self.state = State::DcsParam,
            (State::DcsParam, 0x3c..=0x3f) | (State::DcsIntermediate, 0x30..=0x3f) => self.state = State::DcsIgnore,
            (State::DcsEntry | State::DcsParam | State::DcsIntermediate, 0x40..=0x7e) => {
                self.state = State::DcsPassthrough
            }
            (State::DcsPassthrough, 0x9c) => self.state = State::Ground,
            _ => {}
        }
    }

    fn byte(&mut self, b: u8, out: &mut Scanned) {
        let c0 = executes(b);
        match self.state {
            State::Ground => {
                if b == 0x1b {
                    self.utf8 = 0;
                    self.cr = false;
                    self.begin_escape();
                    return;
                }
                out.bytes.push(b);
                // UTF-8: only whether a character is unfinished matters here
                match b {
                    0x80..=0xbf if self.utf8 > 0 => self.utf8 -= 1,
                    0xc2..=0xdf => self.utf8 = 1,
                    0xe0..=0xef => self.utf8 = 2,
                    0xf0..=0xf4 => self.utf8 = 3,
                    _ => self.utf8 = 0,
                }
                if b < 0x20 {
                    self.execute(b, true, out);
                } else {
                    self.cr = false;
                }
            }
            State::Escape => match b {
                0x18 | 0x1a => {
                    self.pass_controls(out);
                    self.long = false;
                    out.bytes.push(b);
                    self.execute(b, false, out);
                    self.state = State::Ground;
                }
                _ if c0 => {
                    self.hold(b, out);
                    self.execute(b, false, out);
                }
                0x20..=0x2f => {
                    self.pass_held(out);
                    out.bytes.push(b);
                    self.collect(b);
                    self.state = State::EscapeIntermediate;
                }
                0x50 => self.begin_string(State::DcsEntry, out),
                0x58 | 0x5e | 0x5f => self.begin_string(State::SosPmApc, out),
                0x5b => {
                    self.hold(b, out);
                    self.reset_params();
                    self.state = State::CsiEntry;
                }
                0x5d => {
                    self.osc.clear();
                    self.begin_string(State::Osc, out);
                }
                0x30..=0x7e => {
                    self.pass_held(out);
                    out.bytes.push(b);
                    self.state = State::Ground;
                    self.esc_dispatch(b, out);
                }
                // ESC, DEL and the rest are ignored by `vte`; kept for passing on as written
                _ => self.hold(b, out),
            },
            State::EscapeIntermediate => match b {
                0x18 | 0x1a => {
                    out.bytes.push(b);
                    self.execute(b, false, out);
                    self.state = State::Ground;
                }
                0x1b => self.begin_escape(),
                _ if c0 => {
                    out.bytes.push(b);
                    self.execute(b, false, out);
                }
                0x20..=0x2f => {
                    out.bytes.push(b);
                    self.collect(b);
                }
                0x30..=0x7e => {
                    out.bytes.push(b);
                    self.state = State::Ground;
                    self.esc_dispatch(b, out);
                }
                // Ignored by `vte` in the state `vt100` is in as well
                _ => out.bytes.push(b),
            },
            State::CsiEntry | State::CsiParam | State::CsiIntermediate | State::CsiIgnore => match b {
                0x18 | 0x1a => {
                    self.pass_controls(out);
                    self.long = false;
                    out.bytes.push(b);
                    self.execute(b, false, out);
                    self.state = State::Ground;
                }
                0x1b => {
                    self.pass_controls(out);
                    self.begin_escape();
                }
                _ if c0 => {
                    self.hold(b, out);
                    self.execute(b, false, out);
                }
                0x40..=0x7e => self.csi_final(b, out),
                _ => {
                    self.hold(b, out);
                    self.csi_byte(b);
                }
            },
            State::Osc
            | State::DcsEntry
            | State::DcsParam
            | State::DcsIntermediate
            | State::DcsPassthrough
            | State::DcsIgnore
            | State::SosPmApc => self.string_byte(b, out),
        }
    }

    /// A parameter or intermediate byte of a control sequence (or one `vte` ignores there).
    fn csi_byte(&mut self, b: u8) {
        match (self.state, b) {
            (State::CsiEntry | State::CsiParam, 0x20..=0x2f) | (State::CsiIntermediate, 0x20..=0x2f) => {
                self.collect(b);
                self.state = State::CsiIntermediate;
            }
            (State::CsiEntry | State::CsiParam, 0x30..=0x39) => {
                self.param_digit(b);
                self.state = State::CsiParam;
            }
            (State::CsiEntry | State::CsiParam, 0x3a) => {
                self.param_end(false);
                self.state = State::CsiParam;
            }
            (State::CsiEntry | State::CsiParam, 0x3b) => {
                self.param_end(true);
                self.state = State::CsiParam;
            }
            (State::CsiEntry, 0x3c..=0x3f) => {
                self.collect(b);
                self.marker = true;
                self.state = State::CsiParam;
            }
            (State::CsiParam, 0x3c..=0x3f) | (State::CsiIntermediate, 0x30..=0x3f) => self.state = State::CsiIgnore,
            // DEL, bytes above 0x7f, and everything in CsiIgnore: ignored
            _ => {}
        }
    }

    /// The final byte of a control sequence: pass it on, as written or rewritten.
    fn csi_final(&mut self, b: u8, out: &mut Scanned) {
        if self.state == State::CsiIgnore {
            // `vte` dispatches nothing
            out.simple = false;
            self.state = State::Ground;
            self.pass_controls(out);
            self.long = false;
            return;
        }
        self.state = State::Ground;
        self.param_end(true);
        let clamp = self.clamp(b);
        let controls = !self.long && self.seq.iter().any(|&c| executes(c));
        let start;
        if self.long || clamp.is_some() || controls {
            self.pass_controls(out);
            start = out.bytes.len();
            self.canonical(b, clamp, out);
        } else {
            start = out.bytes.len();
            out.bytes.extend_from_slice(&self.seq);
            out.bytes.push(b);
            self.seq.clear();
        }
        self.long = false;
        out.cost = out.cost.saturating_add(self.cost(b));
        self.csi_dispatch(start, b, out);
    }

    /// The count to use instead of the first parameter, for the operations `vt100` repeats
    /// that many times (module documentation): beyond the screen's width or height a
    /// repetition changes nothing.
    fn clamp(&self, b: u8) -> Option<u16> {
        if self.n_intermediates > 0 {
            return None;
        }
        let cap = match b {
            b'@' | b'P' | b'X' => self.cols,
            b'L' | b'M' | b'S' | b'T' => self.rows,
            _ => return None,
        };
        (self.params[0] > cap).then_some(cap)
    }

    /// The control sequence as `vte` parsed it (first parameter `first` if given), which `vte`
    /// parses back to the same: `ESC [`, the private marker, the parameters with their
    /// separators, the other intermediates, the final byte.
    fn canonical(&self, b: u8, first: Option<u16>, out: &mut Scanned) {
        out.bytes.extend_from_slice(b"\x1b[");
        if self.marker {
            out.bytes.push(self.intermediates[0]);
        }
        for i in 0..self.count {
            let value = match (i, first) {
                (0, Some(v)) => v,
                _ => self.params[i],
            };
            out.bytes.extend_from_slice(value.to_string().as_bytes());
            if i + 1 < self.count {
                out.bytes.push(if self.ends[i] { b';' } else { b':' });
            }
        }
        out.bytes
            .extend_from_slice(&self.intermediates[usize::from(self.marker)..self.n_intermediates]);
        out.bytes.push(b);
    }

    /// The work of a control sequence beyond the ordinary, in cells: what clears or allocates
    /// whole screens, and the operations `vt100` repeats per count (each insertion moves the rest
    /// of the line, each inserted line allocates one).
    fn cost(&self, b: u8) -> u64 {
        let (cols, rows) = (u64::from(self.cols), u64::from(self.rows));
        let cells = cols * rows;
        let line = cols + 2 * rows;
        let count = |cap: u16| u64::from(self.params[0].clamp(1, cap));
        match (self.intermediates[..self.n_intermediates].first(), b) {
            (None, b'@') => 2 * count(self.cols) * cols,
            (None, b'P') => count(self.cols) * cols,
            (None, b'L' | b'M' | b'S' | b'T') => count(self.rows) * line,
            // 3: the scrollback, a row at a time
            (None | Some(b'?'), b'J') if self.params[0] == 3 => SCROLLBACK,
            (None | Some(b'?'), b'J') => cells,
            (Some(b'?'), b'h' | b'l') => {
                let switches = self.groups().filter(|g| matches!(g.0, 47 | 1047 | 1049)).count();
                switches as u64 * cells
            }
            (Some(b'!'), b'p') => 2 * cells,
            _ => 0,
        }
    }

    fn esc_dispatch(&mut self, b: u8, out: &mut Scanned) {
        if self.n_intermediates > 0 {
            // Character set designations (vt100 ignores them): only whether they leave ASCII
            if matches!(self.intermediates[0], b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/') && b != b'B' {
                self.redraw = true;
            }
            return;
        }
        match b {
            b'c' => {
                out.simple = false;
                out.actions.push((out.bytes.len(), Action::FullReset, out.line_feeds));
                let (cols, rows) = (u64::from(self.cols), u64::from(self.rows));
                out.cost = out.cost.saturating_add(2 * cols * rows + SCROLLBACK * cols);
                self.focus = false;
                self.urxvt = false;
                self.cursor_style = 0;
                self.redraw = false;
            }
            // What vt100 acts on (index and next line it does not)
            b'7' | b'8' | b'=' | b'>' | b'M' => out.simple = false,
            _ => {}
        }
    }

    /// A control sequence passed on from `start` to the end of `out`.
    fn csi_dispatch(&mut self, start: usize, b: u8, out: &mut Scanned) {
        let at = out.bytes.len();
        let intermediates = &self.intermediates[..self.n_intermediates];
        match (intermediates.first(), b) {
            (None, b'm') => out.sgr.push((start, at)),
            (None, b'r') => {
                let mut groups = self.groups();
                let top = groups.next().map_or(0, |g| g.0);
                let bottom = groups.next().map_or(0, |g| g.0);
                out.simple = false;
                out.actions
                    .push((at, Action::ScrollRegion(top, bottom), out.line_feeds));
            }
            (None, b'J') => {
                out.simple = false;
                if matches!(self.groups().next().map(|g| g.0), Some(2 | 3)) {
                    self.redraw = false;
                }
            }
            (Some(b' '), b'q') => {
                let style = self.groups().next().map_or(0, |g| g.0);
                if style <= 6 {
                    self.cursor_style = style as u8;
                }
            }
            (Some(b'!'), b'p') => {
                out.simple = false;
                out.actions.push((at, Action::SoftReset, out.line_feeds));
            }
            (Some(b'?'), b'h' | b'l') => {
                out.simple = false;
                let set = b == b'h';
                let mut action = None;
                let modes: Vec<(u16, bool)> = self.groups().collect();
                for (mode, sub) in modes {
                    if sub {
                        continue;
                    }
                    match mode {
                        6 if set => self.redraw = true,
                        1004 => self.focus = set,
                        1015 => self.urxvt = set,
                        1049 if set => action = Some(Action::EnterAlternate),
                        47 | 1049 => action = action.or(Some(Action::Switch)),
                        _ => {}
                    }
                }
                if let Some(action) = action {
                    out.actions.push((at, action, out.line_feeds));
                }
            }
            (Some(b'?'), b'J' | b'K') => out.simple = false,
            // vt100 ignores other private and intermediate forms
            (Some(_), _) => {}
            (None, _) => out.simple = false,
        }
    }

    fn osc_end(&mut self) {
        let osc = std::mem::take(&mut self.osc);
        let Some(split) = osc.iter().position(|&c| c == b';') else {
            return;
        };
        let text = String::from_utf8_lossy(&osc[split + 1..]).into_owned();
        match &osc[..split] {
            b"0" => {
                self.title = text.clone();
                self.icon = text;
            }
            b"1" => self.icon = text,
            b"2" => self.title = text,
            _ => {}
        }
        self.osc = osc;
        self.osc.clear();
    }
}
