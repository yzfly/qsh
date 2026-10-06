//! A scanner beside the `vt100` model: it follows the escape-sequence state machine of `vte`
//! (the parser inside `vt100`) byte for byte, so that it agrees with the model on where every
//! sequence begins and ends, and it keeps what `vt100` does not (m2.md 6.2):
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

/// The most bytes of an OSC string kept (a title is at most 256 bytes of it).
const MAX_OSC: usize = 4096;
/// `vte`'s limits.
const MAX_PARAMS: usize = 32;
const MAX_INTERMEDIATES: usize = 2;

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

/// What one chunk contained.
#[derive(Debug, Default)]
pub(super) struct Scanned {
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
    /// Where the current sequence started in this chunk (for SGR ranges).
    start: usize,
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
    /// In the ground state with no partial UTF-8 character: the model's parser is too.
    pub fn at_rest(&self) -> bool {
        self.state == State::Ground && self.utf8 == 0
    }

    /// Scan `bytes`, updating what the scanner follows.
    pub fn scan(&mut self, bytes: &[u8], out: &mut Scanned) {
        out.simple = true;
        out.actions.clear();
        out.line_feeds = 0;
        out.cuts.clear();
        out.sgr.clear();
        if self.state != State::Ground {
            self.start = usize::MAX;
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.byte(i, b, out);
        }
    }

    fn reset_params(&mut self, at: usize) {
        self.count = 0;
        self.param = 0;
        self.n_intermediates = 0;
        self.start = at;
    }

    /// A C0 control executed (in the ground state or inside a sequence).
    fn execute(&mut self, at: usize, b: u8, ground: bool, out: &mut Scanned) {
        match b {
            0x0a..=0x0c => {
                out.line_feeds += 1;
                if b == 0x0a && ground && self.cr {
                    out.cuts.push(at + 1);
                }
            }
            0x0e | 0x0f => self.redraw = true,
            _ => {}
        }
        self.cr = ground && b == 0x0d;
    }

    /// CAN, SUB and ESC anywhere (`vte`'s "anywhere" transitions); other bytes are ignored.
    fn anywhere(&mut self, at: usize, b: u8, out: &mut Scanned) {
        match b {
            0x18 | 0x1a => {
                self.execute(at, b, false, out);
                self.state = State::Ground;
            }
            0x1b => {
                self.reset_params(at);
                self.state = State::Escape;
            }
            _ => {}
        }
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

    fn byte(&mut self, at: usize, b: u8, out: &mut Scanned) {
        let c0 = matches!(b, 0x00..=0x17 | 0x19 | 0x1c..=0x1f);
        match self.state {
            State::Ground => {
                if b == 0x1b {
                    self.utf8 = 0;
                    self.cr = false;
                    self.reset_params(at);
                    self.state = State::Escape;
                    return;
                }
                // UTF-8: only whether a character is unfinished matters here
                match b {
                    0x80..=0xbf if self.utf8 > 0 => self.utf8 -= 1,
                    0xc2..=0xdf => self.utf8 = 1,
                    0xe0..=0xef => self.utf8 = 2,
                    0xf0..=0xf4 => self.utf8 = 3,
                    _ => self.utf8 = 0,
                }
                if b < 0x20 {
                    self.execute(at, b, true, out);
                } else {
                    self.cr = false;
                }
            }
            State::Escape => match b {
                _ if c0 => self.execute(at, b, false, out),
                0x20..=0x2f => {
                    self.collect(b);
                    self.state = State::EscapeIntermediate;
                }
                0x50 => {
                    self.reset_params(at);
                    self.state = State::DcsEntry;
                }
                0x58 | 0x5e | 0x5f => self.state = State::SosPmApc,
                0x5b => {
                    // CSI: the sequence started at the ESC, one byte back
                    let start = self.start;
                    self.reset_params(start);
                    self.state = State::CsiEntry;
                }
                0x5d => {
                    self.osc.clear();
                    self.state = State::Osc;
                }
                0x30..=0x7e => {
                    self.esc_dispatch(at, b, out);
                    self.state = State::Ground;
                }
                0x18 | 0x1a => {
                    self.execute(at, b, false, out);
                    self.state = State::Ground;
                }
                _ => {}
            },
            State::EscapeIntermediate => match b {
                _ if c0 => self.execute(at, b, false, out),
                0x20..=0x2f => self.collect(b),
                0x30..=0x7e => {
                    self.esc_dispatch(at, b, out);
                    self.state = State::Ground;
                }
                0x7f => {}
                _ => self.anywhere(at, b, out),
            },
            State::CsiEntry => match b {
                _ if c0 => self.execute(at, b, false, out),
                0x20..=0x2f => {
                    self.collect(b);
                    self.state = State::CsiIntermediate;
                }
                0x30..=0x39 => {
                    self.param_digit(b);
                    self.state = State::CsiParam;
                }
                0x3a => {
                    self.param_end(false);
                    self.state = State::CsiParam;
                }
                0x3b => {
                    self.param_end(true);
                    self.state = State::CsiParam;
                }
                0x3c..=0x3f => {
                    self.collect(b);
                    self.state = State::CsiParam;
                }
                0x40..=0x7e => self.csi_dispatch(at, b, out),
                _ => self.anywhere(at, b, out),
            },
            State::CsiParam => match b {
                _ if c0 => self.execute(at, b, false, out),
                0x20..=0x2f => {
                    self.collect(b);
                    self.state = State::CsiIntermediate;
                }
                0x30..=0x39 => self.param_digit(b),
                0x3a => self.param_end(false),
                0x3b => self.param_end(true),
                0x3c..=0x3f => self.state = State::CsiIgnore,
                0x40..=0x7e => self.csi_dispatch(at, b, out),
                0x7f => {}
                _ => self.anywhere(at, b, out),
            },
            State::CsiIntermediate => match b {
                _ if c0 => self.execute(at, b, false, out),
                0x20..=0x2f => self.collect(b),
                0x30..=0x3f => self.state = State::CsiIgnore,
                0x40..=0x7e => self.csi_dispatch(at, b, out),
                _ => self.anywhere(at, b, out),
            },
            State::CsiIgnore => match b {
                _ if c0 => self.execute(at, b, false, out),
                0x40..=0x7e => {
                    out.simple = false;
                    self.state = State::Ground;
                }
                0x20..=0x3f | 0x7f => {}
                _ => self.anywhere(at, b, out),
            },
            State::Osc => match b {
                0x07 => {
                    self.osc_end();
                    self.state = State::Ground;
                }
                0x18 | 0x1a => {
                    self.osc_end();
                    self.execute(at, b, false, out);
                    self.state = State::Ground;
                }
                0x1b => {
                    self.osc_end();
                    self.reset_params(at);
                    self.state = State::Escape;
                }
                0x00..=0x06 | 0x08..=0x17 | 0x19 | 0x1c..=0x1f => {}
                _ => {
                    if self.osc.len() < MAX_OSC {
                        self.osc.push(b);
                    }
                }
            },
            State::DcsEntry => match b {
                _ if c0 => {}
                0x20..=0x2f => self.state = State::DcsIntermediate,
                0x30..=0x3b => self.state = State::DcsParam,
                0x3c..=0x3f => self.state = State::DcsParam,
                0x40..=0x7e => self.state = State::DcsPassthrough,
                0x7f => {}
                _ => self.anywhere(at, b, out),
            },
            State::DcsIntermediate => match b {
                _ if c0 => {}
                0x20..=0x2f => {}
                0x30..=0x3f => self.state = State::DcsIgnore,
                0x40..=0x7e => self.state = State::DcsPassthrough,
                0x7f => {}
                _ => self.anywhere(at, b, out),
            },
            State::DcsParam => match b {
                _ if c0 => {}
                0x20..=0x2f => self.state = State::DcsIntermediate,
                0x30..=0x3b => {}
                0x3c..=0x3f => self.state = State::DcsIgnore,
                0x40..=0x7e => self.state = State::DcsPassthrough,
                0x7f => {}
                _ => self.anywhere(at, b, out),
            },
            State::DcsPassthrough => match b {
                0x18 | 0x1a => {
                    self.execute(at, b, false, out);
                    self.state = State::Ground;
                }
                0x1b => {
                    self.reset_params(at);
                    self.state = State::Escape;
                }
                0x9c => self.state = State::Ground,
                _ => {}
            },
            State::DcsIgnore | State::SosPmApc => self.anywhere(at, b, out),
        }
    }

    fn esc_dispatch(&mut self, at: usize, b: u8, out: &mut Scanned) {
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
                out.actions.push((at + 1, Action::FullReset, out.line_feeds));
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

    fn csi_dispatch(&mut self, at: usize, b: u8, out: &mut Scanned) {
        self.param_end(true);
        self.state = State::Ground;
        let intermediates = &self.intermediates[..self.n_intermediates];
        match (intermediates.first(), b) {
            (None, b'm') => {
                // Only a sequence that began in this chunk is a range of it
                if self.start != usize::MAX {
                    out.sgr.push((self.start, at + 1));
                }
            }
            (None, b'r') => {
                let mut groups = self.groups();
                let top = groups.next().map_or(0, |g| g.0);
                let bottom = groups.next().map_or(0, |g| g.0);
                out.simple = false;
                out.actions
                    .push((at + 1, Action::ScrollRegion(top, bottom), out.line_feeds));
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
                out.actions.push((at + 1, Action::SoftReset, out.line_feeds));
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
                    out.actions.push((at + 1, action, out.line_feeds));
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
