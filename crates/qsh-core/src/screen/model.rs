//! The screen model on `vt100` (m2.md 6.2), with the [`Scanner`] beside it for what `vt100`
//! does not keep, and two things `vt100` lacks:
//!
//! - **DECSTR** (`CSI ! p`): emulated with sequences `vt100` knows (pen, cursor visibility,
//!   cursor keys, keypad, origin mode and scroll region of both screens, saved cursor), keeping
//!   the cursor where it was. Every snapshot starts with it.
//! - **Lazy feeding.** `vt100` scrolls a `Vec` of rows on every line feed, about 10 MB/s on
//!   `yes`. Output that is "simple" (text, line feeds, SGR, OSC: a flood of lines, a build
//!   log) on the normal screen without a scroll region is kept in `pending` instead, and only
//!   the end of it that can still be seen is ever fed: once `pending` holds more than
//!   2 × rows + 100 line feeds after a CR LF, everything before is dropped except its SGR
//!   sequences (the pen). That is exact: after that many line feeds from column 0, every row
//!   on the screen and the last 100 rows of the scrollback were written by what was kept, and
//!   nothing else of what was dropped can be seen (the cursor column is 0 after CR LF, the
//!   pen is replayed, the scanner keeps titles and modes). The property test in `tests.rs`
//!   compares lazy and direct feeding.

use super::scan::{Action, Scanned, Scanner};
use super::snapshot::{Capture, Cell, Color, Grid, Intensity, Line, Modes, Mouse, MouseEncoding, Pen};
use super::{Model, SNAPSHOT_TAIL_LINES};

/// The most output kept for lazy feeding: beyond, it is fed.
const PENDING_MAX: usize = 256 * 1024;

/// A screen model on the `vt100` crate.
pub struct Vt100Model {
    parser: vt100::Parser,
    scan: Scanner,
    scanned: Scanned,
    cols: u16,
    rows: u16,
    /// The scroll regions of the normal and alternate screens as `vt100` keeps them, (top,
    /// bottom) from 0 (its own are private).
    regions: [(u16, u16); 2],
    pending: Pending,
    /// Keep simple output for later (always, except to test that it changes nothing).
    lazy: bool,
    /// The start of a multi-byte character at the end of the last chunk, held back: `vte`
    /// 0.15.0 drops the character that follows one split across two calls (its
    /// `advance_partial_utf8` counts the following bytes as used).
    carry: Vec<u8>,
    /// A resize to apply once the parser is between two sequences.
    pending_resize: Option<(u16, u16)>,
}

impl std::fmt::Debug for Vt100Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vt100Model")
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("pending", &self.pending.bytes.len())
            .finish()
    }
}

/// Simple output not fed to `vt100` yet.
#[derive(Debug, Default)]
struct Pending {
    bytes: Vec<u8>,
    /// Indexes just after each CR LF in the ground state.
    cuts: Vec<usize>,
    /// The SGR sequences.
    sgr: Vec<(usize, usize)>,
}

impl Vt100Model {
    /// An empty `cols` × `rows` screen.
    pub fn new(cols: u16, rows: u16) -> Vt100Model {
        let (cols, rows) = (cols.max(1), rows.max(1));
        Vt100Model {
            parser: vt100::Parser::new(rows, cols, SNAPSHOT_TAIL_LINES),
            scan: Scanner::default(),
            scanned: Scanned::default(),
            cols,
            rows,
            regions: [(0, rows - 1); 2],
            pending: Pending::default(),
            lazy: true,
            carry: Vec::new(),
            pending_resize: None,
        }
    }

    /// Output kept for lazy feeding.
    #[cfg(test)]
    pub(super) fn pending_len(&self) -> usize {
        self.pending.bytes.len()
    }

    /// Feed everything at once instead of lazily (module documentation): for the tests and the
    /// fuzz target, which compare both.
    pub fn set_lazy(&mut self, lazy: bool) {
        self.flush();
        self.lazy = lazy;
    }

    /// Line feeds kept in `pending` beyond which the rest can be dropped.
    fn keep(&self) -> usize {
        2 * usize::from(self.rows) + SNAPSHOT_TAIL_LINES
    }

    fn alternate_active(&self) -> bool {
        self.parser.screen().alternate_screen()
    }

    fn full(&self) -> (u16, u16) {
        (0, self.rows - 1)
    }

    /// Drop what `pending` holds before the last [`Vt100Model::keep`] line feeds, feeding
    /// only its SGR sequences.
    fn trim(&mut self) {
        let keep = self.keep();
        let p = &mut self.pending;
        if p.cuts.len() <= keep {
            return;
        }
        let cut = p.cuts[p.cuts.len() - 1 - keep];
        let mut pen = Vec::new();
        for &(start, end) in p.sgr.iter().take_while(|r| r.1 <= cut) {
            pen.extend_from_slice(&p.bytes[start..end]);
        }
        if !pen.is_empty() {
            self.parser.process(&pen);
        }
        p.bytes.drain(..cut);
        p.cuts.retain(|&c| c > cut);
        p.cuts.iter_mut().for_each(|c| *c -= cut);
        p.sgr.retain(|r| r.0 >= cut);
        p.sgr.iter_mut().for_each(|r| {
            r.0 -= cut;
            r.1 -= cut;
        });
    }

    /// Feed `pending` to `vt100`.
    fn flush(&mut self) {
        if self.pending.bytes.is_empty() {
            return;
        }
        self.trim();
        let mut bytes = std::mem::take(&mut self.pending.bytes);
        self.parser.process(&bytes);
        bytes.clear();
        self.pending = Pending {
            bytes,
            ..Pending::default()
        };
    }

    /// The scroll region rule of `vt100` (`Grid::set_scroll_region`) for parameters as
    /// written.
    fn set_region(&mut self, top: u16, bottom: u16) {
        let top = top.max(1) - 1;
        let bottom = if bottom == 0 { self.rows } else { bottom } - 1;
        let bottom = bottom.min(self.rows - 1);
        let grid = usize::from(self.alternate_active());
        self.regions[grid] = if top < bottom { (top, bottom) } else { self.full() };
    }

    /// DECSTR (`CSI ! p`), which `vt100` does not implement, with what it knows: the pen,
    /// cursor visibility, cursor keys, keypad, and origin mode, scroll region and saved cursor
    /// of the active screen (and origin mode and scroll region of the normal screen too,
    /// since `vt100` keeps them per screen and a terminal keeps one), the cursor staying where
    /// it was.
    fn soft_reset(&mut self) {
        let (row, col) = self.parser.screen().cursor_position();
        self.parser.process(b"\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b[?6l\x1b[r\x1b7");
        self.parser.process(cup(row, col.min(self.cols - 1)).as_bytes());
        if self.alternate_active() {
            self.regions[1] = self.full();
            self.parser.process(b"\x1b[?47l");
            let (row, col) = self.parser.screen().cursor_position();
            // Its saved cursor too: leaving the alternate screen with 1049 restores it, and
            // with it origin mode
            self.parser.process(b"\x1b[?6l\x1b[r\x1b7");
            self.parser.process(cup(row, col.min(self.cols - 1)).as_bytes());
            self.parser.process(b"\x1b[?47h");
        }
        self.regions[0] = self.full();
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::SoftReset => self.soft_reset(),
            Action::ScrollRegion(top, bottom) => self.set_region(top, bottom),
            Action::EnterAlternate => self.regions[1] = self.full(),
            Action::FullReset => self.regions = [self.full(); 2],
            Action::Switch => {}
        }
    }
}

/// vt100's `Grid::set_size` for a scroll region.
fn resized_region(region: (u16, u16), old_rows: u16, rows: u16) -> (u16, u16) {
    let (mut top, mut bottom) = region;
    if bottom == old_rows - 1 {
        bottom = rows - 1;
    }
    if bottom >= rows {
        bottom = rows - 1;
    }
    if bottom < top {
        top = 0;
    }
    (top, bottom)
}

/// A line cut or extended to `cols` cells; a wide character that no longer fits is dropped.
fn cut_line(line: &mut Line, cols: u16) {
    let cols = usize::from(cols);
    if line.cells.len() != cols {
        line.wrapped = false;
    }
    line.cells.resize(cols, Cell::default());
    if let Some(last) = line.cells.last_mut() {
        if last.wide {
            *last = Cell {
                pen: last.pen,
                ..Cell::default()
            };
        }
    }
}

fn cup(row: u16, col: u16) -> String {
    format!("\x1b[{};{}H", u32::from(row) + 1, u32::from(col) + 1)
}

fn color(c: vt100::Color) -> Color {
    match c {
        vt100::Color::Default => Color::Default,
        vt100::Color::Idx(n) => Color::Index(n),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

fn cell_pen(cell: &vt100::Cell) -> Pen {
    Pen {
        fg: color(cell.fgcolor()),
        bg: color(cell.bgcolor()),
        intensity: if cell.bold() {
            Intensity::Bold
        } else if cell.dim() {
            Intensity::Faint
        } else {
            Intensity::Normal
        },
        italic: cell.italic(),
        underline: cell.underline(),
        inverse: cell.inverse(),
        ..Pen::default()
    }
}

/// Row `row` of what `screen` shows.
fn line(screen: &vt100::Screen, row: u16, cols: u16) -> Line {
    let cells = (0..cols)
        .map(|col| match screen.cell(row, col) {
            Some(cell) => Cell {
                text: cell.contents().to_string(),
                pen: cell_pen(cell),
                wide: cell.is_wide(),
                continuation: cell.is_wide_continuation(),
            },
            None => Cell::default(),
        })
        .collect();
    Line {
        cells,
        wrapped: screen.row_wrapped(row),
    }
}

fn grid(screen: &vt100::Screen, cols: u16, rows: u16) -> Grid {
    let (row, col) = screen.cursor_position();
    Grid {
        lines: (0..rows).map(|r| line(screen, r, cols)).collect(),
        cursor: (row.min(rows - 1), col),
    }
}

/// The length of an unfinished UTF-8 character at the end of `data` (0 if none).
fn unfinished_utf8(data: &[u8]) -> usize {
    for back in 1..=data.len().min(3) {
        let b = data[data.len() - back];
        if (0x80..0xc0).contains(&b) {
            continue;
        }
        let needs = match b {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return 0,
        };
        return if back < needs { back } else { 0 };
    }
    0
}

impl Model for Vt100Model {
    fn feed(&mut self, bytes: &[u8]) -> u64 {
        let joined;
        let data = if self.carry.is_empty() {
            bytes
        } else {
            let mut j = std::mem::take(&mut self.carry);
            j.extend_from_slice(bytes);
            joined = j;
            &joined[..]
        };
        let (now, later) = data.split_at(data.len() - unfinished_utf8(data));
        self.carry = later.to_vec();
        self.feed_whole(now)
    }

    fn held(&self) -> usize {
        self.carry.len()
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.resize_to(cols, rows)
    }

    fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    fn alternate(&self) -> bool {
        self.alternate_active()
    }

    fn capture(&mut self, tail: usize) -> Capture {
        self.capture_now(tail)
    }
}

impl Vt100Model {
    /// Feed bytes that end on a character boundary.
    fn feed_whole(&mut self, bytes: &[u8]) -> u64 {
        if let Some((cols, rows)) = self.pending_resize {
            if self.scan.at_rest() {
                self.resize_to(cols, rows);
            }
        }
        let at_rest = self.scan.at_rest();
        let mut scanned = std::mem::take(&mut self.scanned);
        self.scan.scan(bytes, &mut scanned);
        let normal = !self.alternate_active() && self.regions[0] == self.full();
        let line_feeds = if self.lazy && scanned.simple && at_rest && normal {
            // Kept for later: only its end will be fed (module documentation)
            let base = self.pending.bytes.len();
            self.pending.bytes.extend_from_slice(bytes);
            self.pending.cuts.extend(scanned.cuts.iter().map(|c| c + base));
            self.pending
                .sgr
                .extend(scanned.sgr.iter().map(|&(s, e)| (s + base, e + base)));
            if self.pending.cuts.len() > 2 * self.keep() {
                self.trim();
            }
            // Output without line ends (a progress bar redrawn with CR) cannot be trimmed
            if self.pending.bytes.len() > PENDING_MAX {
                self.flush();
            }
            scanned.line_feeds
        } else {
            self.flush();
            let mut at = 0;
            let mut counted = 0;
            let mut normal_feeds = 0;
            // Line feeds count when they ran on the normal screen; a switch of screens always
            // ends a segment, so the screen before a segment is the one it ran on
            for &(end, action, feeds) in &scanned.actions {
                let on_normal = !self.alternate_active();
                self.parser.process(&bytes[at..end]);
                if on_normal {
                    normal_feeds += feeds - counted;
                }
                counted = feeds;
                self.act(action);
                at = end;
            }
            let on_normal = !self.alternate_active();
            self.parser.process(&bytes[at..]);
            if on_normal {
                normal_feeds += scanned.line_feeds - counted;
            }
            normal_feeds
        };
        self.scanned = scanned;
        line_feeds
    }

    fn resize_to(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = (cols.max(1), rows.max(1));
        self.pending_resize = None;
        if (cols, rows) == (self.cols, self.rows) {
            return;
        }
        self.flush();
        if cols < self.cols {
            // vt100's set_size can leave a wide character in the last column of a row (or of
            // its other screen), and the next character written over it panics (an index past
            // the row): rebuild the model at the new size from a snapshot instead, between
            // two sequences
            if self.scan.at_rest() {
                self.rebuild(cols, rows);
            } else {
                self.pending_resize = Some((cols, rows));
            }
            return;
        }
        self.parser.screen_mut().set_size(rows, cols);
        // vt100's Grid::set_size, for both screens
        let old = self.rows;
        for region in self.regions.iter_mut() {
            *region = resized_region(*region, old, rows);
        }
        self.cols = cols;
        self.rows = rows;
    }

    /// A new model at `cols` × `rows` showing what this one shows, cut as `vt100` would
    /// (rows kept from the top, cells from the left, wrap flags dropped), the tail of the
    /// scrollback kept.
    fn rebuild(&mut self, cols: u16, rows: u16) {
        let mut capture = self.capture_now(SNAPSHOT_TAIL_LINES);
        let old_rows = capture.rows;
        let cut_grid = |g: &mut Grid| {
            g.lines.truncate(usize::from(rows));
            while g.lines.len() < usize::from(rows) {
                g.lines.push(Line {
                    cells: vec![Cell::default(); usize::from(cols)],
                    wrapped: false,
                });
            }
            for line in g.lines.iter_mut() {
                cut_line(line, cols);
            }
            g.cursor = (g.cursor.0.min(rows - 1), g.cursor.1.min(cols - 1));
        };
        cut_grid(&mut capture.normal);
        if let Some(a) = capture.alternate.as_mut() {
            cut_grid(a);
        }
        for line in capture.tail.iter_mut() {
            cut_line(line, cols);
        }
        capture.region = capture
            .region
            .map(|r| resized_region(r, old_rows, rows))
            .filter(|r| *r != (0, rows - 1));
        capture.cols = cols;
        capture.rows = rows;
        let skip = capture.alternate.is_none() && !capture.tail.is_empty();
        let data = super::snapshot::encode(&capture, skip);
        let mut fresh = Vt100Model::new(cols, rows);
        fresh.lazy = false;
        fresh.feed_whole(&data);
        fresh.scan.redraw = self.scan.redraw;
        fresh.lazy = self.lazy;
        fresh.carry = std::mem::take(&mut self.carry);
        *self = fresh;
    }

    fn capture_now(&mut self, tail: usize) -> Capture {
        self.flush();
        let (cols, rows) = (self.cols, self.rows);
        let alternate = self.alternate_active();
        let screen = self.parser.screen();
        let active = grid(screen, cols, rows);
        let (normal, alternate_grid) = if alternate {
            // The normal screen as the program finds it when it leaves the alternate screen
            // (1049 restores the cursor saved when it entered)
            let mut leave = vt100::Parser::new(rows, cols, 0);
            *leave.screen_mut() = screen.clone();
            leave.process(b"\x1b[?1049l");
            (grid(leave.screen(), cols, rows), Some(active))
        } else {
            (active, None)
        };
        let pen = Pen {
            fg: color(screen.fgcolor()),
            bg: color(screen.bgcolor()),
            intensity: if screen.bold() {
                Intensity::Bold
            } else if screen.dim() {
                Intensity::Faint
            } else {
                Intensity::Normal
            },
            italic: screen.italic(),
            underline: screen.underline(),
            inverse: screen.inverse(),
            ..Pen::default()
        };
        let modes = Modes {
            app_cursor: screen.application_cursor(),
            app_keypad: screen.application_keypad(),
            hidden_cursor: screen.hide_cursor(),
            bracketed_paste: screen.bracketed_paste(),
            mouse: match screen.mouse_protocol_mode() {
                vt100::MouseProtocolMode::None => Mouse::Off,
                vt100::MouseProtocolMode::Press => Mouse::Press,
                vt100::MouseProtocolMode::PressRelease => Mouse::PressRelease,
                vt100::MouseProtocolMode::ButtonMotion => Mouse::ButtonMotion,
                vt100::MouseProtocolMode::AnyMotion => Mouse::AnyMotion,
            },
            mouse_encoding: match screen.mouse_protocol_encoding() {
                vt100::MouseProtocolEncoding::Default => MouseEncoding::Default,
                vt100::MouseProtocolEncoding::Utf8 => MouseEncoding::Utf8,
                vt100::MouseProtocolEncoding::Sgr => MouseEncoding::Sgr,
            },
            urxvt_mouse: self.scan.urxvt,
            focus: self.scan.focus,
        };
        let region = self.regions[usize::from(alternate)];
        let region = (region != self.full()).then_some(region);
        // The tail: the newest lines of the normal screen's scrollback
        let mut lines = Vec::new();
        if !alternate && tail > 0 {
            let screen = self.parser.screen_mut();
            screen.set_scrollback(usize::MAX);
            let available = screen.scrollback();
            let want = tail.min(available).min(SNAPSHOT_TAIL_LINES);
            // With the view `k` lines up, its first row is the k-th newest scrollback line
            let mut k = want;
            while k > 0 {
                screen.set_scrollback(k);
                let n = k.min(usize::from(rows));
                for r in 0..n {
                    lines.push(line(screen, r as u16, cols));
                }
                k -= n;
            }
            screen.set_scrollback(0);
        }
        Capture {
            cols,
            rows,
            normal,
            alternate: alternate_grid,
            tail: lines,
            pen,
            modes,
            region,
            title: self.scan.title.clone(),
            icon: self.scan.icon.clone(),
            cursor_style: self.scan.cursor_style,
            redraw: self.scan.redraw,
        }
    }
}
