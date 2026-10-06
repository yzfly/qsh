//! Snapshots (protocol.md 7.8.4): a [`Capture`] of a screen model, its encoding as terminal
//! bytes that follow the content profile exactly, and an independent check of that profile.
//!
//! The encoder works on the capture only, never on the program's output: nothing a program
//! writes can reach a snapshot except as cell contents, the window title and icon name, all
//! of them filtered to printable characters.

use std::fmt::Write as _;

/// A color as the model keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    /// The terminal's default.
    #[default]
    Default,
    /// One of the 256 indexed colors (0 to 15: the 16 basic ones).
    Index(u8),
    /// 24-bit.
    Rgb(u8, u8, u8),
}

/// Bold, faint or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Intensity {
    /// Normal.
    #[default]
    Normal,
    /// SGR 1.
    Bold,
    /// SGR 2.
    Faint,
}

/// SGR attributes of a cell, or the current pen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pen {
    /// Foreground.
    pub fg: Color,
    /// Background.
    pub bg: Color,
    /// Bold or faint.
    pub intensity: Intensity,
    /// SGR 3.
    pub italic: bool,
    /// SGR 4.
    pub underline: bool,
    /// SGR 5.
    pub blink: bool,
    /// SGR 7.
    pub inverse: bool,
    /// SGR 8.
    pub invisible: bool,
    /// SGR 9.
    pub strike: bool,
}

impl Pen {
    fn is_default(&self) -> bool {
        *self == Pen::default()
    }
}

/// One cell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cell {
    /// The character with its combining characters; empty for a blank cell.
    pub text: String,
    /// Its attributes.
    pub pen: Pen,
    /// A wide character, which takes this cell and the next.
    pub wide: bool,
    /// The second half of a wide character.
    pub continuation: bool,
}

impl Cell {
    /// Blank, with default attributes: what EL leaves.
    fn is_empty(&self) -> bool {
        (self.text.is_empty() || self.text == " ") && self.pen.is_default() && !self.continuation
    }
}

/// One row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Line {
    /// Exactly `columns` cells.
    pub cells: Vec<Cell>,
    /// The text continues on the next row (automatic wrap).
    pub wrapped: bool,
}

/// One screen buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grid {
    /// Exactly `rows` rows.
    pub lines: Vec<Line>,
    /// The cursor, (row, column) from 0.
    pub cursor: (u16, u16),
}

/// Mouse tracking (modes 9, 1000, 1002, 1003; at most one is on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mouse {
    /// Off.
    #[default]
    Off,
    /// 9: X10, presses.
    Press,
    /// 1000: presses and releases.
    PressRelease,
    /// 1002: and motion with a button down.
    ButtonMotion,
    /// 1003: and all motion.
    AnyMotion,
}

/// The mouse encoding of modes 1005 and 1006 (at most one is on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MouseEncoding {
    /// Neither.
    #[default]
    Default,
    /// 1005.
    Utf8,
    /// 1006.
    Sgr,
}

/// The modes a snapshot restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modes {
    /// Mode 1: application cursor keys.
    pub app_cursor: bool,
    /// DECKPAM: application keypad.
    pub app_keypad: bool,
    /// Mode 25 reset.
    pub hidden_cursor: bool,
    /// Mode 2004.
    pub bracketed_paste: bool,
    /// Modes 9, 1000, 1002, 1003.
    pub mouse: Mouse,
    /// Modes 1005, 1006.
    pub mouse_encoding: MouseEncoding,
    /// Mode 1015.
    pub urxvt_mouse: bool,
    /// Mode 1004.
    pub focus: bool,
}

/// Everything a snapshot reproduces (protocol.md 7.8.4), taken from a model at one offset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capture {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// The normal screen; while the alternate screen is active, as the program finds it when
    /// it leaves the alternate screen (its cursor restored).
    pub normal: Grid,
    /// The alternate screen, when it is the active one.
    pub alternate: Option<Grid>,
    /// Lines that scrolled off the top of the normal screen, oldest first, at most
    /// [`super::SNAPSHOT_TAIL_LINES`]: the tail of a skip snapshot.
    pub tail: Vec<Line>,
    /// The current SGR pen.
    pub pen: Pen,
    /// The modes.
    pub modes: Modes,
    /// The active screen's scroll region, (top, bottom) from 0, when it is not the whole
    /// screen.
    pub region: Option<(u16, u16)>,
    /// The window title.
    pub title: String,
    /// The icon name.
    pub icon: String,
    /// DECSCUSR, 0 (the terminal's default) to 6.
    pub cursor_style: u8,
    /// The program used origin mode or a non-ASCII character set since the screen was last
    /// cleared: what the snapshot cannot express; it should redraw.
    pub redraw: bool,
}

/// The longest title or icon name a snapshot carries, in bytes.
pub const MAX_TITLE: usize = 256;

fn csi(out: &mut Vec<u8>, body: &str) {
    out.extend_from_slice(b"\x1b[");
    out.extend_from_slice(body.as_bytes());
}

fn cup(out: &mut Vec<u8>, row: u16, col: u16) {
    csi(out, &format!("{};{}H", u32::from(row) + 1, u32::from(col) + 1));
}

fn color_params(color: Color, background: bool, params: &mut Vec<String>) {
    let base = if background { 40 } else { 30 };
    match color {
        Color::Default => params.push((base + 9).to_string()),
        Color::Index(n) if n < 8 => params.push((base + u32::from(n)).to_string()),
        Color::Index(n) if n < 16 => params.push((base + 60 + u32::from(n) - 8).to_string()),
        Color::Index(n) => params.push(format!("{};5;{n}", base + 8)),
        Color::Rgb(r, g, b) => params.push(format!("{};2;{r};{g};{b}", base + 8)),
    }
}

/// The SGR sequence that changes the pen `from` into `to` (nothing when they are equal).
fn sgr(out: &mut Vec<u8>, from: &Pen, to: &Pen) {
    if from == to {
        return;
    }
    if to.is_default() {
        csi(out, "m");
        return;
    }
    let mut params = Vec::new();
    if from.intensity != to.intensity {
        if from.intensity != Intensity::Normal {
            params.push("22".to_string());
        }
        match to.intensity {
            Intensity::Bold => params.push("1".to_string()),
            Intensity::Faint => params.push("2".to_string()),
            Intensity::Normal => {}
        }
    }
    for (was, now, on, off) in [
        (from.italic, to.italic, "3", "23"),
        (from.underline, to.underline, "4", "24"),
        (from.blink, to.blink, "5", "25"),
        (from.inverse, to.inverse, "7", "27"),
        (from.invisible, to.invisible, "8", "28"),
        (from.strike, to.strike, "9", "29"),
    ] {
        if was != now {
            params.push(if now { on } else { off }.to_string());
        }
    }
    if from.fg != to.fg {
        color_params(to.fg, false, &mut params);
    }
    if from.bg != to.bg {
        color_params(to.bg, true, &mut params);
    }
    csi(out, &format!("{}m", params.join(";")));
}

/// Printable characters only (no C0, DEL or C1), at most `max` bytes, cut at a character.
fn printable(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// Write the cells of `line`, from a default pen, ending with a default pen.
///
/// - `wraps`: the row wraps into the next: every cell up to the last column, so that the
///   terminal's own wrap joins them. Otherwise up to the last cell that is not empty, then EL
///   when the rest of the row is empty.
/// - `after_wrap`: the previous row wraps into this one: at least one character is written
///   (the terminal wraps only when one is; EL at the pending wrap would erase the previous
///   row's last column).
/// - `fresh`: a line scrolled in for the tail, blank already: no EL.
///
/// A row written to its last column that does not wrap is erased first, which also clears a
/// wrap flag the terminal may have from before (right after the cursor is placed; after the
/// first character when the previous row wraps into it).
fn row(out: &mut Vec<u8>, line: &Line, wraps: bool, after_wrap: bool, fresh: bool) {
    let cols = line.cells.len();
    let end = if wraps {
        cols
    } else {
        let used = line.cells.iter().rposition(|c| !c.is_empty()).map_or(0, |i| i + 1);
        used.max(usize::from(after_wrap)).min(cols)
    };
    let preclear = !fresh && !wraps && end == cols && cols > 0;
    if preclear && !after_wrap {
        csi(out, "K");
    }
    let mut pen = Pen::default();
    let mut col = 0;
    while col < end {
        let cell = &line.cells[col];
        if cell.pen != pen {
            sgr(out, &pen, &cell.pen);
            pen = cell.pen;
        }
        let text = printable(&cell.text, 64);
        let fits = cell.wide && col + 1 < cols && line.cells[col + 1].continuation;
        if cell.continuation || text.is_empty() || (cell.wide && !fits) {
            // Blank, a stray half of a wide character, or a wide one that cannot fit: a space
            out.push(b' ');
            col += 1;
        } else {
            out.extend_from_slice(text.as_bytes());
            col += if fits { 2 } else { 1 };
        }
        if preclear && after_wrap && col < cols && (col == 1 || col == 2 && fits) {
            if !pen.is_default() {
                csi(out, "m");
                pen = Pen::default();
            }
            csi(out, "K");
        }
    }
    if !pen.is_default() {
        csi(out, "m");
    }
    if !fresh && !wraps && end < cols {
        csi(out, "K");
    }
}

fn screen(out: &mut Vec<u8>, grid: &Grid) {
    let rows = grid.lines.len();
    let mut wraps_into = false;
    for (r, line) in grid.lines.iter().enumerate() {
        if !wraps_into {
            cup(out, r as u16, 0);
        }
        // The last row cannot wrap
        let wraps = line.wrapped && r + 1 < rows;
        row(out, line, wraps, wraps_into, false);
        wraps_into = wraps;
    }
}

/// Encode `capture` as snapshot data (protocol.md 7.8.4). A skip snapshot (`skip`) of the
/// normal screen first pushes the terminal's screen and the tail into its scrollback; a resync
/// snapshot, or one of the alternate screen, does not.
pub fn encode(capture: &Capture, skip: bool) -> Vec<u8> {
    let mut out = Vec::new();
    csi(&mut out, "!p");
    csi(&mut out, "?1049l");
    let rows = capture.normal.lines.len();
    if skip && capture.alternate.is_none() {
        // The scroll-push: only scrolling, which every terminal keeps in its scrollback
        cup(&mut out, rows.max(1) as u16 - 1, 0);
        out.extend_from_slice(b"\r\n");
        for line in &capture.tail {
            row(&mut out, line, false, false, true);
            csi(&mut out, "m");
            out.extend_from_slice(b"\r\n");
        }
        for _ in 1..rows {
            out.extend_from_slice(b"\r\n");
        }
    }
    screen(&mut out, &capture.normal);
    if let Some(alternate) = &capture.alternate {
        cup(
            &mut out,
            capture.normal.cursor.0,
            clamp(capture.normal.cursor.1, capture.cols),
        );
        csi(&mut out, "?1049h");
        screen(&mut out, alternate);
    }
    // A region of one row (a terminal shrunk below it) cannot be set again
    if let Some((top, bottom)) = capture.region.filter(|r| r.0 < r.1) {
        csi(&mut out, &format!("{};{}r", u32::from(top) + 1, u32::from(bottom) + 1));
    }
    let m = &capture.modes;
    let mut set: Vec<u16> = Vec::new();
    let mut reset: Vec<u16> = Vec::new();
    if m.app_cursor {
        set.push(1);
    }
    for (mode, on) in [
        (9, m.mouse == Mouse::Press),
        (1000, m.mouse == Mouse::PressRelease),
        (1002, m.mouse == Mouse::ButtonMotion),
        (1003, m.mouse == Mouse::AnyMotion),
        (1004, m.focus),
        (1005, m.mouse_encoding == MouseEncoding::Utf8),
        (1006, m.mouse_encoding == MouseEncoding::Sgr),
        (1015, m.urxvt_mouse),
        (2004, m.bracketed_paste),
    ] {
        if on {
            set.push(mode);
        } else {
            reset.push(mode);
        }
    }
    let list = |modes: &[u16]| modes.iter().map(|m| m.to_string()).collect::<Vec<_>>().join(";");
    if !reset.is_empty() {
        csi(&mut out, &format!("?{}l", list(&reset)));
    }
    if !set.is_empty() {
        csi(&mut out, &format!("?{}h", list(&set)));
    }
    if m.app_keypad {
        out.extend_from_slice(b"\x1b=");
    }
    let title = printable(&capture.title, MAX_TITLE);
    if !title.is_empty() {
        out.extend_from_slice(format!("\x1b]2;{title}\x1b\\").as_bytes());
    }
    let icon = printable(&capture.icon, MAX_TITLE);
    if !icon.is_empty() {
        out.extend_from_slice(format!("\x1b]1;{icon}\x1b\\").as_bytes());
    }
    if (1..=6).contains(&capture.cursor_style) {
        csi(&mut out, &format!("{} q", capture.cursor_style));
    }
    sgr(&mut out, &Pen::default(), &capture.pen);
    let active = capture.alternate.as_ref().unwrap_or(&capture.normal);
    cup(&mut out, active.cursor.0, clamp(active.cursor.1, capture.cols));
    if m.hidden_cursor {
        csi(&mut out, "?25l");
    }
    out
}

/// A cursor column within the screen (a pending wrap is not reproduced).
fn clamp(col: u16, cols: u16) -> u16 {
    col.min(cols.saturating_sub(1))
}

/// Why data does not follow the content profile of protocol.md 7.8.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot outside the content profile: {}", self.0)
    }
}

impl std::error::Error for ProfileError {}

fn bad<T>(why: impl Into<String>) -> Result<T, ProfileError> {
    Err(ProfileError(why.into()))
}

/// Check that `data` (a whole snapshot, decompressed and concatenated) consists only of what
/// the content profile of protocol.md 7.8.4 allows: printable UTF-8, CR LF, and the listed
/// sequences with decimal parameters; and that it starts with DECSTR. Independent of the
/// encoder: a client may run it before writing a snapshot (7.8.4, client processing), and the
/// tests and the fuzz target run it on everything the encoder makes.
pub fn check_profile(data: &[u8]) -> Result<(), ProfileError> {
    let Ok(text) = std::str::from_utf8(data) else {
        return bad("invalid UTF-8");
    };
    if !text.starts_with("\x1b[!p") {
        return bad("does not start with DECSTR");
    }
    // EL is allowed with the default pen only
    let mut pen_default = true;
    let mut i = 0;
    while let Some(c) = text[i..].chars().next() {
        i += c.len_utf8();
        match c {
            '\r' => {
                if !text[i..].starts_with('\n') {
                    return bad("CR without LF");
                }
                i += 1;
            }
            '\x1b' => i += escape(&text[i..], &mut pen_default)?,
            c if c.is_control() => return bad(format!("control character {:#x}", c as u32)),
            _ => {}
        }
    }
    Ok(())
}

/// Parameters: decimal numbers separated by `;`, each present.
fn numbers(params: &str) -> Result<Vec<u32>, ProfileError> {
    if params.is_empty() {
        return Ok(Vec::new());
    }
    params
        .split(';')
        .map(|p| {
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
                bad(format!("parameter {p:?}"))
            } else {
                Ok(p.parse().expect("digits"))
            }
        })
        .collect()
}

/// One escape sequence at the start of `rest` (after ESC): the bytes it uses.
fn escape(rest: &str, pen_default: &mut bool) -> Result<usize, ProfileError> {
    let bytes = rest.as_bytes();
    match bytes.first() {
        Some(b'=') | Some(b'>') => Ok(1),
        Some(b']') => {
            // OSC 1 or 2 ; text ST
            let Some(kind) = bytes.get(1).filter(|k| matches!(k, b'1' | b'2')) else {
                return bad("OSC other than 1 and 2");
            };
            let _ = kind;
            if bytes.get(2) != Some(&b';') {
                return bad("OSC without its text");
            }
            let Some(end) = rest[3..].find('\x1b') else {
                return bad("OSC without ST");
            };
            let title = &rest[3..3 + end];
            if title.len() > MAX_TITLE || title.chars().any(|c| c.is_control()) {
                return bad("title too long or not printable");
            }
            if bytes.get(3 + end + 1) != Some(&b'\\') {
                return bad("OSC not ended by ST");
            }
            Ok(3 + end + 2)
        }
        Some(b'[') => {
            let body = &rest[1..];
            let Some(end) = body.find(|c: char| ('\x40'..='\x7e').contains(&c)) else {
                return bad("CSI without its final byte");
            };
            let (params, last) = (&body[..end], body.as_bytes()[end]);
            let used = 1 + end + 1;
            match (params, last) {
                ("!", b'p') => {
                    *pen_default = true;
                    Ok(used)
                }
                ("?1049", b'h' | b'l') => Ok(used),
                (p, b'h' | b'l') if p.starts_with('?') => {
                    let modes = numbers(&p[1..])?;
                    if modes.is_empty()
                        || modes
                            .iter()
                            .any(|m| ![1, 9, 25, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 2004].contains(m))
                    {
                        return bad(format!("private modes {p:?}"));
                    }
                    Ok(used)
                }
                (p, b'H') => match numbers(p)?.as_slice() {
                    [r, c] if *r > 0 && *c > 0 => Ok(used),
                    _ => bad("CUP without row and column"),
                },
                ("", b'K') => {
                    if !*pen_default {
                        return bad("EL with a pen other than the default");
                    }
                    Ok(used)
                }
                (p, b'r') => match numbers(p)?.as_slice() {
                    [t, b] if *t > 0 && t < b => Ok(used),
                    _ => bad("DECSTBM without top and bottom"),
                },
                (p, b'q') => {
                    let Some(style) = p.strip_suffix(' ') else {
                        return bad("CSI q without SP");
                    };
                    match numbers(style)?.as_slice() {
                        [s] if *s <= 6 => Ok(used),
                        _ => bad("DECSCUSR style"),
                    }
                }
                (p, b'm') => {
                    let params = numbers(p)?;
                    *pen_default = sgr_allowed(&params)?;
                    Ok(used)
                }
                _ => bad(format!("CSI {params:?} {}", last as char)),
            }
        }
        _ => bad("escape sequence outside the profile"),
    }
}

/// Whether an SGR parameter list is allowed; Ok(true) when it leaves the default pen.
fn sgr_allowed(params: &[u32]) -> Result<bool, ProfileError> {
    if params.is_empty() || params == [0] {
        return Ok(true);
    }
    let mut i = 0;
    let mut reset = false;
    while i < params.len() {
        match params[i] {
            0 => reset = true,
            1..=5 | 7..=9 | 22..=25 | 27..=29 | 30..=37 | 39 | 40..=47 | 49 | 90..=97 | 100..=107 => reset = false,
            38 | 48 => {
                reset = false;
                match params.get(i + 1) {
                    Some(5) if params.get(i + 2).is_some_and(|n| *n <= 255) => i += 2,
                    Some(2) if params.get(i + 2..i + 5).is_some_and(|c| c.iter().all(|n| *n <= 255)) => i += 4,
                    _ => return bad("extended color"),
                }
            }
            n => return bad(format!("SGR {n}")),
        }
        i += 1;
    }
    Ok(reset)
}

/// Whether `reproduced` (a model fed the snapshot of `original`, after anything) shows what
/// `original` shows, on everything the content profile carries (protocol.md 7.8.4): the round
/// trip of m2.md 12.1. Blank cells written as spaces, a cursor at a pending wrap, the wrap flag
/// of the last row, and the title, icon name and cursor style when the original had none (a
/// snapshot leaves the terminal's own) are not differences; the tail counts only for a skip
/// snapshot of the normal screen. For the tests and the fuzz target.
pub fn equivalent(original: &Capture, reproduced: &Capture, skip: bool) -> Result<(), String> {
    let mut expected = normalized(original.clone(), original);
    let mut got = normalized(reproduced.clone(), original);
    if !(skip && expected.alternate.is_none()) {
        expected.tail.clear();
        got.tail.clear();
    }
    if expected == got {
        Ok(())
    } else {
        Err(differences(&expected, &got))
    }
}

/// A capture with what a snapshot cannot reproduce taken out, and equal things made equal:
/// blank cells written as spaces, a cursor at a pending wrap, the last row's wrap flag, titles
/// and the cursor style when the original had none (a snapshot leaves the terminal's).
fn normalized(mut c: Capture, original: &Capture) -> Capture {
    let fix = |g: &mut Grid, o: &Grid, cols: u16| {
        g.cursor.1 = g.cursor.1.min(cols.saturating_sub(1));
        let rows = g.lines.len();
        for r in 0..rows {
            fix_line(&mut g.lines[r]);
            if r + 1 == rows {
                g.lines[r].wrapped = false;
            }
            // A row of two columns filled by the wide character that the previous row's wrap
            // put there cannot be erased first: a stale wrap flag of the terminal survives
            if cols == 2
                && r > 0
                && o.lines.get(r - 1).is_some_and(|l| l.wrapped)
                && o.lines.get(r).and_then(|l| l.cells.first()).is_some_and(|c| c.wide)
            {
                g.lines[r].wrapped = o.lines[r].wrapped;
            }
        }
    };
    fix(&mut c.normal, &original.normal, c.cols);
    if let (Some(a), Some(o)) = (c.alternate.as_mut(), original.alternate.as_ref()) {
        fix(a, o, c.cols);
    }
    for line in c.tail.iter_mut() {
        fix_line(line);
        line.wrapped = false;
    }
    if original.title.is_empty() {
        c.title.clear();
    }
    if original.icon.is_empty() {
        c.icon.clear();
    }
    if original.cursor_style == 0 {
        c.cursor_style = 0;
    }
    c.title = printable(&c.title, MAX_TITLE);
    c.icon = printable(&c.icon, MAX_TITLE);
    c.redraw = false;
    c.region = c.region.filter(|r| r.0 < r.1);
    c
}

fn fix_line(line: &mut Line) {
    for cell in line.cells.iter_mut() {
        if cell.text == " " {
            cell.text.clear();
        }
    }
}

/// What differs between two captures, briefly.
fn differences(a: &Capture, b: &Capture) -> String {
    let mut out = Vec::new();
    let grids = |name: &str, x: &Grid, y: &Grid, out: &mut Vec<String>| {
        if x.cursor != y.cursor {
            out.push(format!("{name} cursor {:?} vs {:?}", x.cursor, y.cursor));
        }
        for (r, (l, m)) in x.lines.iter().zip(&y.lines).enumerate() {
            if l != m {
                let first = l.cells.iter().zip(&m.cells).position(|(c, d)| c != d);
                out.push(format!(
                    "{name} row {r}: wrapped {} vs {}; first cell {first:?}: {:?} vs {:?}\n  {:?}\n  {:?}",
                    l.wrapped,
                    m.wrapped,
                    first.map(|i| &l.cells[i]),
                    first.map(|i| &m.cells[i]),
                    plain(&Grid {
                        lines: vec![l.clone()],
                        cursor: (0, 0)
                    }),
                    plain(&Grid {
                        lines: vec![m.clone()],
                        cursor: (0, 0)
                    }),
                ));
                break;
            }
        }
    };
    grids("normal", &a.normal, &b.normal, &mut out);
    match (&a.alternate, &b.alternate) {
        (Some(x), Some(y)) => grids("alternate", x, y, &mut out),
        (x, y) if x.is_some() != y.is_some() => out.push(format!("alternate {} vs {}", x.is_some(), y.is_some())),
        _ => {}
    }
    if a.tail != b.tail {
        out.push(format!("tail {} vs {} lines", a.tail.len(), b.tail.len()));
    }
    for (name, x, y) in [
        ("pen", format!("{:?}", a.pen), format!("{:?}", b.pen)),
        ("modes", format!("{:?}", a.modes), format!("{:?}", b.modes)),
        ("region", format!("{:?}", a.region), format!("{:?}", b.region)),
        ("title", a.title.clone(), b.title.clone()),
        ("icon", a.icon.clone(), b.icon.clone()),
        ("style", a.cursor_style.to_string(), b.cursor_style.to_string()),
    ] {
        if x != y {
            out.push(format!("{name} {x} vs {y}"));
        }
    }
    out.join("\n")
}

/// Text of a capture for messages in tests: its rows as plain text.
pub fn plain(grid: &Grid) -> String {
    let mut s = String::new();
    for line in &grid.lines {
        for cell in &line.cells {
            if !cell.continuation {
                s.push_str(if cell.text.is_empty() { " " } else { &cell.text });
            }
        }
        let _ = writeln!(s);
    }
    s
}
