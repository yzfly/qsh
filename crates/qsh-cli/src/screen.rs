//! What qsh draws on the user's terminal besides the session's output: the notice shown while
//! the connection is lost.
//!
//! The notice must not corrupt what the remote program drew, so where it goes depends on the
//! screen the program uses, which [`AltScreen`] follows in the output:
//!
//! - **The alternate screen** (vim, less, htop, tmux: full-screen programs): the notice is an
//!   overlay on the bottom line, drawn with the cursor saved and restored (DECSC / DECRC, which
//!   also keep the colors), in reverse video, and redrawn with the time elapsed. When the
//!   connection is back the line is erased and the program is made to repaint the whole screen
//!   (a resize to one row less and back, which full-screen programs answer with a full redraw),
//!   so nothing of the notice remains.
//! - **The normal screen** (a shell, a command printing lines): one line of text, like ssh's
//!   own messages. It becomes part of the scrollback, where it is true, and there is nothing to
//!   clean up; overwriting a line there could not be undone, since a shell does not repaint.

/// Follows whether the output switched the terminal to its alternate screen: `CSI ? 1049 h`,
/// `CSI ? 1047 h` or `CSI ? 47 h` and their `l` counterparts, and a full reset (`ESC c`).
/// Sequences split across chunks are recognized.
#[derive(Debug, Default, Clone)]
pub struct AltScreen {
    active: bool,
    state: Scan,
    private: bool,
    params: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Scan {
    #[default]
    Ground,
    Escape,
    Csi,
}

/// Longest parameter string kept; longer ones are not screen switches.
const MAX_PARAMS: usize = 32;

impl AltScreen {
    /// True while the alternate screen is in use.
    pub fn active(&self) -> bool {
        self.active
    }

    /// Look at the next output bytes.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match self.state {
                Scan::Ground => {
                    if b == 0x1b {
                        self.state = Scan::Escape;
                    }
                }
                Scan::Escape => {
                    self.state = match b {
                        b'[' => {
                            self.private = false;
                            self.params.clear();
                            Scan::Csi
                        }
                        b'c' => {
                            // RIS, a full reset: back to the normal screen
                            self.active = false;
                            Scan::Ground
                        }
                        0x1b => Scan::Escape,
                        _ => Scan::Ground,
                    };
                }
                Scan::Csi => match b {
                    b'?' if self.params.is_empty() && !self.private => self.private = true,
                    b'0'..=b'9' | b';' => {
                        if self.params.len() < MAX_PARAMS {
                            self.params.push(b);
                        }
                    }
                    0x20..=0x2f | b'<' | b'=' | b'>' | b'?' | b':' => {}
                    0x40..=0x7e => {
                        if self.private && (b == b'h' || b == b'l') && self.params.len() < MAX_PARAMS {
                            let switches = self
                                .params
                                .split(|c| *c == b';')
                                .any(|p| matches!(p, b"1049" | b"1047" | b"47"));
                            if switches {
                                self.active = b == b'h';
                            }
                        }
                        self.state = Scan::Ground;
                    }
                    0x1b => self.state = Scan::Escape,
                    // A control character inside a sequence (allowed by ECMA-48) or garbage
                    _ => {}
                },
            }
        }
    }
}

/// Draw `text` on the bottom line of a `cols` × `rows` screen, keeping the cursor, its position
/// and the colors as they were.
pub fn overlay(text: &str, cols: u16, rows: u16) -> Vec<u8> {
    let width = usize::from(cols.max(2)) - 1;
    let text: String = text.chars().filter(|c| !c.is_control()).take(width).collect();
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1b7");
    out.extend_from_slice(format!("\x1b[{};1H\x1b[0;7m\x1b[2K {text}", rows.max(1)).as_bytes());
    out.extend_from_slice(b"\x1b[0m\x1b8");
    out
}

/// Erase what [`overlay`] drew, keeping the cursor and colors as they were.
pub fn clear_overlay(rows: u16) -> Vec<u8> {
    format!("\x1b7\x1b[{};1H\x1b[0m\x1b[2K\x1b8", rows.max(1)).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_alternate_screen() {
        let mut s = AltScreen::default();
        s.feed(b"plain \x1b[1mbold\x1b[0m");
        assert!(!s.active());
        s.feed(b"\x1b[?1049h");
        assert!(s.active());
        s.feed(b"\x1b[?1049l");
        assert!(!s.active());
        // Split across chunks, several parameters, the older modes
        s.feed(b"\x1b[?10");
        assert!(!s.active());
        s.feed(b"49;1h");
        assert!(s.active());
        s.feed(b"\x1b[?47l");
        assert!(!s.active());
        s.feed(b"\x1b[?1047h");
        assert!(s.active());
        // A full reset leaves it
        s.feed(b"\x1bc");
        assert!(!s.active());
        // Not private, other modes, other finals: no switch
        s.feed(b"\x1b[1049h\x1b[?25h\x1b[?1049m\x1b[?2004h");
        assert!(!s.active());
        // A long parameter string is not a switch, and does not grow without bound
        let mut long = b"\x1b[?".to_vec();
        long.extend(std::iter::repeat_n(b'1', 10_000));
        long.extend_from_slice(b";1049h");
        s.feed(&long);
        assert!(!s.active());
        assert!(s.params.len() <= MAX_PARAMS);
    }

    #[test]
    fn the_overlay_keeps_the_cursor() {
        let o = String::from_utf8(overlay("lost\x07 link", 20, 30)).unwrap();
        assert!(o.starts_with("\x1b7\x1b[30;1H"), "{o:?}");
        assert!(o.ends_with("\x1b[0m\x1b8"), "{o:?}");
        assert!(o.contains(" lost link") && !o.contains('\x07'), "{o:?}");
        let o = String::from_utf8(overlay(&"x".repeat(100), 10, 5)).unwrap();
        assert_eq!(o.matches('x').count(), 9);
        assert_eq!(clear_overlay(30), b"\x1b7\x1b[30;1H\x1b[0m\x1b[2K\x1b8");
    }
}
