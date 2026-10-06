//! ssh-style escape sequences: `~` right after Enter (or at the very start) begins one.
//!
//! | keys | action |
//! |---|---|
//! | `~.` | end the session |
//! | `~d` | detach: the session keeps running on the server |
//! | `~s` | connection status (transport, round trip time, bytes) |
//! | `~?` | help |
//! | `~~` | a literal `~` |
//!
//! Any other key after `~` sends both, as ssh does. The escape character can be another one,
//! or none (qsh_config(5) `escape_char`).

/// What the user's keystrokes amount to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Bytes for the session.
    Send(Vec<u8>),
    /// `~.`
    End,
    /// `~d`
    Detach,
    /// `~s`
    Status,
    /// `~?`
    Help,
}

/// The default escape character.
pub const ESCAPE: u8 = b'~';

/// How people write the escape character `c`: itself, or `^X` for a control character.
pub fn escape_name(c: u8) -> String {
    match c {
        0x7f => "^?".into(),
        0..=0x1f => format!("^{}", char::from(c + 0x40)),
        c => char::from(c).to_string(),
    }
}

/// The help text for `~?` with escape character `c`, with terminal line ends.
pub fn help(c: u8) -> String {
    let e = escape_name(c);
    format!(
        "Supported escape sequences:\r\n \
  {e}.  end the session\r\n \
  {e}d  detach (the session keeps running on the server)\r\n \
  {e}s  connection status\r\n \
  {e}?  this help\r\n \
  {e}{e}  send {e}\r\n\
(Escapes are only recognized right after Enter.)\r\n"
    )
}

/// Splits keyboard input into bytes to send and escape actions.
#[derive(Debug, Clone)]
pub struct EscapeFilter {
    escape: Option<u8>,
    at_line_start: bool,
    pending: bool,
}

impl Default for EscapeFilter {
    fn default() -> Self {
        EscapeFilter::with(Some(ESCAPE))
    }
}

impl EscapeFilter {
    /// A filter at the start of a line, with `~`.
    pub fn new() -> EscapeFilter {
        EscapeFilter::default()
    }

    /// A filter with escape character `escape`; None: no escapes, everything is sent.
    pub fn with(escape: Option<u8>) -> EscapeFilter {
        EscapeFilter {
            escape,
            at_line_start: true,
            pending: false,
        }
    }

    /// Process keyboard input. Bytes between actions keep their order.
    pub fn feed(&mut self, input: &[u8]) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut send = Vec::with_capacity(input.len());
        let flush = |send: &mut Vec<u8>, actions: &mut Vec<Action>| {
            if !send.is_empty() {
                actions.push(Action::Send(std::mem::take(send)));
            }
        };
        let Some(escape) = self.escape else {
            if !input.is_empty() {
                actions.push(Action::Send(input.to_vec()));
            }
            return actions;
        };
        for &b in input {
            if self.pending {
                self.pending = false;
                let action = match b {
                    b'.' => Some(Action::End),
                    b'd' => Some(Action::Detach),
                    b's' => Some(Action::Status),
                    b'?' => Some(Action::Help),
                    _ if b == escape => {
                        send.push(escape);
                        self.at_line_start = false;
                        None
                    }
                    _ => {
                        send.push(escape);
                        send.push(b);
                        self.at_line_start = b == b'\r' || b == b'\n';
                        None
                    }
                };
                if let Some(action) = action {
                    flush(&mut send, &mut actions);
                    actions.push(action);
                    // After an action the next ~ starts an escape again, as in ssh
                    self.at_line_start = true;
                }
                continue;
            }
            if b == escape && self.at_line_start {
                self.pending = true;
                continue;
            }
            send.push(b);
            self.at_line_start = b == b'\r' || b == b'\n';
        }
        flush(&mut send, &mut actions);
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(s: &str) -> Action {
        Action::Send(s.as_bytes().to_vec())
    }

    #[test]
    fn escapes_only_after_enter() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~."), vec![Action::End]);
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"ls ~.\r"), vec![send("ls ~.\r")]);
        assert_eq!(f.feed(b"~d"), vec![Action::Detach]);
        assert_eq!(f.feed(b"~s"), vec![Action::Status]);
        assert_eq!(f.feed(b"echo\r~?x"), vec![send("echo\r"), Action::Help, send("x")]);
    }

    #[test]
    fn tilde_tilde_sends_one_and_others_pass_through() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~~"), vec![send("~")]);
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~a"), vec![send("~a")]);
        // Split across reads
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"x\r~"), vec![send("x\r")]);
        assert_eq!(f.feed(b"."), vec![Action::End]);
    }

    #[test]
    fn another_escape_character_or_none() {
        let mut f = EscapeFilter::with(Some(0x1d));
        assert_eq!(f.feed(b"~."), vec![send("~.")]);
        assert_eq!(f.feed(b"\r\x1d."), vec![send("\r"), Action::End]);
        assert_eq!(f.feed(b"\x1d\x1d"), vec![send("\x1d")]);
        let mut f = EscapeFilter::with(None);
        assert_eq!(f.feed(b"~.\r~d"), vec![send("~.\r~d")]);
        assert_eq!(escape_name(b'~'), "~");
        assert_eq!(escape_name(0x1d), "^]");
        assert!(help(0x1d).contains("^]d  detach"));
    }

    #[test]
    fn tilde_then_enter_keeps_the_line_start() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~\r~."), vec![send("~\r"), Action::End]);
    }
}
