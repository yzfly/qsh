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
//! Any other key after `~` sends both, as ssh does.

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

/// The escape character.
pub const ESCAPE: u8 = b'~';

/// The help text for `~?`, with terminal line ends.
pub const HELP: &str = "Supported escape sequences:\r\n \
  ~.  end the session\r\n \
  ~d  detach (the session keeps running on the server)\r\n \
  ~s  connection status\r\n \
  ~?  this help\r\n \
  ~~  send ~\r\n\
(Escapes are only recognized right after Enter.)\r\n";

/// Splits keyboard input into bytes to send and escape actions.
#[derive(Debug, Clone)]
pub struct EscapeFilter {
    at_line_start: bool,
    pending: bool,
}

impl Default for EscapeFilter {
    fn default() -> Self {
        EscapeFilter {
            at_line_start: true,
            pending: false,
        }
    }
}

impl EscapeFilter {
    /// A filter at the start of a line.
    pub fn new() -> EscapeFilter {
        EscapeFilter::default()
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
        for &b in input {
            if self.pending {
                self.pending = false;
                let action = match b {
                    b'.' => Some(Action::End),
                    b'd' => Some(Action::Detach),
                    b's' => Some(Action::Status),
                    b'?' => Some(Action::Help),
                    ESCAPE => {
                        send.push(ESCAPE);
                        self.at_line_start = false;
                        None
                    }
                    _ => {
                        send.push(ESCAPE);
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
            if b == ESCAPE && self.at_line_start {
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
    fn tilde_then_enter_keeps_the_line_start() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~\r~."), vec![send("~\r"), Action::End]);
    }
}
