//! Containment of panics in complex code that runs on data from elsewhere: the screen model
//! (`vt100` and our snapshot encoder, fed with every program's output), the zstd encoder
//! (`ruzstd`) and our zstd decoder (data from the server), the handoff state parser.
//!
//! A fault there must cost that one feature for that one session (or that one message), never
//! the daemon and every session of the user, nor the client's connection for good. So every
//! call into that code goes through [`contain`], which catches the panic (release builds unwind
//! for this; see the workspace `Cargo.toml`) and returns a [`Fault`]. What the panicking code
//! held is never used again: the caller drops the model, sends the message uncompressed, or
//! treats the frame as an error. That is why [`contain`] may assert unwind safety.
//!
//! Panic hooks run before the unwinding, also for a panic that [`contain`] will catch. A
//! program's hook calls [`hook`] first: for a contained panic it records the location (for the
//! [`Fault`], which the caller logs with its context) and returns true, and the hook then says
//! nothing (the client's terminal is in raw mode, and the message of a panic can quote the data
//! that caused it); for any other panic it returns false and the hook reports it ([`report`]).

use std::cell::Cell;
use std::fmt;
use std::panic::{AssertUnwindSafe, PanicHookInfo};

thread_local! {
    /// Calls of [`contain`] in progress on this thread.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    /// Where the last contained panic on this thread happened, as a panic hook saw it.
    static LOCATION: Cell<Option<String>> = const { Cell::new(None) };
}

/// A panic caught by [`contain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// `file:line:column` of the panic, when a panic hook recorded it ([`hook`]).
    pub location: Option<String>,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.location {
            Some(at) => write!(f, "a panic at {at}"),
            None => f.write_str("a panic"),
        }
    }
}

impl std::error::Error for Fault {}

/// Run `f`; a panic in it is caught and returned as a [`Fault`].
///
/// The caller must not use anything `f` changed, other than through the result, once it got
/// a [`Fault`]: that state may be half updated. (Hence `AssertUnwindSafe` here: every caller
/// in qsh drops or disables what the closure touched.) The panic's payload is dropped unread:
/// its message may quote the data that caused it.
pub fn contain<T>(f: impl FnOnce() -> T) -> Result<T, Fault> {
    DEPTH.with(|d| d.set(d.get() + 1));
    LOCATION.with(|l| l.take());
    let result = std::panic::catch_unwind(AssertUnwindSafe(f));
    DEPTH.with(|d| d.set(d.get() - 1));
    match result {
        Ok(value) => Ok(value),
        Err(payload) => {
            // Dropping the payload runs no code of the failed callee (a String or a &str in
            // practice); contained all the same
            let _ = std::panic::catch_unwind(AssertUnwindSafe(move || drop(payload)));
            Err(Fault {
                location: LOCATION.with(|l| l.take()),
            })
        }
    }
}

/// Whether a panic on this thread now would be caught by [`contain`].
pub fn contained() -> bool {
    DEPTH.with(|d| d.get() > 0)
}

/// For a panic hook, first thing: true when [`contain`] will catch this panic (its location is
/// then recorded for the [`Fault`], and the hook should say nothing more).
pub fn hook(info: &PanicHookInfo<'_>) -> bool {
    if !contained() {
        return false;
    }
    LOCATION.with(|l| l.set(info.location().map(|l| l.to_string())));
    true
}

/// One line about a panic that is not contained, for a daemon's log: the thread, the location
/// and the message, unless the message may quote data (it then says so instead: the output of
/// a user's programs has no place in a log).
pub fn report(info: &PanicHookInfo<'_>) -> String {
    let thread = std::thread::current();
    let thread = thread.name().unwrap_or("unnamed");
    let at = info
        .location()
        .map_or_else(|| "an unknown location".to_string(), |l| l.to_string());
    let message = if let Some(s) = info.payload().downcast_ref::<&'static str>() {
        // A literal: part of the program, not of its data
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        safe_message(s)
    } else {
        "(no message)".to_string()
    };
    format!("panic in thread '{thread}' at {at}: {message}")
}

/// A formatted panic message as it may be logged: those of the standard library that carry
/// only numbers (an index out of bounds, an overflow) are kept; one that quotes something (in
/// backticks or quotes, as `unwrap` on an error and a bad string slice do) or is long is not.
fn safe_message(s: &str) -> String {
    if s.len() <= 160 && !s.contains(['`', '\'', '"']) && !s.chars().any(char::is_control) {
        s.to_string()
    } else {
        "(message withheld: it may quote session data)".to_string()
    }
}

/// Faults injected by the tests (cargo feature `test-hooks`; never in release or distribution
/// builds): the screen model, the zstd encoder or the zstd decoder panics on data that contains
/// a marker, or the snapshot encoder breaks the content profile. Markers are only ever added, so tests that run in parallel in one process do not
/// disturb each other as long as each uses its own marker.
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    use std::sync::Mutex;

    /// Where a fault is injected.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Hook {
        /// A session's screen model panics when its output contains the marker (models made
        /// after the marker was added).
        Model,
        /// `codec::compress` panics on data that contains the marker.
        Encoder,
        /// `codec::decompress` panics on a frame whose content contains the marker.
        Decoder,
        /// The snapshot encoder makes a snapshot outside the content profile (it asks the
        /// terminal for its cursor position) when the screen shows the marker. No panic: a
        /// server bug that only the client can see (protocol.md 7.8.4).
        Snapshot,
        /// A session's screen model takes 3 s to process output that completes the marker (as
        /// one would on output that is expensive to emulate), holding its lock meanwhile.
        Stall,
    }

    static MARKERS: Mutex<Vec<(Hook, Vec<u8>)>> = Mutex::new(Vec::new());

    /// From now on, panic in `hook` on data that contains `marker` (not empty).
    pub fn panic_on(hook: Hook, marker: &[u8]) {
        assert!(!marker.is_empty());
        MARKERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((hook, marker.to_vec()));
    }

    /// Whether a marker was added for `hook`.
    pub(crate) fn armed(hook: Hook) -> bool {
        MARKERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(h, _)| *h == hook)
    }

    /// Whether `data` contains a marker of `hook`.
    pub(crate) fn tripped(hook: Hook, data: &[u8]) -> bool {
        MARKERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(h, m)| *h == hook && data.windows(m.len()).any(|w| w == &m[..]))
    }

    /// Panic if `data` contains a marker of `hook`.
    pub(crate) fn check(hook: Hook, data: &[u8]) {
        if tripped(hook, data) {
            panic!("test hook: injected fault in the {hook:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_is_contained_and_nesting_is_tracked() {
        assert!(!contained());
        assert_eq!(contain(|| 7), Ok(7));
        let fault = contain(|| {
            assert!(contained());
            let inner = contain(|| panic!("inner"));
            assert!(inner.is_err());
            // Still inside the outer call
            assert!(contained());
            panic!("outer")
        });
        assert!(fault.is_err());
        assert!(!contained());
        assert_eq!(Fault { location: None }.to_string(), "a panic");
    }

    #[test]
    fn messages_that_may_quote_data_are_withheld() {
        assert_eq!(
            safe_message("index out of bounds: the len is 3 but the index is 5"),
            "index out of bounds: the len is 3 but the index is 5"
        );
        for quoting in [
            "byte index 1 is not a char boundary; it is inside 'é' (bytes 0..2) of `é`",
            "called `Result::unwrap()` on an `Err` value: \"secret\"",
            "line\nbreak",
        ] {
            assert!(safe_message(quoting).starts_with("(message withheld"), "{quoting}");
        }
    }
}
