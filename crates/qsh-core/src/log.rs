//! Minimal logging to stderr: the daemon's stderr goes to journald (service unit) or to the
//! state directory's `daemon.log` (started on demand); the client logs only with `-v`.

use std::fmt::Arguments;
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

/// How much to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing.
    Off = 0,
    /// Problems and lifecycle events (default of the daemon).
    Info = 1,
    /// Every connection and attach.
    Debug = 2,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Off as u8);

/// Set the level for this process.
pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// True when messages of `level` are logged.
pub fn enabled(level: Level) -> bool {
    level != Level::Off && LEVEL.load(Ordering::Relaxed) >= level as u8
}

/// The longest log line, in characters.
const MAX_LINE: usize = 4096;

fn write(level: Level, args: Arguments<'_>) {
    if enabled(level) {
        // Log lines quote what the other side sent (error messages, names): as text only
        let line = crate::text::sanitize(&args.to_string(), MAX_LINE);
        let mut stderr = std::io::stderr().lock();
        // \r: the client's terminal may be in raw mode
        let _ = write!(stderr, "qsh: {line}\r\n");
    }
}

/// Log at [`Level::Info`].
pub fn info(args: Arguments<'_>) {
    write(Level::Info, args)
}

/// Log at [`Level::Debug`].
pub fn debug(args: Arguments<'_>) {
    write(Level::Debug, args)
}
