//! The upgrade in place (m2.md section 10): the state an old daemon image hands to the new one,
//! its binary format (version 1, m2.md 10.5), the checks of the executable to run and its
//! version probe (10.3 steps 1 and 2).
//!
//! The state never leaves the process: it is written, sealed with ChaCha20-Poly1305
//! ([`crate::crypto::seal_state`]), into an anonymous file the new image inherits, with the key
//! in a pipe (security.md 4.8). Its parser is bounded everywhere and is a fuzz target
//! (`fuzz/fuzz_targets/handoff_state.rs`): it never trusts a count or a length before checking
//! it against what is left and against a fixed limit.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::crypto::SessionKey;
use crate::proto::ExitStatus;

/// The first bytes of a state.
pub const MAGIC: &[u8; 12] = b"QSH-HANDOFF\n";

/// The state format this version writes.
pub const FORMAT: u16 = 1;

/// The state formats this version reads (announced by `qsh-server handoff-probe` and `status`).
pub const FORMATS: &[u16] = &[1];

/// Most listeners in a state: primary UDP and TCP, 8 extra ports of each, the control socket,
/// the lock; with room to spare.
pub const MAX_LISTENERS: usize = 32;

/// Most sessions in a state.
pub const MAX_SESSIONS: usize = 100_000;

/// Largest replay buffer capacity in a state (1 GiB).
pub const MAX_BUFFER: u64 = 1 << 30;

/// Largest input queue in a state.
pub const MAX_INPUT_QUEUE: usize = 64 << 20;

/// Largest screen model snapshot in a state: what a snapshot may be on the wire (a model's
/// state is handed over as a resync snapshot, which its writer keeps within this).
pub use crate::proto::message::MAX_SNAPSHOT;

/// Largest command in a state.
pub const MAX_COMMAND: usize = 1 << 20;

/// Largest sealed state file a new image reads (64 GiB).
pub const MAX_STATE_FILE: u64 = 64 << 30;

/// A descriptor number that is not there (a closed pipe).
pub const NO_FD: u32 = u32::MAX;

/// Most programs a state remembers as refused or failed ([`State::refused`]).
pub const MAX_REFUSED: usize = 64;

/// How long the version probe may take (10.3 step 2).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Most bytes of the probe's output read.
pub const PROBE_MAX_OUTPUT: usize = 4096;

/// What a listener descriptor of the state is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// A UDP socket (QUIC).
    Udp,
    /// A listening TCP socket (TLS).
    Tcp,
    /// The control socket's listener (unix).
    Control,
    /// The daemon's lock file (`daemon.lock`, held with `flock`).
    Lock,
}

impl ListenerKind {
    fn code(self) -> u8 {
        match self {
            ListenerKind::Udp => 1,
            ListenerKind::Tcp => 2,
            ListenerKind::Control => 3,
            ListenerKind::Lock => 4,
        }
    }

    fn from_code(code: u8) -> Option<ListenerKind> {
        Some(match code {
            1 => ListenerKind::Udp,
            2 => ListenerKind::Tcp,
            3 => ListenerKind::Control,
            4 => ListenerKind::Lock,
            _ => return None,
        })
    }
}

/// A descriptor of the daemon itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// What it is.
    pub kind: ListenerKind,
    /// The descriptor number.
    pub fd: u32,
    /// The port (UDP, TCP), 0 otherwise.
    pub port: u16,
}

/// The descriptors of a session's program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFds {
    /// A tty session: the pseudo-terminal master.
    Tty {
        /// The master.
        master: u32,
    },
    /// A pipe session: [`NO_FD`] for a pipe already closed.
    Pipe {
        /// The write end of the program's stdin.
        stdin: u32,
        /// The read end of its stdout.
        stdout: u32,
        /// The read end of its stderr.
        stderr: u32,
    },
}

impl SessionFds {
    /// The descriptor numbers, without [`NO_FD`].
    pub fn numbers(&self) -> Vec<u32> {
        match *self {
            SessionFds::Tty { master } => vec![master],
            SessionFds::Pipe { stdin, stdout, stderr } => {
                [stdin, stdout, stderr].into_iter().filter(|fd| *fd != NO_FD).collect()
            }
        }
    }
}

/// A replay buffer: its capacity, and the bytes it holds from `base`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BufferState {
    /// The most bytes it keeps.
    pub capacity: u64,
    /// The stream offset of the first byte held.
    pub base: u64,
    /// The bytes held.
    pub bytes: Vec<u8>,
}

/// The program's end, as far as the old image knew it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitState {
    /// How it ended (reaped).
    pub status: ExitStatus,
    /// Milliseconds since the end was published to attachments (EXIT), or None while it waits
    /// for the program's output to reach its end.
    pub published_ms_ago: Option<u64>,
}

/// The screen model of a tty session (m2.md 6.8), as a resync snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelState {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// The snapshot's bytes.
    pub snapshot: Vec<u8>,
}

/// One session.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// The session id.
    pub id: [u8; 16],
    /// The current key.
    pub current_key: SessionKey,
    /// The pending key, until KEY_CONFIRM.
    pub pending_key: Option<SessionKey>,
    /// The program's pid (also its process group).
    pub pid: u32,
    /// The attach generation.
    pub generation: u64,
    /// When the session started, Unix milliseconds.
    pub created_ms: u64,
    /// Milliseconds since a client was last attached or active.
    pub last_seen_ms_ago: u64,
    /// The program's end, if it was reaped.
    pub exit: Option<ExitState>,
    /// The session's name.
    pub name: Option<String>,
    /// The command, None for a login shell.
    pub command: Option<String>,
    /// The terminal size (tty sessions).
    pub cols: u16,
    /// The terminal size (tty sessions).
    pub rows: u16,
    /// The program's descriptors.
    pub fds: SessionFds,
    /// The output replay buffer.
    pub output: BufferState,
    /// The error output replay buffer (pipe sessions; empty otherwise).
    pub errors: BufferState,
    /// Input received from clients: the offset after the last byte.
    pub input_received: u64,
    /// Input received and acknowledged, not yet written to the program.
    pub input_queue: Vec<u8>,
    /// A pipe session's input was closed at this offset.
    pub input_eof: Option<u64>,
    /// The screen model.
    pub model: Option<ModelState>,
}

impl SessionState {
    /// A pipe session.
    pub fn pipe(&self) -> bool {
        matches!(self.fds, SessionFds::Pipe { .. })
    }
}

/// The identity of a file: device, inode and change time. A package upgrade that replaces a
/// program gives it another inode; an inode number used again later comes with another change
/// time, and so does any change of the file's content or mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// The device.
    pub dev: u64,
    /// The inode.
    pub ino: u64,
    /// The change time, seconds since the epoch.
    pub ctime: i64,
    /// The change time's nanoseconds (below 10^9).
    pub ctime_ns: u32,
}

impl FileId {
    /// The identity of the file `meta` describes.
    pub fn of(meta: &std::fs::Metadata) -> FileId {
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            ctime: meta.ctime(),
            ctime_ns: u32::try_from(meta.ctime_nsec()).unwrap_or(0).min(999_999_999),
        }
    }
}

/// A program the daemon does not try again by itself (security.md 4.8, m2.md 10.2): its probe
/// or its checks said no, or an upgrade to it failed. Only an explicit `qsh-server upgrade
/// --force` tries it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The program.
    pub id: FileId,
    /// An upgrade to it was attempted and failed (rather than refused before an attempt).
    pub failed: bool,
}

/// The daemon's own options (`qsh-server daemon`): handed to the next image inside the state,
/// not on its command line, so that a later version that renames an option still resumes
/// (m2.md 10.3 step 5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DaemonOptions {
    /// Started on demand: exits after an hour without sessions.
    pub on_demand: bool,
    /// `--ports FIRST-LAST` (or `QSH_SERVER_PORTS`), over the configuration files.
    pub ports: Option<(u16, u16)>,
}

/// Everything the new image needs.
#[derive(Debug, Clone)]
pub struct State {
    /// Who wrote it: `qsh-server/<version>`.
    pub writer: String,
    /// When the daemon first started (before any upgrade), Unix milliseconds.
    pub started_ms: u64,
    /// Upgrades in place so far.
    pub restarts: u32,
    /// Upgrades that failed so far.
    pub failures: u32,
    /// The daemon's own options.
    pub options: DaemonOptions,
    /// Programs not to try again by itself, oldest first (at most [`MAX_REFUSED`]).
    pub refused: Vec<Refused>,
    /// The program this state was written for. When it cannot resume and the old image takes
    /// over again (m2.md 10.4), that one adds it to its refused programs: a failed program is
    /// never tried again automatically.
    pub attempt: Option<FileId>,
    /// The primary port (UDP and TCP).
    pub port: u16,
    /// The daemon's own descriptors.
    pub listeners: Vec<Listener>,
    /// The sessions.
    pub sessions: Vec<SessionState>,
}

impl State {
    /// Every descriptor number in the state.
    pub fn descriptors(&self) -> Vec<u32> {
        let mut all: Vec<u32> = self.listeners.iter().map(|l| l.fd).collect();
        for s in &self.sessions {
            all.extend(s.fds.numbers());
        }
        all
    }
}

/// Why a state was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError(pub String);

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad handoff state: {}", self.0)
    }
}

impl std::error::Error for StateError {}

fn bad(what: impl Into<String>) -> StateError {
    StateError(what.into())
}

// ---------------------------------------------------------------------------------------------
// Encoding

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
    fn string(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
    fn opt_string(&mut self, v: Option<&str>) {
        match v {
            Some(s) => {
                self.u8(1);
                self.string(s);
            }
            None => self.u8(0),
        }
    }
    fn buffer(&mut self, b: &BufferState) {
        self.u64(b.capacity);
        self.u64(b.base);
        self.bytes(&b.bytes);
    }
    fn file_id(&mut self, id: &FileId) {
        self.u64(id.dev);
        self.u64(id.ino);
        self.u64(id.ctime as u64);
        self.u32(id.ctime_ns);
    }
}

/// Encode `state` (format [`FORMAT`]). Lengths beyond the format's limits are an error, so
/// that the new image never refuses what the old one wrote for that reason.
pub fn encode(state: &State) -> Result<Vec<u8>, StateError> {
    if state.writer.len() > 64 {
        return Err(bad("writer too long"));
    }
    if state.listeners.len() > MAX_LISTENERS || state.sessions.len() > MAX_SESSIONS {
        return Err(bad("too many listeners or sessions"));
    }
    if state.refused.len() > MAX_REFUSED {
        return Err(bad("too many refused programs"));
    }
    check_options(&state.options)?;
    for id in state.refused.iter().map(|r| &r.id).chain(state.attempt.as_ref()) {
        check_file_id(id)?;
    }
    let size: usize = state
        .sessions
        .iter()
        .map(|s| 512 + s.output.bytes.len() + s.errors.bytes.len() + s.input_queue.len())
        .sum();
    let mut w = Writer(Vec::with_capacity(size + 1024));
    w.0.extend_from_slice(MAGIC);
    w.u16(FORMAT);
    w.string(&state.writer);
    w.u64(state.started_ms);
    w.u32(state.restarts);
    w.u32(state.failures);
    let o = &state.options;
    w.u8(u8::from(o.on_demand) | (u8::from(o.ports.is_some()) << 1));
    if let Some((first, last)) = o.ports {
        w.u16(first);
        w.u16(last);
    }
    w.u16(state.refused.len() as u16);
    for r in &state.refused {
        w.file_id(&r.id);
        w.u8(u8::from(r.failed));
    }
    match &state.attempt {
        Some(id) => {
            w.u8(1);
            w.file_id(id);
        }
        None => w.u8(0),
    }
    w.u16(state.port);
    w.u16(state.listeners.len() as u16);
    for l in &state.listeners {
        w.u8(l.kind.code());
        w.u32(l.fd);
        w.u16(l.port);
    }
    w.u32(state.sessions.len() as u32);
    for s in &state.sessions {
        check_session(s)?;
        w.0.extend_from_slice(&s.id);
        w.0.extend_from_slice(&s.current_key.0);
        match &s.pending_key {
            Some(k) => {
                w.u8(1);
                w.0.extend_from_slice(&k.0);
            }
            None => w.u8(0),
        }
        w.u32(s.pid);
        w.u64(s.generation);
        w.u64(s.created_ms);
        w.u64(s.last_seen_ms_ago);
        match &s.exit {
            None => w.u8(0),
            Some(e) => {
                w.u8(1);
                match &e.status {
                    ExitStatus::Exited(code) => {
                        w.u8(0);
                        w.u32(*code);
                        w.u8(0);
                        w.string("");
                    }
                    ExitStatus::Signaled { signal, core_dumped } => {
                        w.u8(1);
                        w.u32(0);
                        w.u8(u8::from(*core_dumped));
                        w.string(signal);
                    }
                }
                match e.published_ms_ago {
                    Some(ms) => {
                        w.u8(1);
                        w.u64(ms);
                    }
                    None => w.u8(0),
                }
            }
        }
        w.opt_string(s.name.as_deref());
        w.opt_string(s.command.as_deref());
        w.u16(s.cols);
        w.u16(s.rows);
        match s.fds {
            SessionFds::Tty { master } => {
                w.u8(0);
                w.u32(master);
            }
            SessionFds::Pipe { stdin, stdout, stderr } => {
                w.u8(1);
                w.u32(stdin);
                w.u32(stdout);
                w.u32(stderr);
            }
        }
        w.buffer(&s.output);
        w.buffer(&s.errors);
        w.u64(s.input_received);
        w.bytes(&s.input_queue);
        match s.input_eof {
            Some(at) => {
                w.u8(1);
                w.u64(at);
            }
            None => w.u8(0),
        }
        match &s.model {
            Some(m) => {
                w.u8(1);
                w.u16(m.cols);
                w.u16(m.rows);
                w.bytes(&m.snapshot);
            }
            None => w.u8(0),
        }
    }
    Ok(w.0)
}

/// The checks of the options that [`encode`] and [`decode`] share.
fn check_options(o: &DaemonOptions) -> Result<(), StateError> {
    match o.ports {
        Some((first, last)) if first == 0 || first > last => Err(bad("bad port range")),
        _ => Ok(()),
    }
}

/// The checks of a file identity that [`encode`] and [`decode`] share.
fn check_file_id(id: &FileId) -> Result<(), StateError> {
    if id.ctime_ns >= 1_000_000_000 {
        return Err(bad("bad change time"));
    }
    Ok(())
}

/// The checks of one session that [`encode`] and [`decode`] share.
fn check_session(s: &SessionState) -> Result<(), StateError> {
    for (name, b) in [("output", &s.output), ("error", &s.errors)] {
        if b.capacity > MAX_BUFFER || b.bytes.len() as u64 > b.capacity {
            return Err(bad(format!("{name} buffer larger than its capacity")));
        }
        if b.base.checked_add(b.bytes.len() as u64).is_none() {
            return Err(bad(format!("{name} buffer beyond 2^64")));
        }
    }
    if s.input_queue.len() > MAX_INPUT_QUEUE {
        return Err(bad("input queue too long"));
    }
    if s.input_eof.is_some_and(|at| at != s.input_received) {
        return Err(bad("input end of file not at the end of the input"));
    }
    if s.pid <= 1 || s.pid > i32::MAX as u32 {
        return Err(bad("bad pid"));
    }
    if s.name.as_ref().is_some_and(|n| n.len() > 64) || s.command.as_ref().is_some_and(|c| c.len() > MAX_COMMAND) {
        return Err(bad("name or command too long"));
    }
    if s.model.as_ref().is_some_and(|m| m.snapshot.len() > MAX_SNAPSHOT) {
        return Err(bad("model snapshot too long"));
    }
    match s.fds {
        SessionFds::Tty { master } if master == NO_FD => return Err(bad("a tty session without its terminal")),
        SessionFds::Tty { .. } if s.input_eof.is_some() || !s.errors.bytes.is_empty() => {
            return Err(bad("a tty session with pipe session state"))
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Decoding

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StateError> {
        if self.0.len() < n {
            return Err(bad("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], StateError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }
    fn u8(&mut self) -> Result<u8, StateError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, StateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, StateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, StateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn flag(&mut self) -> Result<bool, StateError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad("bad flag")),
        }
    }
    /// A length-prefixed byte string of at most `max` bytes: the length is checked against
    /// the limit and against what is left before anything is allocated.
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, StateError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(bad("length beyond its limit"));
        }
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self, max: usize) -> Result<String, StateError> {
        String::from_utf8(self.bytes(max)?).map_err(|_| bad("not UTF-8"))
    }
    fn opt_string(&mut self, max: usize) -> Result<Option<String>, StateError> {
        Ok(if self.flag()? { Some(self.string(max)?) } else { None })
    }
    fn buffer(&mut self) -> Result<BufferState, StateError> {
        let capacity = self.u64()?;
        let base = self.u64()?;
        if capacity > MAX_BUFFER {
            return Err(bad("buffer capacity beyond its limit"));
        }
        let bytes = self.bytes(capacity as usize)?;
        Ok(BufferState { capacity, base, bytes })
    }
    fn file_id(&mut self) -> Result<FileId, StateError> {
        let id = FileId {
            dev: self.u64()?,
            ino: self.u64()?,
            ctime: self.u64()? as i64,
            ctime_ns: self.u32()?,
        };
        check_file_id(&id)?;
        Ok(id)
    }
}

/// A descriptor number from the state: a plain descriptor above stderr.
fn fd_number(fd: u32, may_be_closed: bool) -> Result<u32, StateError> {
    if fd == NO_FD && may_be_closed {
        return Ok(fd);
    }
    if fd < 3 || fd > i32::MAX as u32 {
        return Err(bad("bad descriptor number"));
    }
    Ok(fd)
}

/// Decode a state (format [`FORMAT`]), checking every count, length and invariant: whatever
/// the bytes, the result is an error or a state that is safe to adopt (every descriptor number
/// at most once, buffers within their capacities, offsets within 2^64).
pub fn decode(bytes: &[u8]) -> Result<State, StateError> {
    let mut r = Reader(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(bad("not a handoff state"));
    }
    let format = r.u16()?;
    if !FORMATS.contains(&format) {
        return Err(bad(format!("format {format} is not known")));
    }
    let writer = r.string(64)?;
    let started_ms = r.u64()?;
    let restarts = r.u32()?;
    let failures = r.u32()?;
    let flags = r.u8()?;
    if flags & !0b11 != 0 {
        return Err(bad("unknown options"));
    }
    let options = DaemonOptions {
        on_demand: flags & 1 != 0,
        ports: if flags & 2 != 0 {
            Some((r.u16()?, r.u16()?))
        } else {
            None
        },
    };
    check_options(&options)?;
    let n = r.u16()? as usize;
    if n > MAX_REFUSED {
        return Err(bad("too many refused programs"));
    }
    let mut refused = Vec::with_capacity(n);
    for _ in 0..n {
        let id = r.file_id()?;
        refused.push(Refused { id, failed: r.flag()? });
    }
    let attempt = if r.flag()? { Some(r.file_id()?) } else { None };
    let port = r.u16()?;
    let n = r.u16()? as usize;
    if n > MAX_LISTENERS {
        return Err(bad("too many listeners"));
    }
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = ListenerKind::from_code(r.u8()?).ok_or_else(|| bad("unknown listener kind"))?;
        let fd = fd_number(r.u32()?, false)?;
        let port = r.u16()?;
        listeners.push(Listener { kind, fd, port });
    }
    let count = |kind| listeners.iter().filter(|l| l.kind == kind).count();
    if count(ListenerKind::Control) != 1 || count(ListenerKind::Lock) != 1 {
        return Err(bad("one control socket and one lock are required"));
    }
    let n = r.u32()? as usize;
    if n > MAX_SESSIONS {
        return Err(bad("too many sessions"));
    }
    let mut sessions = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let id = r.array::<16>()?;
        let current_key = SessionKey(r.array()?);
        let pending_key = if r.flag()? { Some(SessionKey(r.array()?)) } else { None };
        let pid = r.u32()?;
        let generation = r.u64()?;
        let created_ms = r.u64()?;
        let last_seen_ms_ago = r.u64()?;
        let exit = if r.flag()? {
            let kind = r.u8()?;
            let code = r.u32()?;
            let core_dumped = r.flag()?;
            let signal = r.string(32)?;
            // Exactly one encoding of each status: what is decoded encodes back to the same bytes
            let status = match kind {
                0 if code <= 255 && !core_dumped && signal.is_empty() => ExitStatus::Exited(code),
                1 if code == 0 && !signal.is_empty() => ExitStatus::Signaled { signal, core_dumped },
                _ => return Err(bad("bad exit status")),
            };
            let published_ms_ago = if r.flag()? { Some(r.u64()?) } else { None };
            Some(ExitState {
                status,
                published_ms_ago,
            })
        } else {
            None
        };
        let name = r.opt_string(64)?;
        let command = r.opt_string(MAX_COMMAND)?;
        let cols = r.u16()?;
        let rows = r.u16()?;
        let fds = match r.u8()? {
            0 => SessionFds::Tty {
                master: fd_number(r.u32()?, false)?,
            },
            1 => SessionFds::Pipe {
                stdin: fd_number(r.u32()?, true)?,
                stdout: fd_number(r.u32()?, true)?,
                stderr: fd_number(r.u32()?, true)?,
            },
            _ => return Err(bad("unknown session kind")),
        };
        let output = r.buffer()?;
        let errors = r.buffer()?;
        let input_received = r.u64()?;
        let input_queue = r.bytes(MAX_INPUT_QUEUE)?;
        let input_eof = if r.flag()? { Some(r.u64()?) } else { None };
        let model = if r.flag()? {
            Some(ModelState {
                cols: r.u16()?,
                rows: r.u16()?,
                snapshot: r.bytes(MAX_SNAPSHOT)?,
            })
        } else {
            None
        };
        let session = SessionState {
            id,
            current_key,
            pending_key,
            pid,
            generation,
            created_ms,
            last_seen_ms_ago,
            exit,
            name,
            command,
            cols,
            rows,
            fds,
            output,
            errors,
            input_received,
            input_queue,
            input_eof,
            model,
        };
        check_session(&session)?;
        if sessions.iter().any(|s: &SessionState| s.id == id) {
            return Err(bad("a session id twice"));
        }
        sessions.push(session);
    }
    if !r.0.is_empty() {
        return Err(bad("trailing bytes"));
    }
    let state = State {
        writer,
        started_ms,
        restarts,
        failures,
        options,
        refused,
        attempt,
        port,
        listeners,
        sessions,
    };
    let mut numbers = state.descriptors();
    numbers.sort_unstable();
    if numbers.windows(2).any(|w| w[0] == w[1]) {
        return Err(bad("a descriptor number twice"));
    }
    Ok(state)
}

// ---------------------------------------------------------------------------------------------
// The executable to run, its probe, and the new image's command line

/// A test hook (unstable; builds with the cargo feature `test-hooks` only): the directories
/// above this one are not checked by [`Exe::check`]. The tests' worlds live under `/tmp`,
/// which every user can write.
pub(crate) const TEST_TRUSTED_DIR: &str = "QSH_TEST_TRUSTED_DIR";

/// A program opened for an upgrade (m2.md 10.3 step 1, security.md 4.8). It is checked on its
/// descriptor; on Linux it is also probed and executed through that descriptor, never through
/// its path again, so that what runs is what was checked. Elsewhere its path is checked to
/// still name the same file right before the probe and right before the `execve`.
#[derive(Debug)]
pub struct Exe {
    /// The path it was named by.
    pub path: PathBuf,
    /// The same path with every symbolic link resolved: the one whose directories are checked.
    pub real: PathBuf,
    /// The file, open read-only and close-on-exec.
    pub file: std::fs::File,
    /// Its identity when it was opened.
    pub id: FileId,
}

impl Exe {
    /// Open the program at `path`, an absolute path. Its symbolic links are resolved first and
    /// the file is then opened without following another one (one that appears meanwhile is
    /// someone's doing), and without waiting if it is a FIFO.
    pub fn open(path: &Path) -> Result<Exe, String> {
        use std::os::unix::fs::OpenOptionsExt;
        if !path.is_absolute() {
            return Err(format!("{} is not an absolute path", path.display()));
        }
        let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&real)
            .map_err(|e| format!("{}: {e}", real.display()))?;
        let meta = file.metadata().map_err(|e| format!("{}: {e}", real.display()))?;
        Ok(Exe {
            path: path.to_path_buf(),
            real,
            id: FileId::of(&meta),
            file,
        })
    }

    /// Check it (m2.md 10.3 step 1, security.md 4.8), on the open file: a regular file, owned by
    /// root or by this user, not writable by group or others, executable. And every directory
    /// above it: owned by root or by this user, not writable by others (not even with the
    /// sticky bit, like `/tmp`: whoever can create a name in a directory can put a program
    /// where this one is expected), and writable by its group only when that is the user's
    /// private group ([`crate::sys::private_group`]). A directory another user could write,
    /// or a group (Debian's `/usr/local`, `root:staff 2775`), is refused like a file they
    /// could write.
    pub fn check(&self) -> Result<(), String> {
        let path = self.path.display();
        let meta = self.file.metadata().map_err(|e| format!("{path}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{path} is not a regular file"));
        }
        let euid = crate::sys::euid();
        if meta.uid() != 0 && meta.uid() != euid {
            return Err(format!("{path} belongs to another user"));
        }
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "{path} is writable by group or others (mode {:o})",
                mode & 0o7777
            ));
        }
        if mode & 0o111 == 0 {
            return Err(format!("{path} is not executable"));
        }
        let trusted = std::env::var_os(TEST_TRUSTED_DIR)
            .filter(|_| cfg!(feature = "test-hooks"))
            .map(PathBuf::from);
        let private = crate::sys::private_group();
        for dir in self.real.ancestors().skip(1) {
            if trusted.as_deref().is_some_and(|t| t != dir && t.starts_with(dir)) {
                break;
            }
            let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if let Some(why) = dir_refusal(m.uid(), m.gid(), m.mode(), euid, private) {
                return Err(format!(
                    "{path} is in {}, which {why} (mode {:o})",
                    dir.display(),
                    m.mode() & 0o7777
                ));
            }
        }
        Ok(())
    }

    /// True when its path still names the file that was opened: for systems that cannot
    /// execute a descriptor, right before using the path.
    pub fn unchanged(&self) -> bool {
        file_identity(&self.real) == Some(self.id)
    }
}

/// Why a directory (owner `uid`, group `gid`, `mode`) cannot hold a program that user `euid`,
/// whose private group is `private`, executes in place of its daemon. None: it can.
fn dir_refusal(uid: u32, gid: u32, mode: u32, euid: u32, private: Option<u32>) -> Option<&'static str> {
    if uid != 0 && uid != euid {
        return Some("belongs to another user");
    }
    if mode & 0o002 != 0 {
        return Some("every user can write");
    }
    if mode & 0o020 != 0 && Some(gid) != private {
        return Some("its group can write");
    }
    None
}

/// What an executable said about itself (`qsh-server handoff-probe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// Its version.
    pub version: String,
    /// The state formats it reads.
    pub formats: Vec<u16>,
}

/// The line `qsh-server handoff-probe` prints.
pub fn probe_line(version: &str) -> String {
    serde_json::json!({ "qsh-server": version, "handoff": FORMATS }).to_string()
}

/// Parse the output of `handoff-probe`: the last line that is a JSON object with both members.
pub fn parse_probe(output: &[u8]) -> Result<Probe, String> {
    let text = String::from_utf8_lossy(output);
    for line in text.lines().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        let version = value["qsh-server"].as_str().filter(|v| v.len() <= 64);
        let formats = value["handoff"].as_array().map(|a| {
            a.iter()
                .filter_map(|f| f.as_u64().and_then(|f| u16::try_from(f).ok()))
                .collect::<Vec<u16>>()
        });
        if let (Some(version), Some(formats)) = (version, formats) {
            return Ok(Probe {
                version: version.to_string(),
                formats,
            });
        }
    }
    Err("the program did not answer the version probe".into())
}

/// Run `exe handoff-probe` (10.3 step 2): no shell, an empty environment except `PATH`, at
/// most [`PROBE_TIMEOUT`] and [`PROBE_MAX_OUTPUT`] bytes of output. On Linux the program run
/// is the open file (`/proc/self/fd/N`), not whatever its path names now.
pub async fn probe(exe: &Exe) -> Result<Probe, String> {
    use tokio::io::AsyncReadExt;
    let name = exe.path.display();
    let path = std::env::var_os("PATH").unwrap_or_else(|| super::pty::DEFAULT_PATH.into());
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let mut command = {
        use std::os::fd::AsRawFd;
        let fd = exe.file.as_raw_fd();
        let mut command = std::process::Command::new(format!("/proc/self/fd/{fd}"));
        crate::sys::inherit_in_child(&mut command, fd);
        command
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let mut command = {
        if !exe.unchanged() {
            return Err(format!("{name} was replaced while it was being checked"));
        }
        std::process::Command::new(&exe.real)
    };
    {
        use std::os::unix::process::CommandExt;
        command.arg0("qsh-server");
    }
    command
        .arg("handoff-probe")
        .env_clear()
        .env("PATH", path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cannot run {name}: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("no output")?;
    let run = async {
        let mut out = Vec::new();
        (&mut stdout)
            .take(PROBE_MAX_OUTPUT as u64)
            .read_to_end(&mut out)
            .await
            .map_err(|e| e.to_string())?;
        let status = child.wait().await.map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("its version probe failed ({status})"));
        }
        parse_probe(&out)
    };
    match tokio::time::timeout(PROBE_TIMEOUT, run).await {
        Ok(result) => result.map_err(|e| format!("{name}: {e}")),
        Err(_) => Err(format!(
            "{name}: no answer to the version probe within {PROBE_TIMEOUT:?}"
        )),
    }
}

/// A semantic version: (major, minor, patch, pre-release). None when it is not one: three
/// numbers without leading zeros, then optionally `-` and dot-separated identifiers of ASCII
/// letters, digits and hyphens (numeric ones without leading zeros), then optionally `+` and
/// build metadata, which is ignored.
fn parse_version(text: &str) -> Option<(u64, u64, u64, Option<&str>)> {
    let text = text.split('+').next()?;
    let (core, pre) = match text.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (text, None),
    };
    let number = |s: &str| -> Option<u64> {
        let leading_zero = s.len() > 1 && s.starts_with('0');
        (!s.is_empty() && !leading_zero && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let mut parts = core.split('.');
    let major = number(parts.next()?)?;
    let minor = number(parts.next()?)?;
    let patch = number(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    if let Some(pre) = pre {
        let valid = |id: &str| {
            let numeric = id.bytes().all(|b| b.is_ascii_digit());
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !(numeric && id.len() > 1 && id.starts_with('0'))
        };
        if !pre.split('.').all(valid) {
            return None;
        }
    }
    Some((major, minor, patch, pre))
}

/// The precedence of two pre-release tags (semantic versioning 2.0.0, item 11): identifier by
/// identifier, numeric ones numerically, a numeric one lower than an alphanumeric one,
/// alphanumeric ones in ASCII order; when one is a prefix of the other, the shorter is lower.
fn compare_pre(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let numeric = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let (mut x, mut y) = (a.split('.'), b.split('.'));
    loop {
        let order = match (x.next(), y.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            // Numerically, however long: no leading zeros (parse_version), so the longer is larger
            (Some(p), Some(q)) => match (numeric(p), numeric(q)) {
                (true, true) => p.len().cmp(&q.len()).then_with(|| p.cmp(q)),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => p.cmp(q),
            },
        };
        if order != Ordering::Equal {
            return order;
        }
    }
}

/// True when version `a` is strictly newer than `b` by semantic versioning precedence (a
/// pre-release is older than its release; pre-releases compare identifier by identifier, numeric
/// ones numerically and below alphanumeric ones, a shorter prefix lower; build
/// metadata is ignored). Versions that are not semantic versions are never newer.
pub fn newer(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (parse_version(a), parse_version(b)) else {
        return false;
    };
    if (a.0, a.1, a.2) != (b.0, b.1, b.2) {
        return (a.0, a.1, a.2) > (b.0, b.1, b.2);
    }
    match (a.3, b.3) {
        (None, Some(_)) => true,
        (Some(x), Some(y)) => compare_pre(x, y) == std::cmp::Ordering::Greater,
        _ => false,
    }
}

/// The identity of the file at `path`, following symbolic links, to notice that a package
/// upgrade replaced it (m2.md 10.2, upgrades when idle).
pub fn file_identity(path: &Path) -> Option<FileId> {
    std::fs::metadata(path).ok().map(|m| FileId::of(&m))
}

/// The command (`argv[1]`) a new image is started with (m2.md 10.3 step 5). This command
/// line is frozen with the state formats: every version that reads a format accepts it in
/// exactly this form, and the program recognizes it before parsing anything else, so that a
/// later version that changes its other options or subcommands still resumes. The daemon's
/// own options travel in the state ([`DaemonOptions`]).
pub const RESUME_COMMAND: &str = "handoff-resume";

/// What a new image of the daemon was given by the old one (`qsh-server handoff-resume`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resume {
    /// The format of the state.
    pub format: u16,
    /// The sealed state.
    pub state_fd: i32,
    /// The pipe with the state's key.
    pub key_fd: i32,
    /// The old image's executable, to execute again if this one cannot resume (Linux).
    pub fallback_exe_fd: Option<i32>,
    /// This is the old image again: the new one could not resume (m2.md 10.4).
    pub fell_back: bool,
}

impl Resume {
    /// The command line: `qsh-server handoff-resume --format=F --state-fd=N --key-fd=M
    /// [--fallback-exe-fd=E] [--fell-back]`.
    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![
            "qsh-server".to_string(),
            RESUME_COMMAND.into(),
            format!("--format={}", self.format),
            format!("--state-fd={}", self.state_fd),
            format!("--key-fd={}", self.key_fd),
        ];
        if let Some(fd) = self.fallback_exe_fd {
            args.push(format!("--fallback-exe-fd={fd}"));
        }
        if self.fell_back {
            args.push("--fell-back".into());
        }
        args
    }

    /// Recognize the command line of [`Resume::to_args`]: None when `args[1]` is not
    /// [`RESUME_COMMAND`]; an error when it is but the rest is not exactly that form.
    pub fn from_args(args: &[std::ffi::OsString]) -> Option<Result<Resume, String>> {
        if args.get(1).map(|a| a.as_os_str()) != Some(std::ffi::OsStr::new(RESUME_COMMAND)) {
            return None;
        }
        let parse = || -> Result<Resume, String> {
            let (mut format, mut state_fd, mut key_fd, mut fallback_exe_fd, mut fell_back) =
                (None, None, None, None, false);
            for arg in &args[2..] {
                let arg = arg.to_str().ok_or("an argument that is not UTF-8")?;
                let fd = |v: &str| -> Result<i32, String> {
                    v.parse::<i32>()
                        .ok()
                        .filter(|fd| *fd >= 3)
                        .ok_or_else(|| format!("bad descriptor {v:?}"))
                };
                match arg.split_once('=') {
                    Some(("--format", v)) if format.is_none() => {
                        format = Some(v.parse::<u16>().map_err(|_| format!("bad format {v:?}"))?)
                    }
                    Some(("--state-fd", v)) if state_fd.is_none() => state_fd = Some(fd(v)?),
                    Some(("--key-fd", v)) if key_fd.is_none() => key_fd = Some(fd(v)?),
                    Some(("--fallback-exe-fd", v)) if fallback_exe_fd.is_none() => fallback_exe_fd = Some(fd(v)?),
                    None if arg == "--fell-back" && !fell_back => fell_back = true,
                    _ => return Err(format!("unexpected argument {arg:?}")),
                }
            }
            let format = format.ok_or("no --format")?;
            if !FORMATS.contains(&format) {
                return Err(format!("state format {format} is not known"));
            }
            Ok(Resume {
                format,
                state_fd: state_fd.ok_or("no --state-fd")?,
                key_fd: key_fd.ok_or("no --key-fd")?,
                fallback_exe_fd,
                fell_back,
            })
        };
        Some(parse())
    }
}

/// Read the sealed state from `file` (from its start, whatever its offset) and open it with
/// `key`.
pub fn read_sealed(file: &std::fs::File, key: &[u8; crate::crypto::STATE_KEY_LEN]) -> io::Result<State> {
    use std::os::unix::fs::FileExt;
    let len = file.metadata()?.len();
    if len > MAX_STATE_FILE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the state file is too large",
        ));
    }
    let mut sealed = vec![0u8; len as usize];
    file.read_exact_at(&mut sealed, 0)?;
    let mut plain = crate::crypto::open_state(sealed, key)?;
    let state = decode(&plain).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
    zeroize::Zeroize::zeroize(&mut plain);
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(pipe: bool, fd: u32) -> SessionState {
        SessionState {
            id: crate::crypto::random(),
            current_key: SessionKey::generate(),
            pending_key: pipe.then(SessionKey::generate),
            pid: 4242,
            generation: 7,
            created_ms: 1_791_200_000_123,
            last_seen_ms_ago: 1500,
            exit: pipe.then(|| ExitState {
                status: ExitStatus::Signaled {
                    signal: "TERM".into(),
                    core_dumped: true,
                },
                published_ms_ago: None,
            }),
            name: Some("build".into()),
            command: (!pipe).then(|| "make -j8".into()),
            cols: 132,
            rows: 43,
            fds: if pipe {
                SessionFds::Pipe {
                    stdin: NO_FD,
                    stdout: fd,
                    stderr: fd + 1,
                }
            } else {
                SessionFds::Tty { master: fd }
            },
            output: BufferState {
                capacity: 1 << 20,
                base: 1_000_000,
                bytes: b"hello\r\nworld".to_vec(),
            },
            errors: if pipe {
                BufferState {
                    capacity: 65536,
                    base: 3,
                    bytes: b"oops".to_vec(),
                }
            } else {
                BufferState::default()
            },
            input_received: 99,
            input_queue: b"ls\n".to_vec(),
            input_eof: pipe.then_some(99),
            model: (!pipe).then(|| ModelState {
                cols: 132,
                rows: 43,
                snapshot: b"\x1b[H".to_vec(),
            }),
        }
    }

    fn state() -> State {
        State {
            writer: "qsh-server/0.3.0".into(),
            started_ms: 1_791_199_000_000,
            restarts: 2,
            failures: 1,
            options: DaemonOptions {
                on_demand: true,
                ports: Some((60443, 60542)),
            },
            refused: vec![
                Refused {
                    id: FileId {
                        dev: 2049,
                        ino: 1234,
                        ctime: 1_791_199_000,
                        ctime_ns: 5,
                    },
                    failed: true,
                },
                Refused {
                    id: FileId {
                        dev: 2049,
                        ino: 99,
                        ctime: -1,
                        ctime_ns: 999_999_999,
                    },
                    failed: false,
                },
            ],
            attempt: Some(FileId {
                dev: 2049,
                ino: 77,
                ctime: 1_791_199_001,
                ctime_ns: 0,
            }),
            port: 60443,
            listeners: vec![
                Listener {
                    kind: ListenerKind::Udp,
                    fd: 5,
                    port: 60443,
                },
                Listener {
                    kind: ListenerKind::Tcp,
                    fd: 6,
                    port: 60443,
                },
                Listener {
                    kind: ListenerKind::Udp,
                    fd: 7,
                    port: 443,
                },
                Listener {
                    kind: ListenerKind::Control,
                    fd: 8,
                    port: 0,
                },
                Listener {
                    kind: ListenerKind::Lock,
                    fd: 9,
                    port: 0,
                },
            ],
            sessions: vec![session(false, 20), session(true, 21)],
        }
    }

    fn same(a: &State, b: &State) {
        assert_eq!(
            (&a.writer, a.started_ms, a.restarts, a.failures, a.port, &a.listeners),
            (&b.writer, b.started_ms, b.restarts, b.failures, b.port, &b.listeners)
        );
        assert_eq!(
            (&a.options, &a.refused, &a.attempt),
            (&b.options, &b.refused, &b.attempt)
        );
        assert_eq!(a.sessions.len(), b.sessions.len());
        for (x, y) in a.sessions.iter().zip(&b.sessions) {
            assert_eq!(x.id, y.id);
            assert_eq!(x.current_key.0, y.current_key.0);
            assert_eq!(x.pending_key.as_ref().map(|k| k.0), y.pending_key.as_ref().map(|k| k.0));
            assert_eq!(
                (
                    x.pid,
                    x.generation,
                    x.created_ms,
                    x.last_seen_ms_ago,
                    &x.exit,
                    &x.name,
                    &x.command
                ),
                (
                    y.pid,
                    y.generation,
                    y.created_ms,
                    y.last_seen_ms_ago,
                    &y.exit,
                    &y.name,
                    &y.command
                )
            );
            assert_eq!(
                (x.cols, x.rows, x.fds, &x.output, &x.errors),
                (y.cols, y.rows, y.fds, &y.output, &y.errors)
            );
            assert_eq!(
                (x.input_received, &x.input_queue, x.input_eof, &x.model),
                (y.input_received, &y.input_queue, y.input_eof, &y.model)
            );
        }
    }

    /// The state survives encoding, sealing, opening and decoding exactly: sessions, keys,
    /// buffers, offsets, ports, descriptor numbers.
    #[test]
    fn a_state_round_trips_through_the_sealed_file() {
        let s = state();
        let bytes = encode(&s).unwrap();
        same(&decode(&bytes).unwrap(), &s);
        let (sealed, key) = crate::crypto::seal_state(bytes.clone()).unwrap();
        let file = crate::sys::anonymous_file(&std::env::temp_dir()).unwrap();
        use std::io::Write;
        (&file).write_all(&sealed).unwrap();
        same(&read_sealed(&file, &key).unwrap(), &s);
        // Tampering: refused, never parsed
        let mut bad = sealed.clone();
        let n = bad.len();
        bad[n / 2] ^= 0x40;
        let tampered = crate::sys::anonymous_file(&std::env::temp_dir()).unwrap();
        (&tampered).write_all(&bad).unwrap();
        let e = read_sealed(&tampered, &key).unwrap_err();
        assert!(e.to_string().contains("not authentic"), "{e}");
    }

    /// What is accepted encodes back to exactly the same bytes (the fuzz target checks this
    /// for arbitrary input).
    #[test]
    fn decoding_and_encoding_are_inverse() {
        let bytes = encode(&state()).unwrap();
        assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
    }

    /// What the fuzz target checks, on mutations of a valid state: never a panic; whatever is
    /// accepted names every descriptor once and encodes back to the same bytes.
    #[test]
    fn mutated_states_are_refused_or_canonical() {
        let valid = encode(&state()).unwrap();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut accepted = 0;
        for _ in 0..5000 {
            let mut bytes = valid.clone();
            for _ in 0..1 + next() % 3 {
                let at = (next() % bytes.len() as u64) as usize;
                match next() % 3 {
                    0 => bytes[at] ^= 1 << (next() % 8),
                    1 => bytes[at] = next() as u8,
                    _ => bytes.truncate(at),
                }
                if bytes.is_empty() {
                    break;
                }
            }
            if let Ok(s) = decode(&bytes) {
                accepted += 1;
                let mut fds = s.descriptors();
                let n = fds.len();
                fds.sort_unstable();
                fds.dedup();
                assert_eq!(fds.len(), n);
                assert_eq!(encode(&s).unwrap(), bytes);
            }
        }
        assert!(accepted > 0, "some mutations (of buffer bytes, say) are valid states");
    }

    /// Every prefix of a valid state is refused (truncation is detected wherever it happens),
    /// and so are trailing bytes.
    #[test]
    fn truncated_or_extended_states_are_refused() {
        let bytes = encode(&state()).unwrap();
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err(), "prefix of {n} bytes");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer).is_err());
    }

    /// The invariants the adopter relies on are checked, whatever the bytes say.
    #[test]
    fn invariants_are_checked() {
        let check = |f: &dyn Fn(&mut State), why: &str| {
            let mut s = state();
            f(&mut s);
            // Encoded by hand where encode would refuse it: encode checks the same things
            let bytes = match encode(&s) {
                Ok(b) => b,
                Err(_) => return,
            };
            assert!(decode(&bytes).is_err(), "{why}");
        };
        check(&|s| s.listeners[4].fd = 5, "a descriptor twice");
        check(
            &|s| {
                if let SessionFds::Tty { master } = &mut s.sessions[0].fds {
                    *master = 6
                }
            },
            "a session descriptor that is a listener's",
        );
        check(&|s| s.listeners[0].fd = 2, "stderr is not a listener");
        check(&|s| s.listeners.retain(|l| l.kind != ListenerKind::Lock), "no lock");
        check(&|s| s.sessions[1].id = s.sessions[0].id, "a session id twice");
        check(&|s| s.sessions[0].pid = 1, "init is never a session");
        check(&|s| s.options.ports = Some((2, 1)), "an empty port range");
        check(
            &|s| s.refused[0].id.ctime_ns = 1_000_000_000,
            "a change time beyond a second",
        );
        let mut s = state();
        s.refused = vec![s.refused[0]; MAX_REFUSED + 1];
        assert!(encode(&s).is_err(), "too many refused programs");
        // What encode refuses, decode refuses too
        let mut s = state();
        s.sessions[0].output.capacity = 4;
        assert!(encode(&s).is_err());
        let mut s = state();
        s.sessions[1].input_eof = Some(5);
        assert!(encode(&s).is_err());
        // A huge count with nothing behind it allocates nothing and fails
        let mut bytes = encode(&State {
            sessions: vec![],
            ..state()
        })
        .unwrap();
        let n = bytes.len();
        bytes[n - 4..].copy_from_slice(&(MAX_SESSIONS as u32).to_be_bytes());
        assert!(decode(&bytes).is_err());
        let mut wrong = encode(&state()).unwrap();
        wrong[12..14].copy_from_slice(&9u16.to_be_bytes());
        assert!(decode(&wrong).unwrap_err().0.contains("format 9"));
    }

    #[test]
    fn versions_compare_semantically() {
        assert!(newer("0.3.0", "0.2.1"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "1.0.0-rc.1"));
        assert!(newer("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(!newer("0.2.1", "0.2.1"));
        assert!(!newer("0.2.0", "0.2.1"));
        assert!(!newer("1.0.0-rc.1", "1.0.0"));
        assert!(!newer("x", "0.1.0"));
        assert!(!newer("0.3.0", "y"));
        assert!(!newer("0.3", "0.2.0"));
        assert!(newer("0.3.0+build5", "0.2.9"));
    }

    /// Review L4: pre-release tags compared as text made 1.0.0-rc.9 newer than 1.0.0-rc.10
    /// and 1.0.0-alpha.1 newer than 1.0.0-alpha. Semantic versioning 2.0.0, item 11.
    #[test]
    fn pre_releases_follow_semantic_versioning_precedence() {
        // The example of the specification, in increasing precedence
        let order = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for (i, a) in order.iter().enumerate() {
            for (j, b) in order.iter().enumerate() {
                assert_eq!(newer(a, b), i > j, "{a} newer than {b}");
            }
        }
        assert!(newer("1.0.0-rc.10", "1.0.0-rc.9"));
        assert!(!newer("1.0.0-rc.9", "1.0.0-rc.10"));
        // Numeric identifiers of any length
        assert!(newer("1.0.0-99999999999999999999999", "1.0.0-9999999999999999999999"));
        // Numeric lower than alphanumeric
        assert!(newer("1.0.0-a", "1.0.0-1"));
        // Build metadata does not count
        assert!(!newer("1.0.0+2", "1.0.0+1"));
        // Not semantic versions: never newer
        for bad in ["1.0.0-", "1.0.0-a..b", "1.0.0-01", "01.0.0", "1.0.0-a_b", "1.0.0-é"] {
            assert!(!newer(bad, "0.0.1"), "{bad}");
            assert!(!newer("9.9.9", bad), "{bad}");
        }
    }

    /// Review M3: the new image's command line is a frozen form, recognized before anything
    /// else is parsed; anything else in that position is not it.
    #[test]
    fn the_resume_command_line_round_trips_and_is_strict() {
        let os = |v: Vec<String>| v.into_iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        for r in [
            Resume {
                format: FORMAT,
                state_fd: 7,
                key_fd: 8,
                fallback_exe_fd: Some(9),
                fell_back: false,
            },
            Resume {
                format: FORMAT,
                state_fd: 70,
                key_fd: 3,
                fallback_exe_fd: None,
                fell_back: true,
            },
        ] {
            assert_eq!(Resume::from_args(&os(r.to_args())), Some(Ok(r)));
        }
        let parse = |words: &[&str]| Resume::from_args(&os(words.iter().map(|w| w.to_string()).collect()));
        assert_eq!(parse(&["qsh-server", "daemon", "--resume"]), None);
        assert_eq!(parse(&["qsh-server"]), None);
        for bad in [
            &["qsh-server", "handoff-resume"][..],
            &["qsh-server", "handoff-resume", "--format=1", "--state-fd=7"],
            &[
                "qsh-server",
                "handoff-resume",
                "--format=9",
                "--state-fd=7",
                "--key-fd=8",
            ],
            &[
                "qsh-server",
                "handoff-resume",
                "--format=1",
                "--state-fd=1",
                "--key-fd=8",
            ],
            &[
                "qsh-server",
                "handoff-resume",
                "--format=1",
                "--state-fd=7",
                "--key-fd=8",
                "--ports=1-2",
            ],
            &[
                "qsh-server",
                "handoff-resume",
                "--format=1",
                "--state-fd=7",
                "--state-fd=7",
                "--key-fd=8",
            ],
        ] {
            assert!(matches!(parse(bad), Some(Err(_))), "{bad:?}");
        }
    }

    #[test]
    fn the_probe_line_round_trips() {
        let line = probe_line("0.4.0");
        let p = parse_probe(format!("motd junk\n{line}\n").as_bytes()).unwrap();
        assert_eq!(p.version, "0.4.0");
        assert_eq!(p.formats, FORMATS);
        assert!(parse_probe(b"").is_err());
        assert!(parse_probe(b"{\"qsh-server\":\"1\"}").is_err());
    }

    /// 10.3 step 1: only a file this user (or root) controls is ever executed.
    #[test]
    fn only_a_safe_executable_is_accepted() {
        let dir = std::env::temp_dir().join(format!("qsh-handoff-exe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("qsh-server");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let set = |mode| std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(mode)).unwrap();
        // The directories above the test's own are not this test's business (/tmp)
        let check = |path: &Path| {
            std::env::set_var(TEST_TRUSTED_DIR, &dir);
            Exe::open(path).and_then(|e| e.check())
        };
        set(0o755);
        if cfg!(feature = "test-hooks") {
            assert_eq!(check(&exe), Ok(()));
        }
        set(0o775);
        assert!(check(&exe).unwrap_err().contains("writable by group"));
        set(0o757);
        assert!(check(&exe).is_err());
        set(0o644);
        assert!(check(&exe).unwrap_err().contains("not executable"));
        assert!(check(Path::new("qsh-server")).unwrap_err().contains("absolute"));
        assert!(check(&dir).unwrap_err().contains("regular file"));
        assert!(check(&dir.join("missing")).is_err());
        // A FIFO is not waited for
        let fifo = dir.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(check(&fifo).unwrap_err().contains("regular file"));
        std::env::remove_var(TEST_TRUSTED_DIR);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Review M1: every directory above the program is checked too. /tmp, which every user
    /// can write (sticky or not), cannot hold it; nor can a directory its group can write,
    /// unless that group is the user's private group.
    #[test]
    fn the_directories_above_the_program_are_checked() {
        let dir = std::env::temp_dir().join(format!("qsh-handoff-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("qsh-server");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let tmp_is_shared = std::fs::metadata(std::env::temp_dir()).unwrap().mode() & 0o002 != 0;
        if tmp_is_shared && !cfg!(feature = "test-hooks") {
            let error = Exe::open(&exe).and_then(|e| e.check()).unwrap_err();
            assert!(error.contains("every user can write"), "{error}");
        }
        // Through a symbolic link: the real directories are the ones checked
        let link = dir.join("link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let opened = Exe::open(&link).unwrap();
        // canonicalize: on macOS the temporary directory is /var/..., really /private/var/...
        assert_eq!(opened.real, exe.canonicalize().unwrap());
        let me = crate::sys::euid();
        let private = Some(4242);
        assert_eq!(dir_refusal(0, 0, 0o40755, me, None), None);
        assert_eq!(dir_refusal(me, 9, 0o40755, me, None), None);
        assert_eq!(
            dir_refusal(me + 1, 9, 0o40755, me, None),
            Some("belongs to another user")
        );
        assert_eq!(dir_refusal(0, 0, 0o41777, me, None), Some("every user can write"));
        assert_eq!(dir_refusal(me, 0, 0o40757, me, None), Some("every user can write"));
        assert_eq!(dir_refusal(0, 50, 0o42775, me, None), Some("its group can write"));
        assert_eq!(dir_refusal(me, 50, 0o40775, me, private), Some("its group can write"));
        assert_eq!(dir_refusal(me, 4242, 0o40775, me, private), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 10.3 step 2: a program that does not answer properly is not used.
    #[tokio::test]
    async fn the_probe_rejects_programs_that_do_not_answer() {
        let dir = std::env::temp_dir().join(format!("qsh-handoff-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let good = script(
            "good",
            r#"[ "$1" = handoff-probe ] && [ -z "$HOME" ] && echo '{"qsh-server":"9.0.0","handoff":[1]}'"#,
        );
        let run = |path: PathBuf| async move { probe(&Exe::open(&path)?).await };
        assert_eq!(
            run(good.clone()).await.unwrap(),
            Probe {
                version: "9.0.0".into(),
                formats: vec![1]
            }
        );
        assert!(run(script("fails", "exit 3")).await.unwrap_err().contains("failed"));
        assert!(run(script("junk", "echo hello"))
            .await
            .unwrap_err()
            .contains("did not answer"));
        assert!(run(dir.join("missing")).await.is_err());
        // Review M1: what runs is the file that was opened, not what its path names later
        let opened = Exe::open(&good).unwrap();
        let replaced = script("other", "echo '{\"qsh-server\":\"0.0.1\",\"handoff\":[1]}'");
        std::fs::rename(&replaced, &good).unwrap();
        let answer = probe(&opened).await;
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(answer.unwrap().version, "9.0.0");
        } else {
            assert!(answer.unwrap_err().contains("replaced"));
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
