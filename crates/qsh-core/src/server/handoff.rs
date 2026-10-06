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
use std::path::Path;
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

/// Largest screen model snapshot in a state.
pub const MAX_SNAPSHOT: usize = 16 << 20;

/// Largest command in a state.
pub const MAX_COMMAND: usize = 1 << 20;

/// Largest sealed state file a new image reads (64 GiB).
pub const MAX_STATE_FILE: u64 = 64 << 30;

/// A descriptor number that is not there (a closed pipe).
pub const NO_FD: u32 = u32::MAX;

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
// The executable to run, and its probe

/// Check `path` as the program of an upgrade (m2.md 10.3 step 1, security.md 4.8): an
/// absolute path to a regular file, owned by root or by this user, not writable by group or
/// others, executable.
pub fn validate_exe(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.uid() != 0 && meta.uid() != crate::sys::euid() {
        return Err(format!("{} belongs to another user", path.display()));
    }
    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group or others (mode {:o})",
            path.display(),
            mode & 0o7777
        ));
    }
    if mode & 0o111 == 0 {
        return Err(format!("{} is not executable", path.display()));
    }
    Ok(())
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
/// most [`PROBE_TIMEOUT`] and [`PROBE_MAX_OUTPUT`] bytes of output.
pub async fn probe(exe: &Path) -> Result<Probe, String> {
    use tokio::io::AsyncReadExt;
    let path = std::env::var_os("PATH").unwrap_or_else(|| super::pty::DEFAULT_PATH.into());
    let mut child = tokio::process::Command::new(exe)
        .arg("handoff-probe")
        .env_clear()
        .env("PATH", path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
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
        Ok(result) => result.map_err(|e| format!("{}: {e}", exe.display())),
        Err(_) => Err(format!(
            "{}: no answer to the version probe within {PROBE_TIMEOUT:?}",
            exe.display()
        )),
    }
}

/// A semantic version: (major, minor, patch, pre-release). None when unparseable.
fn parse_version(text: &str) -> Option<(u64, u64, u64, Option<&str>)> {
    let text = text.split('+').next()?;
    let (core, pre) = match text.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (text, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, pre))
}

/// True when version `a` is strictly newer than `b` (semantic versioning; a pre-release is
/// older than its release; pre-releases of the same version compare as text). Unparseable
/// versions are never newer.
pub fn newer(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (parse_version(a), parse_version(b)) else {
        return false;
    };
    if (a.0, a.1, a.2) != (b.0, b.1, b.2) {
        return (a.0, a.1, a.2) > (b.0, b.1, b.2);
    }
    match (a.3, b.3) {
        (None, Some(_)) => true,
        (Some(x), Some(y)) => x > y,
        _ => false,
    }
}

/// The identity of the file at `path` (device, inode), to notice that a package upgrade
/// replaced it (m2.md 10.2, upgrades when idle).
pub fn file_identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
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
        let exe = dir.join("qsh-server");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let set = |mode| std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(mode)).unwrap();
        set(0o755);
        assert_eq!(validate_exe(&exe), Ok(()));
        set(0o775);
        assert!(validate_exe(&exe).unwrap_err().contains("writable by group"));
        set(0o757);
        assert!(validate_exe(&exe).is_err());
        set(0o644);
        assert!(validate_exe(&exe).unwrap_err().contains("not executable"));
        assert!(validate_exe(Path::new("qsh-server")).unwrap_err().contains("absolute"));
        assert!(validate_exe(&dir).unwrap_err().contains("regular file"));
        assert!(validate_exe(&dir.join("missing")).is_err());
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
        assert_eq!(
            probe(&good).await.unwrap(),
            Probe {
                version: "9.0.0".into(),
                formats: vec![1]
            }
        );
        assert!(probe(&script("fails", "exit 3")).await.unwrap_err().contains("failed"));
        assert!(probe(&script("junk", "echo hello"))
            .await
            .unwrap_err()
            .contains("did not answer"));
        assert!(probe(&dir.join("missing")).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
