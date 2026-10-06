//! A session's program, on a pseudo terminal (a tty session) or on three pipes (a pipe
//! session, protocol.md 7.14), with its output in replay buffers (protocol.md section 7.1).
//!
//! Sessions live in the daemon, independent of any connection: the program keeps running and
//! its output keeps accumulating while no client is attached.
//!
//! Each session has plain threads for its blocking descriptors: one reader per output (the
//! pty master; or stdout and stderr), one writer for input, and one that waits for the program.
//! None of them keeps the session alive: they hold a weak reference, and every wait on a
//! descriptor can be cancelled ([`sys::Cancel`]), so hanging a session up (or dropping it)
//! closes its terminal or pipes at once, whatever its programs do.
//!
//! For an upgrade in place (m2.md section 10) the reader and writer threads stop and park
//! their descriptors and queues (`PtySession::request_pause`); the session's state is exported
//! with its descriptors by number, and the new image adopts both (`PtySession::adopt`). The
//! program is reaped by pid ([`sys::reap`]), so it is the same in either image.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Notify;

use super::handoff::{BufferState, ExitState, ModelState, SessionFds, SessionState, NO_FD};
use crate::crypto::SessionKey;
use crate::proto::ExitStatus;
use crate::session::{Inbound, ReplayBuffer};
use crate::sys;

/// Receives a session's output as it enters the output replay buffer (m2.md 6.2): the hook
/// through which the daemon's screen model is fed (work package WP-2), so that the model's state
/// at offset `E` is available whenever the buffer's end is `E`.
///
/// [`OutputSink::output`] is called on the session's reader thread **while the output buffer's
/// lock is held** ([`PtySession::output`]), with exactly the bytes appended, in order. It must
/// be quick and must not lock the output buffer itself or block on anything that may wait for
/// it. Code that needs the model and the buffer consistent (a snapshot at `end`) locks the
/// buffer first, then whatever the sink shares with it: always in that order.
pub trait OutputSink: Send {
    /// `bytes` were appended to the output stream at `offset` (the buffer's end is now
    /// `offset + bytes.len()`). Output that fell out of the buffer before the sink was set is
    /// never seen; see [`PtySession::set_output_sink`].
    fn output(&mut self, offset: u64, bytes: &[u8]);

    /// The model's state for an upgrade in place (m2.md 6.8 and 10.5): (columns, rows, a
    /// resync snapshot that reproduces it). Called with the session's threads stopped. The new
    /// image hands it out through [`PtySession::take_resumed_model`]. None (the default): the
    /// session continues without a model.
    fn handoff(&mut self) -> Option<(u16, u16, Vec<u8>)> {
        None
    }
}

/// The installed [`OutputSink`], if any.
struct SinkSlot(Option<Box<dyn OutputSink>>);

impl std::fmt::Debug for SinkSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "Some(OutputSink)" } else { "None" })
    }
}

/// A session id: 16 random bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// A new random id.
    pub fn generate() -> SessionId {
        SessionId(crate::crypto::random())
    }

    /// Lower-case hex, 32 digits.
    pub fn to_hex(&self) -> String {
        crate::crypto::hex(&self.0)
    }

    /// Parse 32 hex digits.
    pub fn from_hex(text: &str) -> Option<SessionId> {
        crate::crypto::unhex::<16>(text).map(SessionId)
    }
}

/// What to run in a new session.
#[derive(Debug, Clone, Default)]
pub struct Spawn {
    /// A command for the user's shell (`<shell> -c`), or None for a login shell.
    pub command: Option<String>,
    /// Terminal columns (tty sessions).
    pub cols: u16,
    /// Terminal rows (tty sessions).
    pub rows: u16,
    /// `TERM` (tty sessions).
    pub term: Option<String>,
    /// Accepted client variables (see `proto::bootstrap::accepted_env_name`).
    pub env: Vec<(String, String)>,
    /// A name for `qsh ls`.
    pub name: Option<String>,
    /// A pipe session (protocol.md 7.14): stdin, stdout and stderr are pipes, no terminal.
    pub pipe: bool,
}

/// Who the session runs as, and where.
#[derive(Debug, Clone)]
pub struct Account {
    /// The login name (`USER`, `LOGNAME`).
    pub user: String,
    /// The login shell.
    pub shell: PathBuf,
    /// The home directory, where sessions start.
    pub home: PathBuf,
    /// The user's `XDG_RUNTIME_DIR`, when the daemon knows it.
    pub runtime_dir: Option<PathBuf>,
}

/// The default `PATH` of sessions, as sshd sets it; login shells usually extend it.
pub const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// How long a hung up session's programs have between SIGHUP and SIGKILL (protocol.md 7.11).
pub const HANGUP_KILL_AFTER: Duration = Duration::from_secs(5);

/// The session key pair of section 6.5: a current key and at most one pending key.
#[derive(Debug, Clone)]
pub struct Keys {
    /// The key last confirmed (or issued by the bootstrap).
    pub current: SessionKey,
    /// The key sent in the last ATTACHED, until KEY_CONFIRM.
    pub pending: Option<SessionKey>,
}

/// The session's input stream as the server received it.
#[derive(Debug, Clone, Copy, Default)]
pub struct InputState {
    /// Input received (accepted into the input queue).
    pub inbound: Inbound,
    /// A pipe session's input was closed at this offset (INPUT_EOF, protocol.md 7.14.4).
    pub eof: Option<u64>,
}

/// One of a session's output streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// The terminal's output, or a pipe session's stdout.
    Output,
    /// A pipe session's stderr.
    Error,
}

enum InputItem {
    Data(Vec<u8>),
    /// Close the program's stdin (pipe sessions).
    Eof,
    /// Stop and park (an upgrade in place, m2.md 10.3 step 3).
    Park,
}

/// A stopped output reader: its descriptor and the sender that tells the waiter it reached
/// the end (it has not).
#[derive(Debug)]
struct ParkedReader {
    fd: File,
    done: Sender<()>,
}

/// The stopped input writer.
#[derive(Debug)]
struct ParkedInput {
    /// The program's input; None once closed (end of input, or broken).
    fd: Option<File>,
    /// Bytes accepted and not yet written, in order, before what `rx` holds.
    pending: Vec<u8>,
    /// Close the input after `pending`.
    eof: bool,
    rx: Receiver<InputItem>,
}

/// The descriptors and queues of a session's threads while they do not run: before they
/// start, and while an upgrade in place has them stopped (m2.md 10.3 step 3). The upgrade
/// exports them; resuming (in this image or the next) starts the threads on them again.
#[derive(Debug, Default)]
struct Parked {
    output: Option<ParkedReader>,
    error: Option<ParkedReader>,
    input: Option<ParkedInput>,
}

/// One session: a program on a pty or on pipes, and the state that outlives connections.
#[derive(Debug)]
pub struct PtySession {
    /// The session id.
    pub id: SessionId,
    /// The valid keys.
    pub keys: Mutex<Keys>,
    /// A pipe session (protocol.md 7.14) rather than a tty session.
    pub pipe: bool,
    /// The pty master, for window sizes (tty sessions; None once hung up).
    master: Mutex<Option<File>>,
    input: Mutex<Option<Sender<InputItem>>>,
    /// Input bytes queued for the program and not yet written (section 7.4).
    input_queued: Arc<AtomicUsize>,
    /// Woken when the program took input from the queue: input an attachment holds may fit.
    pub input_drained: Arc<Notify>,
    /// Output produced by the program: a pipe session's stdout, kept until acknowledged; on a
    /// tty session kept as scrollback, acknowledged or not, the oldest dropped past capacity.
    pub output: Mutex<ReplayBuffer>,
    /// A pipe session's stderr, kept until acknowledged (empty on a tty session).
    pub errors: Mutex<ReplayBuffer>,
    /// Fed with the output as it enters [`PtySession::output`], under its lock.
    sink: Mutex<SinkSlot>,
    /// Woken when acknowledgements make room in a pipe session's buffers.
    room: Condvar,
    /// Input received from clients, and its end.
    pub input_received: Mutex<InputState>,
    /// Woken on new output, the program's end, a newer attach and removal.
    pub changed: Notify,
    exit: Mutex<Option<ExitStatus>>,
    /// Counts attaches: a channel serving an older attach stops (SESSION_TAKEN_OVER).
    pub generation: AtomicU64,
    /// The last time a client was attached or active.
    pub last_seen: Mutex<Instant>,
    exited_at: Mutex<Option<Instant>>,
    attached: AtomicUsize,
    /// Set when the session was removed (HANGUP, kill, TTL): attachments end.
    removed: AtomicBool,
    /// Cancelled on hangup, on drop, and to stop the threads for an upgrade: the threads let
    /// go of the terminal or pipes. A new one for every start of the threads.
    cancel: Mutex<Arc<sys::Cancel>>,
    /// Set while the threads stop for an upgrade: they park their descriptors instead of
    /// closing them.
    pausing: Arc<AtomicBool>,
    /// The threads' descriptors and queues while they do not run.
    parked: Mutex<Parked>,
    /// Threads that hold one of the session's descriptors, still running.
    io_threads: Arc<AtomicUsize>,
    /// The program's status once it was reaped (under this lock): its process group may no
    /// longer be signalled after that, its id could be reused.
    reaped: Arc<Mutex<Option<ExitStatus>>>,
    /// The screen model handed over by the previous image of the daemon (m2.md 6.8), for the
    /// model's owner to take ([`PtySession::take_resumed_model`]).
    resumed_model: Mutex<Option<ModelState>>,
    /// The program's pid, also its process group.
    pub pid: u32,
    /// The command, None for a login shell.
    pub command: Option<String>,
    /// The session's name.
    pub name: Option<String>,
    /// When the session started.
    pub started: SystemTime,
}

/// How the parts of a new [`PtySession`] are put together.
struct Parts {
    id: SessionId,
    keys: Keys,
    pipe: bool,
    master: Option<File>,
    input: Sender<InputItem>,
    input_queued: usize,
    output: ReplayBuffer,
    errors: ReplayBuffer,
    input_received: InputState,
    generation: u64,
    last_seen: Instant,
    exit: Option<(ExitStatus, Instant)>,
    parked: Parked,
    reaped: Option<ExitStatus>,
    model: Option<ModelState>,
    pid: u32,
    command: Option<String>,
    name: Option<String>,
    started: SystemTime,
}

impl PtySession {
    fn assemble(p: Parts) -> io::Result<Arc<PtySession>> {
        Ok(Arc::new(PtySession {
            id: p.id,
            keys: Mutex::new(p.keys),
            pipe: p.pipe,
            master: Mutex::new(p.master),
            input: Mutex::new(Some(p.input)),
            input_queued: Arc::new(AtomicUsize::new(p.input_queued)),
            input_drained: Arc::new(Notify::new()),
            output: Mutex::new(p.output),
            errors: Mutex::new(p.errors),
            sink: Mutex::new(SinkSlot(None)),
            room: Condvar::new(),
            input_received: Mutex::new(p.input_received),
            changed: Notify::new(),
            exit: Mutex::new(p.exit.as_ref().map(|e| e.0.clone())),
            generation: AtomicU64::new(p.generation),
            last_seen: Mutex::new(p.last_seen),
            exited_at: Mutex::new(p.exit.map(|e| e.1)),
            attached: AtomicUsize::new(0),
            removed: AtomicBool::new(false),
            cancel: Mutex::new(Arc::new(sys::Cancel::new()?)),
            pausing: Arc::new(AtomicBool::new(false)),
            parked: Mutex::new(p.parked),
            io_threads: Arc::new(AtomicUsize::new(0)),
            reaped: Arc::new(Mutex::new(p.reaped)),
            resumed_model: Mutex::new(p.model),
            pid: p.pid,
            command: p.command,
            name: p.name,
            started: p.started,
        }))
    }

    /// Start `spawn` as `account`, on a new pty or on pipes, keeping `replay_capacity` bytes
    /// of output (and, for a pipe session, an eighth of that of stderr, at least 64 KiB).
    pub fn start(
        id: SessionId,
        key: SessionKey,
        spawn: &Spawn,
        account: &Account,
        replay_capacity: usize,
    ) -> io::Result<Arc<PtySession>> {
        let mut cmd = Command::new(&account.shell);
        let shell_name = account
            .shell
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "sh".into());
        match &spawn.command {
            // Like sshd: the user's shell runs the command
            Some(command) => {
                cmd.arg("-c").arg(command);
            }
            // A login shell, as login(1) and sshd start it: argv[0] begins with '-'
            None => {
                cmd.arg0(format!("-{shell_name}"));
            }
        }
        // Nothing of the daemon's own environment (section 10.3): it was inherited from
        // whatever ssh session happened to start the daemon
        cmd.env_clear()
            .current_dir(&account.home)
            .env("HOME", &account.home)
            .env("USER", &account.user)
            .env("LOGNAME", &account.user)
            .env("SHELL", &account.shell)
            .env("PATH", DEFAULT_PATH)
            .env("QSH_SESSION", id.to_hex());
        if let Some(dir) = &account.runtime_dir {
            cmd.env("XDG_RUNTIME_DIR", dir);
        }
        for (name, value) in &spawn.env {
            if crate::proto::bootstrap::accepted_env_name(name) && !value.contains('\0') {
                cmd.env(name, value);
            }
        }

        // The descriptors: (reader of output, reader of stderr, writer of input, pty master)
        let (child, output_fd, error_fd, input_fd, master) = if spawn.pipe {
            // As ssh without a pty: no TERM
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            sys::spawn_with_pipes(&mut cmd);
            let mut child = cmd.spawn()?;
            let take = |e: Option<std::os::fd::OwnedFd>| e.map(File::from).ok_or_else(|| io::Error::other("no pipe"));
            let stdin = take(child.stdin.take().map(Into::into))?;
            let stdout = take(child.stdout.take().map(Into::into))?;
            let stderr = take(child.stderr.take().map(Into::into))?;
            (child, stdout, Some(stderr), stdin, None)
        } else {
            let cols = if spawn.cols == 0 { 80 } else { spawn.cols };
            let rows = if spawn.rows == 0 { 24 } else { spawn.rows };
            let (master, slave) = sys::openpty(cols, rows)?;
            let slave = File::from(slave);
            cmd.env(
                "TERM",
                spawn
                    .term
                    .as_deref()
                    .filter(|t| valid_term(t))
                    .unwrap_or("xterm-256color"),
            )
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
            sys::spawn_on_pty(&mut cmd);
            let child = cmd.spawn()?;
            let master = File::from(master);
            (child, master.try_clone()?, None, master.try_clone()?, Some(master))
        };
        for fd in [Some(&output_fd), error_fd.as_ref(), Some(&input_fd)]
            .into_iter()
            .flatten()
        {
            sys::set_nonblocking(fd)?;
        }
        let pid = child.id();
        // Reaped by pid (sys::reap): after an upgrade in place no Child value exists, and the
        // same waiter serves both cases
        drop(child);

        let (input_tx, input_rx) = channel::<InputItem>();
        let (done_tx, done_rx) = channel::<()>();
        let readers = if spawn.pipe { 2 } else { 1 };
        let parked = Parked {
            output: Some(ParkedReader {
                fd: output_fd,
                done: done_tx.clone(),
            }),
            error: error_fd.map(|fd| ParkedReader {
                fd,
                done: done_tx.clone(),
            }),
            input: Some(ParkedInput {
                fd: Some(input_fd),
                pending: Vec::new(),
                eof: false,
                rx: input_rx,
            }),
        };
        drop(done_tx);
        let error_capacity = (replay_capacity / 8).max(64 << 10);
        let session = PtySession::assemble(Parts {
            id,
            keys: Keys {
                current: key,
                pending: None,
            },
            pipe: spawn.pipe,
            master,
            input: input_tx,
            input_queued: 0,
            output: ReplayBuffer::new(replay_capacity),
            errors: ReplayBuffer::new(if spawn.pipe { error_capacity } else { 0 }),
            input_received: InputState::default(),
            generation: 0,
            last_seen: Instant::now(),
            exit: None,
            parked,
            reaped: None,
            model: None,
            pid,
            command: spawn.command.clone(),
            name: spawn.name.clone(),
            started: SystemTime::now(),
        })?;
        session.resume_threads()?;
        spawn_waiter(&session, None, done_rx, readers)?;
        Ok(session)
    }

    /// Start (again) the reader and writer threads on the parked descriptors: after
    /// [`PtySession::start`] and [`PtySession::adopt`], and when an upgrade that stopped them
    /// failed (m2.md 10.3 step 6). A removed session's parked descriptors are closed instead.
    pub(crate) fn resume_threads(self: &Arc<Self>) -> io::Result<()> {
        let cancel = Arc::new(sys::Cancel::new()?);
        *self.cancel.lock().unwrap() = cancel.clone();
        self.pausing.store(false, Ordering::SeqCst);
        let parked = std::mem::take(&mut *self.parked.lock().unwrap());
        if self.is_removed() {
            return Ok(());
        }
        if let Some(reader) = parked.output {
            spawn_reader(self, reader, Stream::Output, &cancel)?;
        }
        if let Some(reader) = parked.error {
            spawn_reader(self, reader, Stream::Error, &cancel)?;
        }
        if let Some(input) = parked.input {
            spawn_writer(self, input, &cancel)?;
        }
        Ok(())
    }

    /// Tell the reader and writer threads to stop and park their descriptors and queues (m2.md
    /// 10.3 step 3); [`PtySession::threads_running`] says when they have. Output the program
    /// writes meanwhile waits in the kernel's terminal or pipe buffer.
    pub(crate) fn request_pause(&self) {
        self.pausing.store(true, Ordering::SeqCst);
        self.cancel.lock().unwrap().cancel();
        if let Some(input) = self.input.lock().unwrap().as_ref() {
            let _ = input.send(InputItem::Park);
        }
        self.room.notify_all();
    }

    /// Reader and writer threads still running.
    pub(crate) fn threads_running(&self) -> usize {
        self.io_threads.load(Ordering::SeqCst)
    }

    /// The session's state for the handoff (m2.md 10.5), with its descriptors by number; the
    /// threads must be stopped ([`PtySession::request_pause`]). None for a removed session.
    /// The descriptors stay owned by this session: they must stay open until the `execve`.
    pub(crate) fn export(&self) -> Option<SessionState> {
        if self.is_removed() {
            return None;
        }
        // Under the input lock no attachment accepts input: what was accepted is in the
        // writer's queue or still in its channel, and both go into the state
        let input = self.input_received.lock().unwrap();
        let mut parked = self.parked.lock().unwrap();
        if let Some(p) = parked.input.as_mut() {
            while let Ok(item) = p.rx.try_recv() {
                match item {
                    InputItem::Data(bytes) => p.pending.extend_from_slice(&bytes),
                    InputItem::Eof => p.eof = true,
                    InputItem::Park => {}
                }
            }
        }
        let raw = |f: &File| f.as_raw_fd() as u32;
        let (fds, cols, rows) = if self.pipe {
            let reader = |r: &Option<ParkedReader>| r.as_ref().map_or(NO_FD, |r| raw(&r.fd));
            let fds = SessionFds::Pipe {
                stdin: parked.input.as_ref().and_then(|p| p.fd.as_ref()).map_or(NO_FD, raw),
                stdout: reader(&parked.output),
                stderr: reader(&parked.error),
            };
            (fds, 0, 0)
        } else {
            let master = self.master.lock().unwrap();
            let master = master.as_ref()?;
            let (cols, rows) = sys::window_size(master).unwrap_or((80, 24));
            (SessionFds::Tty { master: raw(master) }, cols, rows)
        };
        let buffer = |b: &Mutex<ReplayBuffer>| {
            let b = b.lock().unwrap();
            BufferState {
                capacity: b.capacity() as u64,
                base: b.base(),
                bytes: b.read_from(b.base(), usize::MAX).1,
            }
        };
        let output = buffer(&self.output);
        let errors = buffer(&self.errors);
        let model = self.sink.lock().unwrap().0.as_mut().and_then(|s| s.handoff());
        let exit = match (self.exit_status(), *self.exited_at.lock().unwrap()) {
            (Some(status), Some(at)) => Some(ExitState {
                status,
                published_ms_ago: Some(at.elapsed().as_millis() as u64),
            }),
            _ => self.reaped.lock().unwrap().clone().map(|status| ExitState {
                status,
                published_ms_ago: None,
            }),
        };
        let keys = self.keys.lock().unwrap().clone();
        let pending = parked.input.as_ref().map(|p| p.pending.clone()).unwrap_or_default();
        Some(SessionState {
            id: self.id.0,
            current_key: keys.current,
            pending_key: keys.pending,
            pid: self.pid,
            generation: self.current_generation(),
            created_ms: self
                .started
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            last_seen_ms_ago: self.last_seen.lock().unwrap().elapsed().as_millis() as u64,
            exit,
            name: self.name.clone(),
            command: self.command.clone(),
            cols,
            rows,
            fds,
            output,
            errors,
            input_received: input.inbound.received(),
            input_queue: pending,
            input_eof: input.eof,
            model: model.map(|(cols, rows, snapshot)| ModelState { cols, rows, snapshot }),
        })
    }

    /// Rebuild a session from the previous image's state and the descriptors it handed over
    /// (m2.md 10.3 step 8), without starting anything: [`Adopted::start`] does that, once the
    /// new image is committed to the state.
    pub(crate) fn adopt(state: SessionState, fds: AdoptedFds) -> io::Result<Adopted> {
        let now = Instant::now();
        let ago = |ms: u64| now.checked_sub(Duration::from_millis(ms)).unwrap_or(now);
        let restore = |b: &BufferState| {
            let mut buffer = ReplayBuffer::starting_at(b.capacity as usize, b.base);
            buffer.push(&b.bytes);
            buffer
        };
        let (input_tx, input_rx) = channel::<InputItem>();
        let (done_tx, done_rx) = channel::<()>();
        let pipe = state.pipe();
        let mut readers = 0;
        let mut reader = |fd: Option<File>| {
            fd.map(|fd| {
                readers += 1;
                ParkedReader {
                    fd,
                    done: done_tx.clone(),
                }
            })
        };
        let (master, output, error, input_fd) = if pipe {
            (None, reader(fds.stdout), reader(fds.stderr), fds.stdin)
        } else {
            let master = fds
                .master
                .ok_or_else(|| io::Error::other("a tty session without its terminal"))?;
            (
                Some(master.try_clone()?),
                reader(Some(master.try_clone()?)),
                None,
                Some(master),
            )
        };
        drop(done_tx);
        for fd in [&output, &error].into_iter().flatten() {
            sys::set_nonblocking(&fd.fd)?;
        }
        if let Some(fd) = &input_fd {
            sys::set_nonblocking(fd)?;
        }
        // The end of input still to deliver: received, and the pipe still open
        let eof = state.input_eof.is_some() && input_fd.is_some();
        let published = state
            .exit
            .as_ref()
            .and_then(|e| e.published_ms_ago.map(|ms| (e.status.clone(), ago(ms))));
        let reaped = state.exit.as_ref().map(|e| e.status.clone());
        let waiter = match (&published, &reaped) {
            (Some(_), _) => None,
            (None, known) => Some(Waiter {
                known: known.clone(),
                done: done_rx,
                readers,
            }),
        };
        let session = PtySession::assemble(Parts {
            id: SessionId(state.id),
            keys: Keys {
                current: state.current_key.clone(),
                pending: state.pending_key.clone(),
            },
            pipe,
            master,
            input: input_tx,
            input_queued: state.input_queue.len(),
            output: restore(&state.output),
            errors: restore(&state.errors),
            input_received: InputState {
                inbound: Inbound::at(state.input_received),
                eof: state.input_eof,
            },
            generation: state.generation,
            last_seen: ago(state.last_seen_ms_ago),
            exit: published,
            parked: Parked {
                output,
                error,
                input: Some(ParkedInput {
                    fd: input_fd,
                    pending: state.input_queue.clone(),
                    eof,
                    rx: input_rx,
                }),
            },
            reaped,
            model: state.model.clone(),
            pid: state.pid,
            command: state.command.clone(),
            name: state.name.clone(),
            started: std::time::UNIX_EPOCH + Duration::from_millis(state.created_ms),
        })?;
        Ok(Adopted { session, waiter })
    }

    /// The screen model the previous image of the daemon handed over (m2.md 6.8), once.
    pub fn take_resumed_model(&self) -> Option<ModelState> {
        self.resumed_model.lock().unwrap().take()
    }

    /// Install `sink` for the output stream (or remove it with None), and return the output
    /// offset from which it sees everything. Under the output buffer's lock, it is first given
    /// what the buffer holds (from its `base`), so that a sink installed right after
    /// [`PtySession::start`] misses nothing the program wrote meanwhile; then every new chunk.
    pub fn set_output_sink(&self, sink: Option<Box<dyn OutputSink>>) -> u64 {
        let buffer = self.output.lock().unwrap();
        let mut slot = self.sink.lock().unwrap();
        slot.0 = sink;
        let base = buffer.base();
        if let Some(sink) = slot.0.as_mut() {
            let (offset, held) = buffer.read_from(base, usize::MAX);
            if !held.is_empty() {
                sink.output(offset, &held);
            }
        }
        base
    }

    /// The replay buffer of `stream`.
    pub fn buffer(&self, stream: Stream) -> &Mutex<ReplayBuffer> {
        match stream {
            Stream::Output => &self.output,
            Stream::Error => &self.errors,
        }
    }

    /// The client acknowledged `stream` up to `offset`. A pipe session forgets what is before it,
    /// which lets its program write again if it was held back. A tty session keeps it, up to
    /// the buffer's capacity, as scrollback: a new client process attaching (FRESH, from 0) gets
    /// the recent output, not a blank screen (protocol.md 7.2 and 7.5 allow either).
    pub fn ack(&self, stream: Stream, offset: u64) {
        if self.pipe {
            self.buffer(stream).lock().unwrap().ack(offset);
        }
        self.room.notify_all();
    }

    /// Bytes typed by the client, in order, into the session's input queue.
    pub fn write_input(&self, bytes: Vec<u8>) {
        if let Some(input) = self.input.lock().unwrap().as_ref() {
            let n = bytes.len();
            self.input_queued.fetch_add(n, Ordering::SeqCst);
            if input.send(InputItem::Data(bytes)).is_err() {
                self.input_queued.fetch_sub(n, Ordering::SeqCst);
            }
        }
    }

    /// Close the program's stdin once the input queued before is written (pipe sessions).
    pub fn close_input(&self) {
        if let Some(input) = self.input.lock().unwrap().as_ref() {
            let _ = input.send(InputItem::Eof);
        }
    }

    /// Input bytes waiting to be written to the program.
    pub fn input_queued(&self) -> usize {
        self.input_queued.load(Ordering::SeqCst)
    }

    /// Resize the terminal; the program gets SIGWINCH. Zero sizes are ignored, huge ones
    /// clamped; pipe sessions have no terminal.
    pub fn resize(&self, cols: u16, rows: u16) {
        if cols > 0 && rows > 0 {
            if let Some(master) = self.master.lock().unwrap().as_ref() {
                let _ = sys::set_window_size(master, cols.min(4096), rows.min(4096));
            }
        }
    }

    /// Make the program redraw its screen (as on SIGWINCH): shrink by a row and back. Used
    /// after an OUTPUT_GAP (section 7.7).
    pub fn redraw(&self) {
        if let Some(master) = self.master.lock().unwrap().as_ref() {
            if let Some((cols, rows)) = sys::window_size(master) {
                let _ = sys::set_window_size(master, cols, rows.saturating_sub(1).max(1));
                let _ = sys::set_window_size(master, cols, rows);
            }
        }
    }

    /// How the program ended, once it did and its output was read.
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.exit.lock().unwrap().clone()
    }

    /// How long ago the program ended.
    pub fn exited_for(&self) -> Option<Duration> {
        self.exited_at.lock().unwrap().map(|t| t.elapsed())
    }

    /// Note that a client is attached or active now.
    pub fn touch(&self) {
        *self.last_seen.lock().unwrap() = Instant::now();
    }

    /// Count a connection attached until the guard is dropped.
    pub fn attach_guard(self: &Arc<Self>) -> AttachGuard {
        self.attached.fetch_add(1, Ordering::SeqCst);
        self.touch();
        AttachGuard(self.clone())
    }

    /// Channels attached right now.
    pub fn attached(&self) -> usize {
        self.attached.load(Ordering::SeqCst)
    }

    /// The attach generation now.
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// True once the session was removed.
    pub fn is_removed(&self) -> bool {
        self.removed.load(Ordering::SeqCst)
    }

    /// Hang the session up (protocol.md 7.11, step 1 and 5): SIGHUP to its process group, its
    /// side of the terminal (the pty master) or of the pipes closed, SIGKILL to the group if it
    /// still exists [`HANGUP_KILL_AFTER`] later. Attachments notice through
    /// [`PtySession::is_removed`]. Only the first call does anything.
    pub fn hang_up(&self) {
        if self.removed.swap(true, Ordering::SeqCst) {
            return;
        }
        {
            let reaped = self.reaped.lock().unwrap();
            if reaped.is_none() {
                let _ = sys::kill_group(self.pid, sys::Signal::Hangup);
                let (pid, reaped) = (self.pid, self.reaped.clone());
                let _ = std::thread::Builder::new()
                    .name("qsh-session-kill".into())
                    .spawn(move || {
                        std::thread::sleep(HANGUP_KILL_AFTER);
                        let reaped = reaped.lock().unwrap();
                        if reaped.is_none() {
                            let _ = sys::kill_group(pid, sys::Signal::Kill);
                        }
                    });
            }
        }
        // The readers and the writer let go of the master or the pipes; with ours, the
        // terminal is hung up (or the pipes closed)
        self.cancel.lock().unwrap().cancel();
        self.master.lock().unwrap().take();
        self.input.lock().unwrap().take();
        *self.parked.lock().unwrap() = Parked::default();
        self.room.notify_all();
        self.changed.notify_waiters();
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Whatever happened, the threads let go of the terminal or the pipes
        match self.cancel.get_mut() {
            Ok(cancel) => cancel.cancel(),
            Err(poisoned) => poisoned.into_inner().cancel(),
        }
    }
}

/// The descriptors handed over for one session by the previous image ([`PtySession::adopt`]),
/// checked and owned.
#[derive(Debug, Default)]
pub(crate) struct AdoptedFds {
    /// A tty session's master.
    pub master: Option<File>,
    /// A pipe session's stdin (None: closed).
    pub stdin: Option<File>,
    /// A pipe session's stdout (None: it reached its end).
    pub stdout: Option<File>,
    /// A pipe session's stderr (None: it reached its end).
    pub stderr: Option<File>,
}

/// What waits for an adopted session's program.
#[derive(Debug)]
struct Waiter {
    /// The status, when the previous image had reaped the program already.
    known: Option<ExitStatus>,
    done: Receiver<()>,
    readers: usize,
}

/// A session rebuilt from a handoff state, not started yet.
#[derive(Debug)]
pub(crate) struct Adopted {
    /// The session.
    pub session: Arc<PtySession>,
    waiter: Option<Waiter>,
}

impl Adopted {
    /// Start its threads: the readers, the writer and, unless the program's end was already
    /// published, the waiter (the program is still this process's child: a zombie if it ended
    /// during the upgrade, waiting for exactly this).
    pub fn start(self) -> io::Result<Arc<PtySession>> {
        self.session.resume_threads()?;
        if let Some(w) = self.waiter {
            spawn_waiter(&self.session, w.known, w.done, w.readers)?;
        }
        Ok(self.session)
    }
}

/// Wait for the program to end, reap it (unless `known`), wait for its output to reach its
/// end, then publish the status.
fn spawn_waiter(
    session: &Arc<PtySession>,
    known: Option<ExitStatus>,
    done: Receiver<()>,
    readers: usize,
) -> io::Result<()> {
    let weak = Arc::downgrade(session);
    let reaped = session.reaped.clone();
    let (pid, pipe) = (session.pid, session.pipe);
    std::thread::Builder::new()
        .name("qsh-session-wait".into())
        .spawn(move || {
            let status = match known {
                Some(status) => status,
                None => {
                    // Wait without reaping, then reap under the lock that signalling takes:
                    // the process group is never signalled after its id could have been reused
                    let _ = sys::wait_exit_no_reap(pid);
                    let mut reaped = reaped.lock().unwrap();
                    let status = match sys::reap(pid) {
                        Ok(exit) => match (exit.code, exit.signal) {
                            (Some(code), _) => ExitStatus::Exited(code as u32 & 0xff),
                            (None, Some(signal)) => ExitStatus::Signaled {
                                signal: sys::signal_name(signal),
                                core_dumped: exit.core_dumped,
                            },
                            (None, None) => ExitStatus::Exited(255),
                        },
                        Err(_) => ExitStatus::Exited(255),
                    };
                    *reaped = Some(status.clone());
                    status
                }
            };
            if pipe {
                // As ssh: the end is when the program is gone and both pipes reached their end
                // (a background process holding one open delays it)
                for _ in 0..readers {
                    if done.recv().is_err() {
                        break;
                    }
                }
            } else {
                // The output ends when the reader reaches the end of the pty; a background
                // process that keeps the terminal open must not hold the EXIT back for long
                let _ = done.recv_timeout(Duration::from_millis(500));
            }
            if let Some(s) = weak.upgrade() {
                *s.exit.lock().unwrap() = Some(status);
                *s.exited_at.lock().unwrap() = Some(Instant::now());
                s.changed.notify_waiters();
            }
        })?;
    Ok(())
}

/// Read one output of a session into its replay buffer until the end, an error, a hangup or
/// a pause. A pipe session's reader stops reading while the buffer is full of unacknowledged
/// bytes, so the program blocks as under ssh (protocol.md 7.14.5).
fn spawn_reader(
    session: &Arc<PtySession>,
    reader: ParkedReader,
    stream: Stream,
    cancel: &Arc<sys::Cancel>,
) -> io::Result<()> {
    let weak = Arc::downgrade(session);
    let cancel = cancel.clone();
    let pausing = session.pausing.clone();
    let bounded = session.pipe;
    let running = IoThread::start(&session.io_threads);
    std::thread::Builder::new()
        .name("qsh-session-out".into())
        .spawn(move || {
            let ParkedReader { fd, done } = reader;
            if read_output(&fd, stream, bounded, &weak, &cancel, &pausing) {
                if let Some(s) = weak.upgrade() {
                    let mut parked = s.parked.lock().unwrap();
                    let slot = match stream {
                        Stream::Output => &mut parked.output,
                        Stream::Error => &mut parked.error,
                    };
                    *slot = Some(ParkedReader { fd, done });
                    drop(parked);
                    drop(running);
                    return;
                }
            }
            drop(fd);
            drop(running);
            let _ = done.send(());
        })?;
    Ok(())
}

/// Counts a thread that holds a session descriptor while it runs.
struct IoThread(Arc<AtomicUsize>);

impl IoThread {
    fn start(count: &Arc<AtomicUsize>) -> IoThread {
        count.fetch_add(1, Ordering::SeqCst);
        IoThread(count.clone())
    }
}

impl Drop for IoThread {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The reader's loop. True when it stopped for a pause (its descriptor is to be parked), false
/// when the output ended (or failed, or the session was hung up).
fn read_output(
    mut fd: &File,
    stream: Stream,
    bounded: bool,
    weak: &Weak<PtySession>,
    cancel: &sys::Cancel,
    pausing: &AtomicBool,
) -> bool {
    let stopped = || pausing.load(Ordering::SeqCst);
    let mut buf = vec![0u8; 16384];
    loop {
        // Checked on every round, not only when waiting: a program that floods its output
        // never lets the reader wait
        if cancel.is_cancelled() {
            return stopped();
        }
        let mut limit = buf.len();
        if bounded {
            let Some(s) = weak.upgrade() else { return false };
            let replay = s.buffer(stream).lock().unwrap();
            let room = replay.capacity() - replay.len();
            if room == 0 {
                // Full of unacknowledged bytes: wait for acknowledgements (without keeping the
                // session alive in between)
                if cancel.is_cancelled() {
                    return stopped();
                }
                let _ = s.room.wait_timeout(replay, Duration::from_millis(200)).unwrap();
                continue;
            }
            limit = limit.min(room);
        }
        match fd.read(&mut buf[..limit]) {
            // EIO on a pty once the program and everything it started closed the terminal.
            // The server keeps reading whether or not anyone is attached (7.6).
            Ok(0) => return false,
            Ok(n) => {
                let Some(s) = weak.upgrade() else { return false };
                {
                    let mut buffer = s.buffer(stream).lock().unwrap();
                    let offset = buffer.end();
                    buffer.push(&buf[..n]);
                    if stream == Stream::Output {
                        // Under the buffer's lock (m2.md 6.2)
                        if let Some(sink) = s.sink.lock().unwrap().0.as_mut() {
                            sink.output(offset, &buf[..n]);
                        }
                    }
                }
                s.changed.notify_waiters();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match sys::wait_fd(fd, false, cancel, None) {
                Ok(sys::Ready::Cancelled) => return stopped(),
                Err(_) => return false,
                Ok(_) => {}
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// Write the session's input queue to the program, in order. Input after the terminal or pipe
/// closed (or after a hangup) is accepted and discarded (7.4). A pause parks the descriptor
/// and whatever is not written yet.
fn spawn_writer(session: &Arc<PtySession>, input: ParkedInput, cancel: &Arc<sys::Cancel>) -> io::Result<()> {
    let weak = Arc::downgrade(session);
    let cancel = cancel.clone();
    let pausing = session.pausing.clone();
    let queued = session.input_queued.clone();
    let drained = session.input_drained.clone();
    let running = IoThread::start(&session.io_threads);
    std::thread::Builder::new()
        .name("qsh-session-in".into())
        .spawn(move || {
            if let Some(parked) = write_input(input, &queued, &drained, &cancel, &pausing) {
                if let Some(s) = weak.upgrade() {
                    s.parked.lock().unwrap().input = Some(parked);
                }
            }
            drop(running);
        })?;
    Ok(())
}

/// The writer's loop: the parked input to park again after a pause, None when it ended.
fn write_input(
    input: ParkedInput,
    queued: &AtomicUsize,
    drained: &Notify,
    cancel: &sys::Cancel,
    pausing: &AtomicBool,
) -> Option<ParkedInput> {
    let ParkedInput {
        mut fd,
        mut pending,
        mut eof,
        rx,
    } = input;
    loop {
        let paused = pausing.load(Ordering::SeqCst);
        if !paused && !pending.is_empty() {
            let written = match fd.as_ref() {
                Some(f) => match write_some(f, &pending, cancel) {
                    Ok(()) => pending.len(),
                    Err((n, cancelled)) => {
                        if !(cancelled && pausing.load(Ordering::SeqCst)) {
                            // Closed, broken, or hung up: the rest is discarded
                            fd = None;
                            pending.len()
                        } else {
                            n
                        }
                    }
                },
                None => pending.len(),
            };
            queued.fetch_sub(written, Ordering::SeqCst);
            pending.drain(..written);
            if written > 0 {
                drained.notify_waiters();
            }
        }
        if !pausing.load(Ordering::SeqCst) && pending.is_empty() && eof {
            // The program reads end of file
            fd = None;
            eof = false;
        }
        match rx.recv() {
            Ok(InputItem::Data(bytes)) => pending.extend_from_slice(&bytes),
            Ok(InputItem::Eof) => eof = true,
            Ok(InputItem::Park) if pausing.load(Ordering::SeqCst) => {
                return Some(ParkedInput { fd, pending, eof, rx });
            }
            // A pause that ended before this writer saw its request
            Ok(InputItem::Park) => {}
            // Hung up
            Err(_) => return None,
        }
    }
}

/// Write all of `bytes`; on failure, how many were written and whether the wait was cancelled.
fn write_some(mut fd: &File, bytes: &[u8], cancel: &sys::Cancel) -> Result<(), (usize, bool)> {
    let mut written = 0;
    while written < bytes.len() {
        match fd.write(&bytes[written..]) {
            Ok(0) => return Err((written, false)),
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match sys::wait_fd(fd, true, cancel, None) {
                Ok(sys::Ready::Cancelled) => return Err((written, true)),
                Err(_) => return Err((written, false)),
                Ok(_) => {}
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err((written, false)),
        }
    }
    Ok(())
}

/// Holds an attach count of a session; see [`PtySession::attach_guard`].
#[derive(Debug)]
pub struct AttachGuard(Arc<PtySession>);

impl Drop for AttachGuard {
    fn drop(&mut self) {
        self.0.attached.fetch_sub(1, Ordering::SeqCst);
        self.0.touch();
    }
}

/// A TERM value is a short name of safe characters (it ends up in terminfo lookups).
fn valid_term(term: &str) -> bool {
    !term.is_empty() && term.len() <= 64 && term.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
}

/// The account sessions run as: the effective user from the password database, with `home`
/// from the paths (normally the same) and `shell` overriding the login shell if given.
pub fn account(home: &Path, shell: Option<&Path>) -> Account {
    let entry = sys::passwd_entry();
    let user = entry
        .as_ref()
        .map(|e| e.name.clone())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| sys::euid().to_string());
    let shell = shell
        .map(Path::to_path_buf)
        .or_else(|| {
            entry
                .as_ref()
                .map(|e| e.shell.clone())
                .filter(|s| s.is_absolute() && s.exists())
        })
        .unwrap_or_else(|| PathBuf::from("/bin/sh"));
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    Account {
        user,
        shell,
        home: home.to_path_buf(),
        runtime_dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How long the waits of these tests last at most: generous, for slow and emulated builders.
    const PATIENCE: Duration = Duration::from_secs(60);

    async fn wait_for(s: &PtySession, stream: Stream, needle: &str) -> String {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let text = {
                let out = s.buffer(stream).lock().unwrap();
                String::from_utf8_lossy(&out.read_from(0, usize::MAX).1).into_owned()
            };
            if text.contains(needle) {
                return text;
            }
            assert!(Instant::now() < deadline, "no {needle:?} in {text:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_output(s: &PtySession, needle: &str) -> String {
        wait_for(s, Stream::Output, needle).await
    }

    async fn wait_exit(s: &PtySession) -> ExitStatus {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(status) = s.exit_status() {
                return status;
            }
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn sh() -> Account {
        Account {
            user: "tester".into(),
            shell: "/bin/sh".into(),
            home: "/".into(),
            runtime_dir: None,
        }
    }

    fn start(command: &str, pipe: bool) -> Arc<PtySession> {
        let spawn = Spawn {
            command: Some(command.into()),
            cols: 80,
            rows: 24,
            pipe,
            ..Default::default()
        };
        PtySession::start(SessionId::generate(), SessionKey::generate(), &spawn, &sh(), 1 << 20).unwrap()
    }

    /// The output hook (m2.md 6.2): a sink installed after the start gets what the buffer
    /// holds, then every chunk, contiguous and in order, exactly the buffer's bytes.
    #[tokio::test]
    async fn an_output_sink_sees_exactly_the_buffered_output() {
        type Chunks = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;
        struct Collect(Chunks);
        impl OutputSink for Collect {
            fn output(&mut self, offset: u64, bytes: &[u8]) {
                self.0.lock().unwrap().push((offset, bytes.to_vec()));
            }
        }
        let s = start("echo one; read x; echo two-$x; exit 3", false);
        wait_output(&s, "one").await;
        let chunks = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(s.set_output_sink(Some(Box::new(Collect(chunks.clone())))), 0);
        assert!(!chunks.lock().unwrap().is_empty(), "the buffered output first");
        s.write_input(b"x\n".to_vec());
        wait_output(&s, "two-x").await;
        assert_eq!(wait_exit(&s).await, ExitStatus::Exited(3));
        // The buffer's lock first, as the reader thread takes them
        let buffer = s.output.lock().unwrap();
        let buffered = buffer.read_from(0, usize::MAX).1;
        let mut seen = Vec::new();
        for (offset, bytes) in chunks.lock().unwrap().iter() {
            assert_eq!(*offset, seen.len() as u64, "contiguous");
            seen.extend_from_slice(bytes);
        }
        assert_eq!(String::from_utf8_lossy(&seen), String::from_utf8_lossy(&buffered));
        drop(buffer);
        // Removed: no more calls
        assert_eq!(s.set_output_sink(None), 0);
    }

    #[tokio::test]
    async fn runs_a_command_with_a_clean_environment_and_exit_code() {
        std::env::set_var("QSH_TEST_LEAK", "leaked");
        let spawn = Spawn {
            command: Some(
                "echo term=$TERM lang=$LANG user=$USER leak=${QSH_TEST_LEAK:-no} evil=${EVIL:-no} size=$(stty size); read x; echo got-$x; exit 7"
                    .into(),
            ),
            cols: 91,
            rows: 33,
            term: Some("vt100".into()),
            env: vec![("LANG".into(), "en_US.UTF-8".into()), ("EVIL".into(), "1".into())],
            name: None,
            pipe: false,
        };
        let s = PtySession::start(SessionId::generate(), SessionKey::generate(), &spawn, &sh(), 1 << 20).unwrap();
        wait_output(&s, "term=vt100 lang=en_US.UTF-8 user=tester leak=no evil=no size=33 91").await;
        s.write_input(b"abc\n".to_vec());
        wait_output(&s, "got-abc").await;
        assert_eq!(wait_exit(&s).await, ExitStatus::Exited(7));
    }

    /// Review M3: a pipe session carries bytes exactly, with stdout and stderr apart and the
    /// end of input delivered: no 4096-byte line limit, ^C, ^S, CR or ^D are just bytes.
    #[tokio::test]
    async fn a_pipe_session_is_byte_exact_with_stderr_apart() {
        let s = start(
            "echo term=$(/usr/bin/env | grep -c ^TERM=); wc -c; od -An -tx1 </dev/null; echo oops >&2; exit 3",
            true,
        );
        // Through env(1): macOS /bin/sh (bash) sets TERM=dumb in the shell itself when it is unset
        wait_output(&s, "term=0").await;
        let mut input = vec![b'a'; 10000];
        input.extend_from_slice(b"\r\x03\x13\x04\n");
        s.write_input(input);
        {
            let mut st = s.input_received.lock().unwrap();
            st.eof = Some(10005);
        }
        s.close_input();
        let text = wait_output(&s, "10005").await;
        assert!(!text.contains('\r'), "{text:?}");
        assert_eq!(wait_for(&s, Stream::Error, "oops").await, "oops\n");
        assert_eq!(wait_exit(&s).await, ExitStatus::Exited(3));
        // Input after the program closed its stdin is accepted and discarded
        s.write_input(b"late".to_vec());
    }

    /// A pipe session never drops output: when the client does not acknowledge, the program
    /// blocks (protocol.md 7.14.5); acknowledgements let it go on.
    #[tokio::test]
    async fn a_pipe_session_holds_the_program_back_instead_of_dropping_output() {
        let spawn = Spawn {
            command: Some("head -c 300000 /dev/zero; echo done >&2".into()),
            pipe: true,
            ..Default::default()
        };
        let s = PtySession::start(SessionId::generate(), SessionKey::generate(), &spawn, &sh(), 100_000).unwrap();
        // The buffer fills up, however long the program takes to get there
        let deadline = Instant::now() + PATIENCE;
        while s.output.lock().unwrap().len() < 100_000 {
            assert!(Instant::now() < deadline, "the buffer did not fill");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // ... and stays full: the program is held back, nothing is dropped
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let out = s.output.lock().unwrap();
            assert_eq!((out.base(), out.len()), (0, 100_000));
        }
        assert!(s.exit_status().is_none());
        let mut acked = 0;
        while s.exit_status().is_none() {
            acked = s.output.lock().unwrap().end();
            s.ack(Stream::Output, acked);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(s.output.lock().unwrap().end(), 300_000);
        assert!(acked <= 300_000);
        assert_eq!(wait_for(&s, Stream::Error, "done").await, "done\n");
    }

    #[tokio::test]
    async fn a_hangup_ends_the_program_with_sighup() {
        let s = start("echo ready; exec sleep 100", false);
        wait_output(&s, "ready").await;
        s.hang_up();
        assert_eq!(
            wait_exit(&s).await,
            ExitStatus::Signaled {
                signal: "HUP".into(),
                core_dumped: false
            }
        );
        assert!(s.is_removed());
    }

    /// Review M4: a hung up session whose programs ignore SIGHUP (and one that left with
    /// setsid, still holding the terminal) is released: its threads let go, its descriptors
    /// close, and the process group gets SIGKILL after 5 s.
    #[tokio::test]
    async fn a_hung_up_session_is_released_even_if_its_programs_ignore_sighup() {
        let setsid = if Path::new("/usr/bin/setsid").exists() {
            "setsid "
        } else {
            ""
        };
        for pipe in [false, true] {
            let s = start(
                &format!("trap '' HUP; ({setsid}sleep 8) & echo ready; exec sleep 30"),
                pipe,
            );
            wait_output(&s, "ready").await;
            let weak = Arc::downgrade(&s);
            let io_threads = s.io_threads.clone();
            assert_eq!(io_threads.load(Ordering::SeqCst), if pipe { 3 } else { 2 });
            s.hang_up();
            // The threads that held the master or the pipes let go at once, although the
            // background sleep still has the terminal or pipes open: before the SIGKILL, while
            // the program still runs (measured by that, not by a clock: builders are slow)
            let deadline = Instant::now() + PATIENCE;
            while io_threads.load(Ordering::SeqCst) > 0 {
                assert!(Instant::now() < deadline, "descriptors still held");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(s.exit_status().is_none(), "the descriptors were held until the SIGKILL");
            // The program ignores SIGHUP: SIGKILL 5 s later reaps it
            let status = wait_exit(&s).await;
            assert_eq!(
                status,
                ExitStatus::Signaled {
                    signal: "KILL".into(),
                    core_dumped: false
                }
            );
            // Nothing but this test holds the session any more
            drop(s);
            let deadline = Instant::now() + PATIENCE;
            while weak.strong_count() > 0 {
                assert!(Instant::now() < deadline, "the session is still held");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    /// What an `execve` does to a paused session: its descriptors stay open, by number, and
    /// nothing in this image owns them any more.
    fn release_descriptors(s: &PtySession) {
        use std::os::fd::IntoRawFd;
        if let Some(master) = s.master.lock().unwrap().take() {
            let _ = master.into_raw_fd();
        }
        let parked = std::mem::take(&mut *s.parked.lock().unwrap());
        for reader in [parked.output, parked.error].into_iter().flatten() {
            let _ = reader.fd.into_raw_fd();
        }
        if let Some(fd) = parked.input.and_then(|i| i.fd) {
            let _ = fd.into_raw_fd();
        }
    }

    /// The descriptors of an exported session, adopted by number as the next image does.
    fn adopt_descriptors(state: &SessionState) -> AdoptedFds {
        let take = |fd: u32| (fd != NO_FD).then(|| File::from(sys::adopt_fd(fd as i32).expect("open")));
        match state.fds {
            SessionFds::Tty { master } => AdoptedFds {
                master: take(master),
                ..Default::default()
            },
            SessionFds::Pipe { stdin, stdout, stderr } => AdoptedFds {
                master: None,
                stdin: take(stdin),
                stdout: take(stdout),
                stderr: take(stderr),
            },
        }
    }

    async fn wait_paused(s: &PtySession) {
        let deadline = Instant::now() + PATIENCE;
        while s.threads_running() > 0 {
            assert!(Instant::now() < deadline, "the threads did not stop");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// m2.md 10.3 steps 3, 4, 7 and 8 for a tty session: the threads stop and park, input
    /// accepted meanwhile is kept, and the session continues in its next image at the same
    /// offsets, with the same keys, the same program and terminal, nothing lost or repeated.
    #[tokio::test]
    async fn a_paused_tty_session_continues_from_its_exported_state() {
        let s = start("while read line; do echo got-$line; done", false);
        s.write_input(b"one\n".to_vec());
        wait_output(&s, "got-one").await;
        *s.input_received.lock().unwrap() = InputState {
            inbound: Inbound::at(4),
            eof: None,
        };
        s.request_pause();
        wait_paused(&s).await;
        // Accepted while the threads are stopped: kept, written by the next image
        s.write_input(b"two\n".to_vec());
        s.input_received.lock().unwrap().inbound = Inbound::at(8);
        let state = s.export().expect("exported");
        let output_end = s.output.lock().unwrap().end();
        assert_eq!(state.input_queue, b"two\n");
        assert_eq!(
            (
                state.input_received,
                state.output.base + state.output.bytes.len() as u64
            ),
            (8, output_end)
        );
        assert!(matches!(state.fds, SessionFds::Tty { .. }) && state.cols == 80 && state.rows == 24);
        // Through the format, as the next image reads it
        let wire = super::super::handoff::State {
            writer: "qsh-server/test".into(),
            started_ms: 0,
            restarts: 0,
            failures: 0,
            port: 1,
            listeners: vec![
                super::super::handoff::Listener {
                    kind: super::super::handoff::ListenerKind::Control,
                    fd: 1000,
                    port: 0,
                },
                super::super::handoff::Listener {
                    kind: super::super::handoff::ListenerKind::Lock,
                    fd: 1001,
                    port: 0,
                },
            ],
            sessions: vec![state],
        };
        let mut wire = super::super::handoff::decode(&super::super::handoff::encode(&wire).unwrap()).unwrap();
        let state = wire.sessions.remove(0);
        release_descriptors(&s);
        let (id, key, pid) = (s.id, s.keys.lock().unwrap().current.0, s.pid);
        drop(s);
        let fds = adopt_descriptors(&state);
        let t = PtySession::adopt(state, fds).unwrap().start().unwrap();
        assert_eq!((t.id, t.keys.lock().unwrap().current.0, t.pid), (id, key, pid));
        assert_eq!(t.input_received.lock().unwrap().inbound.received(), 8);
        let text = wait_output(&t, "got-two").await;
        assert_eq!(text.matches("got-one").count(), 1, "{text:?}");
        assert_eq!(t.output.lock().unwrap().base(), 0, "the same offsets");
        t.write_input(b"three\n".to_vec());
        wait_output(&t, "got-three").await;
        t.hang_up();
    }

    /// The same for a pipe session, whose input end is delivered after the queued input, and
    /// whose stdout is read on from where the previous image stopped.
    #[tokio::test]
    async fn a_paused_pipe_session_continues_from_its_exported_state() {
        let s = start("cat; echo end >&2", true);
        s.write_input(b"abc".to_vec());
        wait_output(&s, "abc").await;
        s.request_pause();
        wait_paused(&s).await;
        s.write_input(b"def".to_vec());
        {
            let mut input = s.input_received.lock().unwrap();
            input.inbound = Inbound::at(6);
            input.eof = Some(6);
        }
        s.close_input();
        let state = s.export().expect("exported");
        assert_eq!((state.input_queue.as_slice(), state.input_eof), (&b"def"[..], Some(6)));
        let SessionFds::Pipe { stdin, stdout, stderr } = state.fds else {
            panic!("a pipe session")
        };
        assert!(stdin != NO_FD && stdout != NO_FD && stderr != NO_FD);
        release_descriptors(&s);
        drop(s);
        let fds = adopt_descriptors(&state);
        let t = PtySession::adopt(state, fds).unwrap().start().unwrap();
        // cat gets "def" and then the end of its input: it ends, and so does stdout
        assert_eq!(wait_output(&t, "abcdef").await, "abcdef");
        assert_eq!(wait_for(&t, Stream::Error, "end").await, "end\n");
    }

    /// A pause that is not followed by an exec (the upgrade failed, m2.md 10.3 step 6): the
    /// threads start again on their parked descriptors, with nothing lost.
    #[tokio::test]
    async fn a_paused_session_resumes_in_place() {
        let s = start("while read line; do echo got-$line; done", false);
        s.request_pause();
        wait_paused(&s).await;
        s.write_input(b"x\n".to_vec());
        assert!(s.export().is_some());
        s.resume_threads().unwrap();
        wait_output(&s, "got-x").await;
        s.write_input(b"y\n".to_vec());
        wait_output(&s, "got-y").await;
        s.hang_up();
    }

    #[test]
    fn term_values_are_checked() {
        assert!(valid_term("xterm-256color"));
        assert!(!valid_term("../../etc"));
        assert!(!valid_term(""));
    }
}
