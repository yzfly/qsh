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

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Notify;

use crate::crypto::SessionKey;
use crate::proto::ExitStatus;
use crate::session::{Inbound, ReplayBuffer};
use crate::sys;

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
    input: Mutex<Option<std::sync::mpsc::Sender<InputItem>>>,
    /// Input bytes queued for the program and not yet written (section 7.4).
    input_queued: Arc<AtomicUsize>,
    /// Output produced by the program: a pipe session's stdout, kept until acknowledged; on a
    /// tty session kept as scrollback, acknowledged or not, the oldest dropped past capacity.
    pub output: Mutex<ReplayBuffer>,
    /// A pipe session's stderr, kept until acknowledged (empty on a tty session).
    pub errors: Mutex<ReplayBuffer>,
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
    /// Cancelled on hangup and drop: the threads let go of the terminal or pipes.
    cancel: Arc<sys::Cancel>,
    /// Threads that hold one of the session's descriptors, still running.
    io_threads: Arc<AtomicUsize>,
    /// Set (under its lock) when the program was reaped: its process group may no longer be
    /// signalled after that, its id could be reused.
    reaped: Arc<Mutex<bool>>,
    /// The program's pid, also its process group.
    pub pid: u32,
    /// The command, None for a login shell.
    pub command: Option<String>,
    /// The session's name.
    pub name: Option<String>,
    /// When the session started.
    pub started: SystemTime,
}

impl PtySession {
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
        let (mut child, output_fd, error_fd, input_fd, master) = if spawn.pipe {
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

        let (input_tx, input_rx) = std::sync::mpsc::channel::<InputItem>();
        let error_capacity = (replay_capacity / 8).max(64 << 10);
        let session = Arc::new(PtySession {
            id,
            keys: Mutex::new(Keys {
                current: key,
                pending: None,
            }),
            pipe: spawn.pipe,
            master: Mutex::new(master),
            input: Mutex::new(Some(input_tx)),
            input_queued: Arc::new(AtomicUsize::new(0)),
            output: Mutex::new(ReplayBuffer::new(replay_capacity)),
            errors: Mutex::new(ReplayBuffer::new(if spawn.pipe { error_capacity } else { 0 })),
            room: Condvar::new(),
            input_received: Mutex::new(InputState::default()),
            changed: Notify::new(),
            exit: Mutex::new(None),
            generation: AtomicU64::new(0),
            last_seen: Mutex::new(Instant::now()),
            exited_at: Mutex::new(None),
            attached: AtomicUsize::new(0),
            removed: AtomicBool::new(false),
            cancel: Arc::new(sys::Cancel::new()?),
            io_threads: Arc::new(AtomicUsize::new(0)),
            reaped: Arc::new(Mutex::new(false)),
            pid,
            command: spawn.command.clone(),
            name: spawn.name.clone(),
            started: SystemTime::now(),
        });

        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let readers = if spawn.pipe { 2 } else { 1 };
        let bounded = spawn.pipe;
        spawn_reader(&session, output_fd, Stream::Output, bounded, done_tx.clone())?;
        if let Some(fd) = error_fd {
            spawn_reader(&session, fd, Stream::Error, bounded, done_tx)?;
        } else {
            drop(done_tx);
        }
        let queued = session.input_queued.clone();
        let cancel = session.cancel.clone();
        let running = IoThread::start(&session.io_threads);
        std::thread::Builder::new()
            .name("qsh-session-in".into())
            .spawn(move || {
                write_input(input_fd, input_rx, queued, cancel);
                drop(running);
            })?;

        let weak = Arc::downgrade(&session);
        let reaped = session.reaped.clone();
        let pipe = spawn.pipe;
        std::thread::Builder::new()
            .name("qsh-session-wait".into())
            .spawn(move || {
                // Wait without reaping, then reap under the lock that signalling takes: the
                // process group is never signalled after its id could have been reused
                let _ = sys::wait_exit_no_reap(pid);
                let status = {
                    let mut reaped = reaped.lock().unwrap();
                    let status = child.wait();
                    *reaped = true;
                    status
                };
                let status = match status {
                    Ok(status) => match (status.code(), status.signal()) {
                        (Some(code), _) => ExitStatus::Exited(code as u32 & 0xff),
                        (None, Some(signal)) => ExitStatus::Signaled {
                            signal: sys::signal_name(signal),
                            core_dumped: status.core_dumped(),
                        },
                        (None, None) => ExitStatus::Exited(255),
                    },
                    Err(_) => ExitStatus::Exited(255),
                };
                if pipe {
                    // As ssh: the end is when the program is gone and both pipes reached their end
                    // (a background process holding one open delays it)
                    for _ in 0..readers {
                        if done_rx.recv().is_err() {
                            break;
                        }
                    }
                } else {
                    // The output ends when the reader reaches the end of the pty; a background
                    // process that keeps the terminal open must not hold the EXIT back for long
                    let _ = done_rx.recv_timeout(Duration::from_millis(500));
                }
                if let Some(s) = weak.upgrade() {
                    *s.exit.lock().unwrap() = Some(status);
                    *s.exited_at.lock().unwrap() = Some(Instant::now());
                    s.changed.notify_waiters();
                }
            })?;
        Ok(session)
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
            if !*reaped {
                let _ = sys::kill_group(self.pid, sys::Signal::Hangup);
                let (pid, reaped) = (self.pid, self.reaped.clone());
                let _ = std::thread::Builder::new()
                    .name("qsh-session-kill".into())
                    .spawn(move || {
                        std::thread::sleep(HANGUP_KILL_AFTER);
                        let reaped = reaped.lock().unwrap();
                        if !*reaped {
                            let _ = sys::kill_group(pid, sys::Signal::Kill);
                        }
                    });
            }
        }
        // The readers and the writer let go of the master or the pipes; with ours, the
        // terminal is hung up (or the pipes closed)
        self.cancel.cancel();
        self.master.lock().unwrap().take();
        self.input.lock().unwrap().take();
        self.room.notify_all();
        self.changed.notify_waiters();
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Whatever happened, the threads let go of the terminal or the pipes
        self.cancel.cancel();
    }
}

/// Read one output of a session into its replay buffer until the end, an error or cancellation.
/// A pipe session's reader (`bounded`) stops reading while the buffer is full of
/// unacknowledged bytes, so the program blocks as under ssh (protocol.md 7.14.5).
fn spawn_reader(
    session: &Arc<PtySession>,
    fd: File,
    stream: Stream,
    bounded: bool,
    done: std::sync::mpsc::Sender<()>,
) -> io::Result<()> {
    let weak = Arc::downgrade(session);
    let cancel = session.cancel.clone();
    let running = IoThread::start(&session.io_threads);
    std::thread::Builder::new()
        .name("qsh-session-out".into())
        .spawn(move || {
            read_output(&fd, stream, bounded, &weak, &cancel);
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

fn read_output(mut fd: &File, stream: Stream, bounded: bool, weak: &Weak<PtySession>, cancel: &sys::Cancel) {
    let mut buf = vec![0u8; 16384];
    loop {
        let mut limit = buf.len();
        if bounded {
            let Some(s) = weak.upgrade() else { return };
            let replay = s.buffer(stream).lock().unwrap();
            let room = replay.capacity() - replay.len();
            if room == 0 {
                // Full of unacknowledged bytes: wait for acknowledgements (without keeping the
                // session alive in between)
                if cancel.is_cancelled() {
                    return;
                }
                let _ = s.room.wait_timeout(replay, Duration::from_millis(200)).unwrap();
                continue;
            }
            limit = limit.min(room);
        }
        match fd.read(&mut buf[..limit]) {
            // EIO on a pty once the program and everything it started closed the terminal.
            // The server keeps reading whether or not anyone is attached (7.6).
            Ok(0) => return,
            Ok(n) => {
                let Some(s) = weak.upgrade() else { return };
                s.buffer(stream).lock().unwrap().push(&buf[..n]);
                s.changed.notify_waiters();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match sys::wait_fd(fd, false, cancel, None) {
                Ok(sys::Ready::Cancelled) | Err(_) => return,
                Ok(_) => {}
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Write the session's input queue to the program, in order. Input after the terminal or pipe
/// closed (or after cancellation) is accepted and discarded (7.4).
fn write_input(fd: File, rx: std::sync::mpsc::Receiver<InputItem>, queued: Arc<AtomicUsize>, cancel: Arc<sys::Cancel>) {
    let mut fd = Some(fd);
    while let Ok(item) = rx.recv() {
        match item {
            InputItem::Data(bytes) => {
                if let Some(f) = fd.as_ref() {
                    if write_all(f, &bytes, &cancel).is_err() {
                        fd = None;
                    }
                }
                queued.fetch_sub(bytes.len(), Ordering::SeqCst);
            }
            // The program reads end of file
            InputItem::Eof => fd = None,
        }
    }
}

fn write_all(mut fd: &File, mut bytes: &[u8], cancel: &sys::Cancel) -> io::Result<()> {
    while !bytes.is_empty() {
        match fd.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if sys::wait_fd(fd, true, cancel, None)? == sys::Ready::Cancelled {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
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

    #[test]
    fn term_values_are_checked() {
        assert!(valid_term("xterm-256color"));
        assert!(!valid_term("../../etc"));
        assert!(!valid_term(""));
    }
}
