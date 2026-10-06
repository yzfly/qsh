//! A session's program on a pseudo terminal, with its output in a replay buffer
//! (protocol.md section 7.1).
//!
//! Sessions live in the daemon, independent of any connection: the program keeps running and
//! its output keeps accumulating while no client is attached.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
    /// Terminal columns.
    pub cols: u16,
    /// Terminal rows.
    pub rows: u16,
    /// `TERM`.
    pub term: Option<String>,
    /// Accepted client variables (see `proto::bootstrap::accepted_env_name`).
    pub env: Vec<(String, String)>,
    /// A name for `qsh ls`.
    pub name: Option<String>,
    /// The client is not a terminal (a script): no echo, no output translation.
    pub plain: bool,
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

/// The session key pair of section 6.5: a current key and at most one pending key.
#[derive(Debug, Clone)]
pub struct Keys {
    /// The key last confirmed (or issued by the bootstrap).
    pub current: SessionKey,
    /// The key sent in the last ATTACHED, until KEY_CONFIRM.
    pub pending: Option<SessionKey>,
}

/// One session: a program on a pty and the state that outlives connections.
#[derive(Debug)]
pub struct PtySession {
    /// The session id.
    pub id: SessionId,
    /// The valid keys.
    pub keys: Mutex<Keys>,
    master: File,
    input: Mutex<Option<std::sync::mpsc::Sender<Vec<u8>>>>,
    /// Input bytes queued for the pty and not yet written (section 7.4).
    input_queued: Arc<AtomicUsize>,
    /// Output produced by the program, kept until acknowledged (or dropped past capacity).
    pub output: Mutex<ReplayBuffer>,
    /// Input received from clients and written to the pty.
    pub input_received: Mutex<Inbound>,
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
    removed: std::sync::atomic::AtomicBool,
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
    /// Start `spawn` on a new pty as `account`, with an output replay buffer of
    /// `replay_capacity` bytes.
    pub fn start(
        id: SessionId,
        key: SessionKey,
        spawn: &Spawn,
        account: &Account,
        replay_capacity: usize,
    ) -> io::Result<Arc<PtySession>> {
        let cols = if spawn.cols == 0 { 80 } else { spawn.cols };
        let rows = if spawn.rows == 0 { 24 } else { spawn.rows };
        let (master, slave) = sys::openpty(cols, rows)?;
        if spawn.plain {
            sys::plain_terminal(&slave)?;
        }
        let slave = File::from(slave);

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
            .env(
                "TERM",
                spawn
                    .term
                    .as_deref()
                    .filter(|t| valid_term(t))
                    .unwrap_or("xterm-256color"),
            )
            .env("QSH_SESSION", id.to_hex())
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        if let Some(dir) = &account.runtime_dir {
            cmd.env("XDG_RUNTIME_DIR", dir);
        }
        for (name, value) in &spawn.env {
            if crate::proto::bootstrap::accepted_env_name(name) && !value.contains('\0') {
                cmd.env(name, value);
            }
        }
        sys::spawn_on_pty(&mut cmd);
        let mut child = cmd.spawn()?;
        let pid = child.id();

        let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let session = Arc::new(PtySession {
            id,
            keys: Mutex::new(Keys {
                current: key,
                pending: None,
            }),
            master: File::from(master),
            input: Mutex::new(Some(input_tx)),
            input_queued: Arc::new(AtomicUsize::new(0)),
            output: Mutex::new(ReplayBuffer::new(replay_capacity)),
            input_received: Mutex::new(Inbound::default()),
            changed: Notify::new(),
            exit: Mutex::new(None),
            generation: AtomicU64::new(0),
            last_seen: Mutex::new(Instant::now()),
            exited_at: Mutex::new(None),
            attached: AtomicUsize::new(0),
            removed: std::sync::atomic::AtomicBool::new(false),
            pid,
            command: spawn.command.clone(),
            name: spawn.name.clone(),
            started: SystemTime::now(),
        });

        // Plain threads for the pty: blocking reads and writes, three per session
        let (read_done_tx, read_done_rx) = std::sync::mpsc::channel::<()>();
        let mut reader = session.master.try_clone()?;
        let s = session.clone();
        std::thread::Builder::new().name("qsh-pty-read".into()).spawn(move || {
            let mut buf = [0u8; 16384];
            loop {
                match reader.read(&mut buf) {
                    // EIO once the program and everything it started closed the terminal.
                    // The server keeps reading whether or not anyone is attached (7.6).
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        s.output.lock().unwrap().push(&buf[..n]);
                        s.changed.notify_waiters();
                    }
                }
            }
            let _ = read_done_tx.send(());
        })?;
        let mut writer = session.master.try_clone()?;
        let queued = session.input_queued.clone();
        std::thread::Builder::new()
            .name("qsh-pty-write".into())
            .spawn(move || {
                let mut broken = false;
                while let Ok(bytes) = input_rx.recv() {
                    // Input after the terminal closed is accepted and discarded (7.4)
                    if !broken && writer.write_all(&bytes).is_err() {
                        broken = true;
                    }
                    queued.fetch_sub(bytes.len(), Ordering::SeqCst);
                }
            })?;
        let s = session.clone();
        std::thread::Builder::new().name("qsh-pty-wait".into()).spawn(move || {
            let status = match child.wait() {
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
            // The output ends when the reader reaches the end of the pty; a background process
            // that keeps the terminal open must not hold the EXIT back for long
            let _ = read_done_rx.recv_timeout(Duration::from_millis(500));
            *s.exit.lock().unwrap() = Some(status);
            *s.exited_at.lock().unwrap() = Some(Instant::now());
            s.changed.notify_waiters();
        })?;
        Ok(session)
    }

    /// Bytes typed by the client, in order, into the session's input queue.
    pub fn write_input(&self, bytes: Vec<u8>) {
        if let Some(input) = self.input.lock().unwrap().as_ref() {
            let n = bytes.len();
            self.input_queued.fetch_add(n, Ordering::SeqCst);
            if input.send(bytes).is_err() {
                self.input_queued.fetch_sub(n, Ordering::SeqCst);
            }
        }
    }

    /// Input bytes waiting to be written to the pty.
    pub fn input_queued(&self) -> usize {
        self.input_queued.load(Ordering::SeqCst)
    }

    /// Resize the terminal; the program gets SIGWINCH. Zero sizes are ignored, huge ones
    /// clamped.
    pub fn resize(&self, cols: u16, rows: u16) {
        if cols > 0 && rows > 0 {
            let _ = sys::set_window_size(&self.master, cols.min(4096), rows.min(4096));
        }
    }

    /// Make the program redraw its screen (as on SIGWINCH): shrink by a row and back. Used
    /// after an OUTPUT_GAP (section 7.7).
    pub fn redraw(&self) {
        if let Some((cols, rows)) = sys::window_size(&self.master) {
            let _ = sys::set_window_size(&self.master, cols, rows.saturating_sub(1).max(1));
            let _ = sys::set_window_size(&self.master, cols, rows);
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

    /// End the session: its programs get SIGHUP, as when an ssh connection closes, and the
    /// pty's input closes. Attachments notice through [`PtySession::is_removed`].
    pub fn hang_up(&self) {
        self.removed.store(true, Ordering::SeqCst);
        if self.exit_status().is_none() {
            let _ = sys::kill_group(self.pid, sys::Signal::Hangup);
        }
        self.input.lock().unwrap().take();
        self.changed.notify_waiters();
    }
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

    async fn wait_output(s: &PtySession, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = {
                let out = s.output.lock().unwrap();
                String::from_utf8_lossy(&out.read_from(0, usize::MAX).1).into_owned()
            };
            if text.contains(needle) {
                return text;
            }
            assert!(Instant::now() < deadline, "no {needle:?} in {text:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_exit(s: &PtySession) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
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
            plain: false,
        };
        let s = PtySession::start(SessionId::generate(), SessionKey::generate(), &spawn, &sh(), 1 << 20).unwrap();
        wait_output(&s, "term=vt100 lang=en_US.UTF-8 user=tester leak=no evil=no size=33 91").await;
        s.write_input(b"abc\n".to_vec());
        wait_output(&s, "got-abc").await;
        assert_eq!(wait_exit(&s).await, ExitStatus::Exited(7));
    }

    #[tokio::test]
    async fn plain_mode_neither_echoes_nor_translates() {
        let spawn = Spawn {
            command: Some("read x; printf 'got-%s\\n' $x".into()),
            cols: 80,
            rows: 24,
            plain: true,
            ..Default::default()
        };
        let s = PtySession::start(SessionId::generate(), SessionKey::generate(), &spawn, &sh(), 1 << 20).unwrap();
        s.write_input(b"abc\n".to_vec());
        let text = wait_output(&s, "got-abc").await;
        assert_eq!(text, "got-abc\n");
    }

    #[tokio::test]
    async fn a_hangup_ends_the_program_with_sighup() {
        let spawn = Spawn {
            command: Some("echo ready; exec sleep 100".into()),
            cols: 80,
            rows: 24,
            ..Default::default()
        };
        let s = PtySession::start(SessionId::generate(), SessionKey::generate(), &spawn, &sh(), 1 << 20).unwrap();
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

    #[test]
    fn term_values_are_checked() {
        assert!(valid_term("xterm-256color"));
        assert!(!valid_term("../../etc"));
        assert!(!valid_term(""));
    }
}
