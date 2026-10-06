//! The client: the bootstrap over ssh (protocol.md section 10), connections (sections 5, 9,
//! 12), and one terminal session kept alive across them (sections 6 and 7).
//!
//! [`Session::run`] is one session: it bootstraps once, then attaches over whichever transport
//! works, and whenever the connection breaks it connects again and resumes where it stopped,
//! resending input the server missed and receiving the output the client missed.
//!
//! The terminal side is a pair of channels ([`Terminal`]): input and window sizes in, output
//! out. The `qsh` command line connects them to its tty; an embedder to anything it likes.
//!
//! Credentials live where [`ClientConfig::store`] says: in a [`store::SessionStore`] (what `qsh`
//! does, so that `qsh attach` works after the client process is gone), or, for embedders that
//! keep none, in memory only (protocol.md 6.5).
//!
//! # Layout
//!
//! - `client.rs`: the public API (configuration, terminal channels, status, errors) and the
//!   bootstrap over ssh;
//! - `client/conn.rs`: one connection after the hello exchange, with its control stream
//!   ([`Conn`]);
//! - `client/pool.rs`: connections shared per daemon, the transport race planned from path
//!   memory, keepalive learning, background probes and transport upgrades, and the network
//!   watcher ([`Pool`]);
//! - [`paths`]: path memory and NAT keepalive learning (m2.md sections 3 and 4);
//! - `client/session.rs`: one terminal session across connections: attach, the terminal
//!   channel, resume ([`Session`]);
//! - [`store`]: saved credentials (`qsh attach`);
//! - [`transcript`]: the `QSH_TRANSCRIPT` test hook (unstable).

mod conn;
pub mod paths;
mod pool;
mod session;
pub mod store;
pub mod transcript;

pub use conn::{Conn, Offer};
pub use pool::Pool;
pub use session::Session;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::config::{Catchup, Compression, Keepalive};
use crate::crypto;
use crate::proto;
use crate::proto::bootstrap::{self, ErrorKind, Reply, Request, SessionInfo};
use crate::proto::{ExitStatus, WindowSize};
use crate::transport::ssh::{SshCommand, EXIT_CANNOT_EXECUTE, EXIT_COMMAND_NOT_FOUND};
use crate::transport::{RaceConfig, Transport};
use store::SessionStore;

/// Exit status of `qsh` when the server has no qsh-server (protocol.md 10.2).
pub const EXIT_NO_SERVER: i32 = proto::EXIT_NO_SERVER;
/// Exit status of `qsh` for its own errors, like ssh.
pub const EXIT_ERROR: i32 = 255;

/// What to run and how to reach the server.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// ssh to the server, with the user's options.
    pub ssh: SshCommand,
    /// The remote command; None for a login shell.
    pub command: Option<String>,
    /// The terminal type for the session (`TERM`).
    pub term: Option<String>,
    /// Locale and color variables to pass (`LANG`, `LC_*`, `COLORTERM`).
    pub env: BTreeMap<String, String>,
    /// The terminal size at the start.
    pub size: WindowSize,
    /// A session name for `qsh ls`.
    pub name: Option<String>,
    /// Which transports to race, and when each starts without path memory.
    pub race: RaceConfig,
    /// Run the bootstrap's ssh interactively (password and second factor prompts on the
    /// terminal); false adds `BatchMode=yes`.
    pub interactive: bool,
    /// The input is a terminal. False for scripts: ask for a pipe session (protocol.md 7.14),
    /// whose program has pipes instead of a terminal, so that input and output are carried
    /// byte for byte and stderr apart, as with `ssh host command` without a pty.
    pub tty: bool,
    /// Where the session's credentials are saved, so that it can be attached again after this
    /// process is gone (`qsh attach`); every new key is saved there before it is confirmed
    /// (protocol.md 6.5). None: in memory only, the session can then be reached again only
    /// through ssh (bootstrap op `attach`).
    pub store: Option<SessionStore>,
    /// Attaching a session this process has no stream state for (`qsh attach`, a new client):
    /// true replays the output the server still buffers (FRESH from offset 0), false starts at
    /// the current end (LATEST), skipping the backlog. A new session always starts at 0.
    pub replay_on_attach: bool,
    /// The QUIC keepalive interval (qsh_config(5) `keepalive`; m2.md section 4): `Auto` learns
    /// it per network between 5 and 25 s; a fixed interval disables learning. TLS and the ssh
    /// pipe send PING every 15 s either way.
    pub keepalive: Keepalive,
    /// Remember per network which transport and port worked, in the pool's path memory file
    /// (`path_memory`; m2.md section 3). False: neither read nor write it; what is learned
    /// lives only as long as the process.
    pub path_memory: bool,
    /// Accept snapshots on tty sessions (`catchup`; m2.md section 6): when the output is far
    /// behind, the server sends the current screen instead of the backlog. `Off` for output
    /// that does not go to a terminal (`qsh` sets it when its stdout is not one).
    pub catchup: Catchup,
    /// Offer the `zstd` capability (`compression`; m2.md section 7): the server compresses
    /// output on slow paths.
    pub compression: Compression,
}

impl ClientConfig {
    /// A login shell on `destination` with the defaults.
    pub fn new(destination: impl Into<String>) -> ClientConfig {
        ClientConfig {
            ssh: SshCommand::new(destination),
            command: None,
            term: None,
            env: BTreeMap::new(),
            size: WindowSize::new(80, 24),
            name: None,
            race: RaceConfig::default(),
            interactive: true,
            tty: true,
            store: None,
            replay_on_attach: true,
            keepalive: Keepalive::Auto,
            path_memory: true,
            catchup: Catchup::Auto,
            compression: Compression::Auto,
        }
    }
}

/// From the terminal to the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Keystrokes or pasted bytes.
    Data(Vec<u8>),
    /// The terminal's new size.
    Resize(WindowSize),
    /// Detach: the session keeps running on the server (`~d`).
    Detach,
    /// End the session (`~.`).
    Hangup,
    /// The local input reached its end: the program's stdin is closed (INPUT_EOF on a pipe
    /// session; on a tty session the terminal's end-of-file character, `^D`, is typed).
    Eof,
}

/// Things the terminal may want to tell the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Attached over this transport.
    Connected(Transport),
    /// The connection was lost; reconnecting.
    Disconnected(String),
    /// Bytes of output were skipped: they fell out of the server's replay buffer, or a
    /// snapshot of the screen replaced them (smart catch-up).
    OutputSkipped(u64),
}

/// The terminal side of a session.
#[derive(Debug)]
pub struct Terminal {
    /// Input and sizes from the terminal. When it closes, no more input is sent; the session
    /// goes on until its program exits.
    pub input: mpsc::Receiver<Input>,
    /// Output for the terminal, in order. When the receiver is gone the session detaches.
    pub output: mpsc::Sender<Vec<u8>>,
    /// The program's stderr on a pipe session, in order; None: it goes to `output`.
    pub errors: Option<mpsc::Sender<Vec<u8>>>,
    /// Optional notifications.
    pub events: Option<mpsc::UnboundedSender<Event>>,
}

/// What a session is doing, for a status line (`~s`).
#[derive(Debug, Clone, Default)]
pub struct Status {
    /// The transport of the current connection, None while disconnected.
    pub transport: Option<Transport>,
    /// The server's address on the current connection.
    pub remote: Option<SocketAddr>,
    /// The client's address as the server sees it (PATH_INFO).
    pub observed: Option<SocketAddr>,
    /// The last round-trip time measured.
    pub rtt: Option<Duration>,
    /// Output bytes received.
    pub bytes_in: u64,
    /// Input bytes sent (resends included).
    pub bytes_out: u64,
    /// When the current connection attached.
    pub connected_since: Option<Instant>,
    /// Connections after the first.
    pub reconnects: u32,
    /// Output bytes skipped (OUTPUT_GAP, and the backlog a snapshot replaced).
    pub skipped: u64,
    /// Snapshots that replaced a backlog (smart catch-up, m2.md 6).
    pub snapshots: u64,
    /// Output bytes that arrived compressed (OUTPUT_ZSTD), and the bytes of their frames.
    pub compressed: (u64, u64),
    /// The session id.
    pub session: Option<[u8; 16]>,
    /// How each transport fared in the race of the current connection: "used", "failed: why",
    /// "not needed" (the race ended before it answered), "off" or "no port".
    pub attempts: Vec<(Transport, String)>,
}

/// How a session ended without an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The program exited.
    Exited(ExitStatus),
    /// Detached; the session keeps running on the server.
    Detached,
    /// The user ended the session while the server could not be reached: it keeps running
    /// there until it is ended or expires.
    Abandoned,
}

/// Why a session could not go on.
#[derive(Debug)]
pub enum ClientError {
    /// The host has no qsh-server (exit 42).
    NoServer,
    /// qsh-server is there but cannot be executed (another architecture?).
    CannotExecute,
    /// ssh failed with this status; it told the user why on stderr.
    Ssh(i32),
    /// The bootstrap failed.
    Bootstrap(String),
    /// The session is gone: it ended, or the daemon restarted.
    SessionLost(String),
    /// Another client attached the session.
    TakenOver,
    /// Anything else.
    Io(io::Error),
}

impl ClientError {
    /// The exit status of `qsh` for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            ClientError::NoServer => EXIT_NO_SERVER,
            _ => EXIT_ERROR,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::NoServer => f.write_str("qsh-server is not installed on the host"),
            ClientError::CannotExecute => {
                f.write_str("qsh-server on the host cannot be executed (built for another system?)")
            }
            ClientError::Ssh(code) => write!(f, "ssh failed (exit status {code})"),
            ClientError::Bootstrap(e) => write!(f, "bootstrap failed: {e}"),
            ClientError::SessionLost(e) => write!(f, "the session is gone: {e}"),
            ClientError::TakenOver => f.write_str("the session was taken over by another client"),
            ClientError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// The exit status a shell would give for `status`: the code, or 128 + the signal number.
pub fn exit_code(status: &ExitStatus) -> i32 {
    match status {
        ExitStatus::Exited(code) => (*code & 0xff) as i32,
        ExitStatus::Signaled { signal, .. } => crate::sys::signal_number(signal).map_or(EXIT_ERROR, |n| 128 + n),
    }
}

/// Run `qsh-server bootstrap` over ssh with `request` on its stdin, and read the reply. An
/// error reply is an error ([`ClientError::Bootstrap`]); see [`bootstrap_reply`] to tell them
/// apart.
pub async fn bootstrap(ssh: &SshCommand, request: &Request, interactive: bool) -> Result<Reply, ClientError> {
    match bootstrap_reply(ssh, request, interactive).await? {
        Reply::Error(e) => Err(ClientError::Bootstrap(e.to_string())),
        reply => Ok(reply),
    }
}

/// The user's sessions on the host (bootstrap op `list`, protocol.md 10.3).
pub async fn list_sessions(ssh: &SshCommand, interactive: bool) -> Result<Vec<SessionInfo>, ClientError> {
    match bootstrap(ssh, &Request::list(), interactive).await? {
        Reply::Sessions(sessions) => Ok(sessions),
        other => Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
    }
}

/// End a session on the host (bootstrap op `kill`): true when it was ended, false when the
/// server has no such session.
pub async fn kill_session(ssh: &SshCommand, session: &str, interactive: bool) -> Result<bool, ClientError> {
    match bootstrap_reply(ssh, &Request::kill(session), interactive).await? {
        Reply::Ok => Ok(true),
        Reply::Error(e) if e.error == ErrorKind::NoSession => Ok(false),
        Reply::Error(e) => Err(ClientError::Bootstrap(e.to_string())),
        other => Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
    }
}

/// [`bootstrap()`], with an error reply as [`Reply::Error`].
pub async fn bootstrap_reply(ssh: &SshCommand, request: &Request, interactive: bool) -> Result<Reply, ClientError> {
    let mut child = ssh.bootstrap(!interactive)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("ssh without stdin"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("ssh without stdout"))?;
    let line = format!("{}\n", serde_json::to_string(request).map_err(io::Error::other)?);
    // ssh may exit before reading (no server, refused login): a broken pipe here is no error
    let _ = stdin.write_all(line.as_bytes()).await;
    drop(stdin);
    // Section 10.4: read to the end (ssh blocks, and the bootstrap never finishes, when its
    // stdout pipe is full), keeping only the last line that may be the reply
    let mut scanner = bootstrap::ReplyScanner::default();
    let mut buf = vec![0u8; 16384];
    let read_all = async {
        loop {
            let n = stdout.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), io::Error>(());
            }
            scanner.feed(&buf[..n]);
        }
    };
    tokio::pin!(read_all);
    let mut exited = None;
    tokio::select! {
        r = &mut read_all => r?,
        status = child.wait() => {
            // ssh exited; a process it left behind may still hold its stdout open: what is
            // already in the pipe is read, then no more is waited for
            exited = Some(status?);
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut read_all).await;
        }
    }
    zeroize::Zeroize::zeroize(&mut buf);
    drop(stdout);
    let status = match exited {
        Some(status) => status,
        None => child.wait().await?,
    };
    match status.code() {
        Some(proto::EXIT_NO_SERVER) | Some(EXIT_COMMAND_NOT_FOUND) => return Err(ClientError::NoServer),
        Some(EXIT_CANNOT_EXECUTE) => return Err(ClientError::CannotExecute),
        Some(255) => return Err(ClientError::Ssh(255)),
        _ => {}
    }
    let mut output = scanner.finish();
    let reply = bootstrap::parse_reply(&output, request.op);
    // The reply holds the session key
    zeroize::Zeroize::zeroize(&mut output);
    match reply {
        Ok(reply) => Ok(reply),
        Err(e) => match status.code() {
            Some(0) | Some(1) | None => Err(ClientError::Bootstrap(e.to_string())),
            Some(code) => Err(ClientError::Ssh(code)),
        },
    }
}

/// ±20 % (section 12.2).
pub(crate) fn jitter(d: Duration) -> Duration {
    let r = u32::from(crypto::random::<1>()[0]) * 40 / 255;
    d * (80 + r) / 100
}

/// The host part of `[user@]host`.
pub(crate) fn host_of(destination: &str) -> String {
    destination.rsplit('@').next().unwrap_or(destination).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_shell() {
        assert_eq!(exit_code(&ExitStatus::Exited(7)), 7);
        assert_eq!(
            exit_code(&ExitStatus::Signaled {
                signal: "HUP".into(),
                core_dumped: false
            }),
            129
        );
        assert_eq!(
            exit_code(&ExitStatus::Signaled {
                signal: "WEIRD".into(),
                core_dumped: false
            }),
            255
        );
        assert_eq!(ClientError::NoServer.exit_code(), 42);
        assert_eq!(ClientError::TakenOver.exit_code(), 255);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        for _ in 0..100 {
            let j = jitter(Duration::from_secs(10));
            assert!(j >= Duration::from_secs(8) && j <= Duration::from_secs(12), "{j:?}");
        }
        assert_eq!(host_of("user@example.org"), "example.org");
        assert_eq!(host_of("example.org"), "example.org");
    }

    /// Review L4: a bootstrap whose shell start-up files print more than 1 MiB (here 3 MiB on
    /// one line, then the reply) neither hangs nor fails: everything is read, little is kept.
    #[tokio::test]
    async fn a_bootstrap_with_huge_noise_is_read_to_the_end() {
        let dir = std::env::temp_dir().join(format!("qsh-client-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("ssh");
        let reply = format!(
            r#"{{"qsh":1,"versions":[1],"session":"{}","key":"{}","cert_sha256":"{}","udp":1,"tcp":1}}"#,
            "ab".repeat(16),
            "cd".repeat(32),
            "ef".repeat(32)
        );
        std::fs::write(
            &script,
            format!("#!/bin/sh\ncat >/dev/null\nhead -c 3145728 /dev/zero | tr '\\0' x\necho\necho '{reply}'\n"),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut ssh = SshCommand::new("host");
        ssh.program = script.clone().into();
        let request = Request::new_session(80, 24);
        let result = tokio::time::timeout(Duration::from_secs(30), bootstrap(&ssh, &request, false))
            .await
            .expect("the bootstrap must not hang");
        assert!(matches!(result, Ok(Reply::Credentials(_))), "{result:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
