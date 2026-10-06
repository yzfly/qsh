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

pub mod store;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::crypto::{self, Fingerprint, SessionKey};
use crate::netwatch::NetWatch;
use crate::proto::bootstrap::{self, Credentials, ErrorKind, Reply, Request, SessionInfo};
use crate::proto::limits::{ATTACH_TIMEOUT, RESEND_CHUNK};
use crate::proto::message::{ATTACH_FRESH, LATEST, MAX_CONTROL, MAX_HELLO, MAX_TERMINAL, PREFERRED_DATA};
use crate::proto::varint;
use crate::proto::{read_message, write_message, ErrorCode, ExitStatus, FramingError, Message, WindowSize};
use crate::session::{Inbound, ReplayBuffer, INPUT_REPLAY};
use crate::transport::quic::QuicClient;
use crate::transport::ssh::{SshCommand, EXIT_CANNOT_EXECUTE, EXIT_COMMAND_NOT_FOUND};
use crate::transport::{Connection, Race, RaceConfig, RaceError, RecvStream, SendStream, Target, Transport};
use crate::{log, proto};
use store::{SavedSession, SessionLock, SessionStore};

/// Exit status of `qsh` when the server has no qsh-server (protocol.md 10.2).
pub const EXIT_NO_SERVER: i32 = proto::EXIT_NO_SERVER;
/// Exit status of `qsh` for its own errors, like ssh.
pub const EXIT_ERROR: i32 = 255;

/// Send PING this often (section 12.3).
const PING_INTERVAL: Duration = Duration::from_secs(15);
/// Nothing received for this long: the path is dead.
const DEAD_AFTER: Duration = Duration::from_secs(45);
/// Typed input followed by nothing received for this long: the path is dead. The user
/// notices a dead connection when typing, so that is when to find out fast.
const INPUT_ANSWER_WITHIN: Duration = Duration::from_secs(8);
/// Unacknowledged input for this long: PING, so the control stream answers even if the
/// terminal stream is held up.
const INPUT_PING_AFTER: Duration = Duration::from_secs(1);
/// ACK output after this much, or this long after it arrived (section 7.5).
const ACK_BYTES: u64 = 32768;
const ACK_DELAY: Duration = Duration::from_millis(200);
/// A connection that lasted this long was a working one: reconnect at once after it ends.
const STABLE_AFTER: Duration = Duration::from_secs(10);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// After a network change, a connection that answers nothing for this long is dead.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Which transports to race, and when each starts.
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
    /// Bytes of output were skipped: they fell out of the server's replay buffer.
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
    /// Output bytes skipped (OUTPUT_GAP).
    pub skipped: u64,
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

/// A connection after the hello exchange, with its control stream served in the background.
pub struct Conn {
    connection: Connection,
    nonce: [u8; 32],
    control: mpsc::UnboundedSender<Message>,
    last_rx: Mutex<Instant>,
    rtt: Mutex<Option<Duration>>,
    observed: Mutex<Option<SocketAddr>>,
    goaway: AtomicBool,
    /// The server sent GOAWAY (SHUTDOWN): it is stopping, and its sessions with it.
    shutdown: AtomicBool,
    started: Instant,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// How each transport fared in the race that produced this connection.
    attempts: Mutex<Vec<(Transport, String)>>,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").field("connection", &self.connection).finish()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        for t in self.tasks.lock().unwrap().iter() {
            t.abort();
        }
    }
}

fn micros(since: Instant) -> u64 {
    since.elapsed().as_micros() as u64
}

impl Conn {
    /// Open the control stream and do the hello exchange (section 5). Over the pipe the
    /// server's nonce is needed before any ATTACH; elsewhere waiting costs one round trip
    /// and keeps the code simple.
    pub async fn hello(connection: Connection) -> io::Result<Arc<Conn>> {
        let (_, mut send, recv) = connection.open().await?;
        let hello = Message::ClientHello {
            versions: vec![u64::from(proto::VERSION)],
            capabilities: Vec::new(),
            implementation: proto::IMPLEMENTATION.into(),
        };
        write_message(&mut send, &hello).await?;
        let mut recv = BufReader::new(recv);
        let nonce = match read_message(&mut recv, MAX_HELLO).await {
            Ok(Some(Message::ServerHello {
                version,
                nonce,
                capabilities,
                ..
            })) => {
                if version != u64::from(proto::VERSION) || !capabilities.is_empty() {
                    connection.close(ErrorCode::PROTOCOL_VIOLATION, "");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SERVER_HELLO"));
                }
                nonce
            }
            Ok(Some(Message::Error { code, message })) => {
                return Err(io::Error::other(format!(
                    "the server refused the connection: {code} {message}"
                )))
            }
            Ok(Some(_)) => return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected first message")),
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during hello",
                ))
            }
            Err(e) => return Err(e.into()),
        };
        let (control, mut rx) = mpsc::unbounded_channel::<Message>();
        let started = Instant::now();
        let conn = Arc::new(Conn {
            connection,
            nonce,
            control,
            last_rx: Mutex::new(Instant::now()),
            rtt: Mutex::new(None),
            observed: Mutex::new(None),
            goaway: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            started,
            tasks: Mutex::new(Vec::new()),
            attempts: Mutex::new(Vec::new()),
        });
        // The tasks hold only a weak reference: the connection ends when its users drop it
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if write_message(&mut send, &m).await.is_err() {
                    break;
                }
            }
        });
        let reader = tokio::spawn(control_reader(Arc::downgrade(&conn), recv, started));
        *conn.tasks.lock().unwrap() = vec![writer, reader];
        Ok(conn)
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.connection.transport()
    }

    /// True when the connection can carry new attachments.
    pub fn usable(&self) -> bool {
        !self.connection.is_closed() && !self.goaway.load(Ordering::SeqCst)
    }

    /// True once the server said it is stopping (GOAWAY with SHUTDOWN).
    pub fn server_stopping(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Close the connection (it is dead, or no longer needed).
    pub fn close(&self, code: ErrorCode, why: &str) {
        self.connection.close(code, why);
    }

    fn received(&self) {
        *self.last_rx.lock().unwrap() = Instant::now();
    }

    fn last_received(&self) -> Instant {
        *self.last_rx.lock().unwrap()
    }

    fn ping(&self) {
        let _ = self.control.send(Message::Ping {
            data: micros(self.started),
        });
    }

    /// Check the path now (the network changed): PING, and close the connection when nothing
    /// at all arrives within `within`. The sessions on it then race the transports again
    /// instead of waiting for the dead path timers (protocol.md 12.3, 12.4).
    pub(crate) fn probe(self: &Arc<Self>, within: Duration) {
        let sent = Instant::now();
        self.ping();
        let conn = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(within).await;
            if let Some(conn) = conn.upgrade() {
                if conn.last_received() < sent && !conn.connection.is_closed() {
                    log::info(format_args!(
                        "no answer over {} after the network changed; reconnecting",
                        conn.transport()
                    ));
                    conn.close(ErrorCode::NO_ERROR, "path lost");
                }
            }
        });
    }

    /// The round-trip time: QUIC's own estimate, or the last PING.
    pub fn rtt(&self) -> Option<Duration> {
        self.connection.rtt().or(*self.rtt.lock().unwrap())
    }
}

async fn control_reader(conn: std::sync::Weak<Conn>, mut recv: BufReader<RecvStream>, started: Instant) {
    loop {
        let result = read_message(&mut recv, MAX_CONTROL).await;
        let Some(conn) = conn.upgrade() else { return };
        let message = match result {
            Ok(Some(m)) => m,
            Ok(None) => return conn.close(ErrorCode::PROTOCOL_VIOLATION, "control stream finished"),
            Err(FramingError::Io(_)) => return conn.close(ErrorCode::NO_ERROR, ""),
            Err(e) => return conn.close(e.code(), ""),
        };
        conn.received();
        match message {
            Message::Pong { data } => {
                let now = micros(started);
                if data <= now {
                    *conn.rtt.lock().unwrap() = Some(Duration::from_micros(now - data));
                }
            }
            Message::Ping { data } => {
                let _ = conn.control.send(Message::Pong { data });
            }
            Message::PathInfo { address, port, .. } => {
                *conn.observed.lock().unwrap() = address.map(|a| SocketAddr::new(a, port));
            }
            Message::GoAway { code, .. } => {
                log::debug(format_args!("GOAWAY {code}"));
                conn.goaway.store(true, Ordering::SeqCst);
                if code == ErrorCode::SHUTDOWN {
                    conn.shutdown.store(true, Ordering::SeqCst);
                }
            }
            Message::Error { code, message } => {
                log::debug(format_args!("connection error from the server: {code} {message}"));
                return conn.connection.close(ErrorCode::NO_ERROR, "");
            }
            Message::Unknown { .. } => {}
            _ => {
                return conn.close(
                    ErrorCode::PROTOCOL_VIOLATION,
                    "unexpected message on the control stream",
                )
            }
        }
    }
}

/// Which daemon a connection goes to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServerKey {
    destination: String,
    host: String,
    udp: u16,
    tcp: u16,
    fingerprint: [u8; 32],
}

#[derive(Debug, Default)]
struct Slot {
    current: Option<Arc<Conn>>,
    failed_at: Option<Instant>,
    last_error: Option<String>,
    pin_mismatch: bool,
    no_server: bool,
}

/// Connections to servers, one per daemon, shared by the sessions to it (a hub carries all
/// its terminals to a server on one connection). One connection attempt per server at a time.
///
/// Inside a tokio runtime a pool watches the network ([`NetWatch`]): when it changes, the QUIC
/// endpoint moves to the new network, every connection is probed, and sessions waiting to
/// reconnect try at once ([`Pool::network_changed`]).
pub struct Pool {
    quic: Arc<QuicClient>,
    slots: Mutex<HashMap<ServerKey, Arc<tokio::sync::Mutex<Slot>>>>,
    /// Sessions waiting out a back-off wait on this.
    network: Arc<tokio::sync::Notify>,
    watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool").field("quic", &self.quic).finish_non_exhaustive()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(watcher) = self.watcher.lock().unwrap().take() {
            watcher.abort();
        }
    }
}

impl Pool {
    /// A pool with its own QUIC endpoint.
    pub fn new() -> Arc<Pool> {
        Pool::with_quic(Arc::new(QuicClient::new()))
    }

    /// A pool using `quic`'s endpoint. Within a tokio runtime it watches the network.
    pub fn with_quic(quic: Arc<QuicClient>) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            quic,
            slots: Mutex::new(HashMap::new()),
            network: Arc::new(tokio::sync::Notify::new()),
            watcher: Mutex::new(None),
        });
        if tokio::runtime::Handle::try_current().is_ok() {
            match NetWatch::spawn() {
                Ok(net) => {
                    log::debug(format_args!("watching the network ({})", net.mechanism()));
                    let task = tokio::spawn(watch_network(Arc::downgrade(&pool), net));
                    *pool.watcher.lock().unwrap() = Some(task);
                }
                Err(e) => log::debug(format_args!("not watching the network: {e}")),
            }
        }
        pool
    }

    /// The network changed (the pool's own watcher calls this; an embedder that hears of
    /// changes first, such as an Android app, may too): move the QUIC endpoint to a socket on
    /// the new network, which migrates every QUIC connection; PING every connection and drop
    /// those that answer nothing within 2 s, so their sessions race the transports again; and
    /// wake the sessions waiting to reconnect, regardless of their back-off (protocol.md 12.2).
    pub fn network_changed(&self) {
        match self.quic.rebind() {
            Ok(true) => log::debug(format_args!("QUIC moved to {:?}", self.quic.local_addr())),
            Ok(false) => {}
            Err(e) => log::info(format_args!("cannot move QUIC to the new network: {e}")),
        }
        for conn in self.live() {
            conn.probe(PROBE_TIMEOUT);
        }
        self.network.notify_waiters();
    }

    fn live(&self) -> Vec<Arc<Conn>> {
        let slots: Vec<_> = self.slots.lock().unwrap().values().cloned().collect();
        slots
            .into_iter()
            .filter_map(|slot| slot.try_lock().ok().and_then(|s| s.current.clone()))
            .filter(|c| c.usable())
            .collect()
    }

    /// The QUIC endpoint, e.g. to rebind it when the network changed.
    pub fn quic(&self) -> &Arc<QuicClient> {
        &self.quic
    }

    /// A usable connection to `target`: the current one, or a new one from a race.
    pub async fn get(&self, target: &Target, race: &RaceConfig) -> Result<Arc<Conn>, RaceError> {
        let key = ServerKey {
            destination: target.ssh.destination.clone(),
            host: target.host.clone(),
            udp: target.udp,
            tcp: target.tcp,
            fingerprint: target.fingerprint.0,
        };
        let slot = self.slots.lock().unwrap().entry(key).or_default().clone();
        let asked = Instant::now();
        let mut slot = slot.lock().await;
        if let Some(c) = slot.current.as_ref().filter(|c| c.usable()) {
            return Ok(c.clone());
        }
        // Another session just tried and failed while this one waited: share its result
        if slot.failed_at.is_some_and(|t| t >= asked) {
            let mut e = RaceError::default();
            let message = if slot.pin_mismatch {
                crypto::PIN_MISMATCH.to_string()
            } else {
                slot.last_error.clone().unwrap_or_default()
            };
            e.errors.push((Transport::Quic, io::Error::other(message)));
            if slot.no_server {
                e.errors
                    .push((Transport::Ssh, io::Error::new(io::ErrorKind::NotFound, "no qsh-server")));
            }
            return Err(e);
        }
        match establish(target, &self.quic, race).await {
            Ok(c) => {
                slot.current = Some(c.clone());
                slot.failed_at = None;
                Ok(c)
            }
            Err(e) => {
                slot.current = None;
                slot.failed_at = Some(Instant::now());
                slot.last_error = Some(e.to_string());
                slot.pin_mismatch = e.pin_mismatch();
                slot.no_server = e.no_server();
                Err(e)
            }
        }
    }

    /// Close every connection (they reconnect as needed).
    pub fn reset(&self) {
        let slots: Vec<_> = self.slots.lock().unwrap().values().cloned().collect();
        for slot in slots {
            if let Ok(slot) = slot.try_lock() {
                if let Some(c) = &slot.current {
                    c.close(ErrorCode::NO_ERROR, "reset");
                }
            }
        }
    }

    /// The live connections: destination, transport and round-trip time.
    pub fn connections(&self) -> Vec<(String, Transport, Option<Duration>)> {
        let slots: Vec<_> = self
            .slots
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        slots
            .into_iter()
            .filter_map(|(k, slot)| {
                let current = slot
                    .try_lock()
                    .ok()
                    .and_then(|s| s.current.clone())
                    .filter(|c| c.usable())?;
                Some((k.destination, current.transport(), current.rtt()))
            })
            .collect()
    }
}

/// Follow the network for `pool` until it is dropped.
async fn watch_network(pool: std::sync::Weak<Pool>, mut net: NetWatch) {
    loop {
        let change = net.changed().await;
        let Some(pool) = pool.upgrade() else { return };
        log::info(format_args!("the network changed: {}", change.snapshot));
        if !change.snapshot.is_online() {
            // No route anywhere: nothing to try until the next change
            continue;
        }
        pool.network_changed();
    }
}

/// Race the transports and keep the first connection whose hello succeeds within 5 s
/// (section 12.1); the others are dropped.
async fn establish(target: &Target, quic: &Arc<QuicClient>, config: &RaceConfig) -> Result<Arc<Conn>, RaceError> {
    let mut race = Race::start(target, quic, config);
    while let Some(connection) = race.next().await {
        let transport = connection.transport();
        match tokio::time::timeout(ATTACH_TIMEOUT, Conn::hello(connection)).await {
            Ok(Ok(conn)) => {
                log::debug(format_args!("connected over {transport}"));
                *conn.attempts.lock().unwrap() = attempts(target, config, transport, race.errors());
                return Ok(conn);
            }
            Ok(Err(e)) => race.failed(transport, e),
            Err(_) => race.failed(transport, io::Error::new(io::ErrorKind::TimedOut, "no SERVER_HELLO")),
        }
    }
    Err(race.take_errors())
}

/// How each transport fared in a race that `winner` won, for the status line.
fn attempts(target: &Target, config: &RaceConfig, winner: Transport, errors: &RaceError) -> Vec<(Transport, String)> {
    [
        (Transport::Quic, config.quic, target.udp != 0),
        (Transport::Tls, config.tls, target.tcp != 0),
        (Transport::Ssh, config.ssh, true),
    ]
    .into_iter()
    .map(|(transport, delay, port)| {
        let outcome = if transport == winner {
            "used".to_string()
        } else if delay.is_none() {
            "off".to_string()
        } else if !port {
            "no port".to_string()
        } else if let Some((_, e)) = errors.errors.iter().rev().find(|(t, _)| *t == transport) {
            format!("failed: {e}")
        } else {
            "not needed".to_string()
        };
        (transport, outcome)
    })
    .collect()
}

/// Where a session's credentials are saved, and the lock that shows it in use by this process.
struct Persist {
    store: SessionStore,
    record: SavedSession,
    lock: Option<SessionLock>,
}

impl Persist {
    fn new(store: SessionStore, record: SavedSession) -> Persist {
        let lock = store.lock(&record.destination, &record.session).ok().flatten();
        Persist { store, record, lock }
    }

    /// Write the record, durably. Takes the lock if another process held it before.
    fn save(&mut self) -> io::Result<()> {
        if self.lock.is_none() {
            self.lock = self
                .store
                .lock(&self.record.destination, &self.record.session)
                .ok()
                .flatten();
        }
        self.store.save(&self.record)
    }

    /// Save after a change, telling the user (with -v) when it failed.
    fn save_or_log(&mut self) -> bool {
        match self.save() {
            Ok(()) => true,
            Err(e) => {
                log::info(format_args!(
                    "cannot save the session's credentials in {}: {e}",
                    self.store.dir().display()
                ));
                false
            }
        }
    }

    fn forget(&self) {
        if let Err(e) = self.store.remove(&self.record.destination, &self.record.session) {
            log::debug(format_args!("cannot remove the saved session: {e}"));
        }
    }
}

/// The client's state of one session, across connections.
struct State {
    session: [u8; 16],
    key: SessionKey,
    target: Target,
    /// No stream state yet: the next ATTACH sets FRESH.
    fresh: bool,
    output: Inbound,
    /// A pipe session (protocol.md 7.14), as the bootstrap reply said.
    pipe: bool,
    /// A pipe session's stderr as received.
    errors: Inbound,
    input: ReplayBuffer,
    /// The input end, once the local input reached it: INPUT_EOF at this offset (pipe
    /// sessions), sent again on every attachment.
    input_eof: Option<u64>,
    /// The last byte of input, to end a tty session's input as a terminal would.
    last_input: Option<u8>,
    size: WindowSize,
    /// The user asked to end the session; deliver HANGUP on the next attachment.
    hangup: bool,
    input_closed: bool,
    /// Where the credentials are saved; None: in memory only.
    persist: Option<Persist>,
    /// The session is known to be gone (it ended, or the server does not know it).
    gone: bool,
    /// A FRESH attach replays the server's buffer (offset 0) rather than starting at LATEST.
    replay: bool,
}

impl State {
    /// Take input from the terminal into the replay buffer: the bytes to send now, as INPUT
    /// messages with their offsets, or INPUT_EOF. Nothing after the end of input.
    fn take_input(&mut self, input: Input) -> Vec<Message> {
        let data = match input {
            Input::Data(data) if !data.is_empty() && !self.hangup && self.input_eof.is_none() => data,
            Input::Eof if self.input_eof.is_none() && !self.hangup => {
                if self.pipe {
                    let end = self.input.end();
                    self.input_eof = Some(end);
                    return vec![Message::InputEof { offset: end }];
                }
                // A tty session: the line discipline ends the input at ^D at the start of a
                // line; a partial line needs one more ^D to be passed on first
                let eof = if matches!(self.last_input, None | Some(b'\n') | Some(b'\r')) {
                    vec![4]
                } else {
                    vec![4, 4]
                };
                self.input_closed = true;
                eof
            }
            _ => return Vec::new(),
        };
        self.last_input = data.last().copied();
        let mut offset = self.input.end();
        let room = self.input.room();
        let data = &data[..data.len().min(usize::try_from(room).unwrap_or(usize::MAX))];
        self.input.push(data);
        data.chunks(PREFERRED_DATA)
            .map(|chunk| {
                let m = Message::Input {
                    offset,
                    data: chunk.to_vec(),
                };
                offset += chunk.len() as u64;
                m
            })
            .collect()
    }

    /// The client's ACK: output received, and on a pipe session error output received.
    fn ack(&self) -> Message {
        Message::Ack {
            received: self.output.received(),
            error_received: self.pipe.then(|| self.errors.received()),
        }
    }
}

/// Offsets above this are refused from a server (protocol.md 7.3, client step 2): no session
/// comes anywhere near 2^62 bytes, and staying below leaves room for every offset that follows.
const MAX_OFFSET: u64 = varint::MAX;

/// Section 7.3, client side, step 2 (and 7.14.6): whether the offsets of ATTACHED fit the
/// client's state and can be used safely.
fn offsets_consistent(state: &State, sent: (u64, u64), got: (u64, u64, Option<u64>)) -> bool {
    let (output_received, error_received) = sent;
    let (input_received, output_start, error_start) = got;
    let error_start = match (state.pipe, error_start) {
        (true, Some(e)) => e,
        // A pipe session's ATTACHED carries Error Start; nothing else may
        (false, None) => 0,
        _ => return false,
    };
    if input_received > MAX_OFFSET || output_start > MAX_OFFSET || error_start > MAX_OFFSET {
        return false;
    }
    if state.fresh {
        return true;
    }
    output_start == output_received
        && error_start == error_received
        && state.input.base() <= input_received
        && input_received <= state.input.end()
}

/// When a session gives up instead of trying again (section 11.2): one new set of credentials
/// after AUTH_FAILED or a pin mismatch, one more attach after SEQUENCE_ERROR. Both chances come
/// back once an attachment has worked for [`STABLE_AFTER`], so that an incident hours later is
/// not met with "already tried".
#[derive(Debug, Default)]
struct Retries {
    reissued: bool,
    sequence_retry: bool,
}

impl Retries {
    /// An attachment ended after `lasted`.
    fn attachment_ended(&mut self, lasted: Duration) {
        if lasted >= STABLE_AFTER {
            *self = Retries::default();
        }
    }

    /// May the session get new credentials over ssh now?
    fn may_reissue(&mut self) -> bool {
        !std::mem::replace(&mut self.reissued, true)
    }

    /// May the session attach once more after SEQUENCE_ERROR?
    fn may_retry_sequence(&mut self) -> bool {
        !std::mem::replace(&mut self.sequence_retry, true)
    }
}

/// How one attachment ended.
enum End {
    Exited(ExitStatus),
    Detached,
    /// The connection is gone or dead; reconnect.
    Lost(String),
    /// The session cannot go on this way.
    Fatal(ClientError),
    /// The session is gone for good: it ended, or the server does not know it.
    Gone(ClientError),
}

/// One terminal session.
#[derive(Debug)]
pub struct Session {
    config: ClientConfig,
    pool: Arc<Pool>,
    status: Arc<Mutex<Status>>,
}

impl Session {
    /// A session to be run with [`Session::run`], with a QUIC endpoint of its own.
    pub fn new(config: ClientConfig) -> Session {
        Session::with_pool(config, Pool::new())
    }

    /// A session whose connections come from `pool`, shared with other sessions.
    pub fn with_pool(config: ClientConfig, pool: Arc<Pool>) -> Session {
        Session {
            config,
            pool,
            status: Arc::new(Mutex::new(Status::default())),
        }
    }

    /// The live status, updated while the session runs.
    pub fn status(&self) -> Arc<Mutex<Status>> {
        self.status.clone()
    }

    /// Bootstrap a new session and run it until its program exits, it is detached, or it
    /// cannot go on.
    pub async fn run(&self, terminal: Terminal) -> Result<Outcome, ClientError> {
        let config = &self.config;
        let mut request = Request::new_session(config.size.cols, config.size.rows);
        request.command = config.command.clone();
        request.term = config.term.clone();
        request.env = config.env.clone();
        request.name = config.name.clone();
        if !config.tty {
            // A pipe session; the reply says whether the server made one (10.4)
            request.tty = Some(false);
        }
        let credentials = match bootstrap(&config.ssh, &request, config.interactive).await? {
            Reply::Credentials(c) => c,
            other => return Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
        };
        let host = self.daemon_host().await;
        let mut state = state_from(&credentials, host, &config.ssh, config.size)?;
        self.persist(&mut state, config.name.clone(), config.command.clone(), store::now());
        self.drive(state, terminal).await
    }

    /// Attach a session whose credentials were saved (`qsh attach`): straight to the daemon,
    /// no ssh needed. The output the server still buffers is replayed (FRESH from offset 0).
    /// When the key is no longer valid or the daemon's certificate changed, new credentials are
    /// issued over ssh (bootstrap op `attach`).
    pub async fn attach_saved(&self, saved: SavedSession, terminal: Terminal) -> Result<Outcome, ClientError> {
        let target = Target {
            host: saved.host.clone(),
            udp: saved.udp,
            tcp: saved.tcp,
            fingerprint: saved.fingerprint,
            ssh: self.config.ssh.clone(),
        };
        let mut state = State::new(saved.session, saved.key.clone(), target, saved.pipe, self.config.size);
        state.replay = self.config.replay_on_attach;
        if let Some(store) = self.config.store.clone() {
            state.persist = Some(Persist::new(store, saved));
        }
        self.drive(state, terminal).await
    }

    /// Attach session `session` (32 hex digits) with credentials issued over ssh (bootstrap op
    /// `attach`): for a session whose credentials are not saved here. It replaces the session's
    /// keys, so a client attached elsewhere is taken over. `info`, from `list`, is saved with
    /// the credentials.
    pub async fn attach_over_ssh(
        &self,
        session: &str,
        info: Option<&SessionInfo>,
        terminal: Terminal,
    ) -> Result<Outcome, ClientError> {
        let config = &self.config;
        let request = Request::attach(session, config.size.cols, config.size.rows);
        let credentials = match bootstrap_reply(&config.ssh, &request, config.interactive).await? {
            Reply::Credentials(c) => c,
            Reply::Error(e) if e.error == ErrorKind::NoSession => {
                if let (Some(store), Some(id)) = (&config.store, crypto::unhex::<16>(session)) {
                    let _ = store.remove(&config.ssh.destination, &id);
                }
                return Err(ClientError::SessionLost(format!("no session {session} on the host")));
            }
            Reply::Error(e) => return Err(ClientError::Bootstrap(e.to_string())),
            other => return Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
        };
        let host = self.daemon_host().await;
        let mut state = state_from(&credentials, host, &config.ssh, config.size)?;
        state.replay = config.replay_on_attach;
        let (name, command, created) = match info {
            Some(i) => (i.name.clone(), i.command.clone(), i.created),
            None => (None, None, store::now()),
        };
        self.persist(&mut state, name, command, created);
        self.drive(state, terminal).await
    }

    /// Bootstrap and run, as an exit status: the program's, 0 after detaching, or the
    /// error's ([`ClientError::exit_code`]).
    pub async fn connect(config: ClientConfig, terminal: Terminal) -> Result<i32, ClientError> {
        match Session::new(config).run(terminal).await? {
            Outcome::Exited(status) => Ok(exit_code(&status)),
            Outcome::Detached => Ok(0),
            Outcome::Abandoned => Ok(EXIT_ERROR),
        }
    }

    /// The host of the daemon for QUIC and TLS: where ssh connects.
    async fn daemon_host(&self) -> String {
        let ssh = &self.config.ssh;
        ssh.resolve_host().await.unwrap_or_else(|| host_of(&ssh.destination))
    }

    /// Start saving the credentials of a session that has none saved yet.
    fn persist(&self, state: &mut State, name: Option<String>, command: Option<String>, created: u64) {
        let Some(store) = self.config.store.clone() else { return };
        let record = SavedSession {
            destination: self.config.ssh.destination.clone(),
            ssh_options: self
                .config
                .ssh
                .options
                .iter()
                .map(|o| o.to_string_lossy().into_owned())
                .collect(),
            host: state.target.host.clone(),
            udp: state.target.udp,
            tcp: state.target.tcp,
            fingerprint: state.target.fingerprint,
            session: state.session,
            key: state.key.clone(),
            pipe: state.pipe,
            name,
            command,
            created,
        };
        let mut persist = Persist::new(store, record);
        persist.save_or_log();
        state.persist = Some(persist);
    }

    /// Run the session, then forget its saved credentials if it is gone.
    async fn drive(&self, mut state: State, mut terminal: Terminal) -> Result<Outcome, ClientError> {
        self.status.lock().unwrap().session = Some(state.session);
        let result = self.run_attached(&mut state, &mut terminal).await;
        if state.gone || matches!(result, Ok(Outcome::Exited(_))) {
            if let Some(persist) = &state.persist {
                persist.forget();
            }
        }
        result
    }

    async fn run_attached(&self, state: &mut State, terminal: &mut Terminal) -> Result<Outcome, ClientError> {
        let mut backoff = BACKOFF_FIRST;
        let mut wait: Option<Duration> = None;
        let mut retries = Retries::default();
        loop {
            if let Some(d) = wait.take() {
                if let Some(outcome) = offline(state, terminal, d, &self.pool.network).await {
                    return Ok(outcome);
                }
            }
            let conn = match self.pool.get(&state.target, &self.config.race).await {
                Ok(c) => c,
                Err(e) => {
                    log::debug(format_args!("no connection: {e}"));
                    if e.pin_mismatch() && retries.may_reissue() {
                        // The daemon's identity changed: a new pin over ssh, keeping the session
                        self.reissue(state).await?;
                        continue;
                    }
                    if state.hangup {
                        return Ok(Outcome::Abandoned);
                    }
                    notify(terminal, Event::Disconnected(e.to_string()));
                    wait = Some(jitter(backoff));
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            };
            let attached_at = Instant::now();
            let end = self.attach(&conn, state, terminal).await?;
            retries.attachment_ended(attached_at.elapsed());
            match end {
                End::Exited(status) => return Ok(Outcome::Exited(status)),
                End::Detached => return Ok(Outcome::Detached),
                End::Lost(_) if conn.server_stopping() => {
                    // The daemon is stopping and its sessions with it (7.13): no reconnect, and
                    // above all no ssh pipe, whose qsh-server would start a new daemon
                    conn.close(ErrorCode::NO_ERROR, "");
                    state.gone = true;
                    return Err(ClientError::SessionLost("the server stopped".into()));
                }
                End::Lost(why) => {
                    log::debug(format_args!("connection lost: {why}"));
                    conn.close(ErrorCode::NO_ERROR, "");
                    {
                        let mut status = self.status.lock().unwrap();
                        status.transport = None;
                        status.connected_since = None;
                        status.reconnects += 1;
                    }
                    notify(terminal, Event::Disconnected(why));
                    if attached_at.elapsed() >= STABLE_AFTER {
                        backoff = BACKOFF_FIRST;
                    } else {
                        wait = Some(jitter(backoff));
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                    }
                }
                End::Fatal(ClientError::SessionLost(why)) if why == "AUTH_FAILED" && retries.may_reissue() => {
                    // The key is not valid any more: new credentials over ssh (section 6.4)
                    log::info(format_args!("the session key was refused; getting a new one over ssh"));
                    self.reissue(state).await?;
                }
                End::Fatal(ClientError::SessionLost(why))
                    if why == "SEQUENCE_ERROR" && retries.may_retry_sequence() =>
                {
                    // Attach once more; then give up on the session (section 11.2)
                }
                End::Fatal(e) => return Err(e),
                End::Gone(e) => {
                    state.gone = true;
                    return Err(e);
                }
            }
        }
    }

    /// New credentials for the session over ssh (bootstrap op `attach`), saved before use.
    async fn reissue(&self, state: &mut State) -> Result<(), ClientError> {
        let request = Request::attach(&crypto::hex(&state.session), state.size.cols, state.size.rows);
        let credentials = match bootstrap_reply(&self.config.ssh, &request, self.config.interactive).await {
            Ok(Reply::Credentials(c)) => c,
            Ok(Reply::Error(e)) => {
                state.gone = e.error == ErrorKind::NoSession;
                return Err(ClientError::SessionLost(e.to_string()));
            }
            Ok(other) => return Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
            Err(ClientError::Bootstrap(e)) => return Err(ClientError::SessionLost(e)),
            Err(e) => return Err(e),
        };
        let fresh = state_from(&credentials, state.target.host.clone(), &self.config.ssh, state.size)?;
        state.key = fresh.key.clone();
        state.target = fresh.target.clone();
        if let Some(persist) = state.persist.as_mut() {
            let record = &mut persist.record;
            record.key = fresh.key.clone();
            record.udp = fresh.target.udp;
            record.tcp = fresh.target.tcp;
            record.fingerprint = fresh.target.fingerprint;
            persist.save_or_log();
        }
        Ok(())
    }

    /// Attach on `conn` and run the terminal channel until it ends.
    async fn attach(&self, conn: &Arc<Conn>, state: &mut State, terminal: &mut Terminal) -> Result<End, ClientError> {
        let (_, mut send, recv) = match conn.connection.open().await {
            Ok(s) => s,
            Err(e) => return Ok(End::Lost(e.to_string())),
        };
        let mut recv = BufReader::new(recv);
        let cb = conn.connection.channel_binding(&state.session, &conn.nonce)?;
        let key = state.key.clone();
        // FRESH: from the start of what the server buffers, or from its current end (7.2)
        let fresh_start = if state.replay { 0 } else { LATEST };
        let output_received = if state.fresh {
            fresh_start
        } else {
            state.output.received()
        };
        let error_received = if state.fresh {
            fresh_start
        } else {
            state.errors.received()
        };
        let attach = Message::Attach {
            session: state.session,
            proof: key.proof(&cb),
            output_received,
            size: state.size,
            flags: if state.fresh { ATTACH_FRESH } else { 0 },
            error_received: state.pipe.then_some(error_received),
        };
        if let Err(e) = write_message(&mut send, &attach).await {
            return Ok(End::Lost(e.to_string()));
        }
        let reply = match tokio::time::timeout(ATTACH_TIMEOUT, read_message(&mut recv, MAX_TERMINAL)).await {
            Ok(Ok(Some(m))) => m,
            Ok(Ok(None)) => return Ok(End::Lost("the server closed the channel".into())),
            Ok(Err(e)) => return Ok(End::Lost(e.to_string())),
            Err(_) => {
                // Abandon it (section 7.2), and the connection with it
                send.reset(ErrorCode::CANCELLED);
                return Ok(End::Lost("no answer to ATTACH".into()));
            }
        };
        conn.received();
        let (input_received, output_start, error_start, next_key) = match reply {
            Message::Attached {
                input_received,
                output_start,
                next_key,
                server_proof,
                error_start,
            } => {
                if !key.verify_server(&cb, &server_proof) {
                    // Not the session's server: never trust this connection (section 6.3)
                    conn.close(ErrorCode::AUTH_FAILED, "");
                    return Ok(End::Fatal(ClientError::SessionLost("AUTH_FAILED".into())));
                }
                (input_received, output_start, error_start, next_key)
            }
            Message::Error { code, message } => return Ok(attach_error(code, message)),
            _ => {
                conn.close(ErrorCode::PROTOCOL_VIOLATION, "");
                return Ok(End::Lost("unexpected answer to ATTACH".into()));
            }
        };
        // Section 7.3, client side
        if !offsets_consistent(
            state,
            (output_received, error_received),
            (input_received, output_start, error_start),
        ) {
            let error = Message::Error {
                code: ErrorCode::SEQUENCE_ERROR,
                message: String::new(),
            };
            let _ = write_message(&mut send, &error).await;
            return Ok(End::Fatal(ClientError::SessionLost(
                "inconsistent offsets after attaching".into(),
            )));
        }
        if state.fresh {
            let pending = state.input.read_from(0, usize::MAX).1;
            state.input = ReplayBuffer::starting_at(INPUT_REPLAY * 2, input_received);
            // Input typed while attaching follows from there (and the end of input with it)
            state.input.push(&pending);
            if state.input_eof.is_some() {
                state.input_eof = Some(state.input.end());
            }
            state.output = Inbound::at(output_start);
            state.errors = Inbound::at(error_start.unwrap_or(0));
            state.fresh = false;
        }
        state.input.ack(input_received);
        // Section 6.5: the new key is stored where the credentials live before it is confirmed.
        // Without a store, memory is where they live, and the key is confirmed at once. When it
        // cannot be saved, it is not confirmed: the old key stays valid on the server, so a
        // client restarted from the saved state can still attach
        let key_id = next_key.id();
        let confirm = match state.persist.as_mut() {
            None => true,
            Some(persist) => {
                persist.record.key = next_key.clone();
                persist.save_or_log()
            }
        };
        state.key = next_key;
        let mut first = Vec::new();
        if confirm {
            first.push(Message::KeyConfirm { key_id });
        }
        let (mut offset, pending) = state.input.read_from(input_received, usize::MAX);
        for chunk in pending.chunks(RESEND_CHUNK) {
            first.push(Message::Input {
                offset,
                data: chunk.to_vec(),
            });
            offset += chunk.len() as u64;
        }
        if let Some(offset) = state.input_eof {
            // Repeated on every attachment: that is how it survives a lost connection (7.14.4)
            first.push(Message::InputEof { offset });
        }
        if state.hangup {
            first.push(Message::Hangup);
        }
        let mut bytes = Vec::new();
        for m in &first {
            bytes.extend(m.encode());
        }
        let written = async {
            send.write_all(&bytes).await?;
            send.flush().await
        };
        if let Err(e) = written.await {
            return Ok(End::Lost(e.to_string()));
        }
        {
            let mut status = self.status.lock().unwrap();
            status.transport = Some(conn.transport());
            status.remote = conn.connection.remote_address();
            status.connected_since = Some(Instant::now());
            status.bytes_out += pending.len() as u64;
            status.attempts = conn.attempts.lock().unwrap().clone();
        }
        notify(terminal, Event::Connected(conn.transport()));
        let had_pending = !pending.is_empty();
        self.pump(conn, state, terminal, send, recv, had_pending).await
    }

    /// The attached terminal channel (sections 7.4 to 7.11).
    async fn pump(
        &self,
        conn: &Arc<Conn>,
        state: &mut State,
        terminal: &mut Terminal,
        mut send: SendStream,
        recv: BufReader<RecvStream>,
        had_pending: bool,
    ) -> Result<End, ClientError> {
        let (tx, mut rx) = mpsc::channel::<Result<Message, FramingError>>(64);
        let reader = tokio::spawn(async move {
            let mut recv = recv;
            loop {
                let m = match read_message(&mut recv, MAX_TERMINAL).await {
                    Ok(Some(m)) => Ok(m),
                    Ok(None) => break,
                    Err(e) => Err(e),
                };
                let broken = m.is_err();
                if tx.send(m).await.is_err() || broken {
                    break;
                }
            }
        });
        let _reader = AbortOnDrop(reader);

        // What the last ACK said, for both output streams
        let mut acked = (state.output.received(), state.errors.received());
        let mut ack_due: Option<Instant> = None;
        let mut last_ping = Instant::now();
        // Since when typed input waits for any answer, and whether it was PINGed already
        let mut unanswered: Option<Instant> = had_pending.then(Instant::now);
        let mut input_pinged = false;
        let mut hangup_sent = state.hangup;
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let room = state.input.len() < INPUT_REPLAY;
            tokio::select! {
                message = rx.recv() => {
                    conn.received();
                    let message = match message {
                        None => return Ok(End::Lost("the server ended the channel".into())),
                        Some(Err(e)) => return Ok(End::Lost(format!("broken channel: {e}"))),
                        Some(Ok(m)) => m,
                    };
                    let message_ty = MessageTy::of(&message);
                    match message {
                        Message::Output { offset, data } | Message::ErrorOutput { offset, data } => {
                            let error = state.pipe && matches!(message_ty, MessageTy::ErrorOutput);
                            if message_ty == MessageTy::ErrorOutput && !state.pipe {
                                // stderr exists only on a pipe session (7.14.3)
                                return Ok(protocol_violation(&mut send).await);
                            }
                            let stream = if error { &mut state.errors } else { &mut state.output };
                            if offset != stream.received() || data.is_empty() {
                                return Ok(sequence_error(&mut send).await);
                            }
                            let n = data.len() as u64;
                            let sink = match (&terminal.errors, error) {
                                (Some(errors), true) => errors,
                                _ => &terminal.output,
                            };
                            if sink.send(data).await.is_err() {
                                // Nobody shows the output any more: leave the session running
                                return Ok(detach(&mut send, &mut rx).await);
                            }
                            // offset + n cannot overflow: the decoder refuses such messages
                            *stream = Inbound::at(offset + n);
                            self.status.lock().unwrap().bytes_in += n;
                            let unacked = (state.output.received() - acked.0) + (state.errors.received() - acked.1);
                            if unacked >= ACK_BYTES {
                                ack(&mut send, state, &mut acked).await;
                                ack_due = None;
                            } else {
                                ack_due.get_or_insert_with(|| Instant::now() + ACK_DELAY);
                            }
                        }
                        Message::OutputGap { from, to } => {
                            if state.pipe {
                                // A pipe session never skips output (7.14.5)
                                return Ok(protocol_violation(&mut send).await);
                            }
                            if from != state.output.received() || from >= to {
                                return Ok(sequence_error(&mut send).await);
                            }
                            state.output = Inbound::at(to);
                            {
                                let mut status = self.status.lock().unwrap();
                                status.skipped = status.skipped.saturating_add(to - from);
                            }
                            notify(terminal, Event::OutputSkipped(to - from));
                        }
                        Message::Ack { received, .. } => {
                            // 7.5: beyond what was sent is an error, below the last is stale
                            if received > state.input.end() {
                                return Ok(sequence_error(&mut send).await);
                            }
                            state.input.ack(received);
                            if received == state.input.end() {
                                unanswered = None;
                                input_pinged = false;
                            }
                        }
                        Message::Exit { output_end, status, error_end } => {
                            // EXIT comes after all output (7.10): of both streams on a pipe session
                            let errors_complete = !state.pipe || error_end == Some(state.errors.received());
                            if output_end != state.output.received() || !errors_complete {
                                return Ok(sequence_error(&mut send).await);
                            }
                            let _ = write_message(&mut send, &state.ack()).await;
                            let _ = send.shutdown().await;
                            // The server finishes once it has our ACK and FIN: wait for that
                            // briefly, so they are not lost when this process exits right away
                            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                                while let Some(Ok(_)) = rx.recv().await {}
                            })
                            .await;
                            return Ok(End::Exited(status));
                        }
                        Message::Error { code, message } => return Ok(attach_error(code, message)),
                        Message::Unknown { .. } => {}
                        _ => return Ok(protocol_violation(&mut send).await),
                    }
                }
                input = terminal.input.recv(), if room && !state.input_closed => match input {
                    Some(input @ (Input::Data(_) | Input::Eof)) => {
                        let messages = state.take_input(input);
                        if messages.is_empty() {
                            continue;
                        }
                        let mut out = Vec::new();
                        for m in &messages {
                            if let Message::Input { data, .. } = m {
                                self.status.lock().unwrap().bytes_out += data.len() as u64;
                                unanswered.get_or_insert_with(Instant::now);
                            }
                            out.extend(m.encode());
                        }
                        if send.write_all(&out).await.is_err() || send.flush().await.is_err() {
                            return Ok(End::Lost("the channel broke".into()));
                        }
                    }
                    Some(Input::Resize(size)) => {
                        state.size = size;
                        if write_message(&mut send, &Message::Resize(size)).await.is_err() {
                            return Ok(End::Lost("the channel broke".into()));
                        }
                    }
                    Some(Input::Detach) => return Ok(detach(&mut send, &mut rx).await),
                    Some(Input::Hangup) => {
                        state.hangup = true;
                        if !hangup_sent {
                            hangup_sent = true;
                            if write_message(&mut send, &Message::Hangup).await.is_err() {
                                return Ok(End::Lost("the channel broke".into()));
                            }
                        }
                    }
                    None => state.input_closed = true,
                },
                _ = tick.tick() => {
                    let now = Instant::now();
                    if ack_due.is_some_and(|t| now >= t) {
                        ack(&mut send, state, &mut acked).await;
                        ack_due = None;
                    }
                    if conn.connection.is_closed() {
                        return Ok(End::Lost("connection closed".into()));
                    }
                    let last_rx = conn.last_received();
                    if last_rx.elapsed() > DEAD_AFTER {
                        return Ok(End::Lost("nothing received for 45 s".into()));
                    }
                    if let Some(since) = unanswered {
                        if last_rx < since && since.elapsed() > INPUT_ANSWER_WITHIN {
                            return Ok(End::Lost("typed input not answered".into()));
                        }
                        if !input_pinged && since.elapsed() > INPUT_PING_AFTER {
                            input_pinged = true;
                            conn.ping();
                            last_ping = now;
                        }
                    }
                    if last_ping.elapsed() >= PING_INTERVAL {
                        conn.ping();
                        last_ping = now;
                    }
                    let mut status = self.status.lock().unwrap();
                    status.rtt = conn.rtt();
                    status.observed = *conn.observed.lock().unwrap();
                    status.remote = conn.connection.remote_address();
                }
            }
        }
    }
}

/// While no connection is up: keep taking input (it is sent after the next attach), sizes
/// and detach requests, for `duration`, or until the network changes.
async fn offline(
    state: &mut State,
    terminal: &mut Terminal,
    duration: Duration,
    network: &tokio::sync::Notify,
) -> Option<Outcome> {
    let deadline = tokio::time::Instant::now() + duration;
    let changed = network.notified();
    tokio::pin!(changed);
    loop {
        let room = state.input.len() < INPUT_REPLAY;
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return None,
            _ = &mut changed => return None,
            input = terminal.input.recv(), if room && !state.input_closed => match input {
                // Kept, and sent after the next attach
                Some(input @ (Input::Data(_) | Input::Eof)) => {
                    let _ = state.take_input(input);
                }
                Some(Input::Resize(size)) => state.size = size,
                Some(Input::Detach) => return Some(Outcome::Detached),
                // Nothing reaches the server now: leave the session to it
                Some(Input::Hangup) => return Some(Outcome::Abandoned),
                None => state.input_closed = true,
            },
        }
    }
}

async fn ack(send: &mut SendStream, state: &State, acked: &mut (u64, u64)) {
    let now = (state.output.received(), state.errors.received());
    if now != *acked {
        let _ = write_message(send, &state.ack()).await;
        *acked = now;
    }
}

/// The kinds of message the client tells apart after matching on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageTy {
    ErrorOutput,
    Other,
}

impl MessageTy {
    fn of(m: &Message) -> MessageTy {
        match m {
            Message::ErrorOutput { .. } => MessageTy::ErrorOutput,
            _ => MessageTy::Other,
        }
    }
}

async fn protocol_violation(send: &mut SendStream) -> End {
    let error = Message::Error {
        code: ErrorCode::PROTOCOL_VIOLATION,
        message: String::new(),
    };
    let _ = write_message(send, &error).await;
    End::Lost("unexpected message from the server".into())
}

async fn sequence_error(send: &mut SendStream) -> End {
    let _ = write_message(
        send,
        &Message::Error {
            code: ErrorCode::SEQUENCE_ERROR,
            message: String::new(),
        },
    )
    .await;
    let _ = send.shutdown().await;
    End::Fatal(ClientError::SessionLost("SEQUENCE_ERROR".into()))
}

/// DETACH, then wait up to 2 s for the server's FIN so typed input is not lost (7.11).
async fn detach(send: &mut SendStream, rx: &mut mpsc::Receiver<Result<Message, FramingError>>) -> End {
    let _ = write_message(send, &Message::Detach).await;
    let _ = send.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = rx.recv().await {}
    })
    .await;
    End::Detached
}

/// What an ERROR on a terminal channel means for the session (section 11.2).
fn attach_error(code: ErrorCode, message: String) -> End {
    let why = if message.is_empty() {
        code.to_string()
    } else {
        format!("{code}: {message}")
    };
    match code {
        ErrorCode::SESSION_UNKNOWN => End::Gone(ClientError::SessionLost("it ended, or the server restarted".into())),
        ErrorCode::SESSION_ENDED => End::Gone(ClientError::SessionLost("it was ended".into())),
        ErrorCode::SESSION_TAKEN_OVER => End::Fatal(ClientError::TakenOver),
        ErrorCode::AUTH_FAILED => End::Fatal(ClientError::SessionLost("AUTH_FAILED".into())),
        ErrorCode::SEQUENCE_ERROR => End::Fatal(ClientError::SessionLost("SEQUENCE_ERROR".into())),
        _ => End::Lost(why),
    }
}

fn notify(terminal: &Terminal, event: Event) {
    if let Some(events) = &terminal.events {
        let _ = events.send(event);
    }
}

/// ±20 % (section 12.2).
fn jitter(d: Duration) -> Duration {
    let r = u32::from(crypto::random::<1>()[0]) * 40 / 255;
    d * (80 + r) / 100
}

/// The host part of `[user@]host`.
fn host_of(destination: &str) -> String {
    destination.rsplit('@').next().unwrap_or(destination).to_string()
}

fn state_from(c: &Credentials, host: String, ssh: &SshCommand, size: WindowSize) -> Result<State, ClientError> {
    let invalid = || ClientError::Bootstrap("malformed credentials".into());
    let session = crypto::unhex::<16>(&c.session).ok_or_else(invalid)?;
    let key = SessionKey::from_hex(&c.key).ok_or_else(invalid)?;
    let fingerprint = Fingerprint::from_hex(&c.cert_sha256).ok_or_else(invalid)?;
    let target = Target {
        host,
        udp: c.udp,
        tcp: c.tcp,
        fingerprint,
        ssh: ssh.clone(),
    };
    Ok(State::new(session, key, target, c.pipe(), size))
}

impl State {
    /// A session this process has no stream state for yet: the first ATTACH is FRESH.
    fn new(session: [u8; 16], key: SessionKey, target: Target, pipe: bool, size: WindowSize) -> State {
        State {
            session,
            key,
            target,
            fresh: true,
            output: Inbound::default(),
            pipe,
            errors: Inbound::default(),
            // Twice the limit: input is taken while below it, and never dropped
            input: ReplayBuffer::new(INPUT_REPLAY * 2),
            input_eof: None,
            last_input: None,
            size,
            hangup: false,
            input_closed: false,
            persist: None,
            gone: false,
            replay: true,
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
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

    fn state(pipe: bool) -> State {
        let c: Credentials = serde_json::from_str(&format!(
            r#"{{"qsh":1,"versions":[1],"session":"{}","key":"{}","cert_sha256":"{}","udp":1,"tcp":1{}}}"#,
            "ab".repeat(16),
            "cd".repeat(32),
            "ef".repeat(32),
            if pipe { r#","tty":false"# } else { "" }
        ))
        .unwrap();
        state_from(&c, "h".into(), &SshCommand::new("h"), WindowSize::new(80, 24)).unwrap()
    }

    /// Review H2 (client side): the one more attach after SEQUENCE_ERROR, and the one reissue,
    /// come back after an attachment that worked for a while.
    #[test]
    fn retries_come_back_after_a_stable_attachment() {
        let mut r = Retries::default();
        assert!(r.may_retry_sequence());
        assert!(!r.may_retry_sequence());
        assert!(r.may_reissue());
        assert!(!r.may_reissue());
        r.attachment_ended(Duration::from_secs(1));
        assert!(!r.may_retry_sequence() && !r.may_reissue());
        r.attachment_ended(STABLE_AFTER);
        assert!(r.may_retry_sequence());
        assert!(r.may_reissue());
    }

    /// Review L3: offsets from a hostile server that would overflow, or that the session's kind
    /// does not have, are refused instead of panicking later.
    #[test]
    fn impossible_offsets_from_the_server_are_refused() {
        let mut s = state(false);
        assert!(offsets_consistent(&s, (0, 0), (0, 0, None)));
        assert!(offsets_consistent(&s, (0, 0), (5, 1 << 40, None)));
        for bad in [u64::MAX, u64::MAX - 1, MAX_OFFSET + 1] {
            assert!(!offsets_consistent(&s, (0, 0), (bad, 0, None)), "{bad}");
            assert!(!offsets_consistent(&s, (0, 0), (0, bad, None)), "{bad}");
        }
        // A tty session's ATTACHED has no Error Start; a pipe session's must have one
        assert!(!offsets_consistent(&s, (0, 0), (0, 0, Some(0))));
        let mut p = state(true);
        assert!(!offsets_consistent(&p, (0, 0), (0, 0, None)));
        assert!(offsets_consistent(&p, (0, 0), (0, 0, Some(7))));
        // Not FRESH: what was sent must come back
        s.fresh = false;
        s.output = Inbound::at(10);
        assert!(offsets_consistent(&s, (10, 0), (0, 10, None)));
        assert!(!offsets_consistent(&s, (10, 0), (0, 11, None)));
        assert!(!offsets_consistent(&s, (10, 0), (1, 10, None)));
        p.fresh = false;
        assert!(offsets_consistent(&p, (0, 3), (0, 0, Some(3))));
        assert!(!offsets_consistent(&p, (0, 3), (0, 0, Some(4))));
    }

    #[test]
    fn the_end_of_input_is_input_eof_on_a_pipe_session_and_ctrl_d_on_a_tty() {
        let mut p = state(true);
        let m = p.take_input(Input::Data(b"abc".to_vec()));
        assert_eq!(
            m,
            vec![Message::Input {
                offset: 0,
                data: b"abc".to_vec()
            }]
        );
        assert_eq!(p.take_input(Input::Eof), vec![Message::InputEof { offset: 3 }]);
        // Nothing after the end
        assert!(p.take_input(Input::Data(b"x".to_vec())).is_empty());
        assert!(p.take_input(Input::Eof).is_empty());
        assert_eq!(
            p.ack(),
            Message::Ack {
                received: 0,
                error_received: Some(0)
            }
        );
        let mut t = state(false);
        assert_eq!(
            t.take_input(Input::Eof),
            vec![Message::Input {
                offset: 0,
                data: vec![4]
            }]
        );
        let mut t = state(false);
        t.take_input(Input::Data(b"partial".to_vec()));
        assert_eq!(
            t.take_input(Input::Eof),
            vec![Message::Input {
                offset: 7,
                data: vec![4, 4]
            }]
        );
        assert!(t.input_closed);
        assert_eq!(
            t.ack(),
            Message::Ack {
                received: 0,
                error_received: None
            }
        );
    }

    /// The far end of a pipe connection that does the hello and then answers PINGs, or not.
    async fn fake_server(conn: Connection, answer: bool) {
        let (_, mut send, recv) = conn.accept().await.unwrap();
        let mut recv = BufReader::new(recv);
        let _hello = read_message(&mut recv, MAX_HELLO).await.unwrap();
        let hello = Message::ServerHello {
            version: u64::from(proto::VERSION),
            nonce: [0; 32],
            capabilities: Vec::new(),
            implementation: "test".into(),
        };
        write_message(&mut send, &hello).await.unwrap();
        while let Ok(Some(m)) = read_message(&mut recv, MAX_CONTROL).await {
            if let (Message::Ping { data }, true) = (m, answer) {
                write_message(&mut send, &Message::Pong { data }).await.unwrap();
            }
        }
    }

    /// After a network change every connection is probed: one that answers is kept, one that
    /// answers nothing is closed (its sessions then race the transports again), and sessions
    /// waiting out a back-off are woken.
    ///
    /// On paused time: the probe's 300 ms pass only once everything else waits, so the PONG
    /// over the in-memory pipe is always handled first, however slow the machine.
    #[tokio::test(start_paused = true)]
    async fn a_network_change_probes_connections_and_wakes_waiting_sessions() {
        for answer in [true, false] {
            let (a, b) = tokio::io::duplex(1 << 16);
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);
            let client = Connection::pipe(crate::mux::Role::Client, ar, aw, None, None);
            let server = Connection::pipe(crate::mux::Role::Server, br, bw, None, None);
            let far = tokio::spawn(fake_server(server, answer));
            let conn = Conn::hello(client).await.unwrap();
            conn.probe(Duration::from_millis(300));
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert_eq!(conn.connection.is_closed(), !answer, "answer: {answer}");
            far.abort();
        }
        let pool = Pool::new();
        let network = pool.network.clone();
        let waiting = tokio::spawn(async move { network.notified().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        pool.network_changed();
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("woken")
            .unwrap();
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
