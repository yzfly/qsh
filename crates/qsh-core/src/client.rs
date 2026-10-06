//! The client: the bootstrap over ssh (protocol.md section 10), connections (sections 5, 9,
//! 12), and one terminal session kept alive across them (sections 6 and 7).
//!
//! [`Session::run`] is one session: it bootstraps once, then attaches over whichever transport
//! works, and whenever the connection breaks it connects again and resumes where it stopped,
//! resending input the server missed and receiving the output the client missed.
//!
//! The terminal side is a pair of channels ([`Terminal`]): input and window sizes in, output
//! out. The `qsh` command line connects them to its tty; an embedder to anything it likes.

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
use crate::proto::bootstrap::{self, Credentials, Reply, Request};
use crate::proto::limits::{ATTACH_TIMEOUT, RESEND_CHUNK};
use crate::proto::message::{ATTACH_FRESH, MAX_CONTROL, MAX_HELLO, MAX_TERMINAL, PREFERRED_DATA};
use crate::proto::{read_message, write_message, ErrorCode, ExitStatus, FramingError, Message, WindowSize};
use crate::session::{Inbound, ReplayBuffer, INPUT_REPLAY};
use crate::transport::quic::QuicClient;
use crate::transport::ssh::{SshCommand, EXIT_CANNOT_EXECUTE, EXIT_COMMAND_NOT_FOUND};
use crate::transport::{Connection, Race, RaceConfig, RaceError, RecvStream, SendStream, Target, Transport};
use crate::{log, proto};

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
    /// The input is a terminal. False for scripts: the remote pty then neither echoes nor
    /// translates line ends, so output is byte for byte what the program wrote.
    pub tty: bool,
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

/// Run `qsh-server bootstrap` over ssh with `request` on its stdin, and read the reply.
pub async fn bootstrap(ssh: &SshCommand, request: &Request, interactive: bool) -> Result<Reply, ClientError> {
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
    let mut output = Vec::new();
    (&mut stdout)
        .take(bootstrap::MAX_REPLY_OUTPUT as u64)
        .read_to_end(&mut output)
        .await?;
    let status = child.wait().await?;
    match status.code() {
        Some(proto::EXIT_NO_SERVER) | Some(EXIT_COMMAND_NOT_FOUND) => return Err(ClientError::NoServer),
        Some(EXIT_CANNOT_EXECUTE) => return Err(ClientError::CannotExecute),
        Some(255) => return Err(ClientError::Ssh(255)),
        _ => {}
    }
    match bootstrap::parse_reply(&output, request.op) {
        Ok(Reply::Error(e)) => Err(ClientError::Bootstrap(e.to_string())),
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
    started: Instant,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
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
            started,
            tasks: Mutex::new(Vec::new()),
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
#[derive(Debug)]
pub struct Pool {
    quic: Arc<QuicClient>,
    slots: Mutex<HashMap<ServerKey, Arc<tokio::sync::Mutex<Slot>>>>,
}

impl Pool {
    /// A pool with its own QUIC endpoint.
    pub fn new() -> Arc<Pool> {
        Pool::with_quic(Arc::new(QuicClient::new()))
    }

    /// A pool using `quic`'s endpoint.
    pub fn with_quic(quic: Arc<QuicClient>) -> Arc<Pool> {
        Arc::new(Pool {
            quic,
            slots: Mutex::new(HashMap::new()),
        })
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

/// Race the transports and keep the first connection whose hello succeeds within 5 s
/// (section 12.1); the others are dropped.
async fn establish(target: &Target, quic: &Arc<QuicClient>, race: &RaceConfig) -> Result<Arc<Conn>, RaceError> {
    let mut race = Race::start(target, quic, race);
    while let Some(connection) = race.next().await {
        let transport = connection.transport();
        match tokio::time::timeout(ATTACH_TIMEOUT, Conn::hello(connection)).await {
            Ok(Ok(conn)) => {
                log::debug(format_args!("connected over {transport}"));
                return Ok(conn);
            }
            Ok(Err(e)) => race.failed(transport, e),
            Err(_) => race.failed(transport, io::Error::new(io::ErrorKind::TimedOut, "no SERVER_HELLO")),
        }
    }
    Err(race.take_errors())
}

/// The client's state of one session, across connections.
struct State {
    session: [u8; 16],
    key: SessionKey,
    target: Target,
    /// No stream state yet: the next ATTACH sets FRESH.
    fresh: bool,
    output: Inbound,
    input: ReplayBuffer,
    size: WindowSize,
    /// The user asked to end the session; deliver HANGUP on the next attachment.
    hangup: bool,
    input_closed: bool,
}

/// How one attachment ended.
enum End {
    Exited(ExitStatus),
    Detached,
    /// The connection is gone or dead; reconnect.
    Lost(String),
    /// The session cannot go on this way.
    Fatal(ClientError),
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
            request.tty = Some(false);
        }
        let credentials = match bootstrap(&config.ssh, &request, config.interactive).await? {
            Reply::Credentials(c) => c,
            other => return Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
        };
        let host = config
            .ssh
            .resolve_host()
            .await
            .unwrap_or_else(|| host_of(&config.ssh.destination));
        let state = state_from(&credentials, host, &config.ssh, config.size)?;
        self.run_attached(state, terminal).await
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

    async fn run_attached(&self, mut state: State, mut terminal: Terminal) -> Result<Outcome, ClientError> {
        let mut backoff = BACKOFF_FIRST;
        let mut wait: Option<Duration> = None;
        let mut reissued = false;
        let mut sequence_retry = false;
        loop {
            if let Some(d) = wait.take() {
                if let Some(outcome) = offline(&mut state, &mut terminal, d).await {
                    return Ok(outcome);
                }
            }
            let conn = match self.pool.get(&state.target, &self.config.race).await {
                Ok(c) => c,
                Err(e) => {
                    log::debug(format_args!("no connection: {e}"));
                    if e.pin_mismatch() && !reissued {
                        // The daemon's identity changed: a new pin over ssh, keeping the session
                        reissued = true;
                        self.reissue(&mut state).await?;
                        continue;
                    }
                    if state.hangup {
                        return Ok(Outcome::Abandoned);
                    }
                    notify(&terminal, Event::Disconnected(e.to_string()));
                    wait = Some(jitter(backoff));
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            };
            let attached_at = Instant::now();
            match self.attach(&conn, &mut state, &mut terminal).await? {
                End::Exited(status) => return Ok(Outcome::Exited(status)),
                End::Detached => return Ok(Outcome::Detached),
                End::Lost(why) => {
                    log::debug(format_args!("connection lost: {why}"));
                    conn.close(ErrorCode::NO_ERROR, "");
                    {
                        let mut status = self.status.lock().unwrap();
                        status.transport = None;
                        status.connected_since = None;
                        status.reconnects += 1;
                    }
                    notify(&terminal, Event::Disconnected(why));
                    if attached_at.elapsed() >= STABLE_AFTER {
                        backoff = BACKOFF_FIRST;
                    } else {
                        wait = Some(jitter(backoff));
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                    }
                }
                End::Fatal(ClientError::SessionLost(why)) if why == "AUTH_FAILED" && !reissued => {
                    // The key is not valid any more: new credentials over ssh (section 6.4)
                    reissued = true;
                    self.reissue(&mut state).await?;
                }
                End::Fatal(ClientError::SessionLost(why)) if why == "SEQUENCE_ERROR" && !sequence_retry => {
                    // Attach once more; then give up on the session (section 11.2)
                    sequence_retry = true;
                }
                End::Fatal(e) => return Err(e),
            }
        }
    }

    /// New credentials for the session over ssh (bootstrap op `attach`).
    async fn reissue(&self, state: &mut State) -> Result<(), ClientError> {
        let request = Request::attach(&crypto::hex(&state.session), state.size.cols, state.size.rows);
        let credentials = match bootstrap(&self.config.ssh, &request, self.config.interactive).await {
            Ok(Reply::Credentials(c)) => c,
            Ok(other) => return Err(ClientError::Bootstrap(format!("unexpected reply {other:?}"))),
            Err(ClientError::Bootstrap(e)) => return Err(ClientError::SessionLost(e)),
            Err(e) => return Err(e),
        };
        let fresh = state_from(&credentials, state.target.host.clone(), &self.config.ssh, state.size)?;
        state.key = fresh.key;
        state.target = fresh.target;
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
        let output_received = if state.fresh { 0 } else { state.output.received() };
        let attach = Message::Attach {
            session: state.session,
            proof: key.proof(&cb),
            output_received,
            size: state.size,
            flags: if state.fresh { ATTACH_FRESH } else { 0 },
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
        let (input_received, output_start, next_key) = match reply {
            Message::Attached {
                input_received,
                output_start,
                next_key,
                server_proof,
            } => {
                if !key.verify_server(&cb, &server_proof) {
                    // Not the session's server: never trust this connection (section 6.3)
                    conn.close(ErrorCode::AUTH_FAILED, "");
                    return Ok(End::Fatal(ClientError::SessionLost("AUTH_FAILED".into())));
                }
                (input_received, output_start, next_key)
            }
            Message::Error { code, message } => return Ok(attach_error(code, message)),
            _ => {
                conn.close(ErrorCode::PROTOCOL_VIOLATION, "");
                return Ok(End::Lost("unexpected answer to ATTACH".into()));
            }
        };
        // Section 7.3, client side
        if state.fresh {
            let pending = state.input.read_from(0, usize::MAX).1;
            state.input = ReplayBuffer::starting_at(INPUT_REPLAY * 2, input_received);
            // Input typed while attaching follows from there
            state.input.push(&pending);
            state.output = Inbound::at(output_start);
            state.fresh = false;
        } else if output_start != output_received
            || input_received < state.input.base()
            || input_received > state.input.end()
        {
            let error = Message::Error {
                code: ErrorCode::SEQUENCE_ERROR,
                message: String::new(),
            };
            let _ = write_message(&mut send, &error).await;
            return Ok(End::Fatal(ClientError::SessionLost(
                "inconsistent offsets after attaching".into(),
            )));
        }
        state.input.ack(input_received);
        // M0 keeps credentials in this process's memory only, so the key is stored where
        // the credentials live: confirm it (section 6.5)
        state.key = SessionKey(next_key);
        let mut first = vec![Message::KeyConfirm];
        let (mut offset, pending) = state.input.read_from(input_received, usize::MAX);
        for chunk in pending.chunks(RESEND_CHUNK) {
            first.push(Message::Input {
                offset,
                data: chunk.to_vec(),
            });
            offset += chunk.len() as u64;
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

        let mut acked = state.output.received();
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
                    match message {
                        Message::Output { offset, data } => {
                            if offset != state.output.received() || data.is_empty() {
                                return Ok(sequence_error(&mut send).await);
                            }
                            let n = data.len() as u64;
                            if terminal.output.send(data).await.is_err() {
                                // Nobody shows the output any more: leave the session running
                                return Ok(detach(&mut send, &mut rx).await);
                            }
                            state.output = Inbound::at(offset + n);
                            self.status.lock().unwrap().bytes_in += n;
                            if state.output.received() - acked >= ACK_BYTES {
                                ack(&mut send, state.output.received(), &mut acked).await;
                                ack_due = None;
                            } else {
                                ack_due.get_or_insert_with(|| Instant::now() + ACK_DELAY);
                            }
                        }
                        Message::OutputGap { from, to } => {
                            if from != state.output.received() || from >= to {
                                return Ok(sequence_error(&mut send).await);
                            }
                            state.output = Inbound::at(to);
                            self.status.lock().unwrap().skipped += to - from;
                            notify(terminal, Event::OutputSkipped(to - from));
                        }
                        Message::Ack { received } => {
                            if received < state.input.base() || received > state.input.end() {
                                return Ok(sequence_error(&mut send).await);
                            }
                            state.input.ack(received);
                            if received == state.input.end() {
                                unanswered = None;
                                input_pinged = false;
                            }
                        }
                        Message::Exit { output_end, status } => {
                            if output_end != state.output.received() {
                                return Ok(sequence_error(&mut send).await);
                            }
                            let _ = write_message(&mut send, &Message::Ack { received: output_end }).await;
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
                        _ => {
                            let error = Message::Error { code: ErrorCode::PROTOCOL_VIOLATION, message: String::new() };
                            let _ = write_message(&mut send, &error).await;
                            return Ok(End::Lost("unexpected message from the server".into()));
                        }
                    }
                }
                input = terminal.input.recv(), if room && !state.input_closed => match input {
                    Some(Input::Data(data)) => {
                        if data.is_empty() || hangup_sent {
                            continue;
                        }
                        let mut offset = state.input.end();
                        state.input.push(&data);
                        let mut out = Vec::new();
                        for chunk in data.chunks(PREFERRED_DATA) {
                            out.extend(Message::Input { offset, data: chunk.to_vec() }.encode());
                            offset += chunk.len() as u64;
                        }
                        self.status.lock().unwrap().bytes_out += data.len() as u64;
                        unanswered.get_or_insert_with(Instant::now);
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
                        ack(&mut send, state.output.received(), &mut acked).await;
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
/// and detach requests, for `duration`.
async fn offline(state: &mut State, terminal: &mut Terminal, duration: Duration) -> Option<Outcome> {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let room = state.input.len() < INPUT_REPLAY;
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return None,
            input = terminal.input.recv(), if room && !state.input_closed => match input {
                Some(Input::Data(data)) => {
                    if !state.hangup {
                        state.input.push(&data);
                    }
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

async fn ack(send: &mut SendStream, received: u64, acked: &mut u64) {
    if received > *acked {
        let _ = write_message(send, &Message::Ack { received }).await;
        *acked = received;
    }
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
        ErrorCode::SESSION_UNKNOWN => End::Fatal(ClientError::SessionLost("it ended, or the server restarted".into())),
        ErrorCode::SESSION_ENDED => End::Fatal(ClientError::SessionLost("it was ended".into())),
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
    Ok(State {
        session,
        key,
        target: Target {
            host,
            udp: c.udp,
            tcp: c.tcp,
            fingerprint,
            ssh: ssh.clone(),
        },
        fresh: true,
        output: Inbound::default(),
        // Twice the limit: input is taken while below it, and never dropped
        input: ReplayBuffer::new(INPUT_REPLAY * 2),
        size,
        hangup: false,
        input_closed: false,
    })
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
}
