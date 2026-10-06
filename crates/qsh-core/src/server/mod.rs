//! The server side: the per-user daemon that owns the sessions, and the small commands that run
//! over ssh (`qsh-server bootstrap`, `qsh-server pipe`).
//!
//! ```text
//! sshd → qsh-server bootstrap ──unix socket──▶ daemon ── sessions ── pty ── shell
//!                                                ▲  ▲
//!          QUIC (UDP port) and TLS (TCP port) ───┘  └── unix socket ◀── qsh-server pipe ◀── sshd
//! ```
//!
//! One daemon per user, started on demand by the first bootstrap (no init system needed) or
//! by a service unit (`qsh-server daemon --foreground`). It listens on the first port of a range
//! that is free on both UDP and TCP, so every user of a shared host gets one of their own, and
//! on the configured extra ports where it can bind them (m2.md section 5).
//!
//! A daemon upgrades itself in place, keeping its process id, its sessions and its ports
//! (m2.md section 10): it executes the newer `qsh-server` in its own process with its state in
//! an inherited, sealed anonymous file ([`handoff`]), and the new image resumes from it
//! ([`Daemon::resume_until`]).

mod control;
mod gate;
pub mod handoff;
pub mod pty;
mod serve;
mod table;
mod upgrade;

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Notify};

use crate::crypto::{Fingerprint, Identity};
use crate::paths::Paths;
use crate::proto::bootstrap::{ExtraPort, MAX_EXTRA_PORTS};
use crate::proto::ErrorCode;
use crate::sys;

pub use control::{bootstrap, connect_or_start, pipe, request_status, request_stop, request_upgrade, DaemonLauncher};
pub use gate::Limits as PreauthLimits;
pub use table::SessionTable;

/// The default port range of the daemon: the first port free on both UDP and TCP is used.
pub const DEFAULT_PORTS: RangeInclusive<u16> = 60443..=60542;

/// A session nobody was attached to for this long is closed (its programs get SIGHUP).
pub const DETACHED_TTL: Duration = Duration::from_secs(6 * 3600);

/// A session whose program exited is forgotten this long after the exit.
pub const EXITED_TTL: Duration = Duration::from_secs(3600);

/// A daemon started on demand exits after this long without sessions.
pub const ON_DEMAND_IDLE_EXIT: Duration = Duration::from_secs(3600);

/// The UDP receive and send buffers the daemon asks for (m2.md 8.2 `udp-buffers`; the kernel
/// caps the request at `net.core.rmem_max` / `wmem_max`).
pub const UDP_BUFFER: usize = 4 << 20;

/// How often a daemon that upgrades by itself checks whether its executable was replaced
/// (m2.md 10.2).
pub const UPGRADE_CHECK: Duration = Duration::from_secs(600);

/// The version this program reports: its package version, or, in builds with the cargo
/// feature `test-hooks`, `QSH_TEST_VERSION` when set (the chaos and upgrade tests make a daemon
/// look older or newer than it is). An upgraded image never inherits it.
pub fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        std::env::var(upgrade::TEST_VERSION)
            .ok()
            .filter(|_| cfg!(feature = "test-hooks"))
            .filter(|v| !v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_graphic()))
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
    })
}

/// How the daemon executes a newer `qsh-server` in its own process (m2.md section 10). Only
/// a daemon that is a program of its own can: a daemon embedded in another program (the
/// tests, an embedder) has none, and refuses upgrades.
#[derive(Debug, Clone)]
pub struct Reexec {
    /// The daemon's own options (after `daemon`), given again to the new image after
    /// `daemon --resume …`: `--foreground`, `--on-demand`, `--ports …`.
    pub args: Vec<OsString>,
    /// How often to check whether the executable it was started from was replaced, to
    /// upgrade by itself when idle (`upgrade = "auto"`).
    pub check_every: Duration,
}

impl Reexec {
    /// Re-execute with `args`, checking for a replaced executable every [`UPGRADE_CHECK`].
    pub fn new(args: Vec<OsString>) -> Reexec {
        Reexec {
            args,
            check_every: UPGRADE_CHECK,
        }
    }
}

/// What a new image of the daemon was given by the old one (`qsh-server daemon --resume`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resume {
    /// The sealed state ([`handoff`]).
    pub state_fd: RawFd,
    /// The pipe with the state's key.
    pub key_fd: RawFd,
    /// The old image's executable, to execute again if this one cannot resume (Linux).
    pub fallback_exe_fd: Option<RawFd>,
    /// This is the old image again: the new one could not resume (m2.md 10.4).
    pub fell_back: bool,
}

/// How the daemon runs.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Where the control socket, the lock and the identity live.
    pub paths: Paths,
    /// Ports to try, in order: the first one free on both UDP and TCP wins.
    pub ports: RangeInclusive<u16>,
    /// Exit after this long without sessions (daemons started on demand). None: run until
    /// stopped (service units).
    pub idle_exit: Option<Duration>,
    /// See [`DETACHED_TTL`].
    pub detached_ttl: Duration,
    /// See [`EXITED_TTL`].
    pub exited_ttl: Duration,
    /// The shell for sessions; None: the login shell from the password database.
    pub shell: Option<PathBuf>,
    /// Output kept per session for clients that come back (at least 1 MiB).
    pub output_replay: usize,
    /// Limits on unauthenticated connections (protocol.md 6.6).
    pub preauth: PreauthLimits,
    /// The most sessions the daemon keeps; a bootstrap `new` beyond it gets `limit`.
    pub max_sessions: usize,
    /// More ports to listen on, UDP and TCP independently, where the bind succeeds (m2.md
    /// section 5; at most 8, the primary port skipped). Announced in the bootstrap reply.
    pub extra_ports: Vec<u16>,
    /// Keep screen models and offer the `snapshot` capability (m2.md section 6). Not used yet.
    pub snapshot: bool,
    /// Accept the `zstd` capability (m2.md section 7). Not used yet.
    pub compression: bool,
    /// When the daemon upgrades itself in place (m2.md section 10).
    pub upgrade: crate::config::Upgrade,
    /// How to upgrade in place; None: never (an embedded daemon).
    pub reexec: Option<Reexec>,
}

/// The default of [`ServerConfig::max_sessions`].
pub const MAX_SESSIONS: usize = 1000;

impl ServerConfig {
    /// The defaults for `paths`.
    pub fn new(paths: Paths) -> ServerConfig {
        ServerConfig {
            paths,
            ports: DEFAULT_PORTS,
            idle_exit: None,
            detached_ttl: DETACHED_TTL,
            exited_ttl: EXITED_TTL,
            shell: None,
            output_replay: crate::session::OUTPUT_REPLAY,
            preauth: PreauthLimits::default(),
            max_sessions: MAX_SESSIONS,
            extra_ports: Vec::new(),
            snapshot: true,
            compression: true,
            upgrade: crate::config::Upgrade::Auto,
            reexec: None,
        }
    }
}

/// Counters since the daemon started, reported by `qsh-server status`.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub quic_connections: AtomicU64,
    pub tls_connections: AtomicU64,
    pub pipe_connections: AtomicU64,
    pub channels: AtomicU64,
    pub attach_failures: AtomicU64,
}

/// What every task of the daemon shares.
#[derive(Debug)]
pub(crate) struct Shared {
    pub config: ServerConfig,
    /// Control streams of open connections, for GOAWAY on shutdown.
    pub connections: serve::Registry,
    /// Admission of unauthenticated connections (protocol.md 6.6).
    pub gate: Arc<gate::Gate>,
    pub sessions: SessionTable,
    pub port: u16,
    /// The extra ports bound (m2.md 5.2), announced in the bootstrap reply.
    pub extra_ports: Vec<ExtraPort>,
    pub fingerprint: Fingerprint,
    pub account: pty::Account,
    pub stats: Stats,
    pub shutdown: Notify,
    /// When the daemon first started, before any upgrade in place.
    pub started: std::time::SystemTime,
    /// The upgrade in place.
    pub upgrade: upgrade::UpgradeState,
}

/// The per-user daemon.
#[derive(Debug)]
pub struct Daemon;

/// Why the daemon did not start.
#[derive(Debug)]
pub enum StartError {
    /// Another daemon of this user is running (it holds the lock).
    AlreadyRunning,
    /// No port of the range is free on both UDP and TCP.
    NoFreePort(RangeInclusive<u16>),
    /// Anything else.
    Io(io::Error),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::AlreadyRunning => f.write_str("the daemon is already running"),
            StartError::NoFreePort(range) => {
                write!(
                    f,
                    "no port in {}-{} is free on both UDP and TCP",
                    range.start(),
                    range.end()
                )
            }
            StartError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<io::Error> for StartError {
    fn from(e: io::Error) -> Self {
        StartError::Io(e)
    }
}

/// The daemon's own descriptors, which an upgrade in place hands to the next image. The
/// runtime (tokio, quinn) works on duplicates, so that stopping it leaves these open.
#[derive(Debug)]
pub(crate) struct Listeners {
    /// UDP sockets: the primary port first, then the extra ports.
    pub udp: Vec<(u16, UdpSocket)>,
    /// Listening TCP sockets: the primary port first, then the extra ports.
    pub tcp: Vec<(u16, TcpListener)>,
    /// The control socket's listener.
    pub control: UnixListener,
    /// The daemon's lock (`daemon.lock`), held as long as it is open.
    pub lock: File,
}

impl Listeners {
    /// The extra ports, as the bootstrap reply announces them.
    fn extra_ports(&self, primary: u16) -> Vec<ExtraPort> {
        let mut ports: Vec<ExtraPort> = Vec::new();
        let mut add = |port: u16, udp: bool| {
            if port == primary {
                return;
            }
            match ports.iter_mut().find(|p| p.port == port) {
                Some(p) if udp => p.udp = true,
                Some(p) => p.tcp = true,
                None => ports.push(ExtraPort { port, udp, tcp: !udp }),
            }
        };
        for (port, _) in &self.udp {
            add(*port, true);
        }
        for (port, _) in &self.tcp {
            add(*port, false);
        }
        ports.truncate(MAX_EXTRA_PORTS);
        ports
    }
}

/// What runs on the listeners: the QUIC endpoints, the TLS acceptor, and the tasks.
pub(crate) struct Runtime {
    pub listeners: Listeners,
    endpoints: Vec<quinn::Endpoint>,
    acceptor: crate::transport::tls::Acceptor,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Runtime {
    fn new(identity: &Identity, listeners: Listeners) -> io::Result<Runtime> {
        let server = crate::crypto::quic_server(identity)?;
        // Derived from the identity, so the next image (or a restarted daemon) sends stateless
        // resets clients recognize (m2.md 10.6)
        let reset: Arc<dyn quinn::crypto::HmacKey> = Arc::new(identity.stateless_reset_key());
        let runtime = quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime"))?;
        let endpoints = listeners
            .udp
            .iter()
            .map(|(_, socket)| {
                quinn::Endpoint::new(
                    quinn::EndpointConfig::new(reset.clone()),
                    Some(server.clone()),
                    socket.try_clone()?,
                    runtime.clone(),
                )
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Runtime {
            listeners,
            endpoints,
            acceptor: crate::transport::tls::Acceptor::new(identity)?,
            tasks: Vec::new(),
        })
    }

    /// Accept connections and control requests, collect garbage, watch the executable.
    fn start(&mut self, shared: &Arc<Shared>) -> io::Result<()> {
        for endpoint in &self.endpoints {
            self.tasks
                .push(tokio::spawn(serve::accept_quic(shared.clone(), endpoint.clone())));
        }
        for (_, listener) in &self.listeners.tcp {
            let listener = tokio::net::TcpListener::from_std(listener.try_clone()?)?;
            self.tasks.push(tokio::spawn(serve::accept_tls(
                shared.clone(),
                listener,
                self.acceptor.clone(),
            )));
        }
        let control = tokio::net::UnixListener::from_std(self.listeners.control.try_clone()?)?;
        self.tasks.push(tokio::spawn(control::accept(shared.clone(), control)));
        self.tasks.push(tokio::spawn(table::collect_garbage(shared.clone())));
        self.tasks.push(tokio::spawn(upgrade::watch_exe(shared.clone())));
        Ok(())
    }

    /// Stop every task: nothing is accepted any more; the listeners stay open, and their
    /// backlogs (and the UDP sockets' buffers) hold what arrives meanwhile.
    fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }

    /// Make the QUIC endpoints let go of the daemon's UDP sockets (m2.md 10.3 step 3): packets
    /// for the next image wait in the sockets' buffers instead of being consumed by this one.
    /// quinn keeps reading a socket it was moved away from until traffic arrives on the new
    /// one, so each endpoint moves twice, to two sockets nobody sends to.
    fn detach_endpoints(&self) -> io::Result<()> {
        for endpoint in &self.endpoints {
            for _ in 0..2 {
                let dummy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
                dummy.set_nonblocking(true)?;
                endpoint.rebind(dummy)?;
            }
        }
        Ok(())
    }

    /// Undo [`Runtime::detach_endpoints`].
    fn attach_endpoints(&self) -> io::Result<()> {
        for (endpoint, (_, socket)) in self.endpoints.iter().zip(&self.listeners.udp) {
            endpoint.rebind(socket.try_clone()?)?;
        }
        Ok(())
    }

    /// Close every QUIC endpoint (shutdown).
    fn close_endpoints(&self, code: ErrorCode, reason: &[u8]) {
        for endpoint in &self.endpoints {
            endpoint.close(quinn::VarInt::from_u32(code.0 as u32), reason);
        }
    }
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("listeners", &self.listeners)
            .field("tasks", &self.tasks.len())
            .finish()
    }
}

impl Daemon {
    /// Run the daemon until it is stopped (`qsh-server stop`) or, with
    /// [`ServerConfig::idle_exit`], until it had no sessions for that long. Must be called
    /// inside a multi-threaded tokio runtime.
    pub async fn run(config: ServerConfig) -> Result<(), StartError> {
        Daemon::run_until(config, std::future::pending()).await
    }

    /// [`Daemon::run`], and stop also when `stop` completes (for example on SIGTERM). Stopping
    /// follows protocol.md 7.13: no new connections or bootstraps, every session hung up, each
    /// attachment's final EXIT or ERROR (SESSION_ENDED), GOAWAY (SHUTDOWN), then the close.
    pub async fn run_until(
        config: ServerConfig,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> Result<(), StartError> {
        let paths = config.paths.clone();
        paths.ensure_runtime()?;
        paths.ensure_state()?;

        // One daemon per user: the lock lives as long as this process (and its next images)
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.daemon_lock())?;
        if !sys::try_lock(&lock)? {
            return Err(StartError::AlreadyRunning);
        }
        if config.reexec.is_some() {
            // A program of its own: nothing whoever started it left open may reach the next
            // image of an upgrade, or a probed program (security.md 4.8)
            sys::cloexec_from(3);
        }
        let socket = paths.control_socket();
        let _ = std::fs::remove_file(&socket);

        // Section 6.6: the connection limits, not the descriptor table, decide
        if let Err(e) = sys::raise_nofile_limit() {
            crate::log::info(format_args!("cannot raise the limit of open files: {e}"));
        }
        let identity = Identity::load_or_create(&paths.identity_dir())?;
        let (port, udp, tcp) = bind_ports(&config.ports)?;
        let (mut udps, mut tcps) = (vec![(port, udp)], vec![(port, tcp)]);
        bind_extra_ports(&config.extra_ports, port, &mut udps, &mut tcps);
        for (_, socket) in &udps {
            tune_udp(socket);
        }
        for (_, listener) in &tcps {
            tune_tcp(listener);
        }
        let control = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        control.set_nonblocking(true)?;
        let listeners = Listeners {
            udp: udps,
            tcp: tcps,
            control,
            lock,
        };
        let (upgrade, plans) = upgrade::UpgradeState::new(&config, None);
        let shared = Arc::new(Shared {
            extra_ports: listeners.extra_ports(port),
            account: pty::account(&paths.home, config.shell.as_deref()),
            gate: Arc::new(gate::Gate::new(config.preauth)),
            config,
            connections: serve::Registry::default(),
            sessions: SessionTable::default(),
            port,
            fingerprint: identity.fingerprint(),
            stats: Stats::default(),
            shutdown: Notify::new(),
            started: std::time::SystemTime::now(),
            upgrade,
        });
        let runtime = Runtime::new(&identity, listeners)?;
        eprintln!(
            "qsh-server {}: daemon pid {} listening on udp/tcp {port}{}, certificate {}",
            version(),
            std::process::id(),
            describe_extra(&shared.extra_ports),
            shared.fingerprint.to_hex()
        );
        Daemon::serve(shared, runtime, plans, stop).await
    }

    /// Resume as the new image of an upgrade in place (m2.md 10.3 steps 7 to 9): read and
    /// check the state, adopt the descriptors and the sessions, and run. If anything fails
    /// before the first session descriptor is touched (or a panic happens then), the old
    /// image is executed again with the same state (Linux, m2.md 10.4).
    pub async fn resume_until(
        config: ServerConfig,
        resume: Resume,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> Result<(), StartError> {
        let (shared, runtime, plans) = upgrade::resume(config, resume).await?;
        Daemon::serve(shared, runtime, plans, stop).await
    }

    /// Serve until stopped; carry out upgrades in between.
    async fn serve(
        shared: Arc<Shared>,
        mut runtime: Runtime,
        mut plans: mpsc::UnboundedReceiver<upgrade::Plan>,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> Result<(), StartError> {
        runtime.start(&shared)?;
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = shared.shutdown.notified() => break,
                _ = &mut stop => {
                    crate::log::info(format_args!("stopping on a signal"));
                    break;
                }
                Some(plan) = plans.recv() => {
                    // Returns only when the upgrade failed; the daemon goes on as it was
                    let error = upgrade::run(&shared, &mut runtime, plan).await;
                    shared.upgrade.failed(&error);
                    runtime.start(&shared)?;
                }
            }
        }
        // 1. No new connections or bootstrap requests
        runtime.stop();
        let _ = std::fs::remove_file(shared.config.paths.control_socket());
        // 2. Every session hung up at once, so the 2 s waits for the programs overlap
        let sessions = shared.sessions.hang_up_all();
        // 3. Each attachment sends its final EXIT or ERROR (SESSION_ENDED) and ends
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while sessions.iter().any(|s| s.attached() > 0) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // 4. GOAWAY (SHUTDOWN) on every connection; 5. close after a moment for delivery
        serve::goaway_all(&shared, ErrorCode::SHUTDOWN);
        tokio::time::sleep(Duration::from_millis(500)).await;
        serve::close_all(&shared, ErrorCode::SHUTDOWN);
        runtime.close_endpoints(ErrorCode::SHUTDOWN, b"daemon stopped");
        // Give QUIC a moment to send the close to connected clients
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(sessions);
        drop(runtime);
        Ok(())
    }
}

/// ", extra ports …" for the start-up line.
fn describe_extra(ports: &[ExtraPort]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    let list: Vec<String> = ports
        .iter()
        .map(|p| match (p.udp, p.tcp) {
            (true, true) => format!("{}", p.port),
            (true, false) => format!("{}/udp", p.port),
            _ => format!("{}/tcp", p.port),
        })
        .collect();
    format!(", extra ports {}", list.join(" "))
}

/// A listening TCP socket on `port`: IPv6 and IPv4 on one socket where the host has IPv6.
/// Non-blocking, close-on-exec.
fn bind_tcp(port: u16) -> io::Result<TcpListener> {
    let any6: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
    let any4: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
    let listener = match TcpListener::bind(any6) {
        Ok(l) => l,
        Err(_) => TcpListener::bind(any4)?,
    };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// The first port of `range` free on both UDP and TCP, bound.
fn bind_ports(range: &RangeInclusive<u16>) -> Result<(u16, UdpSocket, TcpListener), StartError> {
    for port in range.clone() {
        let Ok(udp) = sys::udp_any(port) else { continue };
        // Port 0 (tests): the TCP port must be the UDP one
        let port = udp.local_addr()?.port();
        let Ok(tcp) = bind_tcp(port) else { continue };
        return Ok((port, udp, tcp));
    }
    Err(StartError::NoFreePort(range.clone()))
}

/// Bind the extra ports (m2.md 5.1), UDP and TCP independently, where it works: a port in
/// use or not permitted is skipped with one log line, and not announced.
fn bind_extra_ports(ports: &[u16], primary: u16, udp: &mut Vec<(u16, UdpSocket)>, tcp: &mut Vec<(u16, TcpListener)>) {
    let mut seen = Vec::new();
    for &port in ports {
        if port == 0 || port == primary || seen.contains(&port) {
            continue;
        }
        if seen.len() == MAX_EXTRA_PORTS {
            crate::log::info(format_args!(
                "more than {MAX_EXTRA_PORTS} extra ports; {port} and later ignored"
            ));
            break;
        }
        seen.push(port);
        match sys::udp_any(port) {
            Ok(socket) => udp.push((port, socket)),
            Err(e) => crate::log::info(format_args!("extra port {port}/udp not used: {e}")),
        }
        match bind_tcp(port) {
            Ok(listener) => tcp.push((port, listener)),
            Err(e) => crate::log::info(format_args!("extra port {port}/tcp not used: {e}")),
        }
    }
}

/// Large UDP buffers: QUIC on long fast paths needs more than the kernel's default.
fn tune_udp(socket: &UdpSocket) {
    match sys::set_socket_buffers(socket, UDP_BUFFER) {
        Ok((rcv, snd)) => crate::log::debug(format_args!("udp buffers: receive {rcv}, send {snd}")),
        Err(e) => crate::log::debug(format_args!("udp buffers unchanged: {e}")),
    }
}

/// BBR for the TLS fallback where the system lets this user choose it (m2.md 8.4): it keeps
/// TCP fast on lossy long paths. Accepted connections inherit it from the listener.
fn tune_tcp(listener: &TcpListener) {
    if let Err(e) = sys::set_tcp_congestion(listener, "bbr") {
        crate::log::debug(format_args!("tcp congestion control unchanged: {e}"));
    }
}

/// The daemon command a bootstrap starts on demand when none runs: this executable with
/// `daemon --foreground --on-demand`.
pub fn default_daemon_args() -> Vec<OsString> {
    ["daemon", "--foreground", "--on-demand"]
        .iter()
        .map(OsString::from)
        .collect()
}

pub(crate) fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The raw number of a descriptor, for the handoff state.
pub(crate) fn fd_number(fd: &impl AsRawFd) -> u32 {
    fd.as_raw_fd() as u32
}

/// Adopt descriptor `fd` of the handoff state as `T`.
pub(crate) fn adopt<T: From<OwnedFd>>(fd: u32) -> io::Result<T> {
    sys::adopt_fd(fd as RawFd)
        .map(T::from)
        .ok_or_else(|| io::Error::other(format!("descriptor {fd} of the handoff state is not open")))
}
