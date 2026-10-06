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
//! that is free on both UDP and TCP, so every user of a shared host gets one of their own.

mod control;
mod gate;
pub mod pty;
mod serve;
mod table;

use std::ffi::OsString;
use std::io;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;

use crate::crypto::{Fingerprint, Identity};
use crate::paths::Paths;
use crate::proto::ErrorCode;
use crate::sys;

pub use control::{bootstrap, connect_or_start, pipe, request_status, request_stop, DaemonLauncher};
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
    /// section 5; at most 8). Not used yet.
    pub extra_ports: Vec<u16>,
    /// Keep screen models and offer the `snapshot` capability (m2.md section 6). Not used yet.
    pub snapshot: bool,
    /// Accept the `zstd` capability (m2.md section 7). Not used yet.
    pub compression: bool,
    /// When the daemon upgrades itself in place (m2.md section 10). Not used yet.
    pub upgrade: crate::config::Upgrade,
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
    pub fingerprint: Fingerprint,
    pub account: pty::Account,
    pub stats: Stats,
    pub shutdown: Notify,
    pub started: std::time::SystemTime,
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

        // One daemon per user: the lock lives as long as this process
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.daemon_lock())?;
        if !sys::try_lock(&lock)? {
            return Err(StartError::AlreadyRunning);
        }
        let socket = paths.control_socket();
        let _ = std::fs::remove_file(&socket);

        // Section 6.6: the connection limits, not the descriptor table, decide
        if let Err(e) = sys::raise_nofile_limit() {
            crate::log::info(format_args!("cannot raise the limit of open files: {e}"));
        }
        let identity = Identity::load_or_create(&paths.identity_dir())?;
        let (port, udp, tcp) = bind_ports(&config.ports).await?;
        let account = pty::account(&paths.home, config.shell.as_deref());
        let gate = Arc::new(gate::Gate::new(config.preauth));
        let shared = Arc::new(Shared {
            config,
            connections: serve::Registry::default(),
            gate,
            sessions: SessionTable::default(),
            port,
            fingerprint: identity.fingerprint(),
            account,
            stats: Stats::default(),
            shutdown: Notify::new(),
            started: std::time::SystemTime::now(),
        });

        let endpoint = crate::transport::quic::server_endpoint(udp, &identity)?;
        let acceptor = crate::transport::tls::Acceptor::new(&identity)?;
        let control = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

        eprintln!(
            "qsh-server {}: daemon pid {} listening on udp/tcp {port}, certificate {}",
            env!("CARGO_PKG_VERSION"),
            std::process::id(),
            shared.fingerprint.to_hex()
        );
        let tasks = [
            tokio::spawn(serve::accept_quic(shared.clone(), endpoint.clone())),
            tokio::spawn(serve::accept_tls(shared.clone(), tcp, acceptor)),
            tokio::spawn(control::accept(shared.clone(), control)),
            tokio::spawn(table::collect_garbage(shared.clone())),
        ];
        tokio::select! {
            _ = shared.shutdown.notified() => {}
            _ = stop => crate::log::info(format_args!("stopping on a signal")),
        }
        // 1. No new connections or bootstrap requests
        for task in tasks {
            task.abort();
        }
        let _ = std::fs::remove_file(&socket);
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
        endpoint.close(quinn::VarInt::from_u32(ErrorCode::SHUTDOWN.0 as u32), b"daemon stopped");
        // Give QUIC a moment to send the close to connected clients
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(sessions);
        drop(lock);
        Ok(())
    }
}

/// The first port of `range` free on both UDP and TCP, bound.
async fn bind_ports(range: &RangeInclusive<u16>) -> Result<(u16, std::net::UdpSocket, TcpListener), StartError> {
    for port in range.clone() {
        let Ok(udp) = sys::udp_any(port) else { continue };
        // Port 0 (tests): the TCP port must be the UDP one
        let port = udp.local_addr()?.port();
        let any6: std::net::SocketAddr = (std::net::Ipv6Addr::UNSPECIFIED, port).into();
        let any4: std::net::SocketAddr = (std::net::Ipv4Addr::UNSPECIFIED, port).into();
        // IPv6 and IPv4 on one socket where the host has IPv6
        let tcp = match TcpListener::bind(any6).await {
            Ok(tcp) => tcp,
            Err(_) => match TcpListener::bind(any4).await {
                Ok(tcp) => tcp,
                Err(_) => continue,
            },
        };
        return Ok((port, udp, tcp));
    }
    Err(StartError::NoFreePort(range.clone()))
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
