//! The daemon's unix control socket and the commands that use it.
//!
//! The socket lives in the private runtime directory (0700) with mode 0600, and the daemon
//! also checks that the peer runs as the same user. Each connection starts with one JSON line:
//!
//! | request | answer |
//! |---|---|
//! | `{"op":"bootstrap","request":{…}}` | one line, the bootstrap reply (protocol.md 10.4) |
//! | `{"op":"pipe","client":"…"}` | `ok`, then the connection carries the mux layer (10.5) |
//! | `{"op":"status"}` | one line of JSON |
//! | `{"op":"stop"}` | `{"ok":true}`, then the daemon stops |
//! | `{"op":"upgrade","exe":"…","force":false}` | `{"restarting":true}`, or `{"ok":false,"error":"…"}` |
//!
//! This protocol is internal to one installation (protocol.md 10.4): the commands and the daemon
//! may be of different versions only across an upgrade, which `"v"` lets each side notice.
//! From version 2 every request also carries the requester's `"version"` and `"exe"`; a daemon
//! that is older upgrades itself to that executable (protocol.md 10.6, m2.md 10.2) and answers
//! `{"restarting":true}`, after which the requester connects again and repeats its request.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use super::pty::{PtySession, SessionId, Spawn};
use super::{count, upgrade, version, Shared};
use crate::crypto::SessionKey;
use crate::log;
use crate::paths::Paths;
use crate::proto::bootstrap::{
    Credentials, ErrorKind, ErrorReply, Op, Request, SessionInfo, BOOTSTRAP_VERSION, MAX_REQUEST,
};
use crate::proto::PIPE_PREFACE;
use crate::sys;

/// Version of the control socket requests (protocol.md 10.6).
const CONTROL_VERSION: u64 = 2;

/// How long a requester repeats a request while the daemon restarts in place (10.6).
const RESTART_WAIT: Duration = Duration::from_secs(10);

/// The answer of a daemon that restarts in place.
fn restarting() -> Value {
    json!({ "restarting": true })
}

/// A requester waited [`RESTART_WAIT`] and the daemon still restarts.
fn still_restarting() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the daemon is still restarting in place after {RESTART_WAIT:?}"),
    )
}

/// True for the answer `{"restarting":true}`.
fn is_restarting(line: &[u8]) -> bool {
    serde_json::from_slice::<Value>(line).is_ok_and(|v| v["restarting"] == true)
}

/// A request to the daemon (version 2): the op, this program's version and executable, and
/// `members`.
fn request_value(op: &str, members: Value) -> Value {
    let mut request = json!({
        "v": CONTROL_VERSION,
        "op": op,
        "version": version(),
    });
    if let Ok(exe) = std::env::current_exe() {
        request["exe"] = json!(exe.to_string_lossy());
    }
    if let Value::Object(members) = members {
        for (k, v) in members {
            request[k] = v;
        }
    }
    request
}

/// Every exchange on the control socket has a deadline: a daemon that hangs (or something
/// else answering on the socket) must not hang `qsh-server bootstrap`, and with it the client's
/// ssh, forever.
#[cfg(not(test))]
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// Run `f` within [`EXCHANGE_TIMEOUT`], as an io::Error when it takes longer.
async fn timed<T>(what: &str, f: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, f).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{what}: no answer within {EXCHANGE_TIMEOUT:?}"),
        )
    })?
}

pub(crate) async fn accept(shared: Arc<Shared>, listener: UnixListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                // Out of file descriptors and the like: wait instead of spinning
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Defense in depth: the directory is already private
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == sys::euid() => {}
            _ => continue,
        }
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(shared, stream).await {
                log::debug(format_args!("control: {e}"));
            }
        });
    }
}

async fn handle(shared: Arc<Shared>, stream: UnixStream) -> io::Result<()> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let line = timed("the request", read_line(&mut reader, MAX_REQUEST + 4096)).await?;
    if line.is_empty() {
        // A liveness check that connected and left
        return Ok(());
    }
    let request: Value = serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let op = request["op"].as_str();
    // A daemon restarting in place serves nothing until it is back; and a request from a newer
    // qsh-server may start the upgrade (protocol.md 10.6)
    if matches!(op, Some("bootstrap" | "pipe" | "doctor" | "stop"))
        && (shared.upgrade.restarting() || (op != Some("stop") && upgrade::upgrade_for(&shared, &request).await))
    {
        return timed("the reply", write_json(&mut w, &restarting())).await;
    }
    match op {
        Some("bootstrap") => {
            let reply = match serde_json::from_value::<Request>(request["request"].clone()) {
                Ok(r) => {
                    // Sessions do not change while an upgrade collects them
                    let _gate = shared.upgrade.gate.read().unwrap_or_else(|e| e.into_inner());
                    if shared.upgrade.restarting() {
                        restarting()
                    } else {
                        bootstrap_op(&shared, &r)
                    }
                }
                Err(e) => error_value(ErrorKind::BadRequest, format!("bad request: {e}")),
            };
            timed("the reply", write_json(&mut w, &reply)).await?;
        }
        Some("pipe") => {
            w.write_all(b"ok\n").await?;
            count(&shared.stats.pipe_connections);
            let client = request["client"].as_str().and_then(parse_ssh_client);
            super::serve::pipe_connection(shared, reader, w, client).await;
        }
        Some("status") => write_json(&mut w, &status(&shared)).await?,
        Some("stop") => {
            write_json(&mut w, &json!({ "ok": true })).await?;
            log::info(format_args!("stopping on request"));
            shared.shutdown.notify_one();
        }
        Some("upgrade") => {
            let reply = upgrade_op(&shared, &request).await;
            timed("the reply", write_json(&mut w, &reply)).await?;
        }
        _ => write_json(&mut w, &json!({ "ok": false, "error": "unknown request" })).await?,
    }
    Ok(())
}

/// `{"op":"upgrade","exe":"…","force":false}`: upgrade to `exe` now (`qsh-server upgrade`,
/// m2.md 10.2), whatever the `upgrade` setting.
async fn upgrade_op(shared: &Shared, request: &Value) -> Value {
    let Some(exe) = request["exe"].as_str() else {
        return json!({ "ok": false, "error": "no executable named" });
    };
    let force = request["force"] == true;
    let why = if force {
        "forced upgrade requested"
    } else {
        "upgrade requested"
    };
    match upgrade::prepare(shared, std::path::Path::new(exe), force, why).await {
        Ok(plan) => {
            shared.upgrade.start(plan);
            restarting()
        }
        Err(refusal) => json!({
            "ok": false,
            "error": refusal.message,
            "not_newer": refusal.not_newer,
            "version": version(),
        }),
    }
}

/// The client address from `SSH_CONNECTION` ("client_ip client_port server_ip server_port").
fn parse_ssh_client(text: &str) -> Option<std::net::SocketAddr> {
    let mut parts = text.split_whitespace();
    let ip: std::net::IpAddr = parts.next()?.parse().ok()?;
    let port: u16 = parts.next()?.parse().ok()?;
    Some((ip, port).into())
}

fn error_value(kind: ErrorKind, message: impl Into<String>) -> Value {
    serde_json::to_value(ErrorReply::new(kind, message)).unwrap_or(Value::Null)
}

/// Carry out a bootstrap request (protocol.md 10.3).
fn bootstrap_op(shared: &Shared, request: &Request) -> Value {
    if let Err(e) = request.validate() {
        return serde_json::to_value(e).unwrap_or(Value::Null);
    }
    let session_id = request.session.as_deref().and_then(SessionId::from_hex);
    match request.op {
        Op::New => {
            if shared.sessions.len() >= shared.config.max_sessions {
                return error_value(ErrorKind::Limit, "too many sessions");
            }
            let spawn = Spawn {
                command: request.command.clone(),
                cols: request.cols.unwrap_or(80) as u16,
                rows: request.rows.unwrap_or(24) as u16,
                term: request.term.clone(),
                env: request.accepted_env(),
                name: request.name.clone(),
                pipe: request.tty == Some(false),
            };
            let id = SessionId::generate();
            let key = SessionKey::generate();
            match PtySession::start(id, key.clone(), &spawn, &shared.account, shared.config.output_replay) {
                Ok(session) => {
                    log::debug(format_args!("session {} started", &id.to_hex()[..8]));
                    super::serve::install_model(shared, &session);
                    let pipe = session.pipe;
                    shared.sessions.insert(session);
                    credentials(shared, &id, &key, pipe)
                }
                Err(e) => error_value(ErrorKind::Internal, format!("cannot start the session: {e}")),
            }
        }
        Op::Attach => {
            let Some(session) = session_id.and_then(|id| shared.sessions.get(&id)) else {
                return error_value(ErrorKind::NoSession, "no such session");
            };
            // The ssh login is the authorization: a fresh key replaces both valid keys, and the
            // attachment that uses the old one ends on its next attach (section 10.3)
            let key = SessionKey::generate();
            *session.keys.lock().unwrap() = super::pty::Keys {
                current: key.clone(),
                pending: None,
            };
            // The attachment that used the old keys ends (SESSION_TAKEN_OVER)
            session.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            session.changed.notify_waiters();
            credentials(shared, &session.id, &key, session.pipe)
        }
        Op::List => {
            // Oldest first (`all` sorts them), as `qsh ls` shows them
            let sessions: Vec<SessionInfo> = shared
                .sessions
                .all()
                .iter()
                .map(|s| SessionInfo {
                    session: s.id.to_hex(),
                    name: s.name.clone(),
                    command: s.command.clone(),
                    created: s.started.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                    attached: s.attached() > 0,
                    exited: s.exit_status().is_some(),
                    tty: s.pipe.then_some(false),
                })
                .collect();
            json!({ "qsh": BOOTSTRAP_VERSION, "sessions": sessions })
        }
        Op::Kill => match session_id.and_then(|id| shared.sessions.remove(&id)) {
            Some(_) => json!({ "qsh": BOOTSTRAP_VERSION, "ok": true }),
            None => error_value(ErrorKind::NoSession, "no such session"),
        },
    }
}

fn credentials(shared: &Shared, id: &SessionId, key: &SessionKey, pipe: bool) -> Value {
    serde_json::to_value(Credentials {
        qsh: BOOTSTRAP_VERSION,
        versions: vec![u64::from(crate::proto::VERSION)],
        session: id.to_hex(),
        key: key.to_hex(),
        cert_sha256: shared.fingerprint.to_hex(),
        udp: shared.port,
        tcp: shared.port,
        caps: Vec::new(),
        server: format!("qsh-server/{}", version()),
        ssh_addr: None,
        tty: pipe.then_some(false),
        // The extra ports actually bound (m2.md 5.2)
        extra_ports: shared.extra_ports.clone(),
    })
    .unwrap_or(Value::Null)
}

fn status(shared: &Shared) -> Value {
    let secs = |t: std::time::SystemTime| t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let sessions: Vec<Value> = shared
        .sessions
        .all()
        .iter()
        .map(|s| {
            json!({
                "id": &s.id.to_hex()[..8],
                "name": s.name,
                "command": s.command,
                "started": secs(s.started),
                "attached": s.attached(),
                "pid": s.pid,
                "exited": s.exit_status().is_some(),
            })
        })
        .collect();
    let stats = &shared.stats;
    let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    let mut value = json!({
        "v": CONTROL_VERSION,
        "version": version(),
        "pid": std::process::id(),
        "started": secs(shared.started),
        "port": shared.port,
        "udp": shared.port,
        "tcp": shared.port,
        "extra_ports": shared.extra_ports,
        "fingerprint": shared.fingerprint.to_hex(),
        "cert_sha256": shared.fingerprint.to_hex(),
        "session_count": sessions.len(),
        "sessions": sessions,
        "stats": {
            "quic_connections": load(&stats.quic_connections),
            "tls_connections": load(&stats.tls_connections),
            "pipe_connections": load(&stats.pipe_connections),
            "channels": load(&stats.channels),
            "attach_failures": load(&stats.attach_failures),
            "unauthenticated": shared.gate.pending(),
        },
    });
    if let (Value::Object(all), Value::Object(upgrade)) = (&mut value, shared.upgrade.status(&shared.config)) {
        all.extend(upgrade);
    }
    value
}

async fn write_json<W: AsyncWrite + Unpin>(w: &mut W, value: &Value) -> io::Result<()> {
    w.write_all(format!("{value}\n").as_bytes()).await?;
    w.flush().await
}

/// One line without its newline, at most `max` bytes. Empty at end of input.
async fn read_line<R: AsyncRead + Unpin>(r: &mut BufReader<R>, max: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let n = r.take(max as u64 + 1).read_until(b'\n', &mut line).await?;
    if n > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    Ok(line)
}

/// How a bootstrap starts the daemon when none runs.
#[derive(Debug, Clone)]
pub struct DaemonLauncher {
    /// The program, by default this executable.
    pub program: PathBuf,
    /// Its arguments, by default [`super::default_daemon_args`].
    pub args: Vec<OsString>,
}

impl DaemonLauncher {
    /// This executable with [`super::default_daemon_args`].
    pub fn current_exe() -> io::Result<DaemonLauncher> {
        Ok(DaemonLauncher {
            program: std::env::current_exe()?,
            args: super::default_daemon_args(),
        })
    }

    /// Start the daemon in the background, detached from the ssh session that started it, its
    /// stderr appended to the state directory's `daemon.log`.
    fn start(&self, paths: &Paths) -> io::Result<()> {
        paths.ensure_state()?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(paths.daemon_log())?;
        let mut cmd = std::process::Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .current_dir(&paths.home);
        sys::spawn_detached(&mut cmd);
        // The intermediate process exits at once; the daemon is its child, now orphaned
        cmd.spawn()?.wait()?;
        Ok(())
    }
}

/// Connect to the daemon's control socket, starting the daemon with `launcher` if none runs.
///
/// The runtime directory is created if missing and checked before every connection, and the
/// daemon must run as this user ([`Paths::connect_private`]): a socket that someone else could
/// have put there is never used.
pub async fn connect_or_start(paths: &Paths, launcher: &DaemonLauncher) -> io::Result<UnixStream> {
    let socket = paths.control_socket();
    paths.ensure_runtime()?;
    if let Some(stream) = paths.connect_private(&socket).await? {
        return Ok(stream);
    }
    launcher.start(paths)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(stream) = paths.connect_private(&socket).await? {
            return Ok(stream);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the daemon did not start (see {}): nothing listens on {}",
                    paths.daemon_log().display(),
                    socket.display()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `qsh-server bootstrap` (protocol.md 10.4): read the request from `input`, have the daemon
/// (started if needed) carry it out, and write the one reply line to `output`. Errors are
/// reported as an error reply too. Returns true for a success reply (exit status 0), false
/// for an error reply (exit status 1).
pub async fn bootstrap<R, W>(paths: &Paths, launcher: &DaemonLauncher, input: R, mut output: W) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let reply: Value = async {
        let mut reader = BufReader::new(input);
        let line = match tokio::time::timeout(Duration::from_secs(60), read_line(&mut reader, MAX_REQUEST)).await {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return error_value(ErrorKind::BadRequest, format!("cannot read the request: {e}")),
            Err(_) => return error_value(ErrorKind::BadRequest, "no request on stdin"),
        };
        let request: Request = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(e) => {
                // An unknown op is "unsupported", anything else "bad-request"
                let known = |op: &str| serde_json::from_value::<Op>(json!(op)).is_ok();
                let kind = match serde_json::from_slice::<Value>(&line) {
                    Ok(v)
                        if v["op"].as_str().is_some_and(|op| !known(op))
                            && v["qsh"].as_u64() == Some(BOOTSTRAP_VERSION) =>
                    {
                        ErrorKind::Unsupported
                    }
                    _ => ErrorKind::BadRequest,
                };
                return error_value(kind, format!("bad request: {e}"));
            }
        };
        if let Err(e) = request.validate() {
            return serde_json::to_value(e).unwrap_or(Value::Null);
        }
        let asked = async {
            let message = request_value("bootstrap", json!({ "request": request }));
            let line = exchange(paths, Some(launcher), &message)
                .await?
                .ok_or_else(|| io::Error::other("no daemon"))?;
            serde_json::from_slice::<Value>(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        };
        match asked.await {
            Ok(mut reply) => {
                if reply.get("key").is_some() {
                    if let Some(addr) = ssh_server_addr() {
                        reply["ssh_addr"] = json!(addr);
                    }
                }
                reply
            }
            Err(e) => error_value(ErrorKind::Daemon, format!("the daemon could not be reached: {e}")),
        }
    }
    .await;
    // A newline first ends any unterminated text of shell start-up files (10.4)
    output.write_all(format!("\n{reply}\n").as_bytes()).await?;
    output.flush().await?;
    Ok(reply.get("error").is_none())
}

/// The server address of the ssh connection this command runs in, from `SSH_CONNECTION`.
fn ssh_server_addr() -> Option<String> {
    let text = std::env::var("SSH_CONNECTION").ok()?;
    let ip: std::net::IpAddr = text.split_whitespace().nth(2)?.parse().ok()?;
    Some(ip.to_string())
}

/// `qsh-server pipe --version 1` (protocol.md 10.5): connect to the daemon (started if needed),
/// write the preface to `output`, then relay bytes both ways until either side closes. If the daemon
/// was not running, the client's ATTACH fails with SESSION_UNKNOWN and it bootstraps again
/// instead of retrying a transport with nothing behind it.
pub async fn pipe<R, W>(paths: &Paths, launcher: &DaemonLauncher, mut input: R, mut output: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let client = std::env::var("SSH_CONNECTION").unwrap_or_default();
    let message = request_value("pipe", json!({ "client": client }));
    let deadline = Instant::now() + RESTART_WAIT;
    let (mut reader, mut w) = loop {
        let stream = connect_or_start(paths, launcher).await?;
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let answer = timed("the daemon", async {
            write_json(&mut w, &message).await?;
            read_line(&mut reader, 64).await
        })
        .await?;
        if answer == b"ok" {
            break (reader, w);
        }
        // The daemon restarts in place: ask its next image (protocol.md 10.6)
        if !is_restarting(&answer) {
            return Err(io::Error::other("the daemon refused the pipe"));
        }
        if Instant::now() >= deadline {
            return Err(still_restarting());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    output.write_all(PIPE_PREFACE).await?;
    output.flush().await?;
    let up = async {
        tokio::io::copy(&mut input, &mut w).await?;
        // The client finished: let the daemon see the end too
        w.shutdown().await
    };
    let down = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), io::Error>(());
            }
            output.write_all(&buf[..n]).await?;
            output.flush().await?;
        }
    };
    tokio::select! {
        r = up => r?,
        r = down => r?,
    }
    Ok(())
}

/// Send `message` to the daemon and read its one-line answer; while the daemon restarts in
/// place, connect again and repeat it, for up to [`RESTART_WAIT`] (protocol.md 10.6: the
/// control socket's listener survives the restart, connections wait in its backlog, and the
/// security checks of the connection are made again each time). With a launcher the daemon
/// is started when none runs; without one, None when none runs.
async fn exchange(paths: &Paths, launcher: Option<&DaemonLauncher>, message: &Value) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + RESTART_WAIT;
    loop {
        let stream = match launcher {
            Some(launcher) => connect_or_start(paths, launcher).await?,
            None => match paths.connect_private(&paths.control_socket()).await? {
                Some(stream) => stream,
                None => return Ok(None),
            },
        };
        let (r, mut w) = stream.into_split();
        let line = timed("the daemon", async {
            write_json(&mut w, message).await?;
            read_line(&mut BufReader::new(r), 1 << 20).await
        })
        .await?;
        if !is_restarting(&line) {
            return Ok(Some(line));
        }
        // Never the answer to a request: a daemon still restarting after all that time is an
        // error, not a reply (review H1)
        if Instant::now() >= deadline {
            return Err(still_restarting());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn request(paths: &Paths, op: &str, members: Value) -> io::Result<Option<Value>> {
    let Some(line) = exchange(paths, None, &request_value(op, members)).await? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    ))
}

/// `qsh-server status`: the running daemon's status as JSON, None when no daemon runs.
pub async fn request_status(paths: &Paths) -> io::Result<Option<Value>> {
    request(paths, "status", json!({})).await
}

/// `qsh-server upgrade`: ask the running daemon to upgrade in place to `exe` (m2.md 10.2).
/// The answer, None when no daemon runs: `{"restarting":true}` when it started, or
/// `{"ok":false,"error":…,"not_newer":…}`. The daemon goes on with its sessions either way;
/// [`request_status`] tells when the upgrade is done (`restarts`) or failed
/// (`upgrade_failures`, `upgrade_error`).
pub async fn request_upgrade(paths: &Paths, exe: &std::path::Path, force: bool) -> io::Result<Option<Value>> {
    let Some(stream) = paths.connect_private(&paths.control_socket()).await? else {
        return Ok(None);
    };
    let (r, mut w) = stream.into_split();
    let message = request_value("upgrade", json!({ "exe": exe.to_string_lossy(), "force": force }));
    // The daemon probes the program first (up to 5 s)
    let line = tokio::time::timeout(Duration::from_secs(30), async {
        write_json(&mut w, &message).await?;
        read_line(&mut BufReader::new(r), 1 << 20).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the daemon did not answer"))??;
    Ok(Some(
        serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    ))
}

/// `qsh-server stop`: stop the running daemon and wait until it is gone. False when none ran.
pub async fn request_stop(paths: &Paths) -> io::Result<bool> {
    let pid = request_status(paths).await?.and_then(|s| s["pid"].as_u64());
    if request(paths, "stop", json!({})).await?.is_none() {
        return Ok(false);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while let Some(pid) = pid {
        if !sys::process_alive(pid as u32) || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review M1: a daemon (or anything on its socket) that accepts and never answers made
    /// `qsh-server bootstrap` hang; every exchange has a deadline now.
    #[tokio::test]
    async fn a_daemon_that_never_answers_does_not_hang_the_bootstrap() {
        let dir = std::env::temp_dir().join(format!("qsh-control-mute-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths::under(&dir);
        paths.ensure_runtime().unwrap();
        let listener = UnixListener::bind(paths.control_socket()).unwrap();
        let mute = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let launcher = DaemonLauncher {
            program: "/bin/false".into(),
            args: vec![],
        };
        let mut out = Vec::new();
        let request = b"{\"qsh\":1,\"versions\":[1],\"cols\":80,\"rows\":24}\n";
        let ok = tokio::time::timeout(
            Duration::from_secs(10),
            bootstrap(&paths, &launcher, &request[..], &mut out),
        )
        .await
        .expect("no hang")
        .unwrap();
        assert!(!ok);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("\"daemon\"") && text.contains("no answer"), "{text}");
        let status = tokio::time::timeout(Duration::from_secs(10), request_status(&paths))
            .await
            .expect("no hang");
        assert!(status.is_err());
        mute.abort();
        let _ = std::fs::remove_dir_all(dir);
    }
}
