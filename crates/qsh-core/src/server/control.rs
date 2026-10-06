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
//!
//! This protocol is internal to one installation (protocol.md 10.4): the commands and the daemon
//! may be of different versions only across an upgrade, which `"v"` lets each side notice.

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
use super::{count, Shared};
use crate::crypto::SessionKey;
use crate::log;
use crate::paths::Paths;
use crate::proto::bootstrap::{
    Credentials, ErrorKind, ErrorReply, Op, Request, SessionInfo, BOOTSTRAP_VERSION, MAX_REQUEST,
};
use crate::proto::PIPE_PREFACE;
use crate::sys;

/// Version of the control socket requests.
const CONTROL_VERSION: u64 = 1;

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
    let line = read_line(&mut reader, MAX_REQUEST + 4096).await?;
    if line.is_empty() {
        // A liveness check that connected and left
        return Ok(());
    }
    let request: Value = serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    match request["op"].as_str() {
        Some("bootstrap") => {
            let reply = match serde_json::from_value::<Request>(request["request"].clone()) {
                Ok(r) => bootstrap_op(&shared, &r),
                Err(e) => error_value(ErrorKind::BadRequest, format!("bad request: {e}")),
            };
            write_json(&mut w, &reply).await?;
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
        _ => write_json(&mut w, &json!({ "ok": false, "error": "unknown request" })).await?,
    }
    Ok(())
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

/// The most sessions a daemon keeps.
const MAX_SESSIONS: usize = 1000;

/// Carry out a bootstrap request (protocol.md 10.3).
fn bootstrap_op(shared: &Shared, request: &Request) -> Value {
    if let Err(e) = request.validate() {
        return serde_json::to_value(e).unwrap_or(Value::Null);
    }
    let session_id = request.session.as_deref().and_then(SessionId::from_hex);
    match request.op {
        Op::New => {
            if shared.sessions.len() >= MAX_SESSIONS {
                return error_value(ErrorKind::Limit, "too many sessions");
            }
            let spawn = Spawn {
                command: request.command.clone(),
                cols: request.cols.unwrap_or(80) as u16,
                rows: request.rows.unwrap_or(24) as u16,
                term: request.term.clone(),
                env: request.accepted_env(),
                name: request.name.clone(),
                plain: request.tty == Some(false),
            };
            let id = SessionId::generate();
            let key = SessionKey::generate();
            match PtySession::start(id, key.clone(), &spawn, &shared.account, shared.config.output_replay) {
                Ok(session) => {
                    log::debug(format_args!("session {} started", &id.to_hex()[..8]));
                    shared.sessions.insert(session);
                    credentials(shared, &id, &key)
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
            credentials(shared, &session.id, &key)
        }
        Op::List => {
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

fn credentials(shared: &Shared, id: &SessionId, key: &SessionKey) -> Value {
    serde_json::to_value(Credentials {
        qsh: BOOTSTRAP_VERSION,
        versions: vec![u64::from(crate::proto::VERSION)],
        session: id.to_hex(),
        key: key.to_hex(),
        cert_sha256: shared.fingerprint.to_hex(),
        udp: shared.port,
        tcp: shared.port,
        caps: Vec::new(),
        server: format!("qsh-server/{}", env!("CARGO_PKG_VERSION")),
        ssh_addr: None,
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
    json!({
        "v": CONTROL_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "started": secs(shared.started),
        "port": shared.port,
        "fingerprint": shared.fingerprint.to_hex(),
        "sessions": sessions,
        "stats": {
            "quic_connections": load(&stats.quic_connections),
            "tls_connections": load(&stats.tls_connections),
            "pipe_connections": load(&stats.pipe_connections),
            "channels": load(&stats.channels),
            "attach_failures": load(&stats.attach_failures),
        },
    })
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
pub async fn connect_or_start(paths: &Paths, launcher: &DaemonLauncher) -> io::Result<UnixStream> {
    let socket = paths.control_socket();
    if let Ok(stream) = UnixStream::connect(&socket).await {
        return Ok(stream);
    }
    paths.ensure_runtime()?;
    launcher.start(paths)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(&socket).await {
            Ok(stream) => return Ok(stream),
            Err(e) if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("the daemon did not start (see {}): {e}", paths.daemon_log().display()),
                ))
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
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
                let kind = match serde_json::from_slice::<Value>(&line) {
                    Ok(v) if v["op"].is_string() && v["qsh"].as_u64() == Some(BOOTSTRAP_VERSION) => {
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
        let exchange = async {
            let stream = connect_or_start(paths, launcher).await?;
            let (r, mut w) = stream.into_split();
            write_json(
                &mut w,
                &json!({ "v": CONTROL_VERSION, "op": "bootstrap", "request": request }),
            )
            .await?;
            let line = read_line(&mut BufReader::new(r), 1 << 20).await?;
            serde_json::from_slice::<Value>(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        };
        match exchange.await {
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
    let stream = connect_or_start(paths, launcher).await?;
    let (r, mut w) = stream.into_split();
    let client = std::env::var("SSH_CONNECTION").unwrap_or_default();
    write_json(&mut w, &json!({ "v": CONTROL_VERSION, "op": "pipe", "client": client })).await?;
    let mut reader = BufReader::new(r);
    let ok = read_line(&mut reader, 64).await?;
    if ok != b"ok" {
        return Err(io::Error::other("the daemon refused the pipe"));
    }
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

async fn request(paths: &Paths, op: &str) -> io::Result<Option<Value>> {
    let Ok(stream) = UnixStream::connect(paths.control_socket()).await else {
        return Ok(None);
    };
    let (r, mut w) = stream.into_split();
    write_json(&mut w, &json!({ "v": CONTROL_VERSION, "op": op })).await?;
    let line = tokio::time::timeout(Duration::from_secs(5), read_line(&mut BufReader::new(r), 1 << 20))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the daemon does not answer"))??;
    Ok(Some(
        serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    ))
}

/// `qsh-server status`: the running daemon's status as JSON, None when no daemon runs.
pub async fn request_status(paths: &Paths) -> io::Result<Option<Value>> {
    request(paths, "status").await
}

/// `qsh-server stop`: stop the running daemon and wait until it is gone. False when none ran.
pub async fn request_stop(paths: &Paths) -> io::Result<bool> {
    let pid = request_status(paths).await?.and_then(|s| s["pid"].as_u64());
    if request(paths, "stop").await?.is_none() {
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
