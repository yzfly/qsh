//! The hub (feature `hub`): one resident client process that runs many terminal sessions with
//! one connection per server for all of them ([`client::Pool`]). An embedder such as TokenSSH
//! starts it once and relays each terminal through it ([`open`]); a network change is then one
//! QUIC migration ([`Request::Rebind`]) for every session, and a dead path one reconnect.
//!
//! The hub's unix socket (`Paths::hub_socket`, in the private runtime directory, mode 0600)
//! carries messages `[type u8][length u32 big-endian][payload]`:
//!
//! | direction | messages |
//! |---|---|
//! | client → hub | OPEN (JSON), INPUT (bytes), RESIZE (cols u16, rows u16), DETACH, HANGUP, STATUS, RESET, REBIND |
//! | hub → client | OUTPUT (bytes), EXIT (status i32), ANSWER (JSON) |
//!
//! A connection opens one session (OPEN, then the terminal), or carries one request (STATUS,
//! RESET, REBIND) answered by one ANSWER. This protocol is local to one installation, not part
//! of qsh/1.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::client::{self, ClientConfig, ClientError, Input, Outcome, Pool, Session, Terminal};
use crate::paths::Paths;
use crate::proto::WindowSize;
use crate::transport::ssh::SshCommand;
use crate::{log, sys};

const T_OPEN: u8 = 1;
const T_INPUT: u8 = 2;
const T_RESIZE: u8 = 3;
const T_DETACH: u8 = 4;
const T_HANGUP: u8 = 5;
const T_STATUS: u8 = 6;
const T_RESET: u8 = 7;
const T_REBIND: u8 = 8;
const T_OUTPUT: u8 = 16;
const T_EXIT: u8 = 17;
const T_ANSWER: u8 = 18;

const MAX_MESSAGE: usize = 1 << 20;

/// Exit status [`open`] reports when the hub went away in the middle of a session: neither
/// a program's status nor 42, so a caller can fall back to plain ssh.
pub const EXIT_HUB_LOST: i32 = 3;

/// A session to open in the hub.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenRequest {
    /// `[user@]host` or an ssh alias.
    pub destination: String,
    /// ssh options before the destination.
    #[serde(default)]
    pub ssh_options: Vec<String>,
    /// The ssh program, `ssh` when absent.
    #[serde(default)]
    pub ssh_program: Option<String>,
    /// The remote command; None for a login shell.
    #[serde(default)]
    pub command: Option<String>,
    /// Terminal columns.
    pub cols: u16,
    /// Terminal rows.
    pub rows: u16,
    /// `TERM`.
    #[serde(default)]
    pub term: Option<String>,
    /// Locale variables.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// A request to the hub that is not a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// The hub's sessions and connections, as JSON.
    Status,
    /// Close every connection; sessions reconnect.
    Reset,
    /// The network changed: move QUIC connections to a new socket.
    Rebind,
}

/// How the hub runs.
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// Exit after this long without sessions.
    pub idle_exit: Duration,
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            idle_exit: Duration::from_secs(600),
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hub message too large"));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, t: u8, payload: &[u8]) -> io::Result<()> {
    let mut m = Vec::with_capacity(5 + payload.len());
    m.push(t);
    m.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    m.extend_from_slice(payload);
    w.write_all(&m).await?;
    w.flush().await
}

struct Entry {
    destination: String,
    opened: Instant,
    status: Arc<Mutex<client::Status>>,
}

struct Hub {
    pool: Arc<Pool>,
    sessions: Mutex<HashMap<u64, Entry>>,
    next_id: AtomicU64,
    idle_since: Mutex<Instant>,
    started: Instant,
}

/// Run the hub until it had no sessions for `config.idle_exit`. One hub per runtime
/// directory: returns at once when another one runs.
pub async fn run(paths: &Paths, config: HubConfig) -> io::Result<()> {
    paths.ensure_runtime()?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.runtime.join("hub.lock"))?;
    if !sys::try_lock(&lock)? {
        return Ok(());
    }
    let socket = paths.hub_socket();
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    log::info(format_args!("hub started, pid {}", std::process::id()));
    let hub = Arc::new(Hub {
        pool: Pool::new(),
        sessions: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        idle_since: Mutex::new(Instant::now()),
        started: Instant::now(),
    });
    let check = (config.idle_exit / 4).clamp(Duration::from_millis(100), Duration::from_secs(30));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == sys::euid() => {}
                    _ => continue,
                }
                tokio::spawn(handle(hub.clone(), stream));
            }
            _ = tokio::time::sleep(check) => {
                if hub.sessions.lock().unwrap().is_empty() && hub.idle_since.lock().unwrap().elapsed() >= config.idle_exit {
                    log::info(format_args!("hub: no sessions for a while, exiting"));
                    let _ = std::fs::remove_file(&socket);
                    drop(lock);
                    return Ok(());
                }
            }
        }
    }
}

async fn handle(hub: Arc<Hub>, stream: UnixStream) {
    let (mut r, mut w) = stream.into_split();
    // A liveness check connects and leaves without a message
    let Ok((t, payload)) = read_frame(&mut r).await else {
        return;
    };
    let answer = match t {
        T_OPEN => return open_session(hub, r, w, payload).await,
        T_STATUS => hub.status(),
        T_RESET => {
            hub.pool.reset();
            json!({ "ok": true })
        }
        T_REBIND => match hub.pool.quic().rebind() {
            Ok(rebound) => json!({ "ok": true, "rebound": rebound }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        },
        _ => json!({ "ok": false, "error": format!("unknown request {t}") }),
    };
    let _ = write_frame(&mut w, T_ANSWER, answer.to_string().as_bytes()).await;
}

impl Hub {
    fn status(&self) -> Value {
        let sessions: Vec<Value> = {
            let sessions = self.sessions.lock().unwrap();
            let mut ids: Vec<&u64> = sessions.keys().collect();
            ids.sort();
            ids.into_iter()
                .map(|id| {
                    let e = &sessions[id];
                    let s = e.status.lock().unwrap().clone();
                    json!({
                        "id": id,
                        "destination": e.destination,
                        "transport": s.transport.map(|t| t.to_string()),
                        "rtt_ms": s.rtt.map(|r| r.as_millis() as u64),
                        "reconnects": s.reconnects,
                        "age": e.opened.elapsed().as_secs(),
                    })
                })
                .collect()
        };
        let connections: Vec<Value> = self
            .pool
            .connections()
            .into_iter()
            .map(|(d, t, rtt)| json!({ "destination": d, "transport": t.to_string(), "rtt_ms": rtt.map(|r| r.as_millis() as u64) }))
            .collect();
        json!({
            "running": true,
            "pid": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
            "uptime": self.started.elapsed().as_secs(),
            "local": self.pool.quic().local_addr().map(|a| a.to_string()),
            "connections": connections,
            "sessions": sessions,
        })
    }
}

async fn open_session(
    hub: Arc<Hub>,
    mut r: tokio::net::unix::OwnedReadHalf,
    mut w: tokio::net::unix::OwnedWriteHalf,
    payload: Vec<u8>,
) {
    let request: OpenRequest = match serde_json::from_slice(&payload) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_frame(
                &mut w,
                T_OUTPUT,
                format!("qsh hub: bad OPEN request: {e}\r\n").as_bytes(),
            )
            .await;
            let _ = write_frame(&mut w, T_EXIT, &client::EXIT_ERROR.to_be_bytes()).await;
            return;
        }
    };
    let mut ssh = SshCommand::new(request.destination.clone());
    ssh.options = request.ssh_options.iter().map(Into::into).collect();
    if let Some(program) = &request.ssh_program {
        ssh.program = program.into();
    }
    let mut config = ClientConfig::new(request.destination.clone());
    config.ssh = ssh;
    config.command = request.command.clone();
    config.term = request.term.clone();
    config.env = request.env.clone();
    config.size = WindowSize::new(request.cols.max(1), request.rows.max(1));
    // Nobody can answer a password prompt in the hub
    config.interactive = false;

    let session = Session::with_pool(config, hub.pool.clone());
    let id = hub.next_id.fetch_add(1, Ordering::Relaxed);
    hub.sessions.lock().unwrap().insert(
        id,
        Entry {
            destination: request.destination.clone(),
            opened: Instant::now(),
            status: session.status(),
        },
    );

    let (input_tx, input) = mpsc::channel::<Input>(256);
    let (output, mut output_rx) = mpsc::channel::<Vec<u8>>(256);
    let writer = tokio::spawn(async move {
        while let Some(bytes) = output_rx.recv().await {
            if write_frame(&mut w, T_OUTPUT, &bytes).await.is_err() {
                return None;
            }
        }
        Some(w)
    });
    let run = tokio::spawn(async move {
        let terminal = Terminal {
            input,
            output,
            errors: None,
            events: None,
        };
        match session.run(terminal).await {
            Ok(Outcome::Exited(status)) => (client::exit_code(&status), None),
            Ok(Outcome::Detached) => (0, None),
            Ok(Outcome::Abandoned) => (client::EXIT_ERROR, None),
            Err(e) => (e.exit_code(), Some(e)),
        }
    });
    let pump = async {
        loop {
            let input = match read_frame(&mut r).await {
                Ok((T_INPUT, bytes)) => Input::Data(bytes),
                Ok((T_RESIZE, p)) if p.len() == 4 => Input::Resize(WindowSize::new(
                    u16::from_be_bytes([p[0], p[1]]),
                    u16::from_be_bytes([p[2], p[3]]),
                )),
                Ok((T_DETACH, _)) => Input::Detach,
                Ok((T_HANGUP, _)) => Input::Hangup,
                Ok(_) => continue,
                // The client left: detach, the session keeps running on the server
                Err(_) => Input::Detach,
            };
            let detach = input == Input::Detach;
            if input_tx.send(input).await.is_err() || detach {
                break;
            }
        }
    };
    tokio::pin!(run);
    let (code, error) = tokio::select! {
        result = &mut run => result.unwrap_or((client::EXIT_ERROR, None)),
        _ = pump => run.await.unwrap_or((client::EXIT_ERROR, None)),
    };
    if let Ok(Some(mut w)) = writer.await {
        if let Some(e) = &error {
            if !matches!(e, ClientError::NoServer) {
                let _ = write_frame(&mut w, T_OUTPUT, format!("\r\nqsh: {e}\r\n").as_bytes()).await;
            }
        }
        let _ = write_frame(&mut w, T_EXIT, &code.to_be_bytes()).await;
    }
    let mut sessions = hub.sessions.lock().unwrap();
    sessions.remove(&id);
    if sessions.is_empty() {
        *hub.idle_since.lock().unwrap() = Instant::now();
    }
}

/// Run a session in the hub at `paths`, relaying `terminal`: the session's exit status, or
/// None when no hub answered (the caller may then run the session itself).
///
/// The runtime directory and the hub's user are checked first ([`Paths::connect_private`]): an
/// error when someone else could be listening on the socket.
pub async fn open(paths: &Paths, request: &OpenRequest, terminal: Terminal) -> io::Result<Option<i32>> {
    let Some(stream) = paths.connect_private(&paths.hub_socket()).await? else {
        return Ok(None);
    };
    let (mut r, mut w) = stream.into_split();
    let open = serde_json::to_vec(request).map_err(io::Error::other)?;
    if write_frame(&mut w, T_OPEN, &open).await.is_err() {
        return Ok(None);
    }
    let Terminal { mut input, output, .. } = terminal;
    let forward = tokio::spawn(async move {
        while let Some(i) = input.recv().await {
            let (t, payload) = match i {
                Input::Data(d) => (T_INPUT, d),
                Input::Resize(s) => {
                    let mut p = s.cols.to_be_bytes().to_vec();
                    p.extend_from_slice(&s.rows.to_be_bytes());
                    (T_RESIZE, p)
                }
                Input::Detach => (T_DETACH, Vec::new()),
                Input::Hangup => (T_HANGUP, Vec::new()),
                // Hub sessions are tty sessions: the end of input is ^D, as typed
                Input::Eof => (T_INPUT, vec![4]),
            };
            if write_frame(&mut w, t, &payload).await.is_err() {
                return;
            }
        }
    });
    let mut answered = false;
    let result = loop {
        match read_frame(&mut r).await {
            Ok((T_OUTPUT, bytes)) => {
                answered = true;
                if output.send(bytes).await.is_err() {
                    break Ok(Some(0));
                }
            }
            Ok((T_EXIT, code)) if code.len() == 4 => {
                break Ok(Some(i32::from_be_bytes([code[0], code[1], code[2], code[3]])))
            }
            Ok(_) => answered = true,
            Err(_) if !answered => break Ok(None),
            Err(_) => break Ok(Some(EXIT_HUB_LOST)),
        }
    };
    forward.abort();
    result
}

/// Send `request` to the hub: its JSON answer, or None when no hub runs. Checked as in
/// [`open`].
pub async fn request(paths: &Paths, request: Request) -> io::Result<Option<Value>> {
    let Some(mut stream) = paths.connect_private(&paths.hub_socket()).await? else {
        return Ok(None);
    };
    let t = match request {
        Request::Status => T_STATUS,
        Request::Reset => T_RESET,
        Request::Rebind => T_REBIND,
    };
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        write_frame(&mut stream, t, &[]).await?;
        read_frame(&mut stream).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the hub does not answer"))??;
    serde_json::from_slice(&answer.1)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
