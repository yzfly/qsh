//! One terminal session across connections (protocol.md sections 6 and 7): attach, the
//! terminal channel (input, output, acknowledgements, gaps, exit), resume after a lost
//! connection, and the client's state of the session.
//!
//! With the capabilities of m2.md sections 6 and 7 the channel also carries OUTPUT_ZSTD
//! (decompressed under the rules of protocol.md 7.12) and, on a tty session whose output goes
//! to a terminal, SNAPSHOT: the current screen instead of a backlog (7.8), checked against the
//! content profile and written as a whole, after a line that says what was skipped.
//!
//! After a refused snapshot (protocol.md 7.8.4: the profile check, its parts or a part's zstd
//! frame failed) the session attaches again at once without snapshots, for the rest of the
//! process, so that a server whose encoder went wrong cannot make it reconnect in a loop. A
//! refused zstd frame, or a panic of our decoder (contained, `crate::fault`; it breaks the
//! connection, as a protocol error would), counts against the server: after the second, this
//! process offers it no compression any more.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use super::conn::Conn;
use super::pool::Pool;
use super::store::{self, SavedSession, SessionLock, SessionStore};
use super::transcript::{self, Record};
use super::{
    bootstrap, bootstrap_reply, exit_code, host_of, jitter, ClientConfig, ClientError, Event, Input, Outcome, Status,
    Terminal, EXIT_ERROR,
};
use crate::codec::{self, DecodeError};
use crate::crypto::{self, Fingerprint, SessionKey};
use crate::fault;
use crate::log;
use crate::proto::bootstrap::{Credentials, ErrorKind, Reply, Request, SessionInfo};
use crate::proto::limits::{ATTACH_TIMEOUT, RESEND_CHUNK, RESTART_RECONNECT};
use crate::proto::message::{
    ATTACH_ACCEPT_SNAPSHOT, ATTACH_FRESH, LATEST, MAX_SNAPSHOT, MAX_TERMINAL, PREFERRED_DATA, SNAPSHOT_FINAL,
    SNAPSHOT_ZSTD,
};
use crate::proto::varint;
use crate::proto::zstd::MAX_ZSTD_CONTENT;
use crate::proto::{read_message, write_message, ErrorCode, ExitStatus, FramingError, Message, WindowSize};
use crate::screen::snapshot::check_profile;
use crate::session::{Inbound, ReplayBuffer, INPUT_REPLAY};
use crate::transport::ssh::SshCommand;
use crate::transport::{RecvStream, SendStream, Target};

/// Typed input followed by nothing received for this long: the path is dead. The user
/// notices a dead connection when typing, so that is when to find out fast.
const INPUT_ANSWER_WITHIN: Duration = Duration::from_secs(8);
/// Unacknowledged input for this long: PING, so the control stream answers even if the
/// terminal stream is held up.
const INPUT_PING_AFTER: Duration = Duration::from_secs(1);
/// ACK output after this much, or this long after it arrived (section 7.5) …
const ACK_BYTES: u64 = 32768;
const ACK_DELAY: Duration = Duration::from_millis(200);
/// … and on an attachment that accepts snapshots, more often: the server's pacing counts
/// unacknowledged output, and prompt ACKs keep what is queued ahead of an interrupt small.
const ACK_BYTES_SNAPSHOT: u64 = 16384;
const ACK_DELAY_SNAPSHOT: Duration = Duration::from_millis(50);
/// Local input is taken while less than this waits in the outbox: an ACK queued behind input
/// waits for little more than this.
const OUTBOX_INPUT: usize = 64 * 1024;
/// How long the last messages of an attachment (an ACK after EXIT, DETACH, ERROR) may take to
/// be written.
const OUTBOX_FLUSH: Duration = Duration::from_secs(2);
/// A connection that lasted this long was a working one: reconnect at once after it ends.
const STABLE_AFTER: Duration = Duration::from_secs(10);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// zstd frames from one server refused (protocol.md 7.12) or failed on by the decoder (7.8.7)
/// after which this process stops offering it compression (protocol.md 7.8.4: at the latest
/// after the second). The first may be a fluke (the channel starts again); a second one is
/// not, and would repeat on every attach.
const FRAMES_REFUSED: u32 = 2;

/// zstd frames refused per server host (lowercase), in this process.
static REFUSED_FRAMES: Mutex<BTreeMap<String, u32>> = Mutex::new(BTreeMap::new());

/// Whether this process offers compression to `host` (lowercase) no more: [`FRAMES_REFUSED`]
/// of its frames were refused. The pool asks before each hello.
pub(super) fn compression_refused(host: &str) -> bool {
    REFUSED_FRAMES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(host)
        .is_some_and(|&n| n >= FRAMES_REFUSED)
}

/// Count a refused frame from `host` (lowercase); whether compression is now refused for it.
fn frame_refused_by(host: &str) -> bool {
    let mut refused = REFUSED_FRAMES.lock().unwrap_or_else(|e| e.into_inner());
    let n = refused.entry(host.to_string()).or_default();
    *n += 1;
    *n >= FRAMES_REFUSED
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
    /// A snapshot from the server failed the content profile: this session accepts none
    /// any more (for the rest of the process).
    snapshots_refused: bool,
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

/// The output offset after `n` bytes at `offset`, if the client can go on from there
/// (protocol.md 7.3: checked arithmetic, offsets up to [`MAX_OFFSET`]); None is a
/// SEQUENCE_ERROR.
fn output_end(offset: u64, n: u64) -> Option<u64> {
    offset.checked_add(n).filter(|&end| end <= MAX_OFFSET)
}

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
    /// The connection is being retired ([`Conn::retire`]): attach again at once, on another.
    Moved,
    /// The attachment was given up, not the connection (a snapshot was refused): attach again
    /// at once, without back-off.
    Again(String),
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
            extra_ports: saved.extra_ports.clone(),
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
            extra_ports: state.target.extra_ports.clone(),
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
            let conn = match self.pool.get(&state.target, &self.config).await {
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
                End::Moved => {
                    // A transport upgrade (m2.md 3.6): no disconnection, no back-off
                    log::debug(format_args!("moving the session off {}", conn.transport()));
                    backoff = BACKOFF_FIRST;
                }
                End::Again(why) => {
                    // Bounded: what ends an attachment this way is not repeated (State)
                    log::debug(format_args!("attaching again: {why}"));
                    backoff = BACKOFF_FIRST;
                }
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
                    transcript::record(Record::Disconnected {
                        session: &state.session,
                        why: &why,
                    });
                    notify(terminal, Event::Disconnected(why));
                    if conn.server_restarting() {
                        // The daemon restarts in place and keeps the session (protocol.md
                        // 10.6): back in about 500 ms, without back-off
                        backoff = BACKOFF_FIRST;
                        wait = Some(jitter(RESTART_RECONNECT));
                    } else if attached_at.elapsed() >= STABLE_AFTER {
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
            record.extra_ports = fresh.target.extra_ports.clone();
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
        // Snapshots on a tty session, when the server can send them and the output goes to a
        // terminal (7.8.2; `catchup` off otherwise)
        let accept = !state.pipe
            && !state.snapshots_refused
            && conn.capabilities.snapshot
            && self.config.catchup != crate::config::Catchup::Off;
        let mut flags = if state.fresh { ATTACH_FRESH } else { 0 };
        if accept {
            flags |= ATTACH_ACCEPT_SNAPSHOT;
        }
        let attach = Message::Attach {
            session: state.session,
            proof: key.proof(&cb),
            output_received,
            size: state.size,
            flags,
            error_received: state.pipe.then_some(error_received),
        };
        if let Err(e) = write_message(&mut send, &attach).await {
            return Ok(End::Lost(e.to_string()));
        }
        conn.sent();
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
        // Written by the pump, which reads the channel meanwhile: up to a replay buffer of
        // input goes out here, and the server may need our ACKs before it can take it all
        let mut outbox = Outbox::default();
        for m in &first {
            outbox.push(m);
        }
        {
            let mut status = self.status.lock().unwrap();
            status.transport = Some(conn.transport());
            status.remote = conn.connection.remote_address();
            status.connected_since = Some(Instant::now());
            status.bytes_out += pending.len() as u64;
            status.attempts = conn.attempts();
        }
        transcript::record(Record::Connected {
            session: &state.session,
            transport: conn.transport(),
            remote: conn.connection.remote_address(),
        });
        notify(terminal, Event::Connected(conn.transport()));
        let had_pending = !pending.is_empty();
        self.pump(conn, state, terminal, send, recv, outbox, had_pending, accept)
            .await
    }

    /// A snapshot is refused (protocol.md 7.8.4, "After a refused snapshot"): the channel
    /// fails with `code`, and the session attaches again at once, from its unchanged
    /// `received` (nothing of the snapshot was written), accepting no snapshots for the rest of
    /// the process. Otherwise a server whose encoder makes such a snapshot would make the
    /// client reconnect in a loop.
    async fn snapshot_refused(
        &self,
        state: &mut State,
        offset: u64,
        why: &str,
        code: ErrorCode,
        send: &mut SendStream,
        outbox: &mut Outbox,
    ) -> End {
        state.snapshots_refused = true;
        self.status.lock().unwrap().snapshots_refused += 1;
        let session = crypto::hex(&state.session);
        // A warning: the client's highest level
        log::info(format_args!(
            "warning: session {}: the snapshot at offset {offset} was refused ({why}); this session takes no snapshots any more",
            &session[..8]
        ));
        let mut fields = serde_json::Map::new();
        fields.insert("session".into(), session.into());
        fields.insert("offset".into(), offset.into());
        fields.insert("why".into(), why.into());
        transcript::record(Record::Other {
            ev: "snapshot_refused",
            fields: &fields,
        });
        outbox.push(&Message::Error {
            code,
            message: String::new(),
        });
        let _ = outbox.flush(send).await;
        End::Again("a snapshot was refused".into())
    }

    /// A zstd frame was refused under the rules of 7.12, or the decoder failed on it (7.8.7):
    /// counted per server for this process; whether compression is now off for it (no `zstd`
    /// in the hellos of later connections, [`compression_refused`]).
    fn frame_refused(&self, state: &State, error: &DecodeError) -> bool {
        let host = state.target.host.to_lowercase();
        let off = frame_refused_by(&host);
        self.status.lock().unwrap().frames_refused += 1;
        let session = crypto::hex(&state.session);
        log::info(format_args!(
            "warning: session {}: a zstd frame from {host} was refused ({error}){}",
            &session[..8],
            if off {
                "; no compression from this server for the rest of this process"
            } else {
                ""
            }
        ));
        let mut fields = serde_json::Map::new();
        fields.insert("session".into(), session.into());
        fields.insert("why".into(), error.to_string().into());
        fields.insert("compression_off".into(), off.into());
        transcript::record(Record::Other {
            ev: "frame_refused",
            fields: &fields,
        });
        off
    }

    /// The attached terminal channel (sections 7.4 to 7.11).
    ///
    /// One task reads and writes the channel, and it never waits for a write while it could
    /// read: messages to send go to an outbox, written as the transport takes them. Waiting
    /// for a write of input before reading on would deadlock on a pipe session, where the
    /// server may be unable to take more input until our ACKs of its output arrive, and its
    /// output may wait for us to read it (7.4, 7.14.5).
    #[allow(clippy::too_many_arguments)]
    async fn pump(
        &self,
        conn: &Arc<Conn>,
        state: &mut State,
        terminal: &mut Terminal,
        mut send: SendStream,
        recv: BufReader<RecvStream>,
        mut outbox: Outbox,
        had_pending: bool,
        accept: bool,
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
        let (ack_bytes, ack_delay) = if accept {
            (ACK_BYTES_SNAPSHOT, ACK_DELAY_SNAPSHOT)
        } else {
            (ACK_BYTES, ACK_DELAY)
        };
        let zstd = conn.capabilities.zstd;
        // The parts of a snapshot received so far (7.8.3)
        let mut snapshot: Option<Assembly> = None;
        let mut last_ping = Instant::now();
        // Since when typed input waits for any answer, and whether it was PINGed already
        let mut unanswered: Option<Instant> = had_pending.then(Instant::now);
        let mut input_pinged = false;
        let mut hangup_sent = state.hangup;
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let room = state.input.len() < INPUT_REPLAY && outbox.len() < OUTBOX_INPUT;
            tokio::select! {
                written = send.write(outbox.pending()), if !outbox.is_empty() => match written {
                    Ok(n) if n > 0 => {
                        outbox.advance(n);
                        conn.sent();
                    }
                    _ => return Ok(End::Lost("the channel broke".into())),
                },
                message = rx.recv() => {
                    conn.received();
                    let message = match message {
                        None => return Ok(End::Lost("the server ended the channel".into())),
                        Some(Err(e)) => return Ok(End::Lost(format!("broken channel: {e}"))),
                        Some(Ok(m)) => m,
                    };
                    let message_ty = MessageTy::of(&message);
                    // The parts of a snapshot come back to back: no output in between (7.8.3)
                    let output_stream = matches!(
                        message,
                        Message::Output { .. }
                            | Message::OutputZstd { .. }
                            | Message::OutputGap { .. }
                            | Message::Exit { .. }
                    );
                    if let Some(assembly) = snapshot.as_ref().filter(|_| output_stream) {
                        let offset = assembly.offset;
                        return Ok(self
                            .snapshot_refused(state, offset, "output between its parts", ErrorCode::PROTOCOL_VIOLATION, &mut send, &mut outbox)
                            .await);
                    }
                    // Decompressed output is output (7.12)
                    let (message, frame) = match message {
                        Message::OutputZstd { offset, frame } => {
                            if !zstd {
                                return Ok(protocol_violation(&mut send, &mut outbox).await);
                            }
                            match codec::decompress(&frame, MAX_ZSTD_CONTENT) {
                                Ok(data) => {
                                    let mut status = self.status.lock().unwrap();
                                    status.compressed.0 += data.len() as u64;
                                    status.compressed.1 += frame.len() as u64;
                                    (Message::Output { offset, data }, Some(frame.len()))
                                }
                                Err(e) => {
                                    self.frame_refused(state, &e);
                                    if matches!(e, DecodeError::Fault(_)) {
                                        // Our own fault: a protocol error for this connection
                                        // (7.8.7); a new one is made
                                        let end = protocol_violation(&mut send, &mut outbox).await;
                                        conn.close(ErrorCode::PROTOCOL_VIOLATION, "");
                                        return Ok(end);
                                    }
                                    return Ok(frame_error(&mut send, &mut outbox).await);
                                }
                            }
                        }
                        other => (other, None),
                    };
                    match message {
                        Message::Output { offset, data } | Message::ErrorOutput { offset, data } => {
                            let error = state.pipe && matches!(message_ty, MessageTy::ErrorOutput);
                            if message_ty == MessageTy::ErrorOutput && !state.pipe {
                                // stderr exists only on a pipe session (7.14.3)
                                return Ok(protocol_violation(&mut send, &mut outbox).await);
                            }
                            let stream = if error { &mut state.errors } else { &mut state.output };
                            if offset != stream.received() || data.is_empty() {
                                return Ok(sequence_error(&mut send, &mut outbox).await);
                            }
                            let n = data.len() as u64;
                            transcript::record(Record::Output {
                                session: &state.session,
                                errors: error,
                                offset,
                                data: &data,
                                frame,
                            });
                            let sink = match (&terminal.errors, error) {
                                (Some(errors), true) => errors,
                                _ => &terminal.output,
                            };
                            if sink.send(data).await.is_err() {
                                // Nobody shows the output any more: leave the session running
                                return Ok(detach(&mut send, &mut outbox, &mut rx).await);
                            }
                            // Checked: decompressed output has a length the decoder did not see
                            let Some(end) = output_end(offset, n) else {
                                return Ok(sequence_error(&mut send, &mut outbox).await);
                            };
                            *stream = Inbound::at(end);
                            self.status.lock().unwrap().bytes_in += n;
                            let unacked = (state.output.received() - acked.0) + (state.errors.received() - acked.1);
                            if unacked >= ack_bytes {
                                ack(&mut outbox, state, &mut acked);
                                ack_due = None;
                            } else {
                                ack_due.get_or_insert_with(|| Instant::now() + ack_delay);
                            }
                        }
                        Message::Snapshot { offset, flags, cols, rows, data } => {
                            if !accept {
                                // Only on an attachment that accepts them (7.8.2)
                                return Ok(protocol_violation(&mut send, &mut outbox).await);
                            }
                            transcript::record(Record::Snapshot {
                                session: &state.session,
                                offset,
                                flags,
                                cols,
                                rows,
                                data: &data,
                            });
                            let expected = state.output.received();
                            if offset < expected || output_end(offset, 0).is_none() {
                                return Ok(sequence_error(&mut send, &mut outbox).await);
                            }
                            let assembly = snapshot.get_or_insert_with(|| Assembly {
                                offset,
                                cols,
                                rows,
                                data: Vec::new(),
                            });
                            if (assembly.offset, assembly.cols, assembly.rows) != (offset, cols, rows) {
                                let first = assembly.offset;
                                return Ok(self
                                    .snapshot_refused(state, first, "its parts disagree", ErrorCode::PROTOCOL_VIOLATION, &mut send, &mut outbox)
                                    .await);
                            }
                            let part = if flags & SNAPSHOT_ZSTD != 0 {
                                if !zstd {
                                    return Ok(protocol_violation(&mut send, &mut outbox).await);
                                }
                                match codec::decompress(&data, MAX_ZSTD_CONTENT) {
                                    Ok(part) => part,
                                    Err(e) => {
                                        let off = self.frame_refused(state, &e);
                                        let fault = matches!(e, DecodeError::Fault(_));
                                        let (why, code) = if fault {
                                            (e.to_string(), ErrorCode::PROTOCOL_VIOLATION)
                                        } else {
                                            (format!("a part: {e}"), ErrorCode::FRAME_ERROR)
                                        };
                                        let end = self.snapshot_refused(state, offset, &why, code, &mut send, &mut outbox).await;
                                        if !(off || fault) {
                                            return Ok(end);
                                        }
                                        // Compression is off for this server now, or our decoder
                                        // failed: a new connection
                                        conn.close(ErrorCode::PROTOCOL_VIOLATION, "");
                                        return Ok(End::Lost(why));
                                    }
                                }
                            } else {
                                data
                            };
                            if assembly.data.len() + part.len() > MAX_SNAPSHOT {
                                return Ok(self
                                    .snapshot_refused(state, offset, "larger than MAX_SNAPSHOT", ErrorCode::FRAME_ERROR, &mut send, &mut outbox)
                                    .await);
                            }
                            assembly.data.extend_from_slice(&part);
                            if flags & SNAPSHOT_FINAL != 0 {
                                let assembly = snapshot.take().expect("assembling");
                                // Only what the content profile allows reaches the terminal. The
                                // check is ours but runs on the server's data: contained too
                                let refused = match fault::contain(|| check_profile(&assembly.data)) {
                                    Ok(Ok(())) => None,
                                    Ok(Err(e)) => Some(e.to_string()),
                                    Err(fault) => Some(format!("the profile check failed ({fault})")),
                                };
                                if let Some(why) = refused {
                                    return Ok(self
                                        .snapshot_refused(state, offset, &why, ErrorCode::PROTOCOL_VIOLATION, &mut send, &mut outbox)
                                        .await);
                                }
                                let skipped = offset - expected;
                                let mut bytes = Vec::with_capacity(assembly.data.len() + 80);
                                // On the normal screen, a line that marks the skipped output; the
                                // snapshot's scrolling pushes it into the scrollback (6.7)
                                let alternate = assembly.data.windows(8).any(|w| w == b"\x1b[?1049h");
                                if skipped > 0 && !alternate {
                                    bytes.extend_from_slice(skip_notice(skipped).as_bytes());
                                }
                                bytes.extend_from_slice(&assembly.data);
                                if terminal.output.send(bytes).await.is_err() {
                                    return Ok(detach(&mut send, &mut outbox, &mut rx).await);
                                }
                                state.output = Inbound::at(offset);
                                if skipped > 0 {
                                    {
                                        let mut status = self.status.lock().unwrap();
                                        status.skipped = status.skipped.saturating_add(skipped);
                                        status.snapshots += 1;
                                    }
                                    notify(terminal, Event::OutputSkipped(skipped));
                                }
                                // Acknowledged at once: the server sends no other snapshot before
                                ack(&mut outbox, state, &mut acked);
                                ack_due = None;
                            }
                        }
                        Message::OutputGap { from, to } => {
                            if state.pipe {
                                // A pipe session never skips output (7.14.5)
                                return Ok(protocol_violation(&mut send, &mut outbox).await);
                            }
                            if from != state.output.received() || from >= to || output_end(to, 0).is_none() {
                                return Ok(sequence_error(&mut send, &mut outbox).await);
                            }
                            state.output = Inbound::at(to);
                            transcript::record(Record::Gap {
                                session: &state.session,
                                from,
                                to,
                            });
                            {
                                let mut status = self.status.lock().unwrap();
                                status.skipped = status.skipped.saturating_add(to - from);
                            }
                            notify(terminal, Event::OutputSkipped(to - from));
                        }
                        Message::Ack { received, .. } => {
                            // 7.5: beyond what was sent is an error, below the last is stale
                            if received > state.input.end() {
                                return Ok(sequence_error(&mut send, &mut outbox).await);
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
                                return Ok(sequence_error(&mut send, &mut outbox).await);
                            }
                            outbox.push(&state.ack());
                            let _ = outbox.flush(&mut send).await;
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
                        _ => return Ok(protocol_violation(&mut send, &mut outbox).await),
                    }
                }
                input = terminal.input.recv(), if room && !state.input_closed => match input {
                    Some(input @ (Input::Data(_) | Input::Eof)) => {
                        let messages = state.take_input(input);
                        if messages.is_empty() {
                            continue;
                        }
                        for m in &messages {
                            if let Message::Input { data, .. } = m {
                                self.status.lock().unwrap().bytes_out += data.len() as u64;
                                unanswered.get_or_insert_with(Instant::now);
                            }
                            outbox.push(m);
                        }
                    }
                    Some(Input::Resize(size)) => {
                        state.size = size;
                        outbox.push(&Message::Resize(size));
                    }
                    Some(Input::Detach) => return Ok(detach(&mut send, &mut outbox, &mut rx).await),
                    Some(Input::Hangup) => {
                        state.hangup = true;
                        if !hangup_sent {
                            hangup_sent = true;
                            outbox.push(&Message::Hangup);
                        }
                    }
                    None => state.input_closed = true,
                },
                // ACKs on time (7.5): 50 ms matter on an attachment that accepts snapshots
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(ack_due.unwrap_or_else(Instant::now))), if ack_due.is_some() => {
                    ack(&mut outbox, state, &mut acked);
                    ack_due = None;
                }
                _ = tick.tick() => {
                    let now = Instant::now();
                    if ack_due.is_some_and(|t| now >= t) {
                        ack(&mut outbox, state, &mut acked);
                        ack_due = None;
                    }
                    if conn.connection.is_closed() {
                        return Ok(End::Lost("connection closed".into()));
                    }
                    let last_rx = conn.last_received();
                    if let Some(why) = conn.dead() {
                        return Ok(End::Lost(why));
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
                    if conn.ping_due(last_ping) {
                        conn.ping();
                        last_ping = now;
                    }
                    if conn.retiring() && state.input.is_empty() && !hangup_sent {
                        // Every byte of input acknowledged: nothing is in flight to lose
                        ack(&mut outbox, state, &mut acked);
                        let _ = outbox.flush(&mut send).await;
                        return Ok(End::Moved);
                    }
                    let mut status = self.status.lock().unwrap();
                    status.rtt = conn.rtt();
                    status.observed = conn.observed();
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

/// ACK what was received since the last one.
fn ack(outbox: &mut Outbox, state: &State, acked: &mut (u64, u64)) {
    let now = (state.output.received(), state.errors.received());
    if now != *acked {
        outbox.push(&state.ack());
        *acked = now;
    }
}

/// Encoded messages waiting to be written on the terminal channel, in order.
#[derive(Debug, Default)]
struct Outbox {
    bytes: Vec<u8>,
    /// How much of `bytes` was written.
    written: usize,
}

impl Outbox {
    fn push(&mut self, message: &Message) {
        if self.written == self.bytes.len() {
            self.bytes.clear();
            self.written = 0;
        } else if self.written >= OUTBOX_INPUT {
            self.bytes.drain(..self.written);
            self.written = 0;
        }
        self.bytes.extend(message.encode());
    }

    fn pending(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    fn len(&self) -> usize {
        self.bytes.len() - self.written
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn advance(&mut self, n: usize) {
        self.written += n;
    }

    /// Write everything, at the end of an attachment: for at most [`OUTBOX_FLUSH`].
    async fn flush(&mut self, send: &mut SendStream) -> io::Result<()> {
        let written = tokio::time::timeout(OUTBOX_FLUSH, async {
            send.write_all(self.pending()).await?;
            send.flush().await
        })
        .await;
        self.bytes.clear();
        self.written = 0;
        written.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
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

async fn protocol_violation(send: &mut SendStream, outbox: &mut Outbox) -> End {
    outbox.push(&Message::Error {
        code: ErrorCode::PROTOCOL_VIOLATION,
        message: String::new(),
    });
    let _ = outbox.flush(send).await;
    End::Lost("unexpected message from the server".into())
}

/// A frame of compressed data or a snapshot breaks the rules of 7.12 or 7.8.3: FRAME_ERROR
/// (a stream error), and the attachment starts again.
async fn frame_error(send: &mut SendStream, outbox: &mut Outbox) -> End {
    outbox.push(&Message::Error {
        code: ErrorCode::FRAME_ERROR,
        message: String::new(),
    });
    let _ = outbox.flush(send).await;
    End::Lost("a malformed frame from the server".into())
}

/// The parts of a snapshot received so far (7.8.3).
#[derive(Debug)]
struct Assembly {
    offset: u64,
    cols: u16,
    rows: u16,
    data: Vec<u8>,
}

/// The dim line written before a snapshot that skipped `bytes` of output (m2.md 6.7).
fn skip_notice(bytes: u64) -> String {
    let amount = match bytes {
        0..=9999 => format!("{bytes} B"),
        10_000..=9_999_999 => format!("{:.1} kB", bytes as f64 / 1e3),
        _ => format!("{:.1} MB", bytes as f64 / 1e6),
    };
    format!("\r\n\x1b[2mqsh: skipped {amount} of output\x1b[m\r\n")
}

async fn sequence_error(send: &mut SendStream, outbox: &mut Outbox) -> End {
    outbox.push(&Message::Error {
        code: ErrorCode::SEQUENCE_ERROR,
        message: String::new(),
    });
    let _ = outbox.flush(send).await;
    let _ = send.shutdown().await;
    End::Fatal(ClientError::SessionLost("SEQUENCE_ERROR".into()))
}

/// DETACH, then wait up to 2 s for the server's FIN so typed input is not lost (7.11).
async fn detach(
    send: &mut SendStream,
    outbox: &mut Outbox,
    rx: &mut mpsc::Receiver<Result<Message, FramingError>>,
) -> End {
    // After the input before it (7.11)
    outbox.push(&Message::Detach);
    let _ = outbox.flush(send).await;
    let _ = send.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = rx.recv().await {}
    })
    .await;
    End::Detached
}

/// What an ERROR on a terminal channel means for the session (section 11.2).
fn attach_error(code: ErrorCode, message: String) -> End {
    // The server's words, shown to the user: as text only (security.md 4.6)
    let message = crate::text::sanitize(&message, 256);
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
        extra_ports: c.extra_ports.clone(),
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
            snapshots_refused: false,
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
    /// Messages leave the outbox whole and in order, however the transport splits the writes.
    #[test]
    fn the_outbox_keeps_order_across_partial_writes() {
        let mut outbox = Outbox::default();
        let messages: Vec<Message> = (0..40u64)
            .map(|i| Message::Input {
                offset: i * 4000,
                data: vec![i as u8; 4000],
            })
            .collect();
        let mut wire = Vec::new();
        let mut sent = messages.iter();
        // Pushes between partial writes, enough to compact the written part away
        while !outbox.is_empty() || sent.len() > 0 {
            if let Some(m) = sent.next() {
                outbox.push(m);
            }
            let n = outbox.len().min(1500);
            wire.extend_from_slice(&outbox.pending()[..n]);
            outbox.advance(n);
        }
        let mut at = 0;
        for m in &messages {
            let (decoded, used) = crate::proto::message::decode_from(&wire[at..], MAX_TERMINAL)
                .unwrap()
                .unwrap();
            assert_eq!(&decoded, m);
            at += used;
        }
        assert_eq!(at, wire.len());
    }

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

    /// Offsets that OUTPUT_GAP, SNAPSHOT or the length of decompressed output (OUTPUT_ZSTD,
    /// which the decoder cannot check) would take past what the client can count are refused:
    /// OUTPUT_GAP{.., 2^64 − 6} followed by OUTPUT_ZSTD of 64 bytes no longer wraps (or
    /// panics, in a debug build).
    #[test]
    fn output_offsets_are_checked() {
        assert_eq!(output_end(10, 5), Some(15));
        assert_eq!(output_end(MAX_OFFSET, 0), Some(MAX_OFFSET));
        assert_eq!(output_end(MAX_OFFSET - 64, 64), Some(MAX_OFFSET));
        assert_eq!(output_end(u64::MAX - 5, 0), None);
        assert_eq!(output_end(u64::MAX - 5, 64), None);
        assert_eq!(output_end(MAX_OFFSET, 1), None);
        assert_eq!(output_end(u64::MAX, u64::MAX), None);
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
}
