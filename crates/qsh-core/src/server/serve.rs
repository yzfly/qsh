//! Serving qsh/1 connections on the daemon: the control stream (protocol.md section 5),
//! authentication (section 6) and terminal channels (sections 7 and 7.14), on any transport.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::gate::Ticket;
use super::pty::{Keys, PtySession, SessionId, Stream};
use super::{count, Shared};
use crate::crypto::{self, SessionKey};
use crate::log;
use crate::mux::Role;
use crate::proto::limits::*;
use crate::proto::message::{
    canonical_ip, ATTACH_FRESH, LATEST, MAX_ATTACH, MAX_CONTROL, MAX_HELLO, MAX_TERMINAL, PREFERRED_DATA,
};
use crate::proto::{read_message, ErrorCode, ExitStatus, FramingError, Message, IMPLEMENTATION, VERSION};
use crate::transport::{tls, Connection, RecvStream, SendStream, Transport};

/// Output sent but not acknowledged on one attachment, at most, per output stream (7.6).
const PACING_WINDOW: u64 = 512 * 1024;
/// An authenticated connection that received nothing for this long is gone (clients PING
/// every 15 s).
const SILENT_CONNECTION: Duration = Duration::from_secs(90);
/// How long a hung up session's program has to end before the attachment gets SESSION_ENDED
/// instead of EXIT (7.11).
const HANGUP_WAIT: Duration = Duration::from_secs(2);
/// Output messages sent after a hangup at most; the rest is announced as skipped (7.11).
const HANGUP_MESSAGES: usize = 64;
/// Messages from the client handled in a row before the attachment sends again.
const MESSAGES_PER_TURN: usize = 256;

/// Open connections, for GOAWAY and the close on shutdown.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    next: AtomicU64,
    control: Mutex<HashMap<u64, mpsc::UnboundedSender<Control>>>,
}

impl Registry {
    fn broadcast(&self, command: impl Fn() -> Control) {
        for tx in self.control.lock().unwrap().values() {
            let _ = tx.send(command());
        }
    }
}

/// GOAWAY with `code` on every connection: SHUTDOWN at shutdown, step 4 (7.13), RESTART
/// before an upgrade in place (10.6, m2.md 10.3 step 3). Connections stay open until
/// [`close_all`].
pub(crate) fn goaway_all(shared: &Shared, code: ErrorCode) {
    let message = goaway_text(code);
    shared.connections.broadcast(|| {
        Control::Send(Message::GoAway {
            code,
            message: message.into(),
        })
    });
}

/// Close every connection with `code`, after [`goaway_all`] with the same code (shutdown,
/// step 5; or an upgrade in place).
pub(crate) fn close_all(shared: &Shared, code: ErrorCode) {
    shared.connections.broadcast(|| Control::Shutdown(code));
}

fn goaway_text(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::SHUTDOWN => "the server is stopping",
        ErrorCode::RESTART => "the server is restarting in place",
        _ => "",
    }
}

pub(crate) async fn accept_quic(shared: Arc<Shared>, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        // Section 6.6 and 9.1: counted from here, before any handshake state exists; while
        // more than half the places are taken, every new peer proves its address first
        if shared.gate.crowded() && !incoming.remote_address_validated() {
            if incoming.may_retry() {
                let _ = incoming.retry();
            } else {
                incoming.refuse();
            }
            continue;
        }
        let accepted = Instant::now();
        let ticket = match shared.gate.admit(Some(incoming.remote_address().ip())) {
            Ok(ticket) => ticket,
            Err(_) => {
                incoming.refuse();
                continue;
            }
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let Ok(connecting) = incoming.accept() else { return };
            let Ok(Ok(connection)) = tokio::time::timeout(HELLO_TIMEOUT, connecting).await else {
                return;
            };
            if crate::transport::quic::check_alpn(&connection).is_err() {
                connection.close(quinn::VarInt::from_u32(ErrorCode::PROTOCOL_VIOLATION.0 as u32), b"");
                return;
            }
            count(&shared.stats.quic_connections);
            serve_connection(shared, Connection::quic_server(connection), Some(ticket), accepted).await;
        });
    }
}

pub(crate) async fn accept_tls(shared: Arc<Shared>, listener: TcpListener, acceptor: tls::Acceptor) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            // Out of file descriptors and the like: wait instead of spinning
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let accepted = Instant::now();
        // Refused: closed at once, before any TLS (6.6)
        let Ok(ticket) = shared.gate.admit(Some(peer.ip())) else {
            drop(tcp);
            continue;
        };
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let handshake = tokio::time::timeout(HELLO_TIMEOUT, acceptor.accept(tcp)).await;
            if let Ok(Ok(stream)) = handshake {
                count(&shared.stats.tls_connections);
                serve_connection(shared, Connection::tls_server(stream), Some(ticket), accepted).await;
            }
        });
    }
}

/// The ssh pipe: a connection over the control socket, after `ok`. It counts towards the
/// daemon's unauthenticated connections, but has no network source (6.6).
pub(crate) async fn pipe_connection<R, W>(shared: Arc<Shared>, reader: R, writer: W, client: Option<SocketAddr>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let accepted = Instant::now();
    let Ok(ticket) = shared.gate.admit(None) else {
        return;
    };
    let connection = Connection::pipe(Role::Server, reader, writer, client, None);
    serve_connection(shared, connection, Some(ticket), accepted).await;
}

/// Commands for a connection's control stream writer.
#[derive(Debug)]
enum Control {
    /// Send a message.
    Send(Message),
    /// Send ERROR with the code, then close the connection.
    Close(ErrorCode, String),
    /// Send GOAWAY with the code, then close the connection (IDLE).
    GoAwayClose(ErrorCode),
    /// Close the connection with the code (SHUTDOWN, RESTART), after GOAWAY was sent.
    Shutdown(ErrorCode),
}

/// What the tasks of one connection share.
struct Conn {
    shared: Arc<Shared>,
    connection: Connection,
    control: mpsc::UnboundedSender<Control>,
    nonce: [u8; 32],
    established: Instant,
    /// The connection's place among the unauthenticated ones, until it authenticates.
    ticket: Mutex<Option<Ticket>>,
    authenticated: AtomicBool,
    /// Attachments on this connection right now.
    attachments: AtomicUsize,
    /// Failed ATTACHes (AUTH_FAILED) on this connection.
    failures: AtomicUsize,
    last_rx: Mutex<Instant>,
    /// The peer's address, for the failure limit per source (none for the ssh pipe).
    source: Option<IpAddr>,
}

impl Conn {
    fn close(&self, code: ErrorCode, why: &str) {
        let _ = self.control.send(Control::Close(code, why.to_string()));
    }

    fn received(&self) {
        *self.last_rx.lock().unwrap() = Instant::now();
    }

    fn authenticate(&self) {
        if !self.authenticated.swap(true, Ordering::SeqCst) {
            // Its place goes to others, and the pre-authentication limits are lifted (6.6, 9.1)
            self.ticket.lock().unwrap().take();
            self.connection.set_preauth_limit(None);
        }
    }
}

async fn serve_connection(shared: Arc<Shared>, connection: Connection, ticket: Option<Ticket>, accepted: Instant) {
    let transport = connection.transport();

    // The control stream: stream 0, CLIENT_HELLO first, within HELLO_TIMEOUT of acceptance
    let hello = tokio::time::timeout(HELLO_TIMEOUT.saturating_sub(accepted.elapsed()), async {
        let (id, send, recv) = connection.accept().await.ok_or(ErrorCode::NO_ERROR)?;
        if id != 0 {
            return Err(ErrorCode::PROTOCOL_VIOLATION);
        }
        let mut recv = BufReader::new(recv);
        match read_message(&mut recv, MAX_HELLO).await {
            Ok(Some(Message::ClientHello { versions, .. })) => Ok((send, recv, versions)),
            Ok(None) => Err(ErrorCode::NO_ERROR),
            Ok(Some(_)) => Err(ErrorCode::PROTOCOL_VIOLATION),
            Err(e) => Err(e.code()),
        }
    })
    .await;
    let (mut ctl_send, ctl_recv, versions) = match hello {
        Ok(Ok(h)) => h,
        Ok(Err(code)) => {
            connection.close(code, "");
            return;
        }
        Err(_) => {
            connection.close(ErrorCode::TIMEOUT, "no hello");
            return;
        }
    };
    // Over QUIC and TLS ALPN fixed version 1; over the pipe the highest common one, also 1
    if !versions.contains(&u64::from(VERSION)) {
        let _ = write(
            &mut ctl_send,
            &[Message::Error {
                code: ErrorCode::UNSUPPORTED_VERSION,
                message: "qsh/1 only".into(),
            }],
        )
        .await;
        connection.close(ErrorCode::UNSUPPORTED_VERSION, "");
        return;
    }
    // AUTH_TIMEOUT runs from here (6.6)
    let established = Instant::now();
    let nonce = crypto::random::<32>();
    let remote = connection.remote_address();
    let first = [
        Message::ServerHello {
            version: u64::from(VERSION),
            nonce,
            capabilities: Vec::new(),
            implementation: IMPLEMENTATION.into(),
        },
        path_info(0, remote),
    ];
    if write(&mut ctl_send, &first).await.is_err() {
        return;
    }

    let registry = &shared.connections;
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let key = registry.next.fetch_add(1, Ordering::Relaxed);
    registry.control.lock().unwrap().insert(key, control_tx.clone());
    let conn = Arc::new(Conn {
        shared: shared.clone(),
        connection,
        control: control_tx,
        nonce,
        established,
        ticket: Mutex::new(ticket),
        authenticated: AtomicBool::new(false),
        attachments: AtomicUsize::new(0),
        failures: AtomicUsize::new(0),
        last_rx: Mutex::new(Instant::now()),
        source: (transport != Transport::Ssh).then(|| remote.map(|a| a.ip())).flatten(),
    });
    log::debug(format_args!("{transport} connection from {remote:?}"));

    let writer = tokio::spawn(control_writer(conn.clone(), ctl_send, control_rx));
    let reader = tokio::spawn(control_reader(conn.clone(), ctl_recv));
    let channels = tokio::spawn(accept_channels(conn.clone()));
    let watchdog = tokio::spawn(watchdog(conn.clone(), remote));
    conn.connection.closed().await;
    for task in [reader, channels, watchdog] {
        task.abort();
    }
    writer.abort();
    registry.control.lock().unwrap().remove(&key);
    conn.ticket.lock().unwrap().take();
    log::debug(format_args!("{transport} connection from {remote:?} closed"));
}

fn path_info(sequence: u64, remote: Option<SocketAddr>) -> Message {
    Message::PathInfo {
        sequence,
        address: remote.map(|a| canonical_ip(a.ip())),
        port: remote.map_or(0, |a| a.port()),
    }
}

/// Encode messages and write them in one go.
async fn write<W: AsyncWrite + Unpin>(w: &mut W, messages: &[Message]) -> std::io::Result<()> {
    let mut out = Vec::new();
    for m in messages {
        out.extend(m.encode());
    }
    w.write_all(&out).await?;
    w.flush().await
}

async fn control_writer(conn: Arc<Conn>, mut send: SendStream, mut rx: mpsc::UnboundedReceiver<Control>) {
    while let Some(command) = rx.recv().await {
        let (code, why, last) = match command {
            Control::Send(m) => {
                if write(&mut send, &[m]).await.is_err() {
                    break;
                }
                continue;
            }
            Control::Close(code, why) => (code, why.clone(), Some(Message::Error { code, message: why })),
            Control::GoAwayClose(code) => (
                code,
                String::new(),
                Some(Message::GoAway {
                    code,
                    message: String::new(),
                }),
            ),
            Control::Shutdown(code) => (code, goaway_text(code).to_string(), None),
        };
        if let Some(m) = last {
            let _ = tokio::time::timeout(Duration::from_secs(1), write(&mut send, &[m])).await;
        }
        conn.connection.close(code, &why);
        break;
    }
}

async fn control_reader(conn: Arc<Conn>, mut recv: BufReader<RecvStream>) {
    loop {
        let message = match read_message(&mut recv, MAX_CONTROL).await {
            Ok(Some(m)) => m,
            // The control stream must stay open for the connection's lifetime (4.2)
            Ok(None) => return conn.close(ErrorCode::PROTOCOL_VIOLATION, "control stream finished"),
            Err(FramingError::Io(_)) => return conn.close(ErrorCode::NO_ERROR, ""),
            Err(e) => return conn.close(e.code(), &e.to_string()),
        };
        conn.received();
        if !conn.authenticated.load(Ordering::SeqCst) {
            // Before authentication nothing but CLIENT_HELLO (already read) is accepted (6.6)
            return conn.close(ErrorCode::PROTOCOL_VIOLATION, "message before authentication");
        }
        match message {
            Message::Ping { data } => {
                let _ = conn.control.send(Control::Send(Message::Pong { data }));
            }
            Message::Pong { .. } | Message::GoAway { .. } | Message::Unknown { .. } => {}
            // The client closes the connection after its ERROR
            Message::Error { .. } => return conn.connection.close(ErrorCode::NO_ERROR, ""),
            _ => {
                return conn.close(
                    ErrorCode::PROTOCOL_VIOLATION,
                    "unexpected message on the control stream",
                )
            }
        }
    }
}

async fn accept_channels(conn: Arc<Conn>) {
    let mut preauth_channels = 0;
    while let Some((id, send, recv)) = conn.connection.accept().await {
        if !conn.authenticated.load(Ordering::SeqCst) {
            preauth_channels += 1;
            if preauth_channels > MAX_PREAUTH_CHANNELS {
                return conn.close(ErrorCode::LIMIT_EXCEEDED, "too many streams before authentication");
            }
        }
        count(&conn.shared.stats.channels);
        tokio::spawn(channel(conn.clone(), id, send, recv));
    }
}

/// Deadlines: authentication, idle connections, silent connections; PATH_INFO on migration.
async fn watchdog(conn: Arc<Conn>, mut remote: Option<SocketAddr>) {
    let mut sequence = 0;
    let mut idle_since = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if !conn.authenticated.load(Ordering::SeqCst) {
            if conn.established.elapsed() > AUTH_TIMEOUT {
                return conn.close(ErrorCode::TIMEOUT, "no attach");
            }
            continue;
        }
        if conn.attachments.load(Ordering::SeqCst) > 0 {
            idle_since = Instant::now();
        } else if idle_since.elapsed() > IDLE_CONNECTION {
            let _ = conn.control.send(Control::GoAwayClose(ErrorCode::IDLE));
            return;
        }
        if conn.last_rx.lock().unwrap().elapsed() > SILENT_CONNECTION && conn.connection.transport() != Transport::Quic
        {
            return conn.close(ErrorCode::TIMEOUT, "nothing received");
        }
        let now = conn.connection.remote_address();
        if now != remote {
            remote = now;
            sequence += 1;
            let _ = conn.control.send(Control::Send(path_info(sequence, remote)));
        }
    }
}

/// End a channel with a stream error: ERROR on the stream, then finish it.
async fn stream_error(send: &mut SendStream, code: ErrorCode, why: &str) {
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        write(
            send,
            &[Message::Error {
                code,
                message: why.to_string(),
            }],
        ),
    )
    .await;
    let _ = send.shutdown().await;
}

/// Where an attachment starts.
struct Attachment {
    generation: u64,
    /// Output start offset.
    start: u64,
    /// Error output start offset (pipe sessions).
    error_start: u64,
    /// The input offset the next INPUT must have.
    next_input: u64,
    /// Make the program redraw (LATEST).
    redraw: bool,
}

/// Where a stream starts on a new attachment (7.3 step 1, 7.14.5): `received`, or the end for
/// LATEST; past the end is a SEQUENCE_ERROR. A pipe session never skips: below its `base`
/// starts at `base` for a FRESH client, and is a SEQUENCE_ERROR otherwise.
fn start_offset(session: &PtySession, stream: Stream, received: u64, fresh: bool) -> Result<u64, ErrorCode> {
    let buffer = session.buffer(stream).lock().unwrap();
    let start = if received == LATEST { buffer.end() } else { received };
    if start > buffer.end() {
        return Err(ErrorCode::SEQUENCE_ERROR);
    }
    if session.pipe && start < buffer.base() {
        return if fresh {
            Ok(buffer.base())
        } else {
            Err(ErrorCode::SEQUENCE_ERROR)
        };
    }
    Ok(start)
}

/// One channel stream: ATTACH first, then the terminal channel.
async fn channel(conn: Arc<Conn>, id: u64, mut send: SendStream, recv: RecvStream) {
    let mut recv = BufReader::new(recv);
    let deadline = if conn.authenticated.load(Ordering::SeqCst) {
        HELLO_TIMEOUT
    } else {
        AUTH_TIMEOUT.saturating_sub(conn.established.elapsed())
    };
    let first = match tokio::time::timeout(deadline, read_message(&mut recv, MAX_ATTACH)).await {
        Ok(Ok(Some(m))) => m,
        Ok(Ok(None)) | Err(_) => return,
        Ok(Err(e)) => {
            // The framing is broken: the rest of the stream cannot be parsed (11.1)
            send.reset(e.code());
            recv.get_mut().stop(e.code());
            return;
        }
    };
    conn.received();
    let Message::Attach {
        session: session_id,
        proof,
        output_received,
        size,
        flags,
        error_received,
    } = first
    else {
        if !conn.authenticated.load(Ordering::SeqCst) {
            return conn.close(ErrorCode::PROTOCOL_VIOLATION, "not an attach");
        }
        let code = if matches!(first, Message::Unknown { .. }) {
            ErrorCode::UNKNOWN_CHANNEL
        } else {
            ErrorCode::PROTOCOL_VIOLATION
        };
        return stream_error(&mut send, code, "").await;
    };

    // Sections 6.4, 6.5, 7.3 and 7.14.5, atomic with respect to other attaches of the session
    let shared = conn.shared.clone();
    let session = shared.sessions.get(&SessionId(session_id)).filter(|s| !s.is_removed());
    let fresh = flags & ATTACH_FRESH != 0;
    let attach = session.as_ref().ok_or(ErrorCode::SESSION_UNKNOWN).and_then(|s| {
        let cb = conn
            .connection
            .channel_binding(&session_id, &conn.nonce)
            .map_err(|_| ErrorCode::INTERNAL_ERROR)?;
        let mut keys = s.keys.lock().unwrap();
        let pending_ok = keys.pending.as_ref().is_some_and(|k| k.verify(&cb, &proof));
        let matched = if pending_ok {
            keys.pending.clone().expect("checked")
        } else if keys.current.verify(&cb, &proof) {
            keys.current.clone()
        } else {
            return Err(ErrorCode::AUTH_FAILED);
        };
        // Before the key is rotated: offsets the session cannot serve
        let error_received = match (s.pipe, error_received) {
            (true, None) => return Err(ErrorCode::FRAME_ERROR),
            (_, e) => e.unwrap_or(0),
        };
        let start = start_offset(s, Stream::Output, output_received, fresh)?;
        let error_start = if s.pipe {
            start_offset(s, Stream::Error, error_received, fresh)?
        } else {
            0
        };
        if pending_ok {
            // The client got the pending key last time, though its KEY_CONFIRM was lost
            keys.current = matched.clone();
        }
        let next = SessionKey::generate();
        keys.pending = Some(next.clone());
        // Take the session over: the old attachment stops accepting input before the input
        // `received` value is taken (it checks the generation under the same lock)
        let input = s.input_received.lock().unwrap();
        let generation = s.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let input_received = input.inbound.received();
        drop(input);
        s.changed.notify_waiters();
        let attached = Message::Attached {
            input_received,
            output_start: start,
            next_key: next,
            server_proof: matched.server_proof(&cb),
            error_start: s.pipe.then_some(error_start),
        };
        Ok((
            attached,
            Attachment {
                generation,
                start,
                error_start,
                next_input: input_received,
                redraw: output_received == LATEST,
            },
        ))
    });
    let (attached, attachment) = match attach {
        Ok(a) => a,
        Err(code) => {
            count(&shared.stats.attach_failures);
            // Slow down guessing (6.4); this holds back only this stream
            tokio::time::sleep(FAILURE_DELAY).await;
            if code == ErrorCode::AUTH_FAILED {
                // Only a wrong proof is a failed ATTACH (6.4, 6.6)
                if let Some(source) = conn.source {
                    shared.gate.failed(source);
                }
                let failures = conn.failures.fetch_add(1, Ordering::SeqCst) + 1;
                if failures >= MAX_ATTACH_FAILURES && conn.attachments.load(Ordering::SeqCst) == 0 {
                    return conn.close(ErrorCode::LIMIT_EXCEEDED, "too many failed attaches");
                }
            }
            return stream_error(&mut send, code, "").await;
        }
    };
    let session = session.expect("attached");
    conn.authenticate();
    conn.attachments.fetch_add(1, Ordering::SeqCst);
    let _guard = session.attach_guard();
    log::debug(format_args!(
        "session {} attached over {}",
        &SessionId(session_id).to_hex()[..8],
        conn.connection.transport()
    ));
    let outcome = terminal(&conn, &session, attachment, attached, size, &mut send, recv).await;
    conn.attachments.fetch_sub(1, Ordering::SeqCst);
    match outcome {
        Outcome::Finished => {
            let _ = send.shutdown().await;
        }
        Outcome::Error(code) => stream_error(&mut send, code, "").await,
        Outcome::Remove(error) => {
            if let Some(code) = error {
                stream_error(&mut send, code, "").await;
            } else {
                let _ = send.shutdown().await;
            }
            shared.sessions.remove(&session.id);
        }
    }
    let _ = id;
}

/// How an attachment ended.
enum Outcome {
    /// Finish the stream; the session keeps running.
    Finished,
    /// Fail the stream with ERROR.
    Error(ErrorCode),
    /// The session is over: finish the stream (after ERROR with the code, if any) and remove
    /// the session.
    Remove(Option<ErrorCode>),
}

/// One output stream of an attachment (7.5, 7.6).
struct Out {
    stream: Stream,
    /// `sent_end`: just after the last byte sent or skipped.
    sent: u64,
    /// The highest acknowledgement accepted on this attachment.
    last_ack: u64,
    /// The `To` of the latest OUTPUT_GAP: skipped bytes are not in flight.
    gap_to: u64,
}

impl Out {
    fn new(stream: Stream, start: u64) -> Out {
        Out {
            stream,
            sent: start,
            last_ack: start,
            gap_to: start,
        }
    }

    fn in_flight(&self) -> u64 {
        self.sent - self.last_ack.max(self.gap_to)
    }

    /// An acknowledgement of this stream (7.5): beyond what was sent is a SEQUENCE_ERROR, below
    /// the last one is stale and ignored.
    fn ack(&mut self, session: &PtySession, received: u64) -> Result<(), ErrorCode> {
        if received > self.sent {
            return Err(ErrorCode::SEQUENCE_ERROR);
        }
        if received > self.last_ack {
            self.last_ack = received;
            session.ack(self.stream, received);
        }
        Ok(())
    }

    fn message(&self, offset: u64, data: Vec<u8>) -> Message {
        match self.stream {
            Stream::Output => Message::Output { offset, data },
            Stream::Error => Message::ErrorOutput { offset, data },
        }
    }

    /// Up to `max` bytes of output from where this stream is, as messages: OUTPUT_GAP first if
    /// they fell out of the replay buffer. None when there is nothing to send; otherwise
    /// whether there was a gap.
    fn next(&mut self, session: &PtySession, max: usize, batch: &mut Vec<Message>) -> Option<bool> {
        let (start, bytes) = session.buffer(self.stream).lock().unwrap().read_from(self.sent, max);
        if bytes.is_empty() {
            return None;
        }
        let gap = start > self.sent;
        if gap {
            // The client missed output that fell out of the replay buffer (7.7; tty sessions
            // only, a pipe session never drops unacknowledged output)
            batch.push(Message::OutputGap {
                from: self.sent,
                to: start,
            });
            self.gap_to = start;
        }
        self.sent = start + bytes.len() as u64;
        batch.push(self.message(start, bytes));
        Some(gap)
    }

    fn end(&self, session: &PtySession) -> u64 {
        session.buffer(self.stream).lock().unwrap().end()
    }
}

fn exit_message(session: &PtySession, outs: &[Out], status: ExitStatus) -> Message {
    Message::Exit {
        output_end: outs[0].sent,
        status,
        error_end: session.pipe.then(|| outs[1].sent),
    }
}

/// Input of an attachment that arrived while the session's input queue was full (7.4): not
/// received yet, so not acknowledged, and taken into the queue in order as the program reads.
/// The client bounds it: it never has more than its input replay buffer unacknowledged.
#[derive(Default)]
struct Held {
    bytes: VecDeque<u8>,
    /// INPUT_EOF that arrived behind the held bytes (7.14.4).
    eof: Option<u64>,
}

impl Held {
    /// The offset the next INPUT must start at, `received` being the end of the input received.
    fn end(&self, received: u64) -> u64 {
        received + self.bytes.len() as u64
    }
}

/// Move held input into the session's input queue while it has room, then a held INPUT_EOF;
/// `next_input` follows what was received.
fn accept_held(session: &PtySession, generation: u64, held: &mut Held, next_input: &mut u64) -> Result<(), ErrorCode> {
    while !held.bytes.is_empty() {
        let room = INPUT_QUEUE.saturating_sub(session.input_queued());
        if room == 0 {
            return Ok(());
        }
        let mut input = session.input_received.lock().unwrap();
        // Taken over meanwhile: input not yet received is dropped, the client resends it
        if session.current_generation() != generation {
            return Err(ErrorCode::SESSION_TAKEN_OVER);
        }
        let n = held.bytes.len().min(room).min(PREFERRED_DATA);
        let chunk: Vec<u8> = held.bytes.drain(..n).collect();
        match input.inbound.accept(*next_input, &chunk) {
            crate::session::Accepted::New(bytes) if bytes.len() == n => session.write_input(chunk),
            _ => return Err(ErrorCode::SEQUENCE_ERROR),
        }
        *next_input = input.inbound.received();
    }
    if let Some(offset) = held.eof.take() {
        let mut input = session.input_received.lock().unwrap();
        if session.current_generation() != generation {
            return Err(ErrorCode::SESSION_TAKEN_OVER);
        }
        input.eof = Some(offset);
        session.close_input();
    }
    Ok(())
}

async fn terminal(
    conn: &Conn,
    session: &Arc<PtySession>,
    attachment: Attachment,
    attached: Message,
    size: crate::proto::WindowSize,
    send: &mut SendStream,
    recv: BufReader<RecvStream>,
) -> Outcome {
    let Attachment {
        generation,
        start,
        error_start,
        mut next_input,
        redraw,
    } = attachment;
    if write(send, &[attached]).await.is_err() {
        return Outcome::Finished;
    }
    let pipe = session.pipe;
    if !pipe {
        session.resize(size.cols, size.rows);
    }
    session.ack(Stream::Output, start);
    let mut outs = vec![Out::new(Stream::Output, start)];
    if pipe {
        session.ack(Stream::Error, error_start);
        outs.push(Out::new(Stream::Error, error_start));
    }
    if redraw {
        session.redraw();
    }
    let mut exit_sent = false;
    // Input that does not fit in the input queue now. The stream is read on regardless: ACKs
    // behind the input may be what the program waits for (7.14.5), and RESIZE, DETACH, HANGUP
    // and KEY_CONFIRM must not wait for the program to read its input (7.4)
    let mut held = Held::default();
    // Input received, as the last ACK (or ATTACHED) told the client
    let mut acked_input = next_input;

    // Messages are read by a task so that a partly read message is never lost to select!
    let (tx, mut rx) = mpsc::channel::<Result<Message, FramingError>>(64);
    let reader = tokio::spawn(async move {
        let mut recv = recv;
        loop {
            match read_message(&mut recv, MAX_TERMINAL).await {
                Ok(Some(m)) => {
                    if tx.send(Ok(m)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });
    let _reader = AbortOnDrop(reader);

    loop {
        if session.current_generation() != generation {
            return Outcome::Error(ErrorCode::SESSION_TAKEN_OVER);
        }
        let changed = session.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let drained = session.input_drained.notified();
        tokio::pin!(drained);
        drained.as_mut().enable();
        if session.is_removed() && !exit_sent {
            // Hung up by `qsh kill`, a TTL or the daemon stopping (7.11)
            return ending(session, &mut outs, send).await;
        }
        // Held input the queue has room for now
        if let Err(code) = accept_held(session, generation, &mut held, &mut next_input) {
            return Outcome::Error(code);
        }

        let mut batch = Vec::new();
        // The input received since the last ACK (7.5)
        if next_input != acked_input {
            batch.push(Message::Ack {
                received: next_input,
                error_received: None,
            });
            acked_input = next_input;
        }
        // Output, paced: at most PACING_WINDOW in flight per stream (7.6)
        let mut redraw = false;
        if !exit_sent {
            for out in outs.iter_mut() {
                while out.in_flight() < PACING_WINDOW {
                    let room = (PACING_WINDOW - out.in_flight()) as usize;
                    match out.next(session, room.min(PREFERRED_DATA), &mut batch) {
                        Some(gap) => redraw |= gap,
                        None => break,
                    }
                }
            }
            if let Some(status) = session.exit_status() {
                // EXIT comes after all output (7.10)
                if outs.iter().all(|o| o.sent == o.end(session)) {
                    batch.push(exit_message(session, &outs, status));
                    exit_sent = true;
                }
            }
        }
        if !batch.is_empty() {
            if write(send, &batch).await.is_err() {
                return Outcome::Finished;
            }
            if redraw {
                session.redraw();
            }
            continue;
        }

        let first = tokio::select! {
            m = rx.recv() => m,
            // New output, the exit, a newer attach and removal all notify: no polling
            _ = &mut changed => continue,
            // The program read input: held input may fit now
            _ = &mut drained, if !held.bytes.is_empty() => continue,
        };
        // What is already there (a bounded number, so that output is not held back), then
        // one ACK for the input at the top of the loop (7.5)
        let mut next = first;
        let mut processed = 0;
        loop {
            let message = match next {
                None => {
                    // The stream ended without DETACH or HANGUP: like DETACH. After EXIT and the
                    // final ACK, the session is over.
                    let all_acked = outs.iter().all(|o| o.last_ack == o.end(session));
                    return if exit_sent && all_acked {
                        Outcome::Remove(None)
                    } else {
                        Outcome::Finished
                    };
                }
                Some(Err(e)) => {
                    // A broken frame: the rest of the stream cannot be read
                    send.reset(e.code());
                    return Outcome::Finished;
                }
                Some(Ok(m)) => m,
            };
            conn.received();
            session.touch();
            match message {
                Message::Input { offset, data } => {
                    if data.is_empty() || offset != held.end(next_input) {
                        return Outcome::Error(ErrorCode::SEQUENCE_ERROR);
                    }
                    // INPUT after the input was closed (7.14.4)
                    if held.eof.is_some() || session.input_received.lock().unwrap().eof.is_some() {
                        return Outcome::Error(ErrorCode::SEQUENCE_ERROR);
                    }
                    // More unacknowledged input than any client keeps (7.6)
                    if held.bytes.len() + data.len() > MAX_INPUT_IN_FLIGHT {
                        return Outcome::Error(ErrorCode::FLOW_CONTROL_ERROR);
                    }
                    held.bytes.extend(data);
                    if let Err(code) = accept_held(session, generation, &mut held, &mut next_input) {
                        return Outcome::Error(code);
                    }
                }
                Message::InputEof { offset } => {
                    if !pipe {
                        return Outcome::Error(ErrorCode::PROTOCOL_VIOLATION);
                    }
                    let closed = {
                        let input = session.input_received.lock().unwrap();
                        if session.current_generation() != generation {
                            return Outcome::Error(ErrorCode::SESSION_TAKEN_OVER);
                        }
                        input.eof
                    };
                    match closed.or(held.eof) {
                        // Repeated after a reconnect: ignored
                        Some(at) if at == offset => {}
                        Some(_) => return Outcome::Error(ErrorCode::SEQUENCE_ERROR),
                        None if offset != held.end(next_input) => return Outcome::Error(ErrorCode::SEQUENCE_ERROR),
                        // Closed once the input before it is in the queue
                        None => held.eof = Some(offset),
                    }
                    if let Err(code) = accept_held(session, generation, &mut held, &mut next_input) {
                        return Outcome::Error(code);
                    }
                }
                Message::Ack {
                    received,
                    error_received,
                } => {
                    if let Err(code) = outs[0].ack(session, received) {
                        return Outcome::Error(code);
                    }
                    if pipe {
                        // The appended field is required on a pipe session (7.14.2)
                        let Some(error_received) = error_received else {
                            return Outcome::Error(ErrorCode::FRAME_ERROR);
                        };
                        if let Err(code) = outs[1].ack(session, error_received) {
                            return Outcome::Error(code);
                        }
                    }
                }
                // A pipe session has no terminal: RESIZE is ignored (7.14.5)
                Message::Resize(size) => {
                    if !pipe {
                        session.resize(size.cols, size.rows)
                    }
                }
                Message::KeyConfirm { key_id } => {
                    // Promote the pending key only if this is the key the client confirms,
                    // on the session's current attachment (6.5); anything else is ignored
                    let mut keys = session.keys.lock().unwrap();
                    let current = session.current_generation() == generation;
                    let matches = keys
                        .pending
                        .as_ref()
                        .is_some_and(|pending| crypto::constant_time_eq(&pending.id(), &key_id));
                    if current && matches {
                        let pending = keys.pending.take().expect("checked");
                        *keys = Keys {
                            current: pending,
                            pending: None,
                        };
                    }
                }
                Message::Detach => {
                    // All input before it was processed: acknowledge what was received and
                    // finish (7.11). Input still held was not received: the client keeps it
                    let _ = write(
                        send,
                        &[Message::Ack {
                            received: next_input,
                            error_received: None,
                        }],
                    )
                    .await;
                    return Outcome::Finished;
                }
                Message::Hangup => {
                    session.hang_up();
                    return ending(session, &mut outs, send).await;
                }
                Message::Error { .. } => return Outcome::Finished,
                Message::Unknown { .. } => {}
                _ => return Outcome::Error(ErrorCode::PROTOCOL_VIOLATION),
            }
            processed += 1;
            if processed == MESSAGES_PER_TURN {
                break;
            }
            match rx.try_recv() {
                Ok(m) => next = Some(m),
                Err(_) => break,
            }
        }
    }
}

/// The end of an attachment of a hung up session (7.11, steps 2 and 3): wait up to 2 s for the
/// program to end; then exactly one final message: EXIT after the remaining output, or ERROR
/// (SESSION_ENDED). Remaining output beyond [`HANGUP_MESSAGES`] messages is not sent: on a tty
/// session it is announced with OUTPUT_GAP before EXIT, on a pipe session (which never skips)
/// the attachment ends with SESSION_ENDED instead.
async fn ending(session: &Arc<PtySession>, outs: &mut [Out], send: &mut SendStream) -> Outcome {
    let deadline = tokio::time::Instant::now() + HANGUP_WAIT;
    while session.exit_status().is_none() && tokio::time::Instant::now() < deadline {
        let changed = session.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if session.exit_status().is_some() {
            break;
        }
        let _ = tokio::time::timeout_at(deadline, changed).await;
    }
    let Some(status) = session.exit_status() else {
        return Outcome::Remove(Some(ErrorCode::SESSION_ENDED));
    };
    let mut batch = Vec::new();
    for out in outs.iter_mut() {
        while batch.len() < HANGUP_MESSAGES {
            if out.next(session, PREFERRED_DATA, &mut batch).is_none() {
                break;
            }
        }
    }
    let complete = outs.iter().all(|o| o.sent == o.end(session));
    let mut outcome = Outcome::Remove(None);
    if !complete {
        if session.pipe {
            outcome = Outcome::Remove(Some(ErrorCode::SESSION_ENDED));
        } else {
            let out = &mut outs[0];
            let end = out.end(session);
            batch.push(Message::OutputGap {
                from: out.sent,
                to: end,
            });
            out.sent = end;
        }
    }
    if matches!(outcome, Outcome::Remove(None)) {
        batch.push(exit_message(session, outs, status));
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), write(send, &batch)).await;
    outcome
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
