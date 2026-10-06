//! Serving qsh/1 connections on the daemon: the control stream (protocol.md section 5),
//! authentication (section 6) and terminal channels (section 7), on any transport.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::pty::{Keys, PtySession, SessionId};
use super::{count, Shared};
use crate::crypto::{self, SessionKey};
use crate::log;
use crate::mux::Role;
use crate::proto::limits::*;
use crate::proto::message::{
    canonical_ip, ATTACH_FRESH, LATEST, MAX_ATTACH, MAX_CONTROL, MAX_HELLO, MAX_TERMINAL, PREFERRED_DATA,
};
use crate::proto::{read_message, ErrorCode, FramingError, Message, IMPLEMENTATION, VERSION};
use crate::transport::{tls, Connection, RecvStream, SendStream, Transport};

/// Output sent but not acknowledged on one attachment, at most (section 7.6).
const PACING_WINDOW: u64 = 512 * 1024;
/// Unauthenticated connections the daemon holds at once (section 6.6).
const MAX_UNAUTHENTICATED: usize = 64;
/// An authenticated connection that received nothing for this long is gone (clients PING
/// every 15 s).
const SILENT_CONNECTION: Duration = Duration::from_secs(90);

/// Open connections, for GOAWAY on shutdown, and the count of unauthenticated ones.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    next: AtomicU64,
    control: Mutex<HashMap<u64, mpsc::UnboundedSender<Control>>>,
    unauthenticated: AtomicUsize,
}

/// Tell every connection the daemon stops (GOAWAY SHUTDOWN), then give them a moment.
pub(crate) async fn goaway_all(shared: &Shared) {
    let senders: Vec<_> = shared.connections.control.lock().unwrap().values().cloned().collect();
    for tx in &senders {
        let _ = tx.send(Control::Close(
            ErrorCode::SHUTDOWN,
            "the server is stopping".into(),
            true,
        ));
    }
    if !senders.is_empty() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub(crate) async fn accept_quic(shared: Arc<Shared>, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        if shared.connections.unauthenticated.load(Ordering::SeqCst) >= MAX_UNAUTHENTICATED {
            incoming.refuse();
            continue;
        }
        let shared = shared.clone();
        tokio::spawn(async move {
            let Ok(Ok(connection)) = tokio::time::timeout(HELLO_TIMEOUT, incoming).await else {
                return;
            };
            count(&shared.stats.quic_connections);
            serve_connection(shared, Connection::quic(connection)).await;
        });
    }
}

pub(crate) async fn accept_tls(shared: Arc<Shared>, listener: TcpListener, acceptor: tls::Acceptor) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            // Out of file descriptors and the like: wait instead of spinning
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        if shared.connections.unauthenticated.load(Ordering::SeqCst) >= MAX_UNAUTHENTICATED {
            continue;
        }
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(tcp).await {
                count(&shared.stats.tls_connections);
                serve_connection(shared, Connection::tls_server(stream)).await;
            }
        });
    }
}

/// The ssh pipe: a connection over the control socket, after `ok`.
pub(crate) async fn pipe_connection<R, W>(shared: Arc<Shared>, reader: R, writer: W, client: Option<SocketAddr>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_connection(shared, Connection::pipe(Role::Server, reader, writer, client, None)).await;
}

/// Commands for a connection's control stream writer.
#[derive(Debug)]
enum Control {
    /// Send a message.
    Send(Message),
    /// Send ERROR (or GOAWAY when the flag is set) with the code, then close the connection.
    Close(ErrorCode, String, bool),
}

/// What the tasks of one connection share.
struct Conn {
    shared: Arc<Shared>,
    connection: Connection,
    control: mpsc::UnboundedSender<Control>,
    nonce: [u8; 32],
    established: Instant,
    authenticated: AtomicBool,
    /// Attachments on this connection right now.
    attachments: AtomicUsize,
    failures: AtomicUsize,
    last_rx: Mutex<Instant>,
}

impl Conn {
    fn close(&self, code: ErrorCode, why: &str) {
        let _ = self.control.send(Control::Close(code, why.to_string(), false));
    }

    fn received(&self) {
        *self.last_rx.lock().unwrap() = Instant::now();
    }

    fn authenticate(&self) {
        if !self.authenticated.swap(true, Ordering::SeqCst) {
            self.shared.connections.unauthenticated.fetch_sub(1, Ordering::SeqCst);
            // Lift the pre-authentication limits (section 6.6, 9.1)
            self.connection.set_preauth_limit(None);
        }
    }
}

async fn serve_connection(shared: Arc<Shared>, connection: Connection) {
    let registry = &shared.connections;
    registry.unauthenticated.fetch_add(1, Ordering::SeqCst);
    if connection.transport() != Transport::Quic {
        // Over QUIC the small connection receive window does this (crypto::quic_server)
        connection.set_preauth_limit(Some(MAX_PREAUTH_BYTES));
    }
    let transport = connection.transport();

    // The control stream: stream 0, CLIENT_HELLO first
    let hello = tokio::time::timeout(HELLO_TIMEOUT, async {
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
            registry.unauthenticated.fetch_sub(1, Ordering::SeqCst);
            connection.close(code, "");
            return;
        }
        Err(_) => {
            registry.unauthenticated.fetch_sub(1, Ordering::SeqCst);
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
        registry.unauthenticated.fetch_sub(1, Ordering::SeqCst);
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
        registry.unauthenticated.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let key = registry.next.fetch_add(1, Ordering::Relaxed);
    registry.control.lock().unwrap().insert(key, control_tx.clone());
    let conn = Arc::new(Conn {
        shared: shared.clone(),
        connection,
        control: control_tx,
        nonce,
        established,
        authenticated: AtomicBool::new(false),
        attachments: AtomicUsize::new(0),
        failures: AtomicUsize::new(0),
        last_rx: Mutex::new(Instant::now()),
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
    if !conn.authenticated.load(Ordering::SeqCst) {
        registry.unauthenticated.fetch_sub(1, Ordering::SeqCst);
    }
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
        match command {
            Control::Send(m) => {
                if write(&mut send, &[m]).await.is_err() {
                    break;
                }
            }
            Control::Close(code, why, goaway) => {
                let m = if goaway {
                    Message::GoAway {
                        code,
                        message: why.clone(),
                    }
                } else {
                    Message::Error {
                        code,
                        message: why.clone(),
                    }
                };
                let _ = tokio::time::timeout(Duration::from_secs(1), write(&mut send, &[m])).await;
                conn.connection.close(code, &why);
                break;
            }
        }
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
            let _ = conn.control.send(Control::Close(ErrorCode::IDLE, String::new(), true));
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

    // Sections 6.4, 6.5 and 7.3, atomic with respect to other attaches of the session
    let shared = conn.shared.clone();
    let session = shared.sessions.get(&SessionId(session_id)).filter(|s| !s.is_removed());
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
        let end = s.output.lock().unwrap().end();
        let start = if output_received == LATEST && flags & ATTACH_FRESH != 0 {
            end
        } else {
            output_received
        };
        if start > end {
            return Err(ErrorCode::SEQUENCE_ERROR);
        }
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
        let input_received = input.received();
        drop(input);
        s.changed.notify_waiters();
        let attached = Message::Attached {
            input_received,
            output_start: start,
            next_key: next.0,
            server_proof: matched.server_proof(&cb),
        };
        Ok((attached, generation, start, input_received))
    });
    let (attached, generation, start, input_received) = match attach {
        Ok(a) => a,
        Err(code) => {
            count(&shared.stats.attach_failures);
            let failures = conn.failures.fetch_add(1, Ordering::SeqCst) + 1;
            // Slow down guessing (6.4)
            tokio::time::sleep(FAILURE_DELAY).await;
            if failures >= MAX_ATTACH_FAILURES {
                return conn.close(ErrorCode::LIMIT_EXCEEDED, "too many failed attaches");
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
    let redraw = output_received == LATEST;
    let attachment = Attachment {
        generation,
        start,
        next_input: input_received,
        redraw,
    };
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

/// Where an attachment starts.
struct Attachment {
    generation: u64,
    /// Output start offset.
    start: u64,
    /// The input offset the next INPUT must have.
    next_input: u64,
    /// Make the program redraw (LATEST).
    redraw: bool,
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
        mut next_input,
        redraw,
    } = attachment;
    if write(send, &[attached]).await.is_err() {
        return Outcome::Finished;
    }
    session.resize(size.cols, size.rows);
    session.output.lock().unwrap().ack(start);
    if redraw {
        session.redraw();
    }
    let mut sent = start;
    let mut client_acked = start;
    let mut exit_sent = false;
    let mut confirmed = false;

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
        if session.is_removed() && session.exit_status().is_none() {
            return Outcome::Error(ErrorCode::SESSION_ENDED);
        }

        // Output, paced: at most PACING_WINDOW unacknowledged on the way (7.6)
        let mut batch = Vec::new();
        let mut redraw = false;
        while !exit_sent && sent - client_acked < PACING_WINDOW {
            let room = (PACING_WINDOW - (sent - client_acked)) as usize;
            let (start, bytes) = session.output.lock().unwrap().read_from(sent, room.min(PREFERRED_DATA));
            if bytes.is_empty() {
                break;
            }
            if start > sent {
                // The client missed output that fell out of the replay buffer (7.7)
                batch.push(Message::OutputGap { from: sent, to: start });
                client_acked = client_acked.max(start);
                redraw = true;
            }
            sent = start + bytes.len() as u64;
            batch.push(Message::Output {
                offset: start,
                data: bytes,
            });
        }
        if !exit_sent {
            if let Some(status) = session.exit_status() {
                let end = session.output.lock().unwrap().end();
                if sent == end {
                    batch.push(Message::Exit {
                        output_end: end,
                        status,
                    });
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
        };
        // Everything that is already there, then one ACK for the input (7.5)
        let mut next = first;
        let mut input_arrived = false;
        loop {
            let message = match next {
                None => {
                    // The stream ended without DETACH or HANGUP: like DETACH. After EXIT and the
                    // final ACK, the session is over.
                    let end = session.output.lock().unwrap().end();
                    return if exit_sent && client_acked == end {
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
                    if data.is_empty() || offset != next_input {
                        return Outcome::Error(ErrorCode::SEQUENCE_ERROR);
                    }
                    // The queue is full: stop reading the stream until the program reads (7.4)
                    while session.input_queued() >= INPUT_QUEUE {
                        if session.current_generation() != generation || session.is_removed() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    let mut inbound = session.input_received.lock().unwrap();
                    // Taken over meanwhile: input not yet accepted is dropped, the client resends
                    if session.current_generation() != generation {
                        return Outcome::Error(ErrorCode::SESSION_TAKEN_OVER);
                    }
                    match inbound.accept(offset, &data) {
                        crate::session::Accepted::New(bytes) => session.write_input(bytes.to_vec()),
                        _ => return Outcome::Error(ErrorCode::SEQUENCE_ERROR),
                    }
                    next_input = inbound.received();
                    input_arrived = true;
                }
                Message::Ack { received } => {
                    if received < client_acked || received > sent {
                        return Outcome::Error(ErrorCode::SEQUENCE_ERROR);
                    }
                    client_acked = received;
                    session.output.lock().unwrap().ack(received);
                }
                Message::Resize(size) => session.resize(size.cols, size.rows),
                Message::KeyConfirm => {
                    if !confirmed {
                        confirmed = true;
                        let mut keys = session.keys.lock().unwrap();
                        if let Some(pending) = keys.pending.take() {
                            *keys = Keys {
                                current: pending,
                                pending: None,
                            };
                        }
                    }
                }
                Message::Detach => {
                    // All input before it was processed: acknowledge it and finish (7.11)
                    let _ = write(send, &[Message::Ack { received: next_input }]).await;
                    return Outcome::Finished;
                }
                Message::Hangup => {
                    session.hang_up();
                    return hang_up(session, sent, send).await;
                }
                Message::Error { .. } => return Outcome::Finished,
                Message::Unknown { .. } => {}
                _ => return Outcome::Error(ErrorCode::PROTOCOL_VIOLATION),
            }
            match rx.try_recv() {
                Ok(m) => next = Some(m),
                Err(_) => break,
            }
        }
        if input_arrived && write(send, &[Message::Ack { received: next_input }]).await.is_err() {
            return Outcome::Finished;
        }
    }
}

/// After HANGUP: send the remaining output and EXIT if the program ends within 2 s, then
/// remove the session (7.11).
async fn hang_up(session: &Arc<PtySession>, mut sent: u64, send: &mut SendStream) -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(2);
    while session.exit_status().is_none() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Not ended within 2 s: SESSION_ENDED without an exit status (7.11)
    let Some(status) = session.exit_status() else {
        return Outcome::Remove(Some(ErrorCode::SESSION_ENDED));
    };
    let mut batch = Vec::new();
    loop {
        let (start, bytes) = session.output.lock().unwrap().read_from(sent, PREFERRED_DATA);
        if bytes.is_empty() {
            break;
        }
        if start > sent {
            batch.push(Message::OutputGap { from: sent, to: start });
        }
        sent = start + bytes.len() as u64;
        batch.push(Message::Output {
            offset: start,
            data: bytes,
        });
        if batch.len() > 64 {
            // A lot of output is not worth waiting for after a hangup
            break;
        }
    }
    if session.output.lock().unwrap().end() == sent {
        batch.push(Message::Exit {
            output_end: sent,
            status,
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), write(send, &batch)).await;
    Outcome::Remove(None)
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
