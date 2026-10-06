//! Stream multiplexing over a byte stream (protocol.md section 8): TLS over TCP and the ssh pipe
//! carry the same bidirectional streams as QUIC, with the same ids, per-stream and connection
//! flow control, half-close and abort.
//!
//! A [`Mux`] owns the byte stream through two tasks: a reader that demultiplexes frames into
//! stream buffers (returning connection credit at once, so one stalled stream never blocks the
//! others), and a writer that sends control frames first and then DATA round-robin, the control
//! stream (0) ahead of the rest. [`MuxSend`] and [`MuxRecv`] are the two halves of a stream and
//! implement tokio's `AsyncWrite` and `AsyncRead`.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

use crate::proto::{varint, ErrorCode};

/// Largest DATA frame payload.
pub const MAX_DATA: usize = 16384;
/// Initial stream credit, per stream and direction.
pub const STREAM_WINDOW: u64 = 262_144;
/// Initial connection credit, per direction.
pub const CONN_WINDOW: u64 = 1_048_576;
/// Open streams per initiator.
pub const MAX_STREAMS: usize = 128;
/// Bytes a stream's writer may queue before `poll_write` waits.
const SEND_QUEUE: usize = 64 * 1024;
/// Connection credit returned in batches of at least this much.
const CONN_CREDIT_BATCH: u64 = 32 * 1024;

const T_DATA: u8 = 0x00;
const T_FIN: u8 = 0x01;
const T_RESET: u8 = 0x02;
const T_WINDOW: u8 = 0x03;
const T_CONN_WINDOW: u8 = 0x04;

/// A mux frame (section 8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Stream data, 1 to [`MAX_DATA`] bytes.
    Data {
        /// Stream id.
        stream: u64,
        /// The bytes.
        data: Vec<u8>,
    },
    /// The sender finished sending on the stream.
    Fin {
        /// Stream id.
        stream: u64,
    },
    /// Both directions of the stream are aborted.
    Reset {
        /// Stream id.
        stream: u64,
        /// Why.
        code: ErrorCode,
    },
    /// More stream credit.
    Window {
        /// Stream id.
        stream: u64,
        /// Additional bytes.
        increment: u64,
    },
    /// More connection credit.
    ConnWindow {
        /// Additional bytes.
        increment: u64,
    },
}

/// A malformed frame: always a connection error with FRAME_ERROR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameError(pub &'static str);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed mux frame: {}", self.0)
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// Append the frame's encoding to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Data { stream, data } => {
                out.push(T_DATA);
                varint::encode(*stream, out);
                varint::encode(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Frame::Fin { stream } => {
                out.push(T_FIN);
                varint::encode(*stream, out);
            }
            Frame::Reset { stream, code } => {
                out.push(T_RESET);
                varint::encode(*stream, out);
                varint::encode(code.0, out);
            }
            Frame::Window { stream, increment } => {
                out.push(T_WINDOW);
                varint::encode(*stream, out);
                varint::encode(*increment, out);
            }
            Frame::ConnWindow { increment } => {
                out.push(T_CONN_WINDOW);
                varint::encode(*increment, out);
            }
        }
    }

    /// Decode one frame from the start of `input`: the frame and the bytes it took, or None
    /// when `input` does not hold a complete frame yet. Never allocates more than
    /// [`MAX_DATA`] bytes.
    pub fn decode(input: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
        let Some(&ty) = input.first() else { return Ok(None) };
        let mut at = 1;
        let next = |at: &mut usize| -> Option<u64> {
            let (v, n) = varint::decode(&input[*at..]).ok()?;
            *at += n;
            Some(v)
        };
        let frame = match ty {
            T_DATA => {
                let Some(stream) = next(&mut at) else { return Ok(None) };
                let Some(len) = next(&mut at) else { return Ok(None) };
                if len == 0 || len > MAX_DATA as u64 {
                    return Err(FrameError("bad DATA length"));
                }
                let Some(data) = input.get(at..at + len as usize) else {
                    return Ok(None);
                };
                at += len as usize;
                Frame::Data {
                    stream,
                    data: data.to_vec(),
                }
            }
            T_FIN => {
                let Some(stream) = next(&mut at) else { return Ok(None) };
                Frame::Fin { stream }
            }
            T_RESET => {
                let Some(stream) = next(&mut at) else { return Ok(None) };
                let Some(code) = next(&mut at) else { return Ok(None) };
                Frame::Reset {
                    stream,
                    code: ErrorCode(code),
                }
            }
            T_WINDOW => {
                let Some(stream) = next(&mut at) else { return Ok(None) };
                let Some(increment) = next(&mut at) else {
                    return Ok(None);
                };
                Frame::Window { stream, increment }
            }
            T_CONN_WINDOW => {
                let Some(increment) = next(&mut at) else {
                    return Ok(None);
                };
                Frame::ConnWindow { increment }
            }
            _ => return Err(FrameError("unknown frame type")),
        };
        Ok(Some((frame, at)))
    }
}

/// Which end of the connection this is: the client opens streams 0, 4, 8, …, the server
/// 1, 5, 9, ….
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The client.
    Client,
    /// The server.
    Server,
}

impl Role {
    fn first_id(self) -> u64 {
        match self {
            Role::Client => 0,
            Role::Server => 1,
        }
    }

    fn owns(self, id: u64) -> bool {
        id & 3 == self.first_id()
    }

    fn peer(self) -> Role {
        match self {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }
}

#[derive(Debug, Default)]
struct StreamState {
    // Receiving
    recv: VecDeque<u8>,
    recv_fin: bool,
    /// Total bytes the peer may send on this stream (credit granted so far).
    recv_allowed: u64,
    /// Total bytes received on this stream.
    recv_total: u64,
    /// Consumed by the application and not yet credited back.
    recv_unreturned: u64,
    reader: Option<Waker>,
    reader_gone: bool,
    // Sending
    send: VecDeque<u8>,
    send_credit: u64,
    fin_queued: bool,
    fin_sent: bool,
    writer: Option<Waker>,
    writer_gone: bool,
    /// Aborted, by us or the peer, with this code.
    reset: Option<ErrorCode>,
}

impl StreamState {
    fn new() -> StreamState {
        StreamState {
            recv_allowed: STREAM_WINDOW,
            send_credit: STREAM_WINDOW,
            ..Default::default()
        }
    }

    fn wake(&mut self) {
        if let Some(w) = self.reader.take() {
            w.wake();
        }
        if let Some(w) = self.writer.take() {
            w.wake();
        }
    }

    /// Closed in the sense of section 8.2: FIN sent and received, or RESET sent or received.
    /// Only frames decide, so both ends agree on which streams count against the limit.
    fn closed(&self) -> bool {
        self.reset.is_some() || (self.fin_sent && self.recv_fin)
    }

    /// Closed, and the application holds neither half: the entry can go.
    fn finished(&self) -> bool {
        self.closed() && self.reader_gone && self.writer_gone
    }
}

#[derive(Debug)]
struct State {
    role: Role,
    streams: HashMap<u64, StreamState>,
    next_local: u64,
    /// The next id the peer must use for a new stream.
    next_remote: u64,
    accept: VecDeque<u64>,
    acceptor: Option<Waker>,
    open_waiters: Vec<Waker>,
    /// Frames to send before any DATA.
    control: VecDeque<Frame>,
    /// Streams with data or a FIN to send.
    ready: BTreeSet<u64>,
    /// Round-robin position among ready streams (other than 0).
    last_sent: u64,
    conn_send_credit: u64,
    conn_recv_allowed: u64,
    conn_recv_total: u64,
    conn_recv_unreturned: u64,
    /// DATA bytes the peer may still send before authentication; None: no limit.
    byte_budget: Option<u64>,
    /// Set when the connection ended: the error every stream operation reports.
    closed: Option<(io::ErrorKind, String)>,
    /// The connection error to send when closing on our own initiative.
    close_code: Option<ErrorCode>,
}

impl State {
    fn open_count(&self, role: Role) -> usize {
        self.streams
            .iter()
            .filter(|(id, s)| role.owns(**id) && !s.closed())
            .count()
    }

    fn fail(&mut self, kind: io::ErrorKind, why: String) {
        if self.closed.is_none() {
            self.closed = Some((kind, why));
        }
        for s in self.streams.values_mut() {
            s.wake();
        }
        if let Some(w) = self.acceptor.take() {
            w.wake();
        }
        for w in self.open_waiters.drain(..) {
            w.wake();
        }
    }

    fn closed_error(&self) -> io::Error {
        match &self.closed {
            Some((kind, why)) => io::Error::new(*kind, why.clone()),
            None => io::Error::new(io::ErrorKind::NotConnected, "connection closed"),
        }
    }

    /// After a stream's state changed: wake those waiting to open one once it closed, and
    /// forget it once nobody holds it either.
    fn cleanup(&mut self, id: u64) {
        let Some(s) = self.streams.get(&id) else { return };
        if s.closed() {
            for w in self.open_waiters.drain(..) {
                w.wake();
            }
        }
        if s.finished() {
            self.streams.remove(&id);
            self.ready.remove(&id);
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    /// Wakes the writer task.
    work: Notify,
    /// Signalled once when the connection ended.
    done: Notify,
    /// The reader task, aborted when the writer closes the transport.
    reader: Mutex<Option<tokio::task::AbortHandle>>,
}

impl Inner {
    fn kick(&self) {
        self.work.notify_one();
    }
}

/// A multiplexed connection over a byte stream.
#[derive(Debug, Clone)]
pub struct Mux {
    inner: Arc<Inner>,
}

/// A connection error detected by the mux layer.
#[derive(Debug)]
struct ConnError(ErrorCode, &'static str);

impl Mux {
    /// Start multiplexing over `reader` and `writer` (spawns two tasks on the current tokio
    /// runtime). They end, and the transport is closed, when the connection ends.
    pub fn new<R, W>(role: Role, reader: R, writer: W) -> Mux
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let inner = Arc::new(Inner {
            state: Mutex::new(State {
                role,
                streams: HashMap::new(),
                next_local: role.first_id(),
                next_remote: role.peer().first_id(),
                accept: VecDeque::new(),
                acceptor: None,
                open_waiters: Vec::new(),
                control: VecDeque::new(),
                ready: BTreeSet::new(),
                last_sent: 0,
                conn_send_credit: CONN_WINDOW,
                conn_recv_allowed: CONN_WINDOW,
                conn_recv_total: 0,
                conn_recv_unreturned: 0,
                byte_budget: None,
                closed: None,
                close_code: None,
            }),
            work: Notify::new(),
            done: Notify::new(),
            reader: Mutex::new(None),
        });
        let read_task = tokio::spawn(read_loop(inner.clone(), reader));
        *inner.reader.lock().unwrap() = Some(read_task.abort_handle());
        tokio::spawn(write_loop(inner.clone(), writer));
        Mux { inner }
    }

    /// Open a new stream. Waits while [`MAX_STREAMS`] of ours are open. Nothing is sent until
    /// the first write (the peer learns of the stream from its first DATA frame).
    pub async fn open(&self) -> io::Result<(u64, MuxSend, MuxRecv)> {
        poll_fn(|cx| {
            let mut st = self.inner.state.lock().unwrap();
            if st.closed.is_some() {
                return Poll::Ready(Err(st.closed_error()));
            }
            let role = st.role;
            if st.open_count(role) >= MAX_STREAMS {
                st.open_waiters.push(cx.waker().clone());
                return Poll::Pending;
            }
            let id = st.next_local;
            st.next_local += 4;
            st.streams.insert(id, StreamState::new());
            Poll::Ready(Ok(id))
        })
        .await
        .map(|id| {
            (
                id,
                MuxSend {
                    inner: self.inner.clone(),
                    id,
                },
                MuxRecv {
                    inner: self.inner.clone(),
                    id,
                },
            )
        })
    }

    /// The next stream the peer opened, or None once the connection ended.
    pub async fn accept(&self) -> Option<(u64, MuxSend, MuxRecv)> {
        poll_fn(|cx| {
            let mut st = self.inner.state.lock().unwrap();
            if let Some(id) = st.accept.pop_front() {
                return Poll::Ready(Some(id));
            }
            if st.closed.is_some() {
                return Poll::Ready(None);
            }
            st.acceptor = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
        .map(|id| {
            (
                id,
                MuxSend {
                    inner: self.inner.clone(),
                    id,
                },
                MuxRecv {
                    inner: self.inner.clone(),
                    id,
                },
            )
        })
    }

    /// Limit the DATA bytes the peer may send from now on (before authentication, section 6.6);
    /// None lifts the limit. Exceeding it closes the connection with LIMIT_EXCEEDED.
    pub fn set_byte_budget(&self, budget: Option<u64>) {
        self.inner.state.lock().unwrap().byte_budget = budget;
    }

    /// Close the connection: queued frames are sent, then the transport is closed. `code` is
    /// for the local error of streams still in use; the peer learns why from an ERROR message
    /// sent before (section 8.6).
    pub fn close(&self, code: ErrorCode) {
        let mut st = self.inner.state.lock().unwrap();
        if st.close_code.is_none() {
            st.close_code = Some(code);
        }
        drop(st);
        self.inner.kick();
    }

    /// True once the connection ended.
    pub fn is_closed(&self) -> bool {
        self.inner.state.lock().unwrap().closed.is_some()
    }

    /// Wait until the connection ended.
    pub async fn closed(&self) {
        loop {
            let notified = self.inner.done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }
}

/// Demultiplex frames from the transport until it ends or breaks a rule.
async fn read_loop<R: AsyncRead + Unpin>(inner: Arc<Inner>, mut reader: R) {
    let mut buf: Vec<u8> = Vec::with_capacity(32 * 1024);
    let mut chunk = vec![0u8; 32 * 1024];
    let result: Result<(), ConnError> = async {
        loop {
            loop {
                let decoded = Frame::decode(&buf).map_err(|e| ConnError(ErrorCode::FRAME_ERROR, e.0))?;
                let Some((frame, used)) = decoded else { break };
                buf.drain(..used);
                charge(&inner, used as u64)?;
                handle_frame(&inner, frame)?;
            }
            let n = match reader.read(&mut chunk).await {
                Ok(0) => {
                    return Err(ConnError(
                        ErrorCode::NO_ERROR,
                        if buf.is_empty() {
                            "connection closed"
                        } else {
                            "connection closed inside a frame"
                        },
                    ))
                }
                Ok(n) => n,
                Err(_) => return Err(ConnError(ErrorCode::INTERNAL_ERROR, "connection lost")),
            };
            buf.extend_from_slice(&chunk[..n]);
        }
    }
    .await;
    let (code, why) = match result {
        Err(ConnError(code, why)) => (code, why),
        Ok(()) => (ErrorCode::NO_ERROR, "connection closed"),
    };
    let mut st = inner.state.lock().unwrap();
    let kind = if code == ErrorCode::NO_ERROR || code == ErrorCode::INTERNAL_ERROR {
        io::ErrorKind::ConnectionReset
    } else {
        io::ErrorKind::InvalidData
    };
    st.fail(kind, format!("{why} ({code})"));
    drop(st);
    inner.kick();
    inner.done.notify_waiters();
}

/// Before authentication every byte of every frame counts against the budget (section 6.6).
fn charge(inner: &Inner, bytes: u64) -> Result<(), ConnError> {
    let mut st = inner.state.lock().unwrap();
    if let Some(budget) = st.byte_budget.as_mut() {
        if *budget < bytes {
            return Err(ConnError(
                ErrorCode::LIMIT_EXCEEDED,
                "too much data before authentication",
            ));
        }
        *budget -= bytes;
    }
    Ok(())
}

fn handle_frame(inner: &Inner, frame: Frame) -> Result<(), ConnError> {
    let mut st = inner.state.lock().unwrap();
    let role = st.role;
    let stream_id = match &frame {
        Frame::Data { stream, .. }
        | Frame::Fin { stream }
        | Frame::Reset { stream, .. }
        | Frame::Window { stream, .. } => Some(*stream),
        Frame::ConnWindow { .. } => None,
    };
    if let Some(id) = stream_id {
        if id & 2 != 0 {
            return Err(ConnError(
                ErrorCode::PROTOCOL_VIOLATION,
                "frame for a unidirectional stream",
            ));
        }
        if role.owns(id) && id >= st.next_local {
            return Err(ConnError(
                ErrorCode::PROTOCOL_VIOLATION,
                "frame for a stream not opened",
            ));
        }
        // Only DATA opens a stream of the peer
        if !role.owns(id) && id >= st.next_remote && !matches!(frame, Frame::Data { .. }) {
            return Err(ConnError(
                ErrorCode::PROTOCOL_VIOLATION,
                "frame for a stream the peer has not opened",
            ));
        }
    }
    match frame {
        Frame::Data { stream: id, data } => {
            let len = data.len() as u64;
            st.conn_recv_total += len;
            if st.conn_recv_total > st.conn_recv_allowed {
                return Err(ConnError(ErrorCode::FLOW_CONTROL_ERROR, "connection credit exceeded"));
            }
            // Connection credit follows the demultiplexer, whatever happens to the data
            st.conn_recv_unreturned += len;
            if st.conn_recv_unreturned >= CONN_CREDIT_BATCH {
                let increment = std::mem::take(&mut st.conn_recv_unreturned);
                st.conn_recv_allowed += increment;
                st.control.push_back(Frame::ConnWindow { increment });
                inner.kick();
            }
            if !role.owns(id) && !st.streams.contains_key(&id) {
                if id < st.next_remote {
                    // A closed stream: ignored
                    return Ok(());
                }
                if id != st.next_remote {
                    return Err(ConnError(ErrorCode::PROTOCOL_VIOLATION, "stream ids out of order"));
                }
                if st.open_count(role.peer()) >= MAX_STREAMS {
                    return Err(ConnError(ErrorCode::STREAM_LIMIT, "too many streams"));
                }
                st.next_remote += 4;
                st.streams.insert(id, StreamState::new());
                st.accept.push_back(id);
                if let Some(w) = st.acceptor.take() {
                    w.wake();
                }
            }
            let Some(s) = st.streams.get_mut(&id) else {
                return Ok(());
            };
            if s.reset.is_some() {
                return Ok(());
            }
            if s.recv_fin {
                return Err(ConnError(ErrorCode::PROTOCOL_VIOLATION, "DATA after FIN"));
            }
            s.recv_total += len;
            if s.recv_total > s.recv_allowed {
                return Err(ConnError(ErrorCode::FLOW_CONTROL_ERROR, "stream credit exceeded"));
            }
            if s.reader_gone {
                // Nobody reads: discard, and give the credit back so the peer is not stuck
                s.recv_allowed += len;
                st.control.push_back(Frame::Window {
                    stream: id,
                    increment: len,
                });
                inner.kick();
            } else {
                s.recv.extend(&data);
                if let Some(w) = s.reader.take() {
                    w.wake();
                }
            }
        }
        Frame::Fin { stream: id } => {
            if let Some(s) = st.streams.get_mut(&id) {
                if s.reset.is_none() {
                    s.recv_fin = true;
                    if let Some(w) = s.reader.take() {
                        w.wake();
                    }
                }
                st.cleanup(id);
            }
        }
        Frame::Reset { stream: id, code } => {
            if let Some(s) = st.streams.get_mut(&id) {
                if s.reset.is_none() {
                    s.reset = Some(code);
                    s.recv.clear();
                    s.send.clear();
                    s.wake();
                }
                st.ready.remove(&id);
                // Keep the entry for the halves to see the reset; they forget it on drop
                st.cleanup(id);
            }
        }
        Frame::Window { stream: id, increment } => {
            if let Some(s) = st.streams.get_mut(&id) {
                if s.reset.is_none() {
                    s.send_credit = s.send_credit.saturating_add(increment);
                    if s.send_credit > varint::MAX {
                        return Err(ConnError(ErrorCode::FLOW_CONTROL_ERROR, "stream credit overflow"));
                    }
                    if !s.send.is_empty() || (s.fin_queued && !s.fin_sent) {
                        st.ready.insert(id);
                        inner.kick();
                    }
                    let s = st.streams.get_mut(&id).expect("present");
                    if let Some(w) = s.writer.take() {
                        w.wake();
                    }
                }
            }
        }
        Frame::ConnWindow { increment } => {
            st.conn_send_credit = st.conn_send_credit.saturating_add(increment);
            if st.conn_send_credit > varint::MAX {
                return Err(ConnError(ErrorCode::FLOW_CONTROL_ERROR, "connection credit overflow"));
            }
            inner.kick();
        }
    }
    Ok(())
}

/// Send control frames first, then DATA round-robin (stream 0 first), until the connection
/// ends; then close the transport.
async fn write_loop<W: AsyncWrite + Unpin>(inner: Arc<Inner>, mut writer: W) {
    let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
    loop {
        let notified = inner.work.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (closing, failed) = {
            let mut st = inner.state.lock().unwrap();
            collect(&mut st, &mut out);
            (st.close_code.is_some(), st.closed.is_some())
        };
        if !out.is_empty() {
            if writer.write_all(&out).await.is_err() || writer.flush().await.is_err() {
                break;
            }
            out.clear();
            continue;
        }
        if closing || failed {
            break;
        }
        notified.await;
    }
    // Over TLS this sends close_notify (section 8.6); a dead peer must not keep it waiting
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer.shutdown()).await;
    if let Some(reader) = inner.reader.lock().unwrap().take() {
        reader.abort();
    }
    let mut st = inner.state.lock().unwrap();
    let why = match st.close_code {
        Some(code) => format!("connection closed ({code})"),
        None => "connection lost".to_string(),
    };
    st.fail(io::ErrorKind::ConnectionAborted, why);
    drop(st);
    inner.done.notify_waiters();
}

/// Move what may be sent now into `out`: control frames, then up to about 64 KiB of DATA.
fn collect(st: &mut State, out: &mut Vec<u8>) {
    while let Some(frame) = st.control.pop_front() {
        frame.encode(out);
    }
    let mut finished = Vec::new();
    while out.len() < 64 * 1024 {
        // Stream 0 first, then round-robin after the last stream served
        let next = if st.ready.contains(&0) {
            Some(0)
        } else {
            st.ready
                .range(st.last_sent + 1..)
                .next()
                .or_else(|| st.ready.iter().next())
                .copied()
        };
        let Some(id) = next else { break };
        let conn_credit = st.conn_send_credit;
        let Some(s) = st.streams.get_mut(&id) else {
            st.ready.remove(&id);
            continue;
        };
        let n = s
            .send
            .len()
            .min(MAX_DATA)
            .min(s.send_credit as usize)
            .min(conn_credit as usize);
        if n > 0 {
            let data: Vec<u8> = s.send.drain(..n).collect();
            s.send_credit -= n as u64;
            Frame::Data { stream: id, data }.encode(out);
            if let Some(w) = s.writer.take() {
                w.wake();
            }
        }
        let fin_now = s.send.is_empty() && s.fin_queued && !s.fin_sent;
        if fin_now {
            s.fin_sent = true;
            Frame::Fin { stream: id }.encode(out);
            finished.push(id);
        }
        // Out of the ready set until a write, a WINDOW or a FIN puts it back
        let idle = s.send.is_empty() || s.send_credit == 0;
        st.conn_send_credit -= n as u64;
        st.last_sent = id;
        if idle {
            st.ready.remove(&id);
        } else if n == 0 {
            // Only the connection credit is missing: CONN_WINDOW wakes the writer again
            break;
        }
    }
    for id in finished {
        st.cleanup(id);
    }
}

/// The sending half of a mux stream. Dropping it without `shutdown` finishes the stream too.
#[derive(Debug)]
pub struct MuxSend {
    inner: Arc<Inner>,
    id: u64,
}

/// The receiving half of a mux stream.
#[derive(Debug)]
pub struct MuxRecv {
    inner: Arc<Inner>,
    id: u64,
}

impl MuxSend {
    /// The stream id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Abort both directions of the stream with `code` (RESET).
    pub fn reset(&self, code: ErrorCode) {
        reset(&self.inner, self.id, code);
    }
}

impl MuxRecv {
    /// The stream id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Abort both directions of the stream with `code` (RESET).
    pub fn reset(&self, code: ErrorCode) {
        reset(&self.inner, self.id, code);
    }
}

fn reset(inner: &Inner, id: u64, code: ErrorCode) {
    let mut st = inner.state.lock().unwrap();
    let Some(s) = st.streams.get_mut(&id) else { return };
    if s.reset.is_some() || (s.fin_sent && s.recv_fin) {
        return;
    }
    s.reset = Some(code);
    s.recv.clear();
    s.send.clear();
    s.wake();
    st.ready.remove(&id);
    st.control.push_back(Frame::Reset { stream: id, code });
    drop(st);
    inner.kick();
}

fn reset_error(code: ErrorCode) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, format!("stream reset ({code})"))
}

impl AsyncRead for MuxRecv {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut st = self.inner.state.lock().unwrap();
        let closed = st.closed.is_some();
        let closed_error = st.closed_error();
        let Some(s) = st.streams.get_mut(&self.id) else {
            // Forgotten after both directions finished: the end of the stream
            return Poll::Ready(Ok(()));
        };
        if let Some(code) = s.reset {
            return Poll::Ready(Err(reset_error(code)));
        }
        if s.recv.is_empty() {
            if s.recv_fin {
                return Poll::Ready(Ok(()));
            }
            if closed {
                return Poll::Ready(Err(closed_error));
            }
            s.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = s.recv.len().min(buf.remaining());
        let (a, b) = s.recv.as_slices();
        let from_a = n.min(a.len());
        buf.put_slice(&a[..from_a]);
        buf.put_slice(&b[..n - from_a]);
        s.recv.drain(..n);
        // Stream credit follows the application: return it once half the window is consumed
        s.recv_unreturned += n as u64;
        if s.recv_unreturned >= STREAM_WINDOW / 2 && !s.recv_fin {
            let increment = std::mem::take(&mut s.recv_unreturned);
            s.recv_allowed += increment;
            st.control.push_back(Frame::Window {
                stream: self.id,
                increment,
            });
            drop(st);
            self.inner.kick();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxSend {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut st = self.inner.state.lock().unwrap();
        if st.closed.is_some() {
            return Poll::Ready(Err(st.closed_error()));
        }
        let Some(s) = st.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed")));
        };
        if let Some(code) = s.reset {
            return Poll::Ready(Err(reset_error(code)));
        }
        if s.fin_queued {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream finished")));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = SEND_QUEUE.saturating_sub(s.send.len());
        if room == 0 {
            s.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        s.send.extend(&data[..n]);
        st.ready.insert(self.id);
        drop(st);
        self.inner.kick();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flushed once the writer task took the bytes; it writes them out promptly
        let mut st = self.inner.state.lock().unwrap();
        if st.closed.is_some() {
            return Poll::Ready(Err(st.closed_error()));
        }
        let Some(s) = st.streams.get_mut(&self.id) else {
            return Poll::Ready(Ok(()));
        };
        if let Some(code) = s.reset {
            return Poll::Ready(Err(reset_error(code)));
        }
        if s.send.is_empty() {
            return Poll::Ready(Ok(()));
        }
        s.writer = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        finish(&self.inner, self.id);
        Poll::Ready(Ok(()))
    }
}

fn finish(inner: &Inner, id: u64) {
    let mut st = inner.state.lock().unwrap();
    let Some(s) = st.streams.get_mut(&id) else { return };
    if s.reset.is_some() || s.fin_queued {
        return;
    }
    s.fin_queued = true;
    st.ready.insert(id);
    drop(st);
    inner.kick();
}

impl Drop for MuxSend {
    fn drop(&mut self) {
        finish(&self.inner, self.id);
        let mut st = self.inner.state.lock().unwrap();
        if let Some(s) = st.streams.get_mut(&self.id) {
            s.writer_gone = true;
        }
        st.cleanup(self.id);
    }
}

impl Drop for MuxRecv {
    fn drop(&mut self) {
        let mut st = self.inner.state.lock().unwrap();
        let id = self.id;
        if let Some(s) = st.streams.get_mut(&id) {
            s.reader_gone = true;
            // Unread data is discarded; its credit goes back so the peer is not stuck
            let unread = s.recv.len() as u64 + s.recv_unreturned;
            s.recv.clear();
            s.recv_unreturned = 0;
            if unread > 0 && !s.recv_fin && s.reset.is_none() {
                s.recv_allowed += unread;
                st.control.push_back(Frame::Window {
                    stream: id,
                    increment: unread,
                });
                drop(st);
                self.inner.kick();
                st = self.inner.state.lock().unwrap();
            }
        }
        st.cleanup(id);
    }
}

#[cfg(test)]
mod tests;
