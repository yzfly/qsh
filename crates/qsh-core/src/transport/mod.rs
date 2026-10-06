//! The three transports (protocol.md section 9) behind one [`Connection`] type, and the race
//! between them (section 12.1).
//!
//! Over QUIC every stream is a native QUIC stream; over TLS and the ssh pipe the mux layer
//! provides the same streams. Code above this module cannot tell the transports apart, except
//! for the channel binding of session proofs, which [`Connection::channel_binding`] computes
//! from the transport the connection actually uses.

pub mod quic;
pub mod ssh;
pub mod tls;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::crypto;
use crate::mux::{Mux, MuxRecv, MuxSend, Role};
use crate::proto::limits::MAX_PREAUTH_BYTES;
use crate::proto::{ErrorCode, EXPORTER_LABEL};

/// Which transport a connection uses. Ordered by preference when racing at equal times:
/// QUIC, TLS, the ssh pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    /// QUIC over UDP.
    Quic,
    /// TLS 1.3 over TCP, with the mux layer.
    Tls,
    /// The ssh pipe, with the mux layer.
    Ssh,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Transport::Quic => "QUIC",
            Transport::Tls => "TLS",
            Transport::Ssh => "ssh",
        })
    }
}

/// A TLS stream shared by the mux layer's reader and writer and by the exporter.
trait TlsIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn export(&self, out: &mut [u8; 32], label: &[u8], context: &[u8]) -> Result<(), rustls::Error>;
}

impl TlsIo for tokio_rustls::client::TlsStream<TcpStream> {
    fn export(&self, out: &mut [u8; 32], label: &[u8], context: &[u8]) -> Result<(), rustls::Error> {
        self.get_ref()
            .1
            .export_keying_material(out, label, Some(context))
            .map(|_| ())
    }
}

impl TlsIo for tokio_rustls::server::TlsStream<TcpStream> {
    fn export(&self, out: &mut [u8; 32], label: &[u8], context: &[u8]) -> Result<(), rustls::Error> {
        self.get_ref()
            .1
            .export_keying_material(out, label, Some(context))
            .map(|_| ())
    }
}

/// One TLS stream, split into halves that lock it for each poll (what `tokio::io::split` does),
/// keeping it reachable for the exporter.
struct SharedTls<T>(Arc<Mutex<T>>);

impl<T> Clone for SharedTls<T> {
    fn clone(&self) -> Self {
        SharedTls(self.0.clone())
    }
}

impl<T: TlsIo> AsyncRead for SharedTls<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, buf)
    }
}

impl<T: TlsIo> AsyncWrite for SharedTls<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_shutdown(cx)
    }
}

type Exporter = Arc<dyn Fn(&[u8]) -> io::Result<[u8; 32]> + Send + Sync>;

enum Streams {
    Quic(quinn::Connection),
    Mux(Mux),
}

/// How session proofs are bound to this connection (section 6.2).
#[derive(Clone)]
enum Binding {
    /// The TLS exporter of the connection.
    Exporter(Exporter),
    /// The ssh pipe: a hash of the server's nonce.
    Pipe,
}

/// The stream bytes an unauthenticated QUIC peer may still send (protocol.md 6.6), shared by
/// the streams of its connection. Over the mux layer the mux counts frame bytes itself.
#[derive(Debug)]
pub struct Budget {
    remaining: Mutex<Option<u64>>,
    connection: quinn::Connection,
}

impl Budget {
    /// Count `n` bytes read; false (and the connection closed) when that is more than allowed.
    fn charge(&self, n: usize) -> bool {
        let mut remaining = self.remaining.lock().unwrap();
        let Some(left) = remaining.as_mut() else {
            return true;
        };
        if n as u64 > *left {
            *left = 0;
            self.connection.close(
                quic_code(ErrorCode::LIMIT_EXCEEDED),
                b"too much data before authentication",
            );
            return false;
        }
        *left -= n as u64;
        true
    }
}

/// A qsh connection over any transport.
pub struct Connection {
    transport: Transport,
    streams: Streams,
    binding: Binding,
    remote: Option<SocketAddr>,
    /// The daemon's pre-authentication budget of a QUIC connection.
    budget: Option<Arc<Budget>>,
    /// Keeps the ssh process of a pipe connection.
    _child: Option<tokio::process::Child>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("transport", &self.transport)
            .field("remote", &self.remote)
            .finish()
    }
}

/// The sending half of a stream.
#[derive(Debug)]
pub enum SendStream {
    /// A QUIC stream.
    Quic(quinn::SendStream),
    /// A mux stream.
    Mux(MuxSend),
}

/// The receiving half of a stream.
#[derive(Debug)]
pub enum RecvStream {
    /// A QUIC stream, and the connection's pre-authentication budget on the daemon.
    Quic(quinn::RecvStream, Option<Arc<Budget>>),
    /// A mux stream.
    Mux(MuxRecv),
}

impl SendStream {
    /// Abort the stream with `code` (QUIC: RESET_STREAM; mux: RESET).
    pub fn reset(&mut self, code: ErrorCode) {
        match self {
            SendStream::Quic(s) => {
                let _ = s.reset(quic_code(code));
            }
            SendStream::Mux(s) => s.reset(code),
        }
    }
}

impl RecvStream {
    /// Abort the stream with `code` (QUIC: STOP_SENDING; mux: RESET).
    pub fn stop(&mut self, code: ErrorCode) {
        match self {
            RecvStream::Quic(s, _) => {
                let _ = s.stop(quic_code(code));
            }
            RecvStream::Mux(s) => s.reset(code),
        }
    }
}

fn quic_code(code: ErrorCode) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.0).unwrap_or(quinn::VarInt::from_u32(ErrorCode::INTERNAL_ERROR.0 as u32))
}

impl AsyncWrite for SendStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            SendStream::Quic(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
            SendStream::Mux(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SendStream::Quic(s) => Pin::new(s).poll_flush(cx),
            SendStream::Mux(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SendStream::Quic(s) => Pin::new(s).poll_shutdown(cx),
            SendStream::Mux(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RecvStream::Quic(s, budget) => {
                let before = buf.filled().len();
                let result = Pin::new(s).poll_read(cx, buf);
                let n = buf.filled().len() - before;
                if let Some(budget) = budget {
                    if n > 0 && !budget.charge(n) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "too much data before authentication",
                        )));
                    }
                }
                result
            }
            RecvStream::Mux(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

/// A stream: its id and both halves.
pub type Stream = (u64, SendStream, RecvStream);

fn exporter_of<T: TlsIo>(tls: SharedTls<T>) -> Exporter {
    Arc::new(move |context: &[u8]| {
        let mut out = [0u8; 32];
        tls.0
            .lock()
            .unwrap()
            .export(&mut out, EXPORTER_LABEL, context)
            .map_err(io::Error::other)?;
        Ok(out)
    })
}

impl Connection {
    /// The daemon's side of a QUIC connection: until [`Connection::set_preauth_limit`] lifts it,
    /// the peer may send at most `MAX_PREAUTH_BYTES` of stream data (section 6.6).
    pub fn quic_server(connection: quinn::Connection) -> Connection {
        let budget = Arc::new(Budget {
            remaining: Mutex::new(Some(MAX_PREAUTH_BYTES)),
            connection: connection.clone(),
        });
        let mut c = Connection::quic(connection);
        c.budget = Some(budget);
        c
    }

    /// A QUIC connection (the client's side, or a daemon without pre-authentication limits).
    pub fn quic(connection: quinn::Connection) -> Connection {
        let remote = Some(connection.remote_address());
        let c = connection.clone();
        let exporter: Exporter = Arc::new(move |context: &[u8]| {
            let mut out = [0u8; 32];
            c.export_keying_material(&mut out, EXPORTER_LABEL, context)
                .map_err(|_| io::Error::other("TLS exporter unavailable"))?;
            Ok(out)
        });
        Connection {
            transport: Transport::Quic,
            streams: Streams::Quic(connection),
            binding: Binding::Exporter(exporter),
            remote,
            budget: None,
            _child: None,
        }
    }

    /// The client's side of a TLS connection.
    pub fn tls_client(tls: tokio_rustls::client::TlsStream<TcpStream>) -> Connection {
        let remote = tls.get_ref().0.peer_addr().ok();
        let shared = SharedTls(Arc::new(Mutex::new(tls)));
        let mux = Mux::new(Role::Client, shared.clone(), shared.clone(), None);
        Connection {
            transport: Transport::Tls,
            streams: Streams::Mux(mux),
            binding: Binding::Exporter(exporter_of(shared)),
            remote,
            budget: None,
            _child: None,
        }
    }

    /// The daemon's side of a TLS connection, with the pre-authentication byte budget from the
    /// first byte (section 6.6).
    pub fn tls_server(tls: tokio_rustls::server::TlsStream<TcpStream>) -> Connection {
        let remote = tls.get_ref().0.peer_addr().ok();
        let shared = SharedTls(Arc::new(Mutex::new(tls)));
        let mux = Mux::new(Role::Server, shared.clone(), shared.clone(), Some(MAX_PREAUTH_BYTES));
        Connection {
            transport: Transport::Tls,
            streams: Streams::Mux(mux),
            binding: Binding::Exporter(exporter_of(shared)),
            remote,
            budget: None,
            _child: None,
        }
    }

    /// An ssh pipe over any byte stream (after the preface), on either side. `child` is the
    /// ssh process on the client side, kept as long as the connection. The daemon's side
    /// starts with the pre-authentication byte budget (section 6.6).
    pub fn pipe<R, W>(
        role: Role,
        reader: R,
        writer: W,
        remote: Option<SocketAddr>,
        child: Option<tokio::process::Child>,
    ) -> Connection
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let budget = (role == Role::Server).then_some(MAX_PREAUTH_BYTES);
        let mux = Mux::new(role, reader, writer, budget);
        Connection {
            transport: Transport::Ssh,
            streams: Streams::Mux(mux),
            binding: Binding::Pipe,
            remote,
            budget: None,
            _child: child,
        }
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Tests: a pipe connection that says it is another transport.
    #[cfg(test)]
    pub(crate) fn pretend(mut self, transport: Transport) -> Connection {
        self.transport = transport;
        self
    }

    /// The peer's address, when known.
    pub fn remote_address(&self) -> Option<SocketAddr> {
        match &self.streams {
            // Changes with connection migration
            Streams::Quic(c) => Some(c.remote_address()),
            Streams::Mux(_) => self.remote,
        }
    }

    /// The round-trip time the transport measured (QUIC only).
    pub fn rtt(&self) -> Option<Duration> {
        match &self.streams {
            Streams::Quic(c) => Some(c.rtt()),
            Streams::Mux(_) => None,
        }
    }

    /// The QUIC connection underneath, if any.
    pub fn quic_connection(&self) -> Option<&quinn::Connection> {
        match &self.streams {
            Streams::Quic(c) => Some(c),
            Streams::Mux(_) => None,
        }
    }

    /// Open a stream (client: 0, 4, 8, …).
    pub async fn open(&self) -> io::Result<Stream> {
        match &self.streams {
            Streams::Quic(c) => {
                let (send, recv) = c.open_bi().await.map_err(io::Error::other)?;
                Ok((
                    stream_id(&send),
                    SendStream::Quic(send),
                    RecvStream::Quic(recv, self.budget.clone()),
                ))
            }
            Streams::Mux(m) => {
                let (id, send, recv) = m.open().await?;
                Ok((id, SendStream::Mux(send), RecvStream::Mux(recv)))
            }
        }
    }

    /// The next stream the peer opened; None when the connection ended.
    pub async fn accept(&self) -> Option<Stream> {
        match &self.streams {
            Streams::Quic(c) => {
                let (send, recv) = c.accept_bi().await.ok()?;
                Some((
                    stream_id(&send),
                    SendStream::Quic(send),
                    RecvStream::Quic(recv, self.budget.clone()),
                ))
            }
            Streams::Mux(m) => {
                let (id, send, recv) = m.accept().await?;
                Some((id, SendStream::Mux(send), RecvStream::Mux(recv)))
            }
        }
    }

    /// The channel binding value CB for `session` (section 6.2): the TLS exporter on QUIC and
    /// TLS, a hash of the server's `nonce` on the ssh pipe.
    pub fn channel_binding(&self, session: &[u8; 16], nonce: &[u8; 32]) -> io::Result<[u8; 32]> {
        match &self.binding {
            Binding::Exporter(export) => export(session),
            Binding::Pipe => Ok(crypto::pipe_binding(nonce, session)),
        }
    }

    /// Before authentication the peer may send at most `bytes` (section 6.6); None lifts the
    /// limit. Over QUIC the connection's receive window stays small until the limit is lifted.
    pub fn set_preauth_limit(&self, bytes: Option<u64>) {
        match &self.streams {
            Streams::Quic(c) => {
                if let Some(budget) = &self.budget {
                    *budget.remaining.lock().unwrap() = bytes;
                }
                if bytes.is_none() {
                    c.set_receive_window(quinn::VarInt::from_u32(8 << 20));
                }
            }
            Streams::Mux(m) => m.set_byte_budget(bytes),
        }
    }

    /// Close the connection with `code` (QUIC: CONNECTION_CLOSE; mux: close the transport).
    pub fn close(&self, code: ErrorCode, reason: &str) {
        match &self.streams {
            Streams::Quic(c) => c.close(quic_code(code), reason.as_bytes()),
            Streams::Mux(m) => m.close(code),
        }
    }

    /// True once the connection ended.
    pub fn is_closed(&self) -> bool {
        match &self.streams {
            Streams::Quic(c) => c.close_reason().is_some(),
            Streams::Mux(m) => m.is_closed(),
        }
    }

    /// Wait until the connection ended.
    pub async fn closed(&self) {
        match &self.streams {
            Streams::Quic(c) => {
                c.closed().await;
            }
            Streams::Mux(m) => m.closed().await,
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Nobody can use it any more: close it rather than leave the transport tasks running
        self.close(ErrorCode::NO_ERROR, "");
    }
}

/// The QUIC stream id, the same number the mux layer would use.
fn stream_id(send: &quinn::SendStream) -> u64 {
    quinn::VarInt::from(send.id()).into_inner()
}

/// Where the daemon is and how to reach it.
#[derive(Debug, Clone)]
pub struct Target {
    /// Host name or address for QUIC and TLS.
    pub host: String,
    /// QUIC port, 0 when the daemon does not listen on UDP.
    pub udp: u16,
    /// TLS port, 0 when the daemon does not listen on TCP.
    pub tcp: u16,
    /// The pinned certificate.
    pub fingerprint: crypto::Fingerprint,
    /// ssh, for the pipe.
    pub ssh: ssh::SshCommand,
    /// Further ports of the daemon, as the bootstrap reply announced them (protocol.md 10.4,
    /// m2.md section 5): raced after the primary port ([`Target::candidates`]).
    pub extra_ports: Vec<crate::proto::bootstrap::ExtraPort>,
}

impl Target {
    /// The ports to try for `transport`, in order (m2.md 5.3, protocol.md 12.1): `remembered`
    /// (the port path memory says worked here) if the daemon announced it, the primary port,
    /// then the extra ports that have this transport in announced order, without duplicates.
    /// Empty when the daemon does not listen on that transport. The ssh pipe has one "port", 0.
    pub fn candidates(&self, transport: Transport, remembered: Option<u16>) -> Vec<u16> {
        let (primary, extra): (u16, Vec<u16>) = match transport {
            Transport::Ssh => return vec![0],
            Transport::Quic => (
                self.udp,
                self.extra_ports.iter().filter(|p| p.udp).map(|p| p.port).collect(),
            ),
            Transport::Tls => (
                self.tcp,
                self.extra_ports.iter().filter(|p| p.tcp).map(|p| p.port).collect(),
            ),
        };
        let announced: Vec<u16> = std::iter::once(primary).chain(extra).filter(|&p| p != 0).collect();
        let mut ports: Vec<u16> = remembered.filter(|p| announced.contains(p)).into_iter().collect();
        for p in announced {
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
        ports
    }
}

/// Which transports to try, and when each starts (section 12.1): the configuration
/// (qsh_config(5) `transports`). Path memory turns it into a [`Plan`] for each race.
#[derive(Debug, Clone)]
pub struct RaceConfig {
    /// Start QUIC after this delay; None: do not use QUIC.
    pub quic: Option<Duration>,
    /// Start TLS after this delay; None: do not use TLS.
    pub tls: Option<Duration>,
    /// Start the ssh pipe after this delay; None: do not use it.
    pub ssh: Option<Duration>,
}

impl Default for RaceConfig {
    fn default() -> Self {
        RaceConfig {
            quic: Some(Duration::ZERO),
            tls: Some(Duration::from_millis(400)),
            ssh: Some(Duration::from_secs(3)),
        }
    }
}

impl RaceConfig {
    /// When `transport` starts; None when it is not used.
    pub fn start(&self, transport: Transport) -> Option<Duration> {
        match transport {
            Transport::Quic => self.quic,
            Transport::Tls => self.tls,
            Transport::Ssh => self.ssh,
        }
    }
}

/// Within one transport, each further port starts this long after the previous one, while
/// the earlier ones keep running (m2.md 5.3).
pub const PORT_STAGGER: Duration = Duration::from_millis(300);

/// At most this many QUIC and TLS attempts in one race: below the server's limit of
/// unauthenticated connections per source address (protocol.md 6.6, 12.1).
pub const MAX_DIRECT_ATTEMPTS: usize = 6;

/// One attempt of a race: a transport, a port (0 for the ssh pipe), and when it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    /// The transport.
    pub transport: Transport,
    /// The port; 0 for the ssh pipe.
    pub port: u16,
    /// When it starts, from the start of the race.
    pub delay: Duration,
}

/// The attempts of one race in the order they start (protocol.md 12.1, m2.md 3.5 and 5.3),
/// and the QUIC settings of the connections it makes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The attempts, sorted by start time (at equal times, in order of preference).
    pub attempts: Vec<Attempt>,
    /// The QUIC settings of the connections (the learned keep-alive, m2.md 4.4).
    pub quic: quic::Options,
}

impl Plan {
    /// The plan of `config` without path memory: each transport at its configured start, its
    /// ports 300 ms apart (m2.md 5.3).
    pub fn new(target: &Target, config: &RaceConfig) -> Plan {
        Plan::build(
            target,
            [Transport::Quic, Transport::Tls, Transport::Ssh].map(|t| (t, config.start(t), None)),
        )
    }

    /// A plan from `(transport, start, remembered port)`, in order of preference for attempts
    /// that start at the same time: each transport's candidate ports
    /// ([`Target::candidates`]) from its start, [`PORT_STAGGER`] apart; transports without a
    /// start or without a port are left out, and so are the direct attempts beyond
    /// [`MAX_DIRECT_ATTEMPTS`] (the latest ones).
    pub fn build(
        target: &Target,
        starts: impl IntoIterator<Item = (Transport, Option<Duration>, Option<u16>)>,
    ) -> Plan {
        let mut attempts = Vec::new();
        for (transport, start, remembered) in starts {
            let Some(start) = start else { continue };
            for (i, port) in target.candidates(transport, remembered).into_iter().enumerate() {
                attempts.push(Attempt {
                    transport,
                    port,
                    delay: start + PORT_STAGGER * i as u32,
                });
            }
        }
        // Stable: at equal times the order of `starts` decides (path memory puts the remembered
        // winner first)
        attempts.sort_by_key(|a| a.delay);
        let mut direct = 0;
        attempts.retain(|a| {
            if a.transport == Transport::Ssh {
                return true;
            }
            direct += 1;
            direct <= MAX_DIRECT_ATTEMPTS
        });
        Plan {
            attempts,
            quic: quic::Options::default(),
        }
    }

    /// When `transport` first starts in this plan; None when it is not part of it.
    pub fn start_of(&self, transport: Transport) -> Option<Duration> {
        self.attempts
            .iter()
            .filter(|a| a.transport == transport)
            .map(|a| a.delay)
            .min()
    }
}

/// How an attempt failed, as far as it says something about the network (m2.md 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// No answer to the handshake within the attempt timeout: UDP or TCP silently dropped.
    Timeout,
    /// A TCP reset or an unexpected end of the stream during the handshake: a middlebox.
    Reset,
    /// The handshake completed but no SERVER_HELLO came within 5 s: deep packet inspection.
    Hello,
    /// Nothing listens on the port (ICMP port unreachable, ECONNREFUSED): a fact about the
    /// daemon, not the network.
    Refused,
    /// The certificate did not match the pin (protocol.md 9.4): never a path fact.
    PinMismatch,
    /// Anything else.
    Other,
}

impl FailureKind {
    /// The kind of a failed transport handshake.
    pub fn of(error: &io::Error) -> FailureKind {
        if error.to_string().contains(crypto::PIN_MISMATCH) {
            return FailureKind::PinMismatch;
        }
        match error.kind() {
            io::ErrorKind::TimedOut => FailureKind::Timeout,
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe => FailureKind::Reset,
            io::ErrorKind::ConnectionRefused => FailureKind::Refused,
            _ => match error.get_ref().and_then(|e| e.downcast_ref::<quinn::ConnectionError>()) {
                Some(quinn::ConnectionError::TimedOut) => FailureKind::Timeout,
                _ => FailureKind::Other,
            },
        }
    }

    /// True for the kinds path memory records as "blocked here" (m2.md 3.3).
    pub fn recorded(self) -> bool {
        matches!(self, FailureKind::Timeout | FailureKind::Reset | FailureKind::Hello)
    }

    /// The name used in path memory and the transcript.
    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::Timeout => "timeout",
            FailureKind::Reset => "reset",
            FailureKind::Hello => "hello",
            FailureKind::Refused => "refused",
            FailureKind::PinMismatch => "pin",
            FailureKind::Other => "error",
        }
    }

    /// The kind named `name` ([`FailureKind::as_str`]).
    pub fn parse(name: &str) -> Option<FailureKind> {
        [
            FailureKind::Timeout,
            FailureKind::Reset,
            FailureKind::Hello,
            FailureKind::Refused,
            FailureKind::PinMismatch,
            FailureKind::Other,
        ]
        .into_iter()
        .find(|k| k.as_str() == name)
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why no transport worked.
#[derive(Debug, Default)]
pub struct RaceError {
    /// The error of each transport tried.
    pub errors: Vec<(Transport, io::Error)>,
}

impl RaceError {
    /// True when a transport reached a server whose certificate did not match the pin.
    pub fn pin_mismatch(&self) -> bool {
        self.errors
            .iter()
            .any(|(_, e)| e.to_string().contains(crypto::PIN_MISMATCH))
    }

    /// True when the ssh pipe found no qsh-server on the host.
    pub fn no_server(&self) -> bool {
        self.errors
            .iter()
            .any(|(t, e)| *t == Transport::Ssh && e.kind() == io::ErrorKind::NotFound)
    }
}

impl fmt::Display for RaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return f.write_str("no transport to try");
        }
        let parts: Vec<String> = self.errors.iter().map(|(t, e)| format!("{t}: {e}")).collect();
        f.write_str(&parts.join("; "))
    }
}

impl std::error::Error for RaceError {}

/// A transport handshake in progress.
pub(crate) type Connecting = Pin<Box<dyn Future<Output = io::Result<Connection>> + Send>>;

/// Makes the connection of one attempt: the real transports ([`Direct`]), or a fake in tests.
pub(crate) trait Connector: Send + Sync {
    /// Start `attempt` to `target`.
    fn connect(&self, target: &Target, attempt: &Attempt, options: &quic::Options) -> Connecting;
}

/// The real transports, with one QUIC endpoint.
pub(crate) struct Direct(pub Arc<quic::QuicClient>);

impl Connector for Direct {
    fn connect(&self, target: &Target, attempt: &Attempt, options: &quic::Options) -> Connecting {
        let (quic, target, attempt, options) = (self.0.clone(), target.clone(), *attempt, *options);
        Box::pin(async move {
            match attempt.transport {
                Transport::Quic => quic
                    .connect_with(&target.host, attempt.port, target.fingerprint, &options)
                    .await
                    .map(Connection::quic),
                Transport::Tls => tls::connect(&target.host, attempt.port, target.fingerprint)
                    .await
                    .map(Connection::tls_client),
                Transport::Ssh => connect_pipe(&target.ssh).await,
            }
        })
    }
}

/// A connection that came out of a race.
#[derive(Debug)]
pub struct Won {
    /// The connection.
    pub connection: Connection,
    /// The attempt that made it.
    pub attempt: Attempt,
    /// How long its handshake took (QUIC, TLS: to the end of the TLS handshake; the pipe: to
    /// its preface).
    pub handshake: Duration,
}

/// What happened next in a race ([`Race::next_event`]).
#[derive(Debug)]
pub enum RaceEvent {
    /// An attempt connected.
    Connected(Box<Won>),
    /// An attempt failed.
    Failed {
        /// The attempt.
        attempt: Attempt,
        /// Why.
        error: io::Error,
    },
}

/// The outcome of one attempt, from its task.
struct Finished {
    attempt: Attempt,
    took: Duration,
    result: io::Result<Connection>,
}

/// The attempts of a [`Plan`], started at their delays (protocol.md 12.1). Established
/// connections come out of [`Race::next`] in the order they completed; the caller tries them
/// one at a time and keeps the first on which the hello succeeds. Dropping the race abandons
/// the attempts still running; [`Race::conclude`] lets them finish to learn their outcome.
pub struct Race {
    rx: tokio::sync::mpsc::UnboundedReceiver<Finished>,
    tasks: Vec<(Transport, tokio::task::JoinHandle<()>)>,
    errors: RaceError,
    /// Set when the race is over: attempts that have not started yet never will.
    over: Arc<std::sync::atomic::AtomicBool>,
    /// The attempts that started, and those whose outcome came out of [`Race::next_event`].
    started: Arc<Mutex<Vec<Attempt>>>,
    finished: Vec<Attempt>,
}

impl fmt::Debug for Race {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Race")
            .field("errors", &self.errors)
            .finish_non_exhaustive()
    }
}

impl Race {
    /// Start the attempts of `plan` to `target`.
    pub fn start(target: &Target, quic: &Arc<quic::QuicClient>, plan: &Plan) -> Race {
        Race::with_connector(target, plan, Arc::new(Direct(quic.clone())))
    }

    /// [`Race::start`] with another way to connect (tests).
    pub(crate) fn with_connector(target: &Target, plan: &Plan, connector: Arc<dyn Connector>) -> Race {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let connected = Arc::new(AtomicBool::new(false));
        let over = Arc::new(AtomicBool::new(false));
        let started = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for attempt in plan.attempts.iter().copied() {
            let (tx, target, connector, connected, over, started) = (
                tx.clone(),
                target.clone(),
                connector.clone(),
                connected.clone(),
                over.clone(),
                started.clone(),
            );
            let options = plan.quic;
            let task = tokio::spawn(async move {
                tokio::time::sleep(attempt.delay).await;
                if over.load(Ordering::SeqCst) {
                    return;
                }
                // The pipe is the last resort: only when nothing else got through by then
                if attempt.transport == Transport::Ssh && connected.load(Ordering::SeqCst) {
                    return;
                }
                let begun = tokio::time::Instant::now();
                started.lock().unwrap().push(attempt);
                let result = connector.connect(&target, &attempt, &options).await;
                if result.is_ok() {
                    connected.store(true, Ordering::SeqCst);
                }
                let _ = tx.send(Finished {
                    attempt,
                    took: begun.elapsed(),
                    result,
                });
            });
            tasks.push((attempt.transport, task));
        }
        Race {
            rx,
            tasks,
            errors: RaceError::default(),
            over,
            started,
            finished: Vec::new(),
        }
    }

    /// The next attempt that connected or failed; None when every attempt has.
    pub async fn next_event(&mut self) -> Option<RaceEvent> {
        let finished = self.rx.recv().await?;
        self.finished.push(finished.attempt);
        Some(match finished.result {
            Ok(connection) => RaceEvent::Connected(Box::new(Won {
                connection,
                attempt: finished.attempt,
                handshake: finished.took,
            })),
            Err(error) => {
                let copy = io::Error::new(error.kind(), error.to_string());
                self.errors.errors.push((finished.attempt.transport, copy));
                RaceEvent::Failed {
                    attempt: finished.attempt,
                    error,
                }
            }
        })
    }

    /// The next established connection, in completion order; None when every attempt has
    /// either been handed out or failed.
    pub async fn next(&mut self) -> Option<Connection> {
        loop {
            if let RaceEvent::Connected(won) = self.next_event().await? {
                return Some(won.connection);
            }
        }
    }

    /// The attempts that started and have not come out of [`Race::next_event`] yet: still
    /// waiting for an answer.
    pub fn running(&self) -> Vec<Attempt> {
        let started = self.started.lock().unwrap();
        let mut finished = self.finished.clone();
        started
            .iter()
            .filter(|a| match finished.iter().position(|f| f == *a) {
                Some(i) => {
                    finished.swap_remove(i);
                    false
                }
                None => true,
            })
            .copied()
            .collect()
    }

    /// Record why a handed-out connection was not usable.
    pub fn failed(&mut self, transport: Transport, error: io::Error) {
        self.errors.errors.push((transport, error));
    }

    /// Why nothing worked so far.
    pub fn errors(&self) -> &RaceError {
        &self.errors
    }

    /// Take the errors, leaving none.
    pub fn take_errors(&mut self) -> RaceError {
        std::mem::take(&mut self.errors)
    }

    /// The race is decided: no attempt starts any more, the ssh pipe attempts are abandoned,
    /// and the QUIC and TLS attempts already running go on in the background (for at most
    /// 30 s), so that their outcome is known (path memory records it, m2.md 3.5). `outcome`
    /// is called for each with the handshake time or the failure; a connection that comes
    /// out late is closed at once. Needs a tokio runtime.
    pub fn conclude(self, mut outcome: impl FnMut(Attempt, Result<Duration, FailureKind>) + Send + 'static) {
        self.conclude_keeping(move |attempt, result| match result {
            Ok((connection, took)) => {
                connection.close(ErrorCode::NO_ERROR, "");
                outcome(attempt, Ok(took));
            }
            Err(kind) => outcome(attempt, Err(kind)),
        });
    }

    /// [`Race::conclude`], handing a connection that comes out late to `outcome` with its
    /// handshake time: it keeps it (a better transport than the winner's answered after all,
    /// m2.md 3.6) or closes it. Needs a tokio runtime.
    pub fn conclude_keeping(
        mut self,
        mut outcome: impl FnMut(Attempt, Result<(Connection, Duration), FailureKind>) + Send + 'static,
    ) {
        self.over.store(true, std::sync::atomic::Ordering::SeqCst);
        let tasks = std::mem::take(&mut self.tasks);
        for (transport, task) in &tasks {
            if *transport == Transport::Ssh {
                task.abort();
            }
        }
        let (_, closed) = tokio::sync::mpsc::unbounded_channel();
        let mut rx = std::mem::replace(&mut self.rx, closed);
        tokio::spawn(async move {
            let drain = async {
                while let Some(finished) = rx.recv().await {
                    match finished.result {
                        Ok(connection) => outcome(finished.attempt, Ok((connection, finished.took))),
                        Err(e) => outcome(finished.attempt, Err(FailureKind::of(&e))),
                    }
                }
            };
            if tokio::time::timeout(Duration::from_secs(30), drain).await.is_err() {
                for (_, task) in tasks {
                    task.abort();
                }
            }
        });
    }
}

impl Drop for Race {
    fn drop(&mut self) {
        for (_, task) in &self.tasks {
            task.abort();
        }
    }
}

/// Start `ssh host qsh-server pipe --version 1` and find the preface (protocol.md 10.5).
pub async fn connect_pipe(ssh: &ssh::SshCommand) -> io::Result<Connection> {
    let (mut child, mut stdout, stdin) = ssh.pipe()?;
    let found = tokio::time::timeout(Duration::from_secs(20), find_preface(&mut stdout)).await;
    match found {
        Ok(Ok(())) => Ok(Connection::pipe(Role::Client, stdout, stdin, None, Some(child))),
        Ok(Err(e)) => {
            let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
                .await
                .ok()
                .and_then(|s| s.ok()?.code());
            match status {
                Some(code) if code == crate::proto::EXIT_NO_SERVER || code == ssh::EXIT_COMMAND_NOT_FOUND => {
                    Err(io::Error::new(io::ErrorKind::NotFound, "no qsh-server on the host"))
                }
                Some(ssh::EXIT_CANNOT_EXECUTE) => Err(io::Error::other("qsh-server on the host cannot be executed")),
                Some(code) => Err(io::Error::other(format!("ssh exited with status {code}"))),
                None => Err(e),
            }
        }
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no pipe preface from the server",
        )),
    }
}

/// Discard everything up to and including the preface; give up when it is not within the
/// first 65 536 bytes. Reads byte by byte: nothing after the preface may be consumed here.
async fn find_preface<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    let preface = crate::proto::PIPE_PREFACE;
    let mut window: Vec<u8> = Vec::with_capacity(preface.len());
    let mut byte = [0u8; 1];
    for _ in 0..65536 + preface.len() {
        if r.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the pipe ended before its preface",
            ));
        }
        if window.len() == preface.len() {
            window.remove(0);
        }
        window.push(byte[0]);
        if window == preface {
            return Ok(());
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "no pipe preface"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preface_after_shell_noise() {
        let mut input: &[u8] = b"Welcome!\nunterminated noise\nQSH-PIPE/1\n\x00\x00";
        find_preface(&mut input).await.unwrap();
        assert_eq!(input, b"\x00\x00");
        let mut input: &[u8] = b"\nQSH-PIPE/2\n";
        assert!(find_preface(&mut input).await.is_err());
        let noise = vec![b'a'; 70000];
        let mut input: &[u8] = &noise;
        assert!(find_preface(&mut input).await.is_err());
    }
}
