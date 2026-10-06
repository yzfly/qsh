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
use crate::proto::{ErrorCode, EXPORTER_LABEL};

/// Which transport a connection uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// A qsh connection over any transport.
pub struct Connection {
    transport: Transport,
    streams: Streams,
    binding: Binding,
    remote: Option<SocketAddr>,
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
    /// A QUIC stream.
    Quic(quinn::RecvStream),
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
            RecvStream::Quic(s) => {
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
            RecvStream::Quic(s) => Pin::new(s).poll_read(cx, buf),
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
    /// A QUIC connection (either side).
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
            _child: None,
        }
    }

    /// The client's side of a TLS connection.
    pub fn tls_client(tls: tokio_rustls::client::TlsStream<TcpStream>) -> Connection {
        let remote = tls.get_ref().0.peer_addr().ok();
        let shared = SharedTls(Arc::new(Mutex::new(tls)));
        let mux = Mux::new(Role::Client, shared.clone(), shared.clone());
        Connection {
            transport: Transport::Tls,
            streams: Streams::Mux(mux),
            binding: Binding::Exporter(exporter_of(shared)),
            remote,
            _child: None,
        }
    }

    /// The daemon's side of a TLS connection.
    pub fn tls_server(tls: tokio_rustls::server::TlsStream<TcpStream>) -> Connection {
        let remote = tls.get_ref().0.peer_addr().ok();
        let shared = SharedTls(Arc::new(Mutex::new(tls)));
        let mux = Mux::new(Role::Server, shared.clone(), shared.clone());
        Connection {
            transport: Transport::Tls,
            streams: Streams::Mux(mux),
            binding: Binding::Exporter(exporter_of(shared)),
            remote,
            _child: None,
        }
    }

    /// An ssh pipe over any byte stream (after the preface), on either side. `child` is the
    /// ssh process on the client side, kept as long as the connection.
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
        let mux = Mux::new(role, reader, writer);
        Connection {
            transport: Transport::Ssh,
            streams: Streams::Mux(mux),
            binding: Binding::Pipe,
            remote,
            _child: child,
        }
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.transport
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
                Ok((stream_id(&send), SendStream::Quic(send), RecvStream::Quic(recv)))
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
                Some((stream_id(&send), SendStream::Quic(send), RecvStream::Quic(recv)))
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
    /// limit. Over QUIC this sets the connection's receive window instead.
    pub fn set_preauth_limit(&self, bytes: Option<u64>) {
        match &self.streams {
            Streams::Quic(c) => {
                let window = bytes.unwrap_or(8 << 20);
                c.set_receive_window(quinn::VarInt::from_u64(window).unwrap_or(quinn::VarInt::MAX));
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
}

/// Which transports to try, and when each starts (section 12.1).
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

/// The transports' handshakes, started with staggered delays (protocol.md 12.1). Established
/// connections come out of [`Race::next`] in the order they completed; the caller tries them
/// one at a time and keeps the first on which the hello and the ATTACH succeed. Dropping the
/// race abandons the attempts still running.
#[derive(Debug)]
pub struct Race {
    rx: tokio::sync::mpsc::Receiver<(Transport, io::Result<Connection>)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    errors: RaceError,
}

impl Race {
    /// Start connecting to `target` over the transports `config` enables.
    pub fn start(target: &Target, quic: &Arc<quic::QuicClient>, config: &RaceConfig) -> Race {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut tasks = Vec::new();
        let plan = [
            (Transport::Quic, config.quic),
            (Transport::Tls, config.tls),
            (Transport::Ssh, config.ssh),
        ];
        for (transport, delay) in plan {
            let Some(delay) = delay else { continue };
            if transport == Transport::Quic && target.udp == 0 || transport == Transport::Tls && target.tcp == 0 {
                continue;
            }
            let (tx, target, quic, connected) = (tx.clone(), target.clone(), quic.clone(), connected.clone());
            tasks.push(tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                // The pipe is the last resort: only when nothing else got through by then
                if transport == Transport::Ssh && connected.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let result = match transport {
                    Transport::Quic => quic
                        .connect(&target.host, target.udp, target.fingerprint)
                        .await
                        .map(Connection::quic),
                    Transport::Tls => tls::connect(&target.host, target.tcp, target.fingerprint)
                        .await
                        .map(Connection::tls_client),
                    Transport::Ssh => connect_pipe(&target.ssh).await,
                };
                if result.is_ok() {
                    connected.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let _ = tx.send((transport, result)).await;
            }));
        }
        Race {
            rx,
            tasks,
            errors: RaceError::default(),
        }
    }

    /// The next established connection, in completion order; None when every transport has
    /// either been handed out or failed.
    pub async fn next(&mut self) -> Option<Connection> {
        loop {
            match self.rx.recv().await? {
                (_, Ok(connection)) => return Some(connection),
                (transport, Err(e)) => self.errors.errors.push((transport, e)),
            }
        }
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
}

impl Drop for Race {
    fn drop(&mut self) {
        for task in &self.tasks {
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
