//! The qsh/1 wire format (docs/protocol.md): varints, messages, the error code registry, the
//! bootstrap JSON, and reading and writing messages on streams.

pub mod bootstrap;
pub mod message;
pub mod varint;
pub mod zstd;

use std::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use message::{DecodeError, ExitStatus, Message, WindowSize};

/// The protocol version this implementation speaks.
pub const VERSION: u32 = 1;

/// The ALPN id of version 1.
pub const ALPN: &[u8] = b"qsh/1";

/// The TLS exporter label of the attach channel binding (section 6.2).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-qsh-attach";

/// The label of the ssh pipe channel binding (section 6.2).
pub const PIPE_BINDING_LABEL: &[u8] = b"qsh/1 pipe attach";

/// The preface `qsh-server pipe --version 1` writes before the mux layer starts (section 10.5).
pub const PIPE_PREFACE: &[u8] = b"\nQSH-PIPE/1\n";

/// The label of the server proof in ATTACHED (section 6.3).
pub const SERVER_PROOF_LABEL: &[u8] = b"qsh/1 attached";

/// Exit status of the discovery command when the host has no qsh-server (section 10.2).
pub const EXIT_NO_SERVER: i32 = 42;

/// Timeouts and limits of section 6.6 and appendix C.
pub mod limits {
    use std::time::Duration;

    /// A complete CLIENT_HELLO must arrive within this time.
    pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
    /// The first ATTACH must be accepted within this time.
    pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
    /// Bytes received on all streams before authentication.
    pub const MAX_PREAUTH_BYTES: u64 = 16384;
    /// Channel streams opened before authentication.
    pub const MAX_PREAUTH_CHANNELS: usize = 4;
    /// Failed ATTACH messages per connection.
    pub const MAX_ATTACH_FAILURES: usize = 3;
    /// The least delay before a failed ATTACH is answered.
    pub const FAILURE_DELAY: Duration = Duration::from_millis(500);
    /// Open streams per initiator, control stream included.
    pub const MAX_STREAMS: u64 = 128;
    /// Largest chunk of resent input after an attach.
    pub const RESEND_CHUNK: usize = 16384;
    /// A client abandons a hello or an ATTACH that gets no answer within this time (12.1).
    pub const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
    /// Input the server queues for a session's terminal before it stops reading the stream.
    pub const INPUT_QUEUE: usize = 1 << 20;
    /// The server closes a connection without attachments after this long (GOAWAY IDLE).
    pub const IDLE_CONNECTION: Duration = Duration::from_secs(60);
    /// Unauthenticated connections per daemon, counted from acceptance (`MAX_PREAUTH_CONNS`).
    pub const MAX_PREAUTH_CONNS: usize = 64;
    /// Unauthenticated connections per IPv4 address or IPv6 /64 (`MAX_PREAUTH_PER_SOURCE`).
    pub const MAX_PREAUTH_PER_SOURCE: usize = 8;
    /// AUTH_FAILED per source address in a burst: a token bucket of 10 …
    pub const FAILURE_BURST: u32 = 10;
    /// … refilled with one token every 6 s (10 per minute).
    pub const FAILURE_REFILL: Duration = Duration::from_secs(6);
    /// A client reconnects this long (± 20 %) after GOAWAY with RESTART, without back-off
    /// (10.6).
    pub const RESTART_RECONNECT: Duration = Duration::from_millis(500);
}

/// Capability names (protocol.md 5.4 and 14.3). An implementation offers a capability only
/// once it implements the sections that define it in full; this version offers none.
pub mod caps {
    /// The server may send OUTPUT_ZSTD and compressed SNAPSHOT data (7.12, 7.8.3).
    pub const ZSTD: &str = "zstd";
    /// The server may send SNAPSHOT to an attachment that asked for it (7.8).
    pub const SNAPSHOT: &str = "snapshot";
    /// Port forwarding channels: reserved (M3), never offered.
    pub const FORWARD: &str = "forward";
    /// File copy channels: reserved (M3), never offered.
    pub const COPY: &str = "copy";
    /// ssh agent forwarding: reserved, never offered.
    pub const AGENT: &str = "agent";
}

/// Implementation name sent in the hellos.
pub const IMPLEMENTATION: &str = concat!("qsh-core/", env!("CARGO_PKG_VERSION"));

/// An error code (protocol.md section 11.2), carried by ERROR, GOAWAY, QUIC
/// CONNECTION_CLOSE / RESET_STREAM and mux RESET / CLOSE.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u64);

macro_rules! error_codes {
    ($($name:ident = $value:expr, $text:expr;)*) => {
        impl ErrorCode {
            $(
                #[doc = $text]
                pub const $name: ErrorCode = ErrorCode($value);
            )*

            /// The registered name, or None for an unknown code.
            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some(stringify!($name)),)*
                    _ => None,
                }
            }
        }
    };
}

error_codes! {
    NO_ERROR = 0x00, "Orderly close.";
    PROTOCOL_VIOLATION = 0x01, "The peer broke a rule of the specification.";
    FRAME_ERROR = 0x02, "A malformed message or mux frame.";
    MESSAGE_TOO_LARGE = 0x03, "A `Length` above the limit of its place.";
    UNSUPPORTED_VERSION = 0x04, "No common protocol version.";
    FLOW_CONTROL_ERROR = 0x05, "Mux credit exceeded.";
    STREAM_LIMIT = 0x06, "Too many streams.";
    TIMEOUT = 0x07, "The hello or authentication deadline was missed.";
    LIMIT_EXCEEDED = 0x08, "A pre-authentication or rate limit was exceeded.";
    INTERNAL_ERROR = 0x09, "The sender failed.";
    SHUTDOWN = 0x0a, "The server is stopping.";
    IDLE = 0x0b, "Closed for lack of use.";
    UNKNOWN_CHANNEL = 0x0c, "The first message of a stream was not understood.";
    CANCELLED = 0x0d, "The sender abandoned the stream.";
    SESSION_UNKNOWN = 0x10, "No such session.";
    AUTH_FAILED = 0x11, "The proof matches no valid key.";
    SESSION_TAKEN_OVER = 0x12, "A newer attachment took the session.";
    SESSION_ENDED = 0x13, "The session was ended.";
    SEQUENCE_ERROR = 0x14, "Offsets or acknowledgements were inconsistent.";
    RESTART = 0x15, "The daemon restarts in place and keeps every session (sent in GOAWAY, 10.6).";
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "ErrorCode({:#x})", self.0),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Why a message could not be read from a stream.
#[derive(Debug)]
pub enum FramingError {
    /// The announced length is above the limit of this place (MESSAGE_TOO_LARGE).
    TooLarge,
    /// The payload is malformed (FRAME_ERROR).
    Malformed(DecodeError),
    /// The stream ended inside a message (FRAME_ERROR).
    Truncated,
    /// The transport failed.
    Io(io::Error),
}

impl FramingError {
    /// The error code to report to the peer.
    pub fn code(&self) -> ErrorCode {
        match self {
            FramingError::TooLarge => ErrorCode::MESSAGE_TOO_LARGE,
            FramingError::Malformed(_) | FramingError::Truncated => ErrorCode::FRAME_ERROR,
            FramingError::Io(_) => ErrorCode::INTERNAL_ERROR,
        }
    }
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FramingError::TooLarge => f.write_str("message too large"),
            FramingError::Malformed(e) => write!(f, "{e}"),
            FramingError::Truncated => f.write_str("stream ended inside a message"),
            FramingError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FramingError {}

impl From<FramingError> for io::Error {
    fn from(e: FramingError) -> io::Error {
        match e {
            FramingError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// Read a varint from a stream. None at a clean end of the stream before its first byte.
async fn read_varint<R: AsyncRead + Unpin>(r: &mut R, first: bool) -> Result<Option<u64>, FramingError> {
    let mut buf = [0u8; 8];
    match r.read(&mut buf[..1]).await {
        Ok(0) if first => return Ok(None),
        Ok(0) => return Err(FramingError::Truncated),
        Ok(_) => {}
        Err(e) => return Err(FramingError::Io(e)),
    }
    let n = varint::len_from_first(buf[0]);
    if n > 1 {
        r.read_exact(&mut buf[1..n]).await.map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => FramingError::Truncated,
            _ => FramingError::Io(e),
        })?;
    }
    Ok(Some(varint::decode(&buf[..n]).map_err(|_| FramingError::Truncated)?.0))
}

/// Read one message whose payload may be at most `max` bytes: the limit is checked before the
/// payload is read or allocated (protocol.md 3.2). None at a clean end of the stream.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Option<Message>, FramingError> {
    let Some(ty) = read_varint(r, true).await? else {
        return Ok(None);
    };
    let len = read_varint(r, false).await?.ok_or(FramingError::Truncated)?;
    if len > max as u64 {
        return Err(FramingError::TooLarge);
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await.map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => FramingError::Truncated,
        _ => FramingError::Io(e),
    })?;
    Message::decode(ty, &payload).map(Some).map_err(FramingError::Malformed)
}

/// Write one message and flush it.
pub async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, message: &Message) -> io::Result<()> {
    w.write_all(&message.encode()).await?;
    w.flush().await
}

#[cfg(test)]
mod tests;
