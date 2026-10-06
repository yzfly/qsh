//! qsh/1 messages: `Type (varint) | Length (varint) | Payload` (protocol.md section 3), their
//! payload layouts (sections 5 to 7), encoding and decoding.
//!
//! Decoding never panics and never allocates more than the payload it is given; every malformed
//! payload is an error that maps to FRAME_ERROR. Bytes after the known fields are ignored
//! (section 3.3), except in messages whose last field is `data…`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::varint;
use super::ErrorCode;
use crate::crypto::SessionKey;

/// Message type numbers (protocol.md section 3.5).
pub mod types {
    /// CLIENT_HELLO
    pub const CLIENT_HELLO: u64 = 0x01;
    /// SERVER_HELLO
    pub const SERVER_HELLO: u64 = 0x02;
    /// PING
    pub const PING: u64 = 0x03;
    /// PONG
    pub const PONG: u64 = 0x04;
    /// PATH_INFO
    pub const PATH_INFO: u64 = 0x05;
    /// GOAWAY
    pub const GOAWAY: u64 = 0x06;
    /// ERROR
    pub const ERROR: u64 = 0x07;
    /// ATTACH
    pub const ATTACH: u64 = 0x10;
    /// ATTACHED
    pub const ATTACHED: u64 = 0x11;
    /// KEY_CONFIRM
    pub const KEY_CONFIRM: u64 = 0x12;
    /// INPUT
    pub const INPUT: u64 = 0x13;
    /// OUTPUT
    pub const OUTPUT: u64 = 0x14;
    /// ACK
    pub const ACK: u64 = 0x15;
    /// OUTPUT_GAP
    pub const OUTPUT_GAP: u64 = 0x16;
    /// RESIZE
    pub const RESIZE: u64 = 0x17;
    /// SNAPSHOT
    pub const SNAPSHOT: u64 = 0x18;
    /// EXIT
    pub const EXIT: u64 = 0x19;
    /// DETACH
    pub const DETACH: u64 = 0x1a;
    /// HANGUP
    pub const HANGUP: u64 = 0x1b;
    /// OUTPUT_ZSTD
    pub const OUTPUT_ZSTD: u64 = 0x1c;
    /// INPUT_EOF (pipe sessions)
    pub const INPUT_EOF: u64 = 0x1d;
    /// ERROR_OUTPUT (pipe sessions)
    pub const ERROR_OUTPUT: u64 = 0x1e;
}

/// Maximum payload of the first control message (CLIENT_HELLO / SERVER_HELLO).
pub const MAX_HELLO: usize = 2048;
/// Maximum payload of later control stream messages.
pub const MAX_CONTROL: usize = 4096;
/// Maximum payload of the first message of a channel stream (ATTACH).
pub const MAX_ATTACH: usize = 256;
/// Maximum payload of later terminal channel messages.
pub const MAX_TERMINAL: usize = 65536;
/// Data per INPUT / OUTPUT message senders should not exceed.
pub const PREFERRED_DATA: usize = 16384;

/// Maximum versions in CLIENT_HELLO.
pub const MAX_VERSIONS: u64 = 16;
/// Maximum capabilities in a hello.
pub const MAX_CAPABILITIES: u64 = 32;
/// Maximum length of a capability name.
pub const MAX_CAPABILITY_LEN: usize = 32;
/// Maximum length of an implementation name.
pub const MAX_IMPLEMENTATION_LEN: usize = 64;
/// Maximum length of an ERROR or GOAWAY message text.
pub const MAX_MESSAGE_LEN: usize = 256;
/// Maximum length of a signal name in EXIT.
pub const MAX_SIGNAL_LEN: usize = 32;

/// ATTACH flag: the client accepts SNAPSHOT.
pub const ATTACH_ACCEPT_SNAPSHOT: u64 = 0x1;
/// ATTACH flag: the client has no stream state for the session.
pub const ATTACH_FRESH: u64 = 0x2;
/// `Output Received` of a FRESH ATTACH that starts at the current end of the output.
pub const LATEST: u64 = u64::MAX;
/// SNAPSHOT flag: the last part of a snapshot (7.8.3).
pub const SNAPSHOT_FINAL: u8 = 0x1;
/// SNAPSHOT flag: `Data` is one zstd frame, subject to the rules of OUTPUT_ZSTD (7.8.3, 7.12;
/// only when `zstd` was negotiated).
pub const SNAPSHOT_ZSTD: u8 = 0x2;
/// The most snapshot data of one snapshot (all its messages), after decompression
/// (`MAX_SNAPSHOT`, 7.8.3).
pub const MAX_SNAPSHOT: usize = 1 << 20;
/// EXIT flag: the program dumped core.
pub const EXIT_CORE_DUMPED: u8 = 0x1;

/// How a session's program ended (EXIT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    /// It exited with a status, 0 to 255.
    Exited(u32),
    /// It was killed by a signal, named without "SIG" (e.g. "TERM").
    Signaled {
        /// The signal name.
        signal: String,
        /// It dumped core.
        core_dumped: bool,
    },
}

/// A terminal size (ATTACH, RESIZE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowSize {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// Width in pixels, 0 when unknown.
    pub width_px: u16,
    /// Height in pixels, 0 when unknown.
    pub height_px: u16,
}

impl WindowSize {
    /// A size in characters, pixels unknown.
    pub fn new(cols: u16, rows: u16) -> WindowSize {
        WindowSize {
            cols,
            rows,
            width_px: 0,
            height_px: 0,
        }
    }
}

/// A qsh/1 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// 5.2
    ClientHello {
        /// Supported versions, most preferred first (1 to 16).
        versions: Vec<u64>,
        /// Supported capabilities.
        capabilities: Vec<String>,
        /// Informative, e.g. "qsh-core/0.1.0".
        implementation: String,
    },
    /// 5.3
    ServerHello {
        /// The selected version.
        version: u64,
        /// A fresh random value for this connection (ssh pipe channel binding).
        nonce: [u8; 32],
        /// The negotiated capabilities.
        capabilities: Vec<String>,
        /// Informative.
        implementation: String,
    },
    /// 5.5
    Ping {
        /// Opaque; a monotonic timestamp in microseconds by convention.
        data: u64,
    },
    /// 5.5
    Pong {
        /// Copied from the PING.
        data: u64,
    },
    /// 5.6: the client's address as the server sees it.
    PathInfo {
        /// 0 for the first of a connection, then +1 per change.
        sequence: u64,
        /// None when unknown.
        address: Option<IpAddr>,
        /// 0 when unknown.
        port: u16,
    },
    /// 5.7
    GoAway {
        /// Why.
        code: ErrorCode,
        /// For people.
        message: String,
    },
    /// 5.8
    Error {
        /// What went wrong.
        code: ErrorCode,
        /// For people, never secrets.
        message: String,
    },
    /// 7.2
    Attach {
        /// The session id.
        session: [u8; 16],
        /// HMAC-SHA256(session key, channel binding).
        proof: [u8; 32],
        /// The client's output `received`, or [`LATEST`] with [`ATTACH_FRESH`].
        output_received: u64,
        /// The terminal size.
        size: WindowSize,
        /// [`ATTACH_ACCEPT_SNAPSHOT`], [`ATTACH_FRESH`]; undefined bits are ignored.
        flags: u64,
        /// Pipe sessions (7.14.2): the client's `received` for stderr, or [`LATEST`] with
        /// [`ATTACH_FRESH`]. None when the payload ends after `flags` (a tty session).
        error_received: Option<u64>,
    },
    /// 7.3
    Attached {
        /// The server's input `received`.
        input_received: u64,
        /// The offset at which output on this attachment starts.
        output_start: u64,
        /// The rotated session key (its `Debug` output does not show it).
        next_key: SessionKey,
        /// HMAC-SHA256(session key, "qsh/1 attached" || CB).
        server_proof: [u8; 32],
        /// Pipe sessions (7.14.2): the offset at which stderr on this attachment starts.
        error_start: Option<u64>,
    },
    /// 6.5
    KeyConfirm {
        /// The first 8 bytes of SHA-256(Next Key): which key is confirmed.
        key_id: [u8; 8],
    },
    /// 7.4
    Input {
        /// Offset of the first byte in the input stream.
        offset: u64,
        /// The bytes.
        data: Vec<u8>,
    },
    /// 7.4
    Output {
        /// Offset of the first byte in the output stream.
        offset: u64,
        /// The bytes.
        data: Vec<u8>,
    },
    /// 7.5
    Ack {
        /// First offset not yet received.
        received: u64,
        /// Pipe sessions, client to server (7.14.2): the same for stderr.
        error_received: Option<u64>,
    },
    /// 7.7
    OutputGap {
        /// The offset that should have come.
        from: u64,
        /// Where output continues.
        to: u64,
    },
    /// 7.9
    Resize(WindowSize),
    /// 7.8 (capability `snapshot`)
    Snapshot {
        /// The output offset the screen corresponds to.
        offset: u64,
        /// [`SNAPSHOT_FINAL`], [`SNAPSHOT_ZSTD`]; undefined bits are ignored.
        flags: u8,
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
        /// Terminal bytes that redraw the screen (7.8.4), or one zstd frame of them with
        /// [`SNAPSHOT_ZSTD`] (check it with [`super::zstd::check_frame`]).
        data: Vec<u8>,
    },
    /// 7.10
    Exit {
        /// Total length of the output stream.
        output_end: u64,
        /// How the program ended.
        status: ExitStatus,
        /// Pipe sessions (7.14.2): total length of the stderr stream.
        error_end: Option<u64>,
    },
    /// 7.11
    Detach,
    /// 7.11
    Hangup,
    /// 7.14.4: the program's stdin ends at `offset` (pipe sessions).
    InputEof {
        /// The input end: the offset just after the last byte of input.
        offset: u64,
    },
    /// 7.14.3: the program's stderr (pipe sessions).
    ErrorOutput {
        /// Offset of the first byte in the error output stream.
        offset: u64,
        /// The bytes.
        data: Vec<u8>,
    },
    /// 7.12 (capability `zstd`)
    OutputZstd {
        /// Offset of the first decompressed byte.
        offset: u64,
        /// One zstd frame (check it with [`super::zstd::check_frame`] before decompressing).
        frame: Vec<u8>,
    },
    /// A type this implementation does not know: skipped on extensible channels (3.4).
    Unknown {
        /// The type number.
        ty: u64,
    },
}

/// Why a payload could not be decoded: always a FRAME_ERROR, with a reason for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed message: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

/// Reads fields from a payload.
struct Fields<'a> {
    p: &'a [u8],
}

impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.p.len() < n {
            return Err(DecodeError("payload too short"));
        }
        let (head, tail) = self.p.split_at(n);
        self.p = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let (v, n) = varint::decode(self.p).map_err(|_| DecodeError("varint cut off"))?;
        self.p = &self.p[n..];
        Ok(v)
    }

    fn bytes_of_string(&mut self, max: usize) -> Result<&'a [u8], DecodeError> {
        let len = self.varint()?;
        if len > max as u64 {
            return Err(DecodeError("string too long"));
        }
        self.take(len as usize)
    }

    /// A string shown to people: invalid UTF-8 is replaced (section 2.3). A replacement
    /// character takes three bytes, so the result is cut to `max` bytes at a character
    /// boundary, as [`put_string`] would cut it: what decodes encodes back to the same message.
    fn text(&mut self, max: usize) -> Result<String, DecodeError> {
        let mut text = String::from_utf8_lossy(self.bytes_of_string(max)?).into_owned();
        if text.len() > max {
            let mut end = max;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        Ok(text)
    }

    /// A string that must be valid UTF-8.
    fn strict(&mut self, max: usize) -> Result<String, DecodeError> {
        let bytes = self.bytes_of_string(max)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| DecodeError("invalid UTF-8"))
    }

    fn capabilities(&mut self) -> Result<Vec<String>, DecodeError> {
        let count = self.varint()?;
        if count > MAX_CAPABILITIES {
            return Err(DecodeError("too many capabilities"));
        }
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let name = self.strict(MAX_CAPABILITY_LEN)?;
            if !valid_capability(&name) {
                return Err(DecodeError("invalid capability name"));
            }
            out.push(name);
        }
        Ok(out)
    }

    fn size(&mut self) -> Result<WindowSize, DecodeError> {
        Ok(WindowSize {
            cols: self.u16()?,
            rows: self.u16()?,
            width_px: self.u16()?,
            height_px: self.u16()?,
        })
    }

    /// A u64 a pipe session appends to a message (7.14.2): None when the payload ends here.
    /// Fewer than 8 bytes left are extra bytes of some later revision, ignored (3.3).
    fn optional_u64(&mut self) -> Result<Option<u64>, DecodeError> {
        if self.p.len() < 8 {
            return Ok(None);
        }
        self.u64().map(Some)
    }

    /// `data…` that starts at `offset`: offset + length must not pass 2^64 - 1 (7.1).
    fn data_at(&mut self, offset: u64) -> Result<Vec<u8>, DecodeError> {
        let data = std::mem::take(&mut self.p);
        offset
            .checked_add(data.len() as u64)
            .ok_or(DecodeError("offset overflows"))?;
        Ok(data.to_vec())
    }
}

/// A capability name: 1 to 32 bytes of lowercase ASCII letters, digits, `-` and `.`, starting
/// with a letter or digit (5.4).
pub fn valid_capability(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_CAPABILITY_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'.')
}

fn put_string(out: &mut Vec<u8>, s: &str, max: usize) {
    // Cut at a character boundary rather than produce a message the peer must reject
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    varint::encode(end as u64, out);
    out.extend_from_slice(&s.as_bytes()[..end]);
}

fn put_size(out: &mut Vec<u8>, size: &WindowSize) {
    for v in [size.cols, size.rows, size.width_px, size.height_px] {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

impl Message {
    /// The type number.
    pub fn ty(&self) -> u64 {
        use types::*;
        match self {
            Message::ClientHello { .. } => CLIENT_HELLO,
            Message::ServerHello { .. } => SERVER_HELLO,
            Message::Ping { .. } => PING,
            Message::Pong { .. } => PONG,
            Message::PathInfo { .. } => PATH_INFO,
            Message::GoAway { .. } => GOAWAY,
            Message::Error { .. } => ERROR,
            Message::Attach { .. } => ATTACH,
            Message::Attached { .. } => ATTACHED,
            Message::KeyConfirm { .. } => KEY_CONFIRM,
            Message::InputEof { .. } => INPUT_EOF,
            Message::ErrorOutput { .. } => ERROR_OUTPUT,
            Message::Input { .. } => INPUT,
            Message::Output { .. } => OUTPUT,
            Message::Ack { .. } => ACK,
            Message::OutputGap { .. } => OUTPUT_GAP,
            Message::Resize(_) => RESIZE,
            Message::Snapshot { .. } => SNAPSHOT,
            Message::Exit { .. } => EXIT,
            Message::Detach => DETACH,
            Message::Hangup => HANGUP,
            Message::OutputZstd { .. } => OUTPUT_ZSTD,
            Message::Unknown { ty } => *ty,
        }
    }

    /// The payload bytes. Strings longer than their maximum are cut; lists longer than their
    /// maximum are cut (callers never build such messages).
    pub fn payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        match self {
            Message::ClientHello {
                versions,
                capabilities,
                implementation,
            } => {
                let versions = &versions[..versions.len().min(MAX_VERSIONS as usize)];
                varint::encode(versions.len() as u64, &mut p);
                for v in versions {
                    varint::encode(*v, &mut p);
                }
                put_capabilities(&mut p, capabilities);
                put_string(&mut p, implementation, MAX_IMPLEMENTATION_LEN);
            }
            Message::ServerHello {
                version,
                nonce,
                capabilities,
                implementation,
            } => {
                varint::encode(*version, &mut p);
                p.extend_from_slice(nonce);
                put_capabilities(&mut p, capabilities);
                put_string(&mut p, implementation, MAX_IMPLEMENTATION_LEN);
            }
            Message::Ping { data } | Message::Pong { data } => p.extend_from_slice(&data.to_be_bytes()),
            Message::PathInfo {
                sequence,
                address,
                port,
            } => {
                varint::encode(*sequence, &mut p);
                match address.map(canonical_ip) {
                    None => p.push(0),
                    Some(IpAddr::V4(a)) => {
                        p.push(4);
                        p.extend_from_slice(&a.octets());
                    }
                    Some(IpAddr::V6(a)) => {
                        p.push(6);
                        p.extend_from_slice(&a.octets());
                    }
                }
                p.extend_from_slice(&port.to_be_bytes());
            }
            Message::GoAway { code, message } | Message::Error { code, message } => {
                varint::encode(code.0, &mut p);
                put_string(&mut p, message, MAX_MESSAGE_LEN);
            }
            Message::Attach {
                session,
                proof,
                output_received,
                size,
                flags,
                error_received,
            } => {
                p.extend_from_slice(session);
                p.extend_from_slice(proof);
                p.extend_from_slice(&output_received.to_be_bytes());
                put_size(&mut p, size);
                varint::encode(*flags, &mut p);
                if let Some(e) = error_received {
                    p.extend_from_slice(&e.to_be_bytes());
                }
            }
            Message::Attached {
                input_received,
                output_start,
                next_key,
                server_proof,
                error_start,
            } => {
                p.extend_from_slice(&input_received.to_be_bytes());
                p.extend_from_slice(&output_start.to_be_bytes());
                p.extend_from_slice(&next_key.0);
                p.extend_from_slice(server_proof);
                if let Some(e) = error_start {
                    p.extend_from_slice(&e.to_be_bytes());
                }
            }
            Message::KeyConfirm { key_id } => p.extend_from_slice(key_id),
            Message::Detach | Message::Hangup | Message::Unknown { .. } => {}
            Message::Input { offset, data }
            | Message::Output { offset, data }
            | Message::ErrorOutput { offset, data } => {
                p.extend_from_slice(&offset.to_be_bytes());
                p.extend_from_slice(data);
            }
            Message::InputEof { offset } => p.extend_from_slice(&offset.to_be_bytes()),
            Message::Ack {
                received,
                error_received,
            } => {
                p.extend_from_slice(&received.to_be_bytes());
                if let Some(e) = error_received {
                    p.extend_from_slice(&e.to_be_bytes());
                }
            }
            Message::OutputGap { from, to } => {
                p.extend_from_slice(&from.to_be_bytes());
                p.extend_from_slice(&to.to_be_bytes());
            }
            Message::Resize(size) => put_size(&mut p, size),
            Message::Snapshot {
                offset,
                flags,
                cols,
                rows,
                data,
            } => {
                p.extend_from_slice(&offset.to_be_bytes());
                p.push(*flags);
                p.extend_from_slice(&cols.to_be_bytes());
                p.extend_from_slice(&rows.to_be_bytes());
                p.extend_from_slice(data);
            }
            Message::Exit {
                output_end,
                status,
                error_end,
            } => {
                p.extend_from_slice(&output_end.to_be_bytes());
                match status {
                    ExitStatus::Exited(code) => {
                        p.push(0);
                        p.extend_from_slice(&code.to_be_bytes());
                        p.push(0);
                        put_string(&mut p, "", MAX_SIGNAL_LEN);
                    }
                    ExitStatus::Signaled { signal, core_dumped } => {
                        p.push(1);
                        p.extend_from_slice(&0u32.to_be_bytes());
                        p.push(if *core_dumped { EXIT_CORE_DUMPED } else { 0 });
                        put_string(&mut p, signal, MAX_SIGNAL_LEN);
                    }
                }
                if let Some(e) = error_end {
                    p.extend_from_slice(&e.to_be_bytes());
                }
            }
            Message::OutputZstd { offset, frame } => {
                p.extend_from_slice(&offset.to_be_bytes());
                p.extend_from_slice(frame);
            }
        }
        p
    }

    /// The whole message: type, length and payload.
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.payload();
        let mut out = Vec::with_capacity(payload.len() + 16);
        varint::encode(self.ty(), &mut out);
        varint::encode(payload.len() as u64, &mut out);
        out.extend_from_slice(&payload);
        out
    }

    /// Decode the payload of a message of type `ty`. Unknown types give [`Message::Unknown`].
    pub fn decode(ty: u64, payload: &[u8]) -> Result<Message, DecodeError> {
        use types::*;
        let mut f = Fields { p: payload };
        let m = match ty {
            CLIENT_HELLO => {
                let count = f.varint()?;
                if count == 0 || count > MAX_VERSIONS {
                    return Err(DecodeError("bad version count"));
                }
                let mut versions = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    versions.push(f.varint()?);
                }
                let capabilities = f.capabilities()?;
                let implementation = f.text(MAX_IMPLEMENTATION_LEN)?;
                Message::ClientHello {
                    versions,
                    capabilities,
                    implementation,
                }
            }
            SERVER_HELLO => {
                let version = f.varint()?;
                let nonce = f.array()?;
                let capabilities = f.capabilities()?;
                let implementation = f.text(MAX_IMPLEMENTATION_LEN)?;
                Message::ServerHello {
                    version,
                    nonce,
                    capabilities,
                    implementation,
                }
            }
            PING => Message::Ping { data: f.u64()? },
            PONG => Message::Pong { data: f.u64()? },
            PATH_INFO => {
                let sequence = f.varint()?;
                let address = match f.u8()? {
                    0 => None,
                    4 => Some(IpAddr::V4(Ipv4Addr::from(f.array::<4>()?))),
                    // An IPv4-mapped address means the IPv4 address (5.6), as the encoder sends it
                    6 => Some(canonical_ip(IpAddr::V6(Ipv6Addr::from(f.array::<16>()?)))),
                    _ => return Err(DecodeError("bad address family")),
                };
                Message::PathInfo {
                    sequence,
                    address,
                    port: f.u16()?,
                }
            }
            GOAWAY => Message::GoAway {
                code: ErrorCode(f.varint()?),
                message: f.text(MAX_MESSAGE_LEN)?,
            },
            ERROR => Message::Error {
                code: ErrorCode(f.varint()?),
                message: f.text(MAX_MESSAGE_LEN)?,
            },
            ATTACH => {
                let session = f.array()?;
                let proof = f.array()?;
                let output_received = f.u64()?;
                let size = f.size()?;
                let flags = f.varint()?;
                let error_received = f.optional_u64()?;
                let fresh = flags & ATTACH_FRESH != 0;
                if (output_received == LATEST || error_received == Some(LATEST)) && !fresh {
                    return Err(DecodeError("LATEST without FRESH"));
                }
                Message::Attach {
                    session,
                    proof,
                    output_received,
                    size,
                    flags,
                    error_received,
                }
            }
            ATTACHED => Message::Attached {
                input_received: f.u64()?,
                output_start: f.u64()?,
                next_key: SessionKey(f.array()?),
                server_proof: f.array()?,
                error_start: f.optional_u64()?,
            },
            KEY_CONFIRM => Message::KeyConfirm { key_id: f.array()? },
            INPUT => {
                let offset = f.u64()?;
                Message::Input {
                    offset,
                    data: f.data_at(offset)?,
                }
            }
            OUTPUT => {
                let offset = f.u64()?;
                Message::Output {
                    offset,
                    data: f.data_at(offset)?,
                }
            }
            ACK => Message::Ack {
                received: f.u64()?,
                error_received: f.optional_u64()?,
            },
            INPUT_EOF => Message::InputEof { offset: f.u64()? },
            ERROR_OUTPUT => {
                let offset = f.u64()?;
                Message::ErrorOutput {
                    offset,
                    data: f.data_at(offset)?,
                }
            }
            OUTPUT_GAP => Message::OutputGap {
                from: f.u64()?,
                to: f.u64()?,
            },
            RESIZE => Message::Resize(f.size()?),
            SNAPSHOT => {
                let offset = f.u64()?;
                let flags = f.u8()?;
                let cols = f.u16()?;
                let rows = f.u16()?;
                Message::Snapshot {
                    offset,
                    flags,
                    cols,
                    rows,
                    data: f.p.to_vec(),
                }
            }
            EXIT => {
                let output_end = f.u64()?;
                let kind = f.u8()?;
                let code = f.u32()?;
                let flags = f.u8()?;
                // A signal name is read by programs (the exit status), not only by people:
                // invalid UTF-8 is malformed, not replaced
                let signal = f.strict(MAX_SIGNAL_LEN)?;
                let status = match kind {
                    0 => ExitStatus::Exited(code),
                    1 => ExitStatus::Signaled {
                        signal,
                        core_dumped: flags & EXIT_CORE_DUMPED != 0,
                    },
                    _ => return Err(DecodeError("bad exit kind")),
                };
                Message::Exit {
                    output_end,
                    status,
                    error_end: f.optional_u64()?,
                }
            }
            DETACH => Message::Detach,
            HANGUP => Message::Hangup,
            OUTPUT_ZSTD => {
                let offset = f.u64()?;
                // At least one byte of content follows `offset` (7.12): it must not be 2^64 − 1
                offset.checked_add(1).ok_or(DecodeError("offset overflows"))?;
                Message::OutputZstd {
                    offset,
                    frame: f.p.to_vec(),
                }
            }
            _ => Message::Unknown { ty },
        };
        Ok(m)
    }
}

fn put_capabilities(p: &mut Vec<u8>, capabilities: &[String]) {
    let capabilities = &capabilities[..capabilities.len().min(MAX_CAPABILITIES as usize)];
    varint::encode(capabilities.len() as u64, p);
    for c in capabilities {
        put_string(p, c, MAX_CAPABILITY_LEN);
    }
}

/// IPv4-mapped IPv6 addresses as IPv4 (5.6).
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Decode one complete message from the start of `input`, enforcing `max` on its length:
/// the message and the bytes it took, or None when `input` holds no complete message yet.
pub fn decode_from(input: &[u8], max: usize) -> Result<Option<(Message, usize)>, super::FramingError> {
    use super::FramingError;
    let Ok((ty, a)) = varint::decode(input) else {
        return Ok(None);
    };
    let Ok((len, b)) = varint::decode(&input[a..]) else {
        return Ok(None);
    };
    if len > max as u64 {
        return Err(FramingError::TooLarge);
    }
    let start = a + b;
    let Some(payload) = input.get(start..start + len as usize) else {
        return Ok(None);
    };
    let message = Message::decode(ty, payload).map_err(FramingError::Malformed)?;
    Ok(Some((message, start + len as usize)))
}
