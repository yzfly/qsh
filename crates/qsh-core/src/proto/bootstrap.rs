//! The bootstrap over ssh (protocol.md section 10): one JSON request on the stdin of
//! `qsh-server bootstrap`, one JSON line in reply on its stdout.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The bootstrap format version, member `"qsh"`.
pub const BOOTSTRAP_VERSION: u64 = 1;

/// The largest bootstrap request, in bytes (section 10.3).
pub const MAX_REQUEST: usize = 65536;

/// How much of `qsh-server bootstrap`'s stdout a client reads (section 10.4).
pub const MAX_REPLY_OUTPUT: usize = 1 << 20;

/// Longest `term`, `name` and `client` values.
pub const MAX_SHORT_STRING: usize = 64;

/// Longest accepted `env` value.
pub const MAX_ENV_VALUE: usize = 256;

/// Most extra ports in a reply (`extra_ports`, sections 10.4 and 12.6).
pub const MAX_EXTRA_PORTS: usize = 8;

/// The bootstrap operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// Create a session.
    New,
    /// New credentials for an existing session.
    Attach,
    /// The user's sessions.
    List,
    /// End a session.
    Kill,
}

/// A bootstrap request (section 10.3). Unknown members are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// [`BOOTSTRAP_VERSION`].
    pub qsh: u64,
    /// The operation; `new` when absent.
    #[serde(default = "default_op")]
    pub op: Op,
    /// Protocol versions the client supports (`new`, `attach`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<u64>,
    /// The remote command; None for a login shell (`new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Terminal columns, 1 to 65535 (`new`, `attach`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u64>,
    /// Terminal rows, 1 to 65535 (`new`, `attach`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u64>,
    /// `TERM` (`new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    /// Locale and color variables (`new`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// A session name shown by `qsh ls` (`new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The session id, 32 hex digits (`attach`, `kill`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The client implementation, informative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// False: a pipe session (section 7.14), whose program has pipes for stdin, stdout and
    /// stderr instead of a pseudo-terminal (`new`). Absent or true: a tty session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
}

fn default_op() -> Op {
    Op::New
}

impl Request {
    /// A `new` request for a login shell on a terminal of the given size.
    pub fn new_session(cols: u16, rows: u16) -> Request {
        Request {
            qsh: BOOTSTRAP_VERSION,
            op: Op::New,
            versions: vec![u64::from(super::VERSION)],
            command: None,
            cols: Some(cols.max(1).into()),
            rows: Some(rows.max(1).into()),
            term: None,
            env: BTreeMap::new(),
            name: None,
            session: None,
            client: Some(super::IMPLEMENTATION.into()),
            tty: None,
        }
    }

    /// An `attach` request: new credentials for `session`.
    pub fn attach(session: &str, cols: u16, rows: u16) -> Request {
        Request {
            op: Op::Attach,
            session: Some(session.into()),
            ..Request::new_session(cols, rows)
        }
    }

    /// A `list` request: the user's sessions.
    pub fn list() -> Request {
        Request {
            op: Op::List,
            versions: Vec::new(),
            cols: None,
            rows: None,
            ..Request::new_session(1, 1)
        }
    }

    /// A `kill` request: end `session`.
    pub fn kill(session: &str) -> Request {
        Request {
            op: Op::Kill,
            session: Some(session.into()),
            ..Request::list()
        }
    }

    /// Check what the server needs before it acts: required members and their ranges.
    pub fn validate(&self) -> Result<(), ErrorReply> {
        if self.qsh != BOOTSTRAP_VERSION {
            return Err(ErrorReply::new(
                ErrorKind::Unsupported,
                format!("bootstrap format {} is not supported", self.qsh),
            ));
        }
        let size_ok = |v: Option<u64>| matches!(v, Some(1..=65535));
        match self.op {
            Op::New | Op::Attach => {
                if self.versions.is_empty() {
                    return Err(ErrorReply::new(ErrorKind::BadRequest, "versions missing"));
                }
                if !self.versions.contains(&u64::from(super::VERSION)) {
                    return Err(ErrorReply::new(ErrorKind::Unsupported, "no common protocol version"));
                }
                // REQUIRED for a new tty session; a pipe session has no terminal (10.3)
                let sizes_needed = self.op == Op::New && self.tty != Some(false);
                let size_valid = |v: Option<u64>| v.is_none() || size_ok(v);
                if (sizes_needed && (!size_ok(self.cols) || !size_ok(self.rows)))
                    || !size_valid(self.cols)
                    || !size_valid(self.rows)
                {
                    return Err(ErrorReply::new(
                        ErrorKind::BadRequest,
                        "cols and rows must be 1 to 65535",
                    ));
                }
            }
            Op::List | Op::Kill => {}
        }
        if matches!(self.op, Op::Attach | Op::Kill)
            && self.session.as_deref().and_then(crate::crypto::unhex::<16>).is_none()
        {
            return Err(ErrorReply::new(ErrorKind::BadRequest, "session must be 32 hex digits"));
        }
        let too_long = |s: &Option<String>| s.as_ref().is_some_and(|s| s.len() > MAX_SHORT_STRING);
        if too_long(&self.term) || too_long(&self.name) || too_long(&self.client) {
            return Err(ErrorReply::new(
                ErrorKind::BadRequest,
                "term, name and client are at most 64 bytes",
            ));
        }
        Ok(())
    }

    /// The `env` members a server accepts: `LANG`, `LANGUAGE`, `COLORTERM` and `LC_*`, values
    /// up to 256 bytes without NUL.
    pub fn accepted_env(&self) -> Vec<(String, String)> {
        self.env
            .iter()
            .filter(|(k, v)| accepted_env_name(k) && v.len() <= MAX_ENV_VALUE && !v.contains('\0'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// True for the variable names a session accepts from the client (section 10.3).
pub fn accepted_env_name(name: &str) -> bool {
    matches!(name, "LANG" | "LANGUAGE" | "COLORTERM")
        || (name.starts_with("LC_") && name.len() > 3 && !name.contains('='))
}

/// The reply to `new` and `attach` (section 10.4). Unknown members are ignored. The key is
/// secret: `Debug` does not show it, and it is wiped from memory on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// 1.
    pub qsh: u64,
    /// Protocol versions the server supports.
    pub versions: Vec<u64>,
    /// Session id, 32 lowercase hex digits.
    pub session: String,
    /// Session key, 64 lowercase hex digits. Secret.
    pub key: String,
    /// SHA-256 of the daemon's certificate, 64 lowercase hex digits.
    pub cert_sha256: String,
    /// QUIC port, 0 when not listening on UDP.
    pub udp: u16,
    /// TLS port, 0 when not listening on TCP.
    pub tcp: u16,
    /// Capabilities the server supports (informative).
    #[serde(default)]
    pub caps: Vec<String>,
    /// Server implementation, informative.
    #[serde(default)]
    pub server: String,
    /// The server address of the ssh connection, from `SSH_CONNECTION`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_addr: Option<String>,
    /// False for a pipe session (section 7.14); absent or true for a tty session. Authoritative:
    /// the client uses the pipe-session layouts if and only if this is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
    /// Further ports of the same daemon (sections 10.4 and 12.6), in announced order. Read
    /// leniently: invalid entries, entries beyond the eighth and a member that is not an array
    /// are ignored, never an error. Not sent when empty, so old clients see no difference.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "extra_ports_lenient"
    )]
    pub extra_ports: Vec<ExtraPort>,
}

/// A further port of the daemon, from the bootstrap reply member `extra_ports` (section 10.4):
/// `{"port": N, "udp": bool, "tcp": bool}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtraPort {
    /// The port number, 1 to 65535.
    pub port: u16,
    /// The daemon listens for QUIC on it.
    pub udp: bool,
    /// The daemon listens for TLS on it.
    pub tcp: bool,
}

impl ExtraPort {
    /// One entry of `extra_ports`, if it is valid: an object whose `port` is 1 to 65535, whose
    /// `udp` and `tcp` are booleans (an absent one is false), at least one of them true.
    pub fn from_json(value: &Value) -> Option<ExtraPort> {
        let object = value.as_object()?;
        let port = u16::try_from(object.get("port")?.as_u64()?).ok().filter(|p| *p != 0)?;
        let flag = |name: &str| match object.get(name) {
            None => Some(false),
            Some(v) => v.as_bool(),
        };
        let (udp, tcp) = (flag("udp")?, flag("tcp")?);
        (udp || tcp).then_some(ExtraPort { port, udp, tcp })
    }

    /// The valid entries among the first [`MAX_EXTRA_PORTS`] of `extra_ports`; nothing when
    /// it is not an array.
    pub fn list_from_json(value: &Value) -> Vec<ExtraPort> {
        value
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .take(MAX_EXTRA_PORTS)
                    .filter_map(ExtraPort::from_json)
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn extra_ports_lenient<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<ExtraPort>, D::Error> {
    Ok(ExtraPort::list_from_json(&Value::deserialize(d)?))
}

impl Credentials {
    /// True for a pipe session.
    pub fn pipe(&self) -> bool {
        self.tty == Some(false)
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("qsh", &self.qsh)
            .field("versions", &self.versions)
            .field("session", &self.session)
            .field("key", &"..")
            .field("cert_sha256", &self.cert_sha256)
            .field("udp", &self.udp)
            .field("tcp", &self.tcp)
            .field("caps", &self.caps)
            .field("server", &self.server)
            .field("ssh_addr", &self.ssh_addr)
            .field("tty", &self.tty)
            .field("extra_ports", &self.extra_ports)
            .finish()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// One session in the reply to `list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session id, 32 hex digits.
    pub session: String,
    /// The session's name, if it was given one.
    #[serde(default)]
    pub name: Option<String>,
    /// The command, None for a login shell.
    #[serde(default)]
    pub command: Option<String>,
    /// Seconds since the Unix epoch.
    pub created: u64,
    /// A client is attached.
    pub attached: bool,
    /// The program has exited.
    pub exited: bool,
    /// False for a pipe session; absent for a tty session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
}

/// The bootstrap error codes (section 10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorKind {
    /// Not valid JSON, too long, or a required member is missing.
    BadRequest,
    /// No common protocol version, unknown op or format version.
    Unsupported,
    /// `attach` or `kill` of a session that does not exist.
    NoSession,
    /// The daemon's session limit.
    Limit,
    /// The daemon could not be started or reached.
    Daemon,
    /// Anything else.
    Internal,
}

/// An error reply: `{"qsh":1,"error":"<code>","message":"…"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReply {
    /// 1.
    pub qsh: u64,
    /// The code.
    pub error: ErrorKind,
    /// One line for people.
    #[serde(default)]
    pub message: String,
}

impl ErrorReply {
    /// An error reply.
    pub fn new(error: ErrorKind, message: impl Into<String>) -> ErrorReply {
        // One line, whatever the cause said
        let message: String = message.into().replace(['\n', '\r'], " ");
        ErrorReply {
            qsh: BOOTSTRAP_VERSION,
            error,
            message,
        }
    }
}

impl std::fmt::Display for ErrorReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_value(self.error)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if self.message.is_empty() {
            write!(f, "{code}")
        } else {
            write!(f, "{} ({code})", self.message)
        }
    }
}

/// A reply as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Credentials (`new`, `attach`).
    Credentials(Credentials),
    /// Sessions (`list`).
    Sessions(Vec<SessionInfo>),
    /// `kill` succeeded.
    Ok,
    /// An error.
    Error(ErrorReply),
}

/// Why a client could not use the bootstrap output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyError(pub String);

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReplyError {}

/// Longest line of `qsh-server bootstrap`'s stdout a client looks at (section 10.4).
pub const MAX_REPLY_LINE: usize = 65536;

/// Finds the reply in `qsh-server bootstrap`'s stdout as it arrives, in bounded memory
/// (section 10.4): the last line, of at most [`MAX_REPLY_LINE`] bytes, that parses as a JSON
/// object with a member `qsh`. Shell start-up files may print anything around it, of any
/// length; all of it has to be read (ssh blocks on a full pipe) and none of it kept.
#[derive(Default)]
pub struct ReplyScanner {
    line: Vec<u8>,
    /// The current line is too long to be the reply: skipped up to its end.
    skipping: bool,
    candidate: Vec<u8>,
}

impl std::fmt::Debug for ReplyScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplyScanner(..)")
    }
}

impl ReplyScanner {
    /// Take the next bytes of stdout.
    pub fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let (part, rest, ended) = match bytes.iter().position(|b| *b == b'\n') {
                Some(i) => (&bytes[..i], &bytes[i + 1..], true),
                None => (bytes, &[][..], false),
            };
            if !self.skipping {
                if self.line.len() + part.len() > MAX_REPLY_LINE {
                    self.skipping = true;
                    zeroize::Zeroize::zeroize(&mut self.line);
                    self.line.clear();
                } else {
                    self.line.extend_from_slice(part);
                }
            }
            if ended {
                self.end_line();
            }
            bytes = rest;
        }
    }

    fn end_line(&mut self) {
        if !self.skipping {
            let is_reply =
                serde_json::from_slice::<Value>(&self.line).is_ok_and(|v| v.is_object() && v.get("qsh").is_some());
            if is_reply {
                zeroize::Zeroize::zeroize(&mut self.candidate);
                self.candidate = std::mem::take(&mut self.line);
            }
        }
        zeroize::Zeroize::zeroize(&mut self.line);
        self.line.clear();
        self.skipping = false;
    }

    /// The end of stdout: the reply line found, if any, for [`parse_reply`].
    pub fn finish(mut self) -> Vec<u8> {
        self.end_line();
        std::mem::take(&mut self.candidate)
    }
}

impl Drop for ReplyScanner {
    fn drop(&mut self) {
        // The reply holds the session key
        zeroize::Zeroize::zeroize(&mut self.line);
        zeroize::Zeroize::zeroize(&mut self.candidate);
    }
}

/// Find the reply in the bootstrap's stdout: the last line that parses as a JSON object with a
/// member `qsh` (shell start-up files sometimes print other lines), then check it.
pub fn parse_reply(output: &[u8], op: Op) -> Result<Reply, ReplyError> {
    let output = &output[..output.len().min(MAX_REPLY_OUTPUT)];
    let value = output
        .split(|b| *b == b'\n')
        .rev()
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|v| v.is_object() && v.get("qsh").is_some())
        .ok_or_else(|| ReplyError("no reply from qsh-server bootstrap".into()))?;
    if value["qsh"].as_u64() != Some(BOOTSTRAP_VERSION) {
        return Err(ReplyError(format!(
            "unsupported bootstrap reply format {}",
            value["qsh"]
        )));
    }
    if value.get("error").is_some() {
        let mut e: ErrorReply = serde_json::from_value(value.clone()).unwrap_or_else(|_| {
            ErrorReply::new(
                ErrorKind::Internal,
                value["message"].as_str().unwrap_or("unknown error").to_string(),
            )
        });
        // Shown to the user ("bootstrap failed: …"): as text only (security.md 4.6)
        e.message = crate::text::sanitize(&e.message, 512);
        return Ok(Reply::Error(e));
    }
    match op {
        Op::New | Op::Attach => {
            let c: Credentials =
                serde_json::from_value(value).map_err(|e| ReplyError(format!("bad bootstrap reply: {e}")))?;
            let hex_ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !hex_ok(&c.session, 32) || !hex_ok(&c.key, 64) || !hex_ok(&c.cert_sha256, 64) {
                return Err(ReplyError(
                    "bad bootstrap reply: malformed session, key or cert_sha256".into(),
                ));
            }
            if !c.versions.contains(&u64::from(super::VERSION)) {
                return Err(ReplyError(
                    "the server speaks no protocol version this client knows".into(),
                ));
            }
            Ok(Reply::Credentials(c))
        }
        Op::List => {
            let sessions = serde_json::from_value(value["sessions"].clone())
                .map_err(|e| ReplyError(format!("bad bootstrap reply: {e}")))?;
            Ok(Reply::Sessions(sessions))
        }
        Op::Kill => Ok(Reply::Ok),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review L3: a server's error message is shown to the user ("bootstrap failed: …"): no
    /// escape sequence of it reaches the terminal.
    #[test]
    fn error_messages_are_text_only() {
        let line =
            b"{\"qsh\":1,\"error\":\"internal\",\"message\":\"oops\\u001b]52;c;cm0gLXJmIH4=\\u0007\\u001b[2J done\"}\n";
        let Ok(Reply::Error(e)) = parse_reply(line, Op::New) else {
            panic!("an error reply")
        };
        assert_eq!(e.message, "oops done");
    }

    #[test]
    fn request_validation() {
        let r: Request = serde_json::from_str(r#"{"qsh":1,"versions":[1],"cols":80,"rows":24,"future":true}"#).unwrap();
        assert_eq!(r.op, Op::New);
        assert!(r.validate().is_ok());
        let r: Request = serde_json::from_str(r#"{"qsh":1,"versions":[1],"cols":0,"rows":24}"#).unwrap();
        assert_eq!(r.validate().unwrap_err().error, ErrorKind::BadRequest);
        // A pipe session needs no size, a tty session does
        let r: Request = serde_json::from_str(r#"{"qsh":1,"versions":[1],"tty":false}"#).unwrap();
        assert!(r.validate().is_ok());
        let r: Request = serde_json::from_str(r#"{"qsh":1,"versions":[1],"tty":true}"#).unwrap();
        assert_eq!(r.validate().unwrap_err().error, ErrorKind::BadRequest);
        assert!(serde_json::from_str::<Request>(r#"{"qsh":1,"versions":[1],"tty":"no"}"#).is_err());
        let r: Request = serde_json::from_str(r#"{"qsh":1,"versions":[2],"cols":1,"rows":1}"#).unwrap();
        assert_eq!(r.validate().unwrap_err().error, ErrorKind::Unsupported);
        let r: Request = serde_json::from_str(r#"{"qsh":2}"#).unwrap();
        assert_eq!(r.validate().unwrap_err().error, ErrorKind::Unsupported);
        let r: Request = serde_json::from_str(r#"{"qsh":1,"op":"kill","session":"xyz"}"#).unwrap();
        assert_eq!(r.validate().unwrap_err().error, ErrorKind::BadRequest);
        assert!(serde_json::from_str::<Request>(r#"{"qsh":1,"op":"dance"}"#).is_err());
        // list and kill carry only what they need
        let list = serde_json::to_string(&Request::list()).unwrap();
        assert_eq!(
            list,
            r#"{"qsh":1,"op":"list","client":"qsh/0"}"#.replace("qsh/0", crate::proto::IMPLEMENTATION)
        );
        assert!(Request::list().validate().is_ok());
        let kill = Request::kill(&"ab".repeat(16));
        assert_eq!(kill.op, Op::Kill);
        assert!(kill.validate().is_ok() && kill.versions.is_empty() && kill.cols.is_none());
        assert_eq!(
            Request::kill("xyz").validate().unwrap_err().error,
            ErrorKind::BadRequest
        );
        let mut r = Request::new_session(80, 24);
        r.env.insert("LANG".into(), "C.UTF-8".into());
        r.env.insert("LC_ALL".into(), "x\0".into());
        r.env.insert("PATH".into(), "/evil".into());
        r.env.insert("LANGUAGE".into(), "x".repeat(257));
        assert_eq!(r.accepted_env(), vec![("LANG".into(), "C.UTF-8".into())]);
    }

    /// Review L8: the session key never shows in debug output (logs, panics).
    #[test]
    fn credentials_debug_hides_the_key() {
        let out = br#"{"qsh":1,"versions":[1],"session":"00112233445566778899aabbccddeeff","key":"5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7","cert_sha256":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","udp":1,"tcp":1}"#;
        let reply = parse_reply(out, Op::New).unwrap();
        let text = format!("{reply:?}");
        assert!(text.contains("00112233445566778899aabbccddeeff"), "{text}");
        assert!(!text.contains("5ec7e7"), "{text}");
        let attached = crate::proto::Message::Attached {
            input_received: 0,
            output_start: 0,
            next_key: crate::crypto::SessionKey([0x5e; 32]),
            server_proof: [0; 32],
            error_start: None,
        };
        assert!(!format!("{attached:?}").contains("94, 94"), "{attached:?}");
    }

    /// Section 10.4: any amount of output around the reply, in any chunks, in bounded memory.
    #[test]
    fn the_scanner_keeps_only_the_last_reply_line() {
        let reply = br#"{"qsh":1,"versions":[1],"session":"00112233445566778899aabbccddeeff","key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","cert_sha256":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","udp":1,"tcp":1}"#;
        let mut out = Vec::new();
        out.extend(std::iter::repeat_n(b'x', 3 << 20));
        out.extend_from_slice(b"\n{\"qsh\":0}\n");
        out.extend_from_slice(reply);
        out.extend_from_slice(b"\nbye\n");
        out.extend(std::iter::repeat_n(b'{', 100_000));
        for chunk in [1usize, 7, 4096, 1 << 20] {
            let mut scanner = ReplyScanner::default();
            for part in out.chunks(chunk) {
                scanner.feed(part);
                assert!(scanner.line.len() <= MAX_REPLY_LINE && scanner.candidate.len() <= MAX_REPLY_LINE);
            }
            let line = scanner.finish();
            assert!(
                matches!(parse_reply(&line, Op::New), Ok(Reply::Credentials(_))),
                "{chunk}"
            );
        }
        // Without a final newline
        let mut scanner = ReplyScanner::default();
        scanner.feed(reply);
        assert!(parse_reply(&scanner.finish(), Op::New).is_ok());
    }

    /// Section 10.4: `extra_ports` is read leniently and written only when there are some.
    #[test]
    fn extra_ports_in_the_reply() {
        let reply = |extra: &str| {
            format!(
                r#"{{"qsh":1,"versions":[1],"session":"{}","key":"{}","cert_sha256":"{}","udp":60443,"tcp":60443{extra}}}"#,
                "ab".repeat(16),
                "cd".repeat(32),
                "ef".repeat(32)
            )
        };
        let credentials = |extra: &str| match parse_reply(reply(extra).as_bytes(), Op::New) {
            Ok(Reply::Credentials(c)) => c,
            other => panic!("{extra}: {other:?}"),
        };
        // protocol.md 10.4, the example
        let c = credentials(r#","extra_ports":[{"port":443,"udp":true,"tcp":false}],"caps":["snapshot","zstd"]"#);
        assert_eq!(
            c.extra_ports,
            vec![ExtraPort {
                port: 443,
                udp: true,
                tcp: false
            }]
        );
        assert!(credentials("").extra_ports.is_empty());
        // Invalid entries are skipped, never an error; only the first eight entries count
        let c = credentials(concat!(
            r#","extra_ports":[{"port":0,"udp":true},{"port":70000,"udp":true},"#,
            r#"{"port":1,"udp":false,"tcp":false},{"port":2,"udp":"yes"},"x",null,{"udp":true},"#,
            r#"{"port":61443,"tcp":true},{"port":3,"udp":true}]"#
        ));
        assert_eq!(
            c.extra_ports,
            vec![ExtraPort {
                port: 61443,
                udp: false,
                tcp: true
            }]
        );
        for not_a_list in [
            r#","extra_ports":7"#,
            r#","extra_ports":{"port":443}"#,
            r#","extra_ports":null"#,
        ] {
            assert!(credentials(not_a_list).extra_ports.is_empty(), "{not_a_list}");
        }
        // Written as the protocol says, and not at all when empty (old clients see nothing new)
        let mut c = credentials("");
        assert!(!serde_json::to_string(&c).unwrap().contains("extra_ports"));
        c.extra_ports = vec![
            ExtraPort {
                port: 443,
                udp: true,
                tcp: false,
            },
            ExtraPort {
                port: 61443,
                udp: true,
                tcp: true,
            },
        ];
        let text = serde_json::to_string(&c).unwrap();
        assert!(
            text.contains(
                r#""extra_ports":[{"port":443,"udp":true,"tcp":false},{"port":61443,"udp":true,"tcp":true}]"#
            ),
            "{text}"
        );
        match parse_reply(text.as_bytes(), Op::Attach) {
            Ok(Reply::Credentials(back)) => assert_eq!(back, c),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reply_is_the_last_json_line() {
        let out = b"Welcome to the server!\n{\"not\":\"it\"}\n{\"qsh\":1,\"versions\":[1],\"session\":\"00112233445566778899aabbccddeeff\",\"key\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"cert_sha256\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\"udp\":60443,\"tcp\":60443,\"caps\":[],\"server\":\"x\",\"new\":1}\nbye\n";
        match parse_reply(out, Op::New).unwrap() {
            Reply::Credentials(c) => assert_eq!(c.udp, 60443),
            other => panic!("{other:?}"),
        }
        let err = br#"{"qsh":1,"error":"no-session","message":"gone"}"#;
        assert_eq!(
            parse_reply(err, Op::Attach).unwrap(),
            Reply::Error(ErrorReply::new(ErrorKind::NoSession, "gone"))
        );
        assert!(parse_reply(b"nothing\n", Op::New).is_err());
        assert!(parse_reply(
            br#"{"qsh":1,"versions":[1],"session":"AB","key":"","cert_sha256":"","udp":1,"tcp":1}"#,
            Op::New
        )
        .is_err());
    }
}
