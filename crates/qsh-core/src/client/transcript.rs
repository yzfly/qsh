//! `QSH_TRANSCRIPT`: a test hook, compiled into every build and **unstable** (its format may
//! change in any release; nothing but qsh's own tests should read it).
//!
//! When the environment variable `QSH_TRANSCRIPT` names a file, the client appends one JSON
//! object per line to it for every event of the output stream and of the connection, so that
//! tests (the chaos harness, m2.md section 12.2) can check the stream exactly without parsing a
//! screen. Every line has `ms` (milliseconds since the transcript was opened in this process)
//! and `ev`; session events have `session` (32 hex digits).
//!
//! | `ev` | Other members | Written when |
//! |---|---|---|
//! | `output` | `stream` (`out` or `err`), `offset`, `len`, `sha256` of the bytes; `zstd` (the frame's length) for OUTPUT_ZSTD | OUTPUT, ERROR_OUTPUT or OUTPUT_ZSTD was accepted (`len` and `sha256` describe the decompressed bytes) |
//! | `gap` | `from`, `to` | OUTPUT_GAP was accepted |
//! | `snapshot` | `offset`, `flags`, `cols`, `rows`, `len`, `sha256` of `Data` as received | a SNAPSHOT message was accepted |
//! | `connected` | `transport`, `remote` (or null) | a session attached |
//! | `disconnected` | `why` | a session's connection was lost |
//! | `attempt` | `transport`, `port`, `outcome` | a race attempt ended (path memory, m2.md section 3) |
//! | anything else | whatever [`Record::Other`] carries | for later additions |
//!
//! The file is opened in append mode (created with mode 0600); each record is a single write,
//! so the lines of several processes do not interleave. Write errors are ignored: a test hook
//! never stops a session.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::crypto;
use crate::log;
use crate::transport::Transport;

/// The environment variable that names the transcript file.
pub const ENV: &str = "QSH_TRANSCRIPT";

/// One event for the transcript.
#[derive(Debug, Clone, Copy)]
pub enum Record<'a> {
    /// Output was accepted: OUTPUT, ERROR_OUTPUT, or OUTPUT_ZSTD after decompression.
    Output {
        /// The session id.
        session: &'a [u8; 16],
        /// The error output stream of a pipe session (ERROR_OUTPUT).
        errors: bool,
        /// The offset of the first byte.
        offset: u64,
        /// The bytes (decompressed).
        data: &'a [u8],
        /// For OUTPUT_ZSTD, the length of the zstd frame.
        frame: Option<usize>,
    },
    /// OUTPUT_GAP was accepted.
    Gap {
        /// The session id.
        session: &'a [u8; 16],
        /// `From`.
        from: u64,
        /// `To`.
        to: u64,
    },
    /// One SNAPSHOT message was accepted.
    Snapshot {
        /// The session id.
        session: &'a [u8; 16],
        /// `Offset`.
        offset: u64,
        /// `Flags` (FINAL, ZSTD).
        flags: u8,
        /// `Columns`.
        cols: u16,
        /// `Rows`.
        rows: u16,
        /// `Data` as received.
        data: &'a [u8],
    },
    /// A session attached over a connection.
    Connected {
        /// The session id.
        session: &'a [u8; 16],
        /// The connection's transport.
        transport: Transport,
        /// The server's address, when the transport has one.
        remote: Option<SocketAddr>,
    },
    /// A session's connection was lost.
    Disconnected {
        /// The session id.
        session: &'a [u8; 16],
        /// Why.
        why: &'a str,
    },
    /// A race attempt ended.
    Attempt {
        /// The transport.
        transport: Transport,
        /// The port (0 for the ssh pipe).
        port: u16,
        /// "won", "timeout", "reset", "hello", "refused", "cancelled", …
        outcome: &'a str,
    },
    /// Anything else: `ev` and its members.
    Other {
        /// The event name.
        ev: &'a str,
        /// Its members.
        fields: &'a Map<String, Value>,
    },
}

/// An open transcript file.
#[derive(Debug)]
pub struct Transcript {
    file: Mutex<File>,
    opened: Instant,
}

impl Transcript {
    /// Open (create, append to) the transcript file at `path`.
    pub fn open(path: &Path) -> std::io::Result<Transcript> {
        let file = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        Ok(Transcript {
            file: Mutex::new(file),
            opened: Instant::now(),
        })
    }

    /// Append `record` as one line.
    pub fn write(&self, record: Record<'_>) {
        let mut line = self.line(record).to_string();
        line.push('\n');
        // One write per line: O_APPEND keeps lines whole across processes
        let _ = self.file.lock().unwrap().write_all(line.as_bytes());
    }

    /// The JSON object of `record`.
    fn line(&self, record: Record<'_>) -> Value {
        let ms = self.opened.elapsed().as_millis() as u64;
        let mut v = match record {
            Record::Output {
                session,
                errors,
                offset,
                data,
                frame,
            } => {
                let mut v = json!({
                    "ev": "output",
                    "session": crypto::hex(session),
                    "stream": if errors { "err" } else { "out" },
                    "offset": offset,
                    "len": data.len(),
                    "sha256": sha256(data),
                });
                if let Some(frame) = frame {
                    v["zstd"] = json!(frame);
                }
                v
            }
            Record::Gap { session, from, to } => json!({
                "ev": "gap",
                "session": crypto::hex(session),
                "from": from,
                "to": to,
            }),
            Record::Snapshot {
                session,
                offset,
                flags,
                cols,
                rows,
                data,
            } => json!({
                "ev": "snapshot",
                "session": crypto::hex(session),
                "offset": offset,
                "flags": flags,
                "cols": cols,
                "rows": rows,
                "len": data.len(),
                "sha256": sha256(data),
            }),
            Record::Connected {
                session,
                transport,
                remote,
            } => json!({
                "ev": "connected",
                "session": crypto::hex(session),
                "transport": transport.to_string(),
                "remote": remote.map(|r| r.to_string()),
            }),
            Record::Disconnected { session, why } => json!({
                "ev": "disconnected",
                "session": crypto::hex(session),
                "why": why,
            }),
            Record::Attempt {
                transport,
                port,
                outcome,
            } => json!({
                "ev": "attempt",
                "transport": transport.to_string(),
                "port": port,
                "outcome": outcome,
            }),
            Record::Other { ev, fields } => {
                let mut v = Value::Object(fields.clone());
                v["ev"] = json!(ev);
                v
            }
        };
        v["ms"] = json!(ms);
        v
    }
}

fn sha256(data: &[u8]) -> String {
    crypto::hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

/// The process's transcript: opened on first use from `QSH_TRANSCRIPT`, None when the variable
/// is unset or empty, or the file cannot be opened (logged once).
pub fn get() -> Option<&'static Transcript> {
    static TRANSCRIPT: OnceLock<Option<Transcript>> = OnceLock::new();
    TRANSCRIPT
        .get_or_init(|| {
            let path = std::env::var_os(ENV).filter(|p| !p.is_empty())?;
            match Transcript::open(Path::new(&path)) {
                Ok(t) => Some(t),
                Err(e) => {
                    log::info(format_args!("{ENV}: cannot open {}: {e}", Path::new(&path).display()));
                    None
                }
            }
        })
        .as_ref()
}

/// Append `record` to the process's transcript, if there is one. Costs nothing else.
pub fn record(record: Record<'_>) {
    if let Some(t) = get() {
        t.write(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_json_lines() {
        let dir = std::env::temp_dir().join(format!("qsh-transcript-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.jsonl");
        let t = Transcript::open(&path).unwrap();
        let session = [0xab; 16];
        t.write(Record::Output {
            session: &session,
            errors: false,
            offset: 7,
            data: b"abc",
            frame: Some(12),
        });
        t.write(Record::Gap {
            session: &session,
            from: 10,
            to: 20,
        });
        let mut fields = Map::new();
        fields.insert("x".into(), json!(1));
        t.write(Record::Other {
            ev: "restart",
            fields: &fields,
        });
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["ev"], "output");
        assert_eq!(lines[0]["offset"], 7);
        assert_eq!(lines[0]["len"], 3);
        assert_eq!(lines[0]["zstd"], 12);
        assert_eq!(lines[0]["session"], "ab".repeat(16));
        assert_eq!(
            lines[0]["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            (lines[1]["from"].as_u64(), lines[1]["to"].as_u64()),
            (Some(10), Some(20))
        );
        assert_eq!(lines[2]["ev"], "restart");
        assert_eq!(lines[2]["x"], 1);
        assert!(lines.iter().all(|l| l["ms"].is_u64()));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
