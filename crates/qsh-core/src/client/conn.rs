//! One connection after the hello exchange (protocol.md section 5), with its control stream
//! served in the background: PING / PONG and the round-trip time, PATH_INFO, GOAWAY.
//!
//! Path intelligence (m2.md sections 3 and 4, work package WP-1) builds on this: the observed
//! address ([`Conn::observed`]), the round-trip time ([`Conn::rtt`]) and how the race went
//! ([`Conn::attempts`]).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::BufReader;
use tokio::sync::mpsc;

use crate::proto::message::{MAX_CONTROL, MAX_HELLO};
use crate::proto::{read_message, write_message, ErrorCode, FramingError, Message};
use crate::transport::{Connection, RecvStream, Transport};
use crate::{log, proto};

/// Send PING this often on an attached connection (section 12.3).
const PING_INTERVAL: Duration = Duration::from_secs(15);
/// Nothing received for this long: the path is dead.
const DEAD_AFTER: Duration = Duration::from_secs(45);

/// A connection after the hello exchange, with its control stream served in the background.
pub struct Conn {
    pub(crate) connection: Connection,
    pub(crate) nonce: [u8; 32],
    control: mpsc::UnboundedSender<Message>,
    last_rx: Mutex<Instant>,
    rtt: Mutex<Option<Duration>>,
    observed: Mutex<Option<SocketAddr>>,
    goaway: AtomicBool,
    /// The server sent GOAWAY (SHUTDOWN): it is stopping, and its sessions with it.
    shutdown: AtomicBool,
    /// The server sent GOAWAY (RESTART): it restarts in place and keeps its sessions
    /// (protocol.md 10.6).
    restart: AtomicBool,
    /// The client is moving its sessions to another connection ([`Conn::retire`]).
    retiring: AtomicBool,
    /// When the client last sent something other than a keepalive: ATTACH, INPUT, INPUT_EOF,
    /// ACK, RESIZE, KEY_CONFIRM or HANGUP (m2.md 4.2, condition 3).
    last_tx: Mutex<Instant>,
    started: Instant,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// How each transport fared in the race that produced this connection.
    pub(crate) attempts: Mutex<Vec<(Transport, String)>>,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").field("connection", &self.connection).finish()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        for t in self.tasks.lock().unwrap().iter() {
            t.abort();
        }
    }
}

fn micros(since: Instant) -> u64 {
    since.elapsed().as_micros() as u64
}

impl Conn {
    /// Open the control stream and do the hello exchange (section 5). Over the pipe the
    /// server's nonce is needed before any ATTACH; elsewhere waiting costs one round trip
    /// and keeps the code simple.
    pub async fn hello(connection: Connection) -> io::Result<Arc<Conn>> {
        let (_, mut send, recv) = connection.open().await?;
        let hello = Message::ClientHello {
            versions: vec![u64::from(proto::VERSION)],
            capabilities: Vec::new(),
            implementation: proto::IMPLEMENTATION.into(),
        };
        write_message(&mut send, &hello).await?;
        let mut recv = BufReader::new(recv);
        let nonce = match read_message(&mut recv, MAX_HELLO).await {
            Ok(Some(Message::ServerHello {
                version,
                nonce,
                capabilities,
                ..
            })) => {
                if version != u64::from(proto::VERSION) || !capabilities.is_empty() {
                    connection.close(ErrorCode::PROTOCOL_VIOLATION, "");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SERVER_HELLO"));
                }
                nonce
            }
            Ok(Some(Message::Error { code, message })) => {
                return Err(io::Error::other(format!(
                    "the server refused the connection: {code} {message}"
                )))
            }
            Ok(Some(_)) => return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected first message")),
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during hello",
                ))
            }
            Err(e) => return Err(e.into()),
        };
        let (control, mut rx) = mpsc::unbounded_channel::<Message>();
        let started = Instant::now();
        let conn = Arc::new(Conn {
            connection,
            nonce,
            control,
            last_rx: Mutex::new(Instant::now()),
            rtt: Mutex::new(None),
            observed: Mutex::new(None),
            goaway: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            restart: AtomicBool::new(false),
            retiring: AtomicBool::new(false),
            last_tx: Mutex::new(Instant::now()),
            started,
            tasks: Mutex::new(Vec::new()),
            attempts: Mutex::new(Vec::new()),
        });
        // The tasks hold only a weak reference: the connection ends when its users drop it
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if write_message(&mut send, &m).await.is_err() {
                    break;
                }
            }
        });
        let reader = tokio::spawn(control_reader(Arc::downgrade(&conn), recv, started));
        *conn.tasks.lock().unwrap() = vec![writer, reader];
        Ok(conn)
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.connection.transport()
    }

    /// True when the connection can carry new attachments.
    pub fn usable(&self) -> bool {
        !self.connection.is_closed() && !self.goaway.load(Ordering::SeqCst) && !self.retiring()
    }

    /// Move the sessions off this connection (a transport upgrade, m2.md 3.6): it takes no new
    /// attachments, and each session attached on it ends its attachment once none of its input
    /// is unacknowledged, then attaches again at once on whatever connection the pool gives it,
    /// without telling the user of a disconnection. Closing the connection afterwards is the
    /// caller's business.
    pub fn retire(&self) {
        self.retiring.store(true, Ordering::SeqCst);
    }

    /// True after [`Conn::retire`].
    pub fn retiring(&self) -> bool {
        self.retiring.load(Ordering::SeqCst)
    }

    /// The client sent something on this connection that is not a keepalive: ATTACH, INPUT,
    /// INPUT_EOF, ACK, RESIZE, KEY_CONFIRM, HANGUP. For NAT timeout detection (m2.md
    /// 4.2, condition 3).
    pub(crate) fn sent(&self) {
        *self.last_tx.lock().unwrap() = Instant::now();
    }

    /// When the client last sent something other than a keepalive: ATTACH, INPUT, INPUT_EOF,
    /// ACK, RESIZE, KEY_CONFIRM or HANGUP (m2.md 4.2, condition 3).
    pub fn last_sent(&self) -> Instant {
        *self.last_tx.lock().unwrap()
    }

    /// Whether an attachment that last sent PING at `last_ping` should send one now (12.3):
    /// every 15 s. (Work package WP-1 changes this for QUIC, m2.md 4.4.)
    pub(crate) fn ping_due(&self, last_ping: Instant) -> bool {
        last_ping.elapsed() >= PING_INTERVAL
    }

    /// Why the path is dead, if it is: nothing received for 45 s (12.3). (Work package WP-1
    /// changes this for QUIC, m2.md 4.4.)
    pub(crate) fn dead(&self) -> Option<String> {
        (self.last_received().elapsed() > DEAD_AFTER).then(|| "nothing received for 45 s".to_string())
    }

    /// True once the server said it is stopping (GOAWAY with SHUTDOWN).
    pub fn server_stopping(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// True once the server said it restarts in place (GOAWAY with RESTART, protocol.md 10.6):
    /// its sessions are kept, and the client reconnects after about 500 ms without back-off.
    pub fn server_restarting(&self) -> bool {
        self.restart.load(Ordering::SeqCst)
    }

    /// The client's address as the server sees it (the last PATH_INFO), if known.
    pub fn observed(&self) -> Option<SocketAddr> {
        *self.observed.lock().unwrap()
    }

    /// How each transport fared in the race that produced this connection, for the status
    /// line: "used", "failed: why", "not needed", "off" or "no port".
    pub fn attempts(&self) -> Vec<(Transport, String)> {
        self.attempts.lock().unwrap().clone()
    }

    /// Close the connection (it is dead, or no longer needed).
    pub fn close(&self, code: ErrorCode, why: &str) {
        self.connection.close(code, why);
    }

    pub(crate) fn received(&self) {
        *self.last_rx.lock().unwrap() = Instant::now();
    }

    pub(crate) fn last_received(&self) -> Instant {
        *self.last_rx.lock().unwrap()
    }

    pub(crate) fn ping(&self) {
        let _ = self.control.send(Message::Ping {
            data: micros(self.started),
        });
    }

    /// Check the path now (the network changed): PING, and close the connection when nothing
    /// at all arrives within `within`. The sessions on it then race the transports again
    /// instead of waiting for the dead path timers (protocol.md 12.3, 12.4).
    pub(crate) fn probe(self: &Arc<Self>, within: Duration) {
        let sent = Instant::now();
        self.ping();
        let conn = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(within).await;
            if let Some(conn) = conn.upgrade() {
                if conn.last_received() < sent && !conn.connection.is_closed() {
                    log::info(format_args!(
                        "no answer over {} after the network changed; reconnecting",
                        conn.transport()
                    ));
                    conn.close(ErrorCode::NO_ERROR, "path lost");
                }
            }
        });
    }

    /// The round-trip time: QUIC's own estimate, or the last PING.
    pub fn rtt(&self) -> Option<Duration> {
        self.connection.rtt().or(*self.rtt.lock().unwrap())
    }
}

async fn control_reader(conn: std::sync::Weak<Conn>, mut recv: BufReader<RecvStream>, started: Instant) {
    loop {
        let result = read_message(&mut recv, MAX_CONTROL).await;
        let Some(conn) = conn.upgrade() else { return };
        let message = match result {
            Ok(Some(m)) => m,
            Ok(None) => return conn.close(ErrorCode::PROTOCOL_VIOLATION, "control stream finished"),
            Err(FramingError::Io(_)) => return conn.close(ErrorCode::NO_ERROR, ""),
            Err(e) => return conn.close(e.code(), ""),
        };
        conn.received();
        match message {
            Message::Pong { data } => {
                let now = micros(started);
                if data <= now {
                    *conn.rtt.lock().unwrap() = Some(Duration::from_micros(now - data));
                }
            }
            Message::Ping { data } => {
                let _ = conn.control.send(Message::Pong { data });
            }
            Message::PathInfo { address, port, .. } => {
                *conn.observed.lock().unwrap() = address.map(|a| SocketAddr::new(a, port));
            }
            Message::GoAway { code, .. } => {
                log::debug(format_args!("GOAWAY {code}"));
                conn.goaway.store(true, Ordering::SeqCst);
                if code == ErrorCode::SHUTDOWN {
                    conn.shutdown.store(true, Ordering::SeqCst);
                }
                if code == ErrorCode::RESTART {
                    conn.restart.store(true, Ordering::SeqCst);
                }
            }
            Message::Error { code, message } => {
                log::debug(format_args!("connection error from the server: {code} {message}"));
                return conn.connection.close(ErrorCode::NO_ERROR, "");
            }
            Message::Unknown { .. } => {}
            _ => {
                return conn.close(
                    ErrorCode::PROTOCOL_VIOLATION,
                    "unexpected message on the control stream",
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GOAWAY with RESTART (protocol.md 10.6): the connection takes no new attachments, and the
    /// client knows the server keeps its sessions. A retired connection takes none either.
    #[tokio::test]
    async fn goaway_restart_and_retire() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let client = Connection::pipe(crate::mux::Role::Client, ar, aw, None, None);
        let server = Connection::pipe(crate::mux::Role::Server, br, bw, None, None);
        let far = tokio::spawn(async move {
            let (_, mut send, recv) = server.accept().await.unwrap();
            let mut recv = BufReader::new(recv);
            let _hello = read_message(&mut recv, MAX_HELLO).await.unwrap();
            let hello = Message::ServerHello {
                version: u64::from(proto::VERSION),
                nonce: [0; 32],
                capabilities: Vec::new(),
                implementation: "test".into(),
            };
            write_message(&mut send, &hello).await.unwrap();
            let restart = Message::GoAway {
                code: ErrorCode::RESTART,
                message: String::new(),
            };
            write_message(&mut send, &restart).await.unwrap();
            // Keep the connection open until the test is done
            while let Ok(Some(_)) = read_message(&mut recv, MAX_CONTROL).await {}
        });
        let conn = Conn::hello(client).await.unwrap();
        assert!(!conn.retiring());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !conn.server_restarting() {
            assert!(Instant::now() < deadline, "no GOAWAY seen");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!conn.usable() && !conn.server_stopping());
        assert!(conn.dead().is_none() && !conn.ping_due(Instant::now()));
        conn.retire();
        assert!(conn.retiring());
        far.abort();
    }
}
