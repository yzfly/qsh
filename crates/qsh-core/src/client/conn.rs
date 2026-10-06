//! One connection after the hello exchange (protocol.md section 5), with its control stream
//! served in the background: PING / PONG and the round-trip time, PATH_INFO, GOAWAY.
//!
//! Path intelligence (m2.md sections 3 and 4) builds on this: the observed address
//! ([`Conn::observed`]) and its changes, which the pool uses to detect NAT timeouts; the
//! round-trip time ([`Conn::rtt`]) and loss; how the race went ([`Conn::attempts`]); and the
//! liveness rules, which differ on QUIC (m2.md 4.4): no PING on an idle QUIC connection (its
//! keep-alive holds the NAT mapping), unless the network's learned interval fell below the
//! one the connection was created with, and "dead" means no UDP datagram for
//! max(45 s, 3 × the keepalive interval).
//!
//! Before a path is dead it can be *suspected* (m2.md 3.8): typed input unanswered and nothing
//! at all received (no message, no UDP datagram) for [`Conn::suspect_after`], which scales
//! with the path's round-trip time. A session that suspects its connection says so
//! ([`Conn::suspect`]); the pool then races the transports in the background without giving
//! the connection up, and when another connection answers first it moves the sessions there
//! ([`Conn::abandon`]).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::BufReader;
use tokio::sync::{mpsc, watch};

use crate::proto::message::{MAX_CONTROL, MAX_HELLO};
use crate::proto::{read_message, write_message, ErrorCode, FramingError, Message};
use crate::transport::{Connection, RecvStream, Transport};
use crate::{log, proto};

/// Send PING this often on an attached connection over TLS or the pipe (section 12.3).
const PING_INTERVAL: Duration = Duration::from_secs(15);
/// Nothing received for this long: the path is dead.
const DEAD_AFTER: Duration = Duration::from_secs(45);
/// Sends this far apart belong to different bursts of client activity.
const BURST_GAP: Duration = Duration::from_secs(1);
/// A change of address reaches the client up to this long after the packet that caused it
/// (the server looks every 500 ms, then one trip back).
const REBIND_SLACK: Duration = Duration::from_secs(2);
/// PONGs waiting to be written, at most: beyond, a PING is not answered.
const PENDING_PONGS: usize = 16;
/// Typed input unanswered, and nothing at all received, for at least this long before a
/// connection is suspected, however short its round trip (m2.md 3.8): below it a phone's radio
/// waking up, a Wi-Fi scan or a burst of losses would start races for nothing.
pub(crate) const SUSPECT_MIN: Duration = Duration::from_secs(2);
/// A false alarm (the path answered while the other transports were raced) raises the
/// connection's threshold to this many times the silence it showed …
const FALSE_ALARM_FACTOR: f64 = 1.5;
/// … but not beyond this: the hard limit for typed input is 8 s (protocol.md 12.3).
const SUSPECT_MAX: Duration = Duration::from_secs(6);

/// A point in a connection's life: when, how many messages and how many UDP datagrams it had
/// received by then ([`Conn::mark`], [`Conn::heard_since`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Mark {
    pub(crate) at: tokio::time::Instant,
    messages: u64,
    datagrams: u64,
}

/// The round-trip time from the connection's own exchanges (the hello, PING / PONG), smoothed
/// as TCP and QUIC do (RFC 6298 section 2, RFC 9002 section 5.3).
#[derive(Debug, Clone, Copy)]
struct RttEstimate {
    srtt: Duration,
    rttvar: Duration,
}

impl RttEstimate {
    fn first(sample: Duration) -> RttEstimate {
        RttEstimate {
            srtt: sample,
            rttvar: sample / 2,
        }
    }

    fn update(&mut self, sample: Duration) {
        self.rttvar = (self.rttvar * 3 + self.srtt.abs_diff(sample)) / 4;
        self.srtt = (self.srtt * 7 + sample) / 8;
    }
}

/// When the client sent something other than a keepalive (m2.md 4.2, condition 3), on
/// tokio's clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Activity {
    /// The last send.
    last: tokio::time::Instant,
    /// The last silence of at least [`BURST_GAP`]: from its last send to the next one.
    gap: Option<(tokio::time::Instant, tokio::time::Instant)>,
}

impl Activity {
    pub(crate) fn new(now: tokio::time::Instant) -> Activity {
        Activity { last: now, gap: None }
    }

    pub(crate) fn sent(&mut self, now: tokio::time::Instant) {
        if now.saturating_duration_since(self.last) >= BURST_GAP {
            self.gap = Some((self.last, now));
        }
        self.last = now;
    }

    /// How long the client had been silent when a change of address that was reported at
    /// `arrival` happened (within [`REBIND_SLACK`] before it): the current silence, or the one
    /// a burst that started since then ended; zero while traffic flowed.
    pub(crate) fn idle_before(&self, arrival: tokio::time::Instant) -> Duration {
        let window = arrival.checked_sub(REBIND_SLACK).unwrap_or(arrival);
        if self.last <= window {
            return arrival.saturating_duration_since(self.last);
        }
        match self.gap {
            Some((start, end)) if end >= window => end.saturating_duration_since(start),
            _ => Duration::ZERO,
        }
    }
}

/// The server reported a new address for the client (PATH_INFO, protocol.md 5.6).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PathChange {
    /// When it arrived.
    pub(crate) at: tokio::time::Instant,
    /// How long the client had been sending nothing but keepalives ([`Activity::idle_before`]).
    pub(crate) idle: Duration,
    /// The address before.
    pub(crate) from: SocketAddr,
    /// The address now.
    pub(crate) to: SocketAddr,
}

/// The optional features a client offers in its hello (protocol.md 5.4), and those the server
/// then enabled on the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Offer {
    /// `snapshot` (7.8): the server may send SNAPSHOT to attachments that accept it.
    pub snapshot: bool,
    /// `zstd` (7.12): the server may compress output.
    pub zstd: bool,
}

impl Offer {
    /// What a client with `config` offers: snapshots unless `catchup` is off, compression
    /// unless `compression` is off or this build has no zstd (m2.md 6.7, 7).
    pub fn of(config: &super::ClientConfig) -> Offer {
        Offer {
            snapshot: config.catchup != crate::config::Catchup::Off,
            zstd: crate::codec::AVAILABLE && config.compression != crate::config::Compression::Off,
        }
    }

    fn names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.snapshot {
            names.push(proto::caps::SNAPSHOT.to_string());
        }
        if self.zstd {
            names.push(proto::caps::ZSTD.to_string());
        }
        names
    }
}

/// A connection after the hello exchange, with its control stream served in the background.
pub struct Conn {
    pub(crate) connection: Connection,
    pub(crate) nonce: [u8; 32],
    /// The capabilities negotiated.
    pub(crate) capabilities: Offer,
    control: mpsc::UnboundedSender<Message>,
    /// PONGs queued for the control stream writer, not written yet (at most [`PENDING_PONGS`]).
    pongs: Arc<std::sync::atomic::AtomicUsize>,
    /// When anything last arrived, on tokio's clock.
    last_rx: Mutex<tokio::time::Instant>,
    /// Messages received so far.
    rx_count: std::sync::atomic::AtomicU64,
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
    /// When the client sent something other than a keepalive: ATTACH, INPUT, INPUT_EOF, ACK,
    /// RESIZE, KEY_CONFIRM or HANGUP (m2.md 4.2, condition 3).
    activity: Mutex<Activity>,
    /// The QUIC keep-alive interval the connection was created with; None: not QUIC (or not
    /// made by the pool), PING every 15 s.
    quic_keepalive: Mutex<Option<Duration>>,
    /// The keepalive interval of the network the connection is on now (m2.md 4.4).
    network_keepalive: Mutex<Option<Duration>>,
    /// UDP datagrams received, and when that count last grew (QUIC liveness).
    udp_rx: Mutex<(u64, tokio::time::Instant)>,
    /// The round-trip time from the hello and the PONGs.
    estimate: Mutex<Option<RttEstimate>>,
    /// Raised by false alarms: the connection is suspected only after this much silence.
    suspect_floor: Mutex<Duration>,
    /// A background race for this connection is running, or failed (m2.md 3.8).
    rescuing: AtomicBool,
    /// Where suspicions go (the pool's monitor of this connection).
    suspicions: Mutex<Option<mpsc::UnboundedSender<Mark>>>,
    /// The pool moved the sessions to another connection because this one stopped answering.
    abandoned: AtomicBool,
    /// Tells the sessions attached here at once when the connection is abandoned.
    moved: watch::Sender<bool>,
    /// Where changes of the observed address go.
    path_changes: Mutex<Option<mpsc::UnboundedSender<PathChange>>>,
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
        Conn::hello_offering(connection, Offer::default()).await
    }

    /// [`Conn::hello`], offering the capabilities of `offer`.
    pub async fn hello_offering(connection: Connection, offer: Offer) -> io::Result<Arc<Conn>> {
        let (_, mut send, recv) = connection.open().await?;
        let asked = tokio::time::Instant::now();
        let hello = Message::ClientHello {
            versions: vec![u64::from(proto::VERSION)],
            capabilities: offer.names(),
            implementation: proto::IMPLEMENTATION.into(),
        };
        write_message(&mut send, &hello).await?;
        let mut recv = BufReader::new(recv);
        let (nonce, negotiated) = match read_message(&mut recv, MAX_HELLO).await {
            Ok(Some(Message::ServerHello {
                version,
                nonce,
                capabilities,
                ..
            })) => {
                // Only capabilities we offered (5.4)
                let offered = offer.names();
                if version != u64::from(proto::VERSION) || capabilities.iter().any(|c| !offered.contains(c)) {
                    connection.close(ErrorCode::PROTOCOL_VIOLATION, "");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SERVER_HELLO"));
                }
                let has = |name: &str| capabilities.iter().any(|c| c == name);
                (
                    nonce,
                    Offer {
                        snapshot: has(proto::caps::SNAPSHOT),
                        zstd: has(proto::caps::ZSTD),
                    },
                )
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
        // The hello exchange is the first sample of the round trip
        let hello_rtt = asked.elapsed();
        let (control, mut rx) = mpsc::unbounded_channel::<Message>();
        let pongs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Instant::now();
        let conn = Arc::new(Conn {
            connection,
            nonce,
            capabilities: negotiated,
            control,
            pongs: pongs.clone(),
            last_rx: Mutex::new(tokio::time::Instant::now()),
            rx_count: std::sync::atomic::AtomicU64::new(0),
            rtt: Mutex::new(None),
            observed: Mutex::new(None),
            goaway: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            restart: AtomicBool::new(false),
            retiring: AtomicBool::new(false),
            activity: Mutex::new(Activity::new(tokio::time::Instant::now())),
            quic_keepalive: Mutex::new(None),
            network_keepalive: Mutex::new(None),
            udp_rx: Mutex::new((0, tokio::time::Instant::now())),
            estimate: Mutex::new(Some(RttEstimate::first(hello_rtt))),
            suspect_floor: Mutex::new(SUSPECT_MIN),
            rescuing: AtomicBool::new(false),
            suspicions: Mutex::new(None),
            abandoned: AtomicBool::new(false),
            moved: watch::channel(false).0,
            path_changes: Mutex::new(None),
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
                if matches!(m, Message::Pong { .. }) {
                    pongs.fetch_sub(1, Ordering::SeqCst);
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
        self.activity.lock().unwrap().sent(tokio::time::Instant::now());
    }

    /// When the client last sent something other than a keepalive: ATTACH, INPUT, INPUT_EOF,
    /// ACK, RESIZE, KEY_CONFIRM or HANGUP (m2.md 4.2, condition 3).
    pub fn last_sent(&self) -> Instant {
        self.activity.lock().unwrap().last.into_std()
    }

    /// The connection is QUIC and was created with keep-alive interval `k`; `network` is the
    /// interval of the network it is on (m2.md 4.4).
    pub(crate) fn set_keepalive(&self, quic: Option<Duration>, network: Duration) {
        *self.quic_keepalive.lock().unwrap() = quic;
        *self.network_keepalive.lock().unwrap() = Some(network);
    }

    /// The network's interval changed (learning, or another network).
    pub(crate) fn set_network_keepalive(&self, k: Duration) {
        *self.network_keepalive.lock().unwrap() = Some(k);
    }

    /// The keepalive interval in effect on a QUIC connection: the one it was created with,
    /// or the network's when that is smaller (the client then sends PING at that interval
    /// while idle). None on TLS and the pipe (PING every 15 s).
    pub fn keepalive(&self) -> Option<Duration> {
        let quic = (*self.quic_keepalive.lock().unwrap())?;
        Some(match *self.network_keepalive.lock().unwrap() {
            Some(k) => k.min(quic),
            None => quic,
        })
    }

    /// Changes of the observed address go to `tx` from now on.
    pub(crate) fn watch_path(&self, tx: mpsc::UnboundedSender<PathChange>) {
        *self.path_changes.lock().unwrap() = Some(tx);
    }

    /// Whether an attachment that last sent PING at `last_ping` should send one now
    /// (protocol.md 12.3, m2.md 4.4): every 15 s over TLS and the pipe; over QUIC only while
    /// the network's keepalive interval is below the one the connection was created with,
    /// every that interval while the client sends nothing else.
    pub(crate) fn ping_due(&self, last_ping: tokio::time::Instant) -> bool {
        let Some(quic) = *self.quic_keepalive.lock().unwrap() else {
            return last_ping.elapsed() >= PING_INTERVAL;
        };
        let Some(k) = self.keepalive().filter(|&k| k < quic) else {
            return false;
        };
        last_ping.elapsed() >= k && self.activity.lock().unwrap().last.elapsed() >= k
    }

    /// Why the path is dead, if it is (protocol.md 12.3): nothing received for 45 s; over
    /// QUIC, no UDP datagram (the server's acknowledgements of the keep-alives count) for
    /// max(45 s, 3 × the keepalive interval) (m2.md 4.4).
    pub(crate) fn dead(&self) -> Option<String> {
        let last_rx = *self.last_rx.lock().unwrap();
        let Some(k) = self.keepalive() else {
            return (last_rx.elapsed() > DEAD_AFTER).then(|| "nothing received for 45 s".to_string());
        };
        let limit = DEAD_AFTER.max(k * 3);
        let last = last_rx.max(self.udp_received());
        (last.elapsed() > limit).then(|| format!("nothing received for {} s", limit.as_secs()))
    }

    /// When the QUIC connection last received a UDP datagram, as far as it can tell: when
    /// its count last grew, seen at the latest call.
    fn udp_received(&self) -> tokio::time::Instant {
        let mut udp = self.udp_rx.lock().unwrap();
        if let Some(c) = self.connection.quic_connection() {
            let n = c.stats().udp_rx.datagrams;
            if n != udp.0 {
                *udp = (n, tokio::time::Instant::now());
            }
        }
        udp.1
    }

    /// The QUIC loss ratio of the connection so far: lost packets per packet sent. None on TLS
    /// and the pipe, and before anything was sent.
    pub fn loss(&self) -> Option<f64> {
        let path = self.connection.quic_connection()?.stats().path;
        (path.sent_packets > 0).then(|| path.lost_packets as f64 / path.sent_packets as f64)
    }

    /// Send GOAWAY with `code` (the client closes the connection on purpose, protocol.md 5.7).
    pub(crate) fn goaway(&self, code: ErrorCode) {
        let _ = self.control.send(Message::GoAway {
            code,
            message: String::new(),
        });
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
        *self.last_rx.lock().unwrap() = tokio::time::Instant::now();
        self.rx_count.fetch_add(1, Ordering::SeqCst);
    }

    /// When a message last arrived, on tokio's clock.
    pub(crate) fn last_received(&self) -> tokio::time::Instant {
        *self.last_rx.lock().unwrap()
    }

    /// UDP datagrams received so far (QUIC; 0 on the other transports).
    fn datagrams(&self) -> u64 {
        self.connection
            .quic_connection()
            .map_or(0, |c| c.stats().udp_rx.datagrams)
    }

    /// Now, for [`Conn::heard_since`].
    pub(crate) fn mark(&self) -> Mark {
        Mark {
            at: tokio::time::Instant::now(),
            messages: self.rx_count.load(Ordering::SeqCst),
            datagrams: self.datagrams(),
        }
    }

    /// Whether anything at all arrived since `mark`: a message, or over QUIC a UDP datagram
    /// (an acknowledgement of a keep-alive or of a tail probe proves the path as well).
    pub(crate) fn heard_since(&self, mark: &Mark) -> bool {
        self.rx_count.load(Ordering::SeqCst) > mark.messages || self.datagrams() > mark.datagrams
    }

    /// How long typed input may go unanswered, with nothing at all received, before the
    /// connection is suspected (m2.md 3.8): `max(2 s, 4 × SRTT + 4 × RTTVAR)`, the smoothed
    /// round trip QUIC's own on QUIC, the variation from the hello, the handshake and the
    /// PONGs (half the round trip before a second sample), and at least what false alarms on this connection
    /// showed. Four times the round trip covers a lost packet and its retransmission, the
    /// variation a path whose delay jumps (a phone's radio, queues).
    pub(crate) fn suspect_after(&self) -> Duration {
        let estimate = *self.estimate.lock().unwrap();
        let srtt = self.connection.rtt().or(estimate.map(|e| e.srtt));
        let rttvar = estimate.map(|e| e.rttvar).or(srtt.map(|s| s / 2));
        let threshold = match (srtt, rttvar) {
            (Some(s), Some(v)) => s * 4 + v * 4,
            _ => Duration::ZERO,
        };
        threshold.max(*self.suspect_floor.lock().unwrap())
    }

    /// A round-trip sample from outside the connection's own exchanges: the handshake that
    /// made it (the pool, [`Conn::handshake_took`]).
    fn rtt_sample(&self, sample: Duration) {
        let mut estimate = self.estimate.lock().unwrap();
        match estimate.as_mut() {
            Some(e) => e.update(sample),
            None => *estimate = Some(RttEstimate::first(sample)),
        }
    }

    /// The transport handshake that made this connection took `took`: a second sample of the
    /// round trip besides the hello (m2.md 3.8), so that one lucky sample (a packet that a
    /// queue let through early) does not make the threshold short. QUIC's handshake is one
    /// round trip, TCP's and TLS 1.3's two; the ssh pipe's says nothing (many round trips and
    /// a process start).
    pub(crate) fn handshake_took(&self, took: Duration) {
        match self.transport() {
            Transport::Quic => self.rtt_sample(took),
            Transport::Tls => self.rtt_sample(took / 2),
            Transport::Ssh => {}
        }
    }

    /// Typed input since `mark` was not answered, and nothing at all arrived, for
    /// [`Conn::suspect_after`]: ask the pool to race the transports in the background (m2.md
    /// 3.8). Once per connection while that race runs, and not again after it failed (the
    /// dead path timers decide then). False when nobody was asked.
    pub(crate) fn suspect(&self, mark: Mark) -> bool {
        let suspicions = self.suspicions.lock().unwrap();
        let Some(tx) = suspicions.as_ref() else {
            return false;
        };
        if self.rescuing.swap(true, Ordering::SeqCst) {
            return false;
        }
        if tx.send(mark).is_err() {
            self.rescuing.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Suspicions of this connection go to `tx` from now on (the pool's monitor).
    pub(crate) fn watch_suspicions(&self, tx: mpsc::UnboundedSender<Mark>) {
        *self.suspicions.lock().unwrap() = Some(tx);
    }

    /// The background race for this connection ended without moving its sessions. `silence`:
    /// the path answered after this long without anything (a false alarm), which raises the
    /// threshold of this connection; None: the race failed, and the connection is not
    /// suspected again.
    pub(crate) fn rescue_over(&self, silence: Option<Duration>) {
        if let Some(silence) = silence {
            let mut floor = self.suspect_floor.lock().unwrap();
            *floor = (*floor).max(silence.mul_f64(FALSE_ALARM_FACTOR)).min(SUSPECT_MAX);
            self.rescuing.store(false, Ordering::SeqCst);
        }
    }

    /// The path stopped answering and the pool moved this connection's sessions to another
    /// one (m2.md 3.8): unlike [`Conn::retire`], each session leaves at once, with its
    /// unacknowledged input, which it resends after the next ATTACHED from the offset the
    /// server reports (protocol.md 7.3), so nothing is lost or repeated.
    pub(crate) fn abandon(&self) {
        self.retiring.store(true, Ordering::SeqCst);
        self.abandoned.store(true, Ordering::SeqCst);
        self.moved.send_replace(true);
    }

    /// True after [`Conn::abandon`].
    pub(crate) fn abandoned(&self) -> bool {
        self.abandoned.load(Ordering::SeqCst)
    }

    /// Changes to true when the connection is abandoned.
    pub(crate) fn moved(&self) -> watch::Receiver<bool> {
        self.moved.subscribe()
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
        let before = self.rx_count.load(Ordering::SeqCst);
        self.ping();
        let conn = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(within).await;
            if let Some(conn) = conn.upgrade() {
                if conn.rx_count.load(Ordering::SeqCst) == before && !conn.connection.is_closed() {
                    log::info(format_args!(
                        "no answer over {} after the network changed; reconnecting",
                        conn.transport()
                    ));
                    conn.close(ErrorCode::NO_ERROR, "path lost");
                }
            }
        });
    }

    /// The server reported a new address: tell the pool (keepalive learning, m2.md 4.2).
    fn path_changed(&self, from: SocketAddr, to: SocketAddr) {
        log::debug(format_args!("the server sees this client at {to} now (was {from})"));
        let at = tokio::time::Instant::now();
        let idle = self.activity.lock().unwrap().idle_before(at);
        if let Some(tx) = self.path_changes.lock().unwrap().as_ref() {
            let _ = tx.send(PathChange { at, idle, from, to });
        }
    }

    /// PONGs waiting to be written, for the tests.
    #[cfg(test)]
    pub(crate) fn pongs_pending(&self) -> usize {
        self.pongs.load(Ordering::SeqCst)
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
                    let sample = Duration::from_micros(now - data);
                    *conn.rtt.lock().unwrap() = Some(sample);
                    conn.rtt_sample(sample);
                }
            }
            Message::Ping { data } => {
                // Answered unless too many answers wait to be written already: a server that
                // keeps sending PINGs without reading the answers cannot grow the queue
                if conn.pongs.fetch_add(1, Ordering::SeqCst) < PENDING_PONGS {
                    let _ = conn.control.send(Message::Pong { data });
                } else {
                    conn.pongs.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Message::PathInfo { address, port, .. } => {
                let now = address.map(|a| SocketAddr::new(a, port));
                let before = std::mem::replace(&mut *conn.observed.lock().unwrap(), now);
                if let (Some(from), Some(to)) = (before, now) {
                    if from != to {
                        conn.path_changed(from, to);
                    }
                }
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
        assert!(conn.dead().is_none() && !conn.ping_due(tokio::time::Instant::now()));
        conn.retire();
        assert!(conn.retiring());
        far.abort();
    }
}
