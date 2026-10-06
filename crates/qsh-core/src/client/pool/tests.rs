//! The pool against fake transports, on paused time: what path memory does to the order and
//! timing of attempts, what is recorded, background probes, transport upgrades and keepalive
//! learning from PATH_INFO.

use std::collections::HashMap;
use std::net::IpAddr;

use super::*;
use crate::proto::message::{MAX_CONTROL, MAX_HELLO};
use crate::proto::{self, read_message, write_message, Message};
use crate::transport::{Connecting, Connection};
use tokio::io::BufReader;

/// The far end of a pipe connection that does the hello and then answers PINGs, or not.
async fn fake_server(conn: Connection, answer: bool) {
    let (_, mut send, recv) = conn.accept().await.unwrap();
    let mut recv = BufReader::new(recv);
    let _hello = read_message(&mut recv, MAX_HELLO).await.unwrap();
    let hello = Message::ServerHello {
        version: u64::from(proto::VERSION),
        nonce: [0; 32],
        capabilities: Vec::new(),
        implementation: "test".into(),
    };
    write_message(&mut send, &hello).await.unwrap();
    while let Ok(Some(m)) = read_message(&mut recv, MAX_CONTROL).await {
        if let (Message::Ping { data }, true) = (m, answer) {
            write_message(&mut send, &Message::Pong { data }).await.unwrap();
        }
    }
}

fn pipe_pair() -> (Connection, Connection) {
    let (a, b) = tokio::io::duplex(1 << 16);
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let client = Connection::pipe(crate::mux::Role::Client, ar, aw, None, None);
    let server = Connection::pipe(crate::mux::Role::Server, br, bw, None, None);
    (client, server)
}

/// A server that sends PINGs and never reads the PONGs cannot grow the client's queue of
/// answers without bound: beyond 16 waiting, a PING goes unanswered.
#[tokio::test]
async fn pings_without_reading_the_answers_queue_little() {
    let (client, server) = pipe_pair();
    // As after authentication: no limit on what the client sends
    server.set_preauth_limit(None);
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
        for data in 0..50_000 {
            write_message(&mut send, &Message::Ping { data }).await.unwrap();
        }
        // The control stream stays open, unread
        (send, recv)
    });
    let conn = Conn::hello(client).await.unwrap();
    let _streams = far.await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(conn.pongs_pending() <= 16, "{}", conn.pongs_pending());
}

/// After a network change every connection is probed: one that answers is kept, one that
/// answers nothing is closed (its sessions then race the transports again), and sessions
/// waiting out a back-off are woken.
///
/// On paused time: the probe's 300 ms pass only once everything else waits, so the PONG
/// over the in-memory pipe is always handled first, however slow the machine.
#[tokio::test(start_paused = true)]
async fn a_network_change_probes_connections_and_wakes_waiting_sessions() {
    for answer in [true, false] {
        let (client, server) = pipe_pair();
        let far = tokio::spawn(fake_server(server, answer));
        let conn = Conn::hello(client).await.unwrap();
        conn.probe(Duration::from_millis(300));
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(conn.connection.is_closed(), !answer, "answer: {answer}");
        far.abort();
    }
    let pool = Pool::with_memory(Arc::new(QuicClient::new()), None);
    let network = pool.network.clone();
    let waiting = tokio::spawn(async move { network.notified().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    pool.network_changed();
    tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("woken")
        .unwrap();
}

/// What an attempt to a (transport, port) does.
#[derive(Debug, Clone, Copy)]
enum Behaviour {
    /// The handshake completes after this long; the far end does the hello and answers PINGs.
    Connect(Duration),
    /// The handshake fails after this long.
    Fail(Duration, io::ErrorKind),
}

/// Fake transports: a behaviour per (transport, port), blocked (an 8 s timeout) by default;
/// every attempt's start is logged.
#[derive(Default)]
struct Fake {
    behaviour: Mutex<HashMap<(Transport, u16), Behaviour>>,
    log: Mutex<Vec<(Transport, u16, Instant)>>,
    epoch: Mutex<Option<Instant>>,
    /// Pushes messages to the far end of each connection made, newest last.
    servers: Mutex<Vec<mpsc::UnboundedSender<Message>>>,
}

impl Fake {
    fn new() -> Arc<Fake> {
        let fake = Arc::new(Fake::default());
        fake.restart_log();
        fake
    }

    fn set(&self, transport: Transport, port: u16, b: Behaviour) {
        self.behaviour.lock().unwrap().insert((transport, port), b);
    }

    fn restart_log(&self) {
        self.log.lock().unwrap().clear();
        *self.epoch.lock().unwrap() = Some(Instant::now());
    }

    /// The attempts started since the log was restarted, with their start in milliseconds.
    fn log(&self) -> Vec<(Transport, u16, u64)> {
        let epoch = self.epoch.lock().unwrap().unwrap();
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|&(t, p, at)| (t, p, at.duration_since(epoch).as_millis() as u64))
            .collect()
    }

    /// Send `m` from the far end of the newest connection.
    fn push(&self, m: Message) {
        self.servers.lock().unwrap().last().unwrap().send(m).unwrap();
    }
}

struct FakeConnector(Arc<Fake>);

impl Connector for FakeConnector {
    fn connect(&self, _target: &Target, attempt: &Attempt, _options: &quic::Options) -> Connecting {
        let (fake, attempt) = (self.0.clone(), *attempt);
        Box::pin(async move {
            fake.log
                .lock()
                .unwrap()
                .push((attempt.transport, attempt.port, Instant::now()));
            let behaviour = fake
                .behaviour
                .lock()
                .unwrap()
                .get(&(attempt.transport, attempt.port))
                .copied()
                .unwrap_or(Behaviour::Fail(Duration::from_secs(8), io::ErrorKind::TimedOut));
            match behaviour {
                Behaviour::Connect(after) => {
                    tokio::time::sleep(after).await;
                    let (client, server) = pipe_pair();
                    let (tx, rx) = mpsc::unbounded_channel();
                    fake.servers.lock().unwrap().push(tx);
                    tokio::spawn(far_end(server, rx));
                    Ok(client.pretend(attempt.transport))
                }
                Behaviour::Fail(after, kind) => {
                    tokio::time::sleep(after).await;
                    Err(io::Error::new(kind, "fake failure"))
                }
            }
        })
    }
}

/// The far end of a fake connection: the hello, PONGs, and whatever the test pushes.
async fn far_end(conn: Connection, mut push: mpsc::UnboundedReceiver<Message>) {
    let Some((_, mut send, recv)) = conn.accept().await else {
        return;
    };
    let mut recv = BufReader::new(recv);
    if !matches!(read_message(&mut recv, MAX_HELLO).await, Ok(Some(_))) {
        return;
    }
    let (tx, mut out) = mpsc::unbounded_channel::<Message>();
    let hello = Message::ServerHello {
        version: u64::from(proto::VERSION),
        nonce: [0; 32],
        capabilities: Vec::new(),
        implementation: "test".into(),
    };
    let _ = tx.send(hello);
    let pushed = tx.clone();
    tokio::spawn(async move {
        while let Some(m) = push.recv().await {
            if pushed.send(m).is_err() {
                return;
            }
        }
    });
    let writer = tokio::spawn(async move {
        while let Some(m) = out.recv().await {
            if write_message(&mut send, &m).await.is_err() {
                return;
            }
        }
    });
    while let Ok(Some(m)) = read_message(&mut recv, MAX_CONTROL).await {
        if let Message::Ping { data } = m {
            let _ = tx.send(Message::Pong { data });
        }
    }
    writer.abort();
    drop(conn);
}

const HOST: &str = "server.example";
const NET: &[u8] = b"home";
const OTHER_NET: &[u8] = b"cafe";

fn target(extra: &[(u16, bool, bool)]) -> Target {
    Target {
        host: HOST.into(),
        udp: 60443,
        tcp: 60443,
        fingerprint: crypto::Fingerprint([0; 32]),
        ssh: crate::transport::ssh::SshCommand::new("box"),
        extra_ports: extra
            .iter()
            .map(|&(port, udp, tcp)| crate::proto::bootstrap::ExtraPort { port, udp, tcp })
            .collect(),
    }
}

/// A pool on fake transports, with path memory in this process only, on network `net`.
fn pool(fake: &Arc<Fake>, net: &Arc<Mutex<Vec<u8>>>) -> Arc<Pool> {
    let net = net.clone();
    Pool::build(
        Arc::new(QuicClient::new()),
        Arc::new(FakeConnector(fake.clone())),
        None,
        Box::new(move || net.lock().unwrap().clone()),
    )
}

fn network(key: &[u8]) -> Arc<Mutex<Vec<u8>>> {
    Arc::new(Mutex::new(key.to_vec()))
}

fn entry(pool: &Pool, net: &[u8]) -> paths::Entry {
    pool.volatile.entry(HOST, net).expect("an entry")
}

/// Close a connection and wait until it is closed.
async fn close(conn: &Conn) {
    conn.close(ErrorCode::NO_ERROR, "");
    conn.connection.closed().await;
}

const S: fn(u64) -> Duration = Duration::from_secs;
const MS: fn(u64) -> Duration = Duration::from_millis;

/// S1 at the unit level: on a network that drops UDP, the first race waits for TLS (400 ms)
/// and learns, from the QUIC attempt that keeps running, that QUIC times out here; the next
/// race starts TLS at once and leaves QUIC out.
#[tokio::test(start_paused = true)]
async fn udp_blocked_is_remembered_and_the_next_race_starts_tls_at_once() {
    let fake = Fake::new();
    fake.set(Transport::Tls, 60443, Behaviour::Connect(MS(100)));
    let net = network(NET);
    let pool = pool(&fake, &net);
    let config = ClientConfig::new("box");
    let conn = pool.get(&target(&[]), &config).await.unwrap();
    assert_eq!(conn.transport(), Transport::Tls);
    assert_eq!(fake.log(), [(Transport::Quic, 60443, 0), (Transport::Tls, 60443, 400)]);
    let e = entry(&pool, NET);
    assert_eq!(e.transport(Transport::Tls).unwrap().port, Some(60443));
    assert_eq!(e.last(), Some(Transport::Tls));
    // QUIC started first and has had no answer while TLS, started 400 ms later, connected:
    // recorded as a timeout here at once, not 8 s later when the attempt gives up
    assert!(e.blocked(Transport::Quic, paths::now()), "{e:?}");
    // The attempt goes on in the background and does time out: not counted twice
    tokio::time::sleep(S(9)).await;
    let e = entry(&pool, NET);
    let fail = e.transport(Transport::Quic).unwrap().fail.clone().unwrap();
    assert_eq!((fail.kind(), fail.n), (Some(FailureKind::Timeout), 1));
    // The connection dies; the next race starts TLS at once and leaves QUIC out
    close(&conn).await;
    fake.restart_log();
    let conn = pool.get(&target(&[]), &config).await.unwrap();
    assert_eq!(conn.transport(), Transport::Tls);
    assert_eq!(fake.log(), [(Transport::Tls, 60443, 0)]);
    let status = conn.attempts();
    assert_eq!(status[0].0, Transport::Quic);
    assert!(status[0].1.starts_with("skipped"), "{status:?}");
    // Elsewhere nothing is known: the full race
    *net.lock().unwrap() = OTHER_NET.to_vec();
    close(&conn).await;
    fake.restart_log();
    pool.get(&target(&[]), &config).await.unwrap();
    assert_eq!(fake.log(), [(Transport::Quic, 60443, 0), (Transport::Tls, 60443, 400)]);
}

/// Path memory can be wrong: when the shortened race fails, the full race runs at once and
/// the failure marks go.
#[tokio::test(start_paused = true)]
async fn a_failed_shortened_race_is_followed_by_the_full_race_at_once() {
    let fake = Fake::new();
    let net = network(NET);
    let pool = pool(&fake, &net);
    let now = paths::now();
    pool.volatile.update(HOST, NET, now, |e| {
        e.succeeded(Transport::Tls, 60443, MS(300), now);
        e.failed(Transport::Quic, FailureKind::Timeout, now);
    });
    fake.set(
        Transport::Tls,
        60443,
        Behaviour::Fail(MS(100), io::ErrorKind::ConnectionRefused),
    );
    fake.set(Transport::Ssh, 0, Behaviour::Fail(MS(10), io::ErrorKind::Other));
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(50)));
    let conn = pool.get(&target(&[]), &ClientConfig::new("box")).await.unwrap();
    assert_eq!(conn.transport(), Transport::Quic);
    assert_eq!(
        fake.log(),
        [
            (Transport::Tls, 60443, 0),
            (Transport::Ssh, 0, 3000),
            (Transport::Quic, 60443, 3010)
        ]
    );
    let e = entry(&pool, NET);
    assert!(!e.blocked(Transport::Quic, paths::now()));
    assert!(e.transport(Transport::Quic).unwrap().ok.is_some());
    // TLS was refused: a fact about the daemon, not recorded as blocked
    assert!(!e.blocked(Transport::Tls, paths::now()));
}

/// m2.md 5.3: the primary port first, each extra port 300 ms later while the earlier ones
/// keep running; the port that won is remembered and tried first next time.
#[tokio::test(start_paused = true)]
async fn extra_ports_are_raced_in_order_and_the_winner_is_remembered() {
    let fake = Fake::new();
    fake.set(Transport::Quic, 443, Behaviour::Connect(MS(50)));
    let net = network(NET);
    let pool = pool(&fake, &net);
    let config = ClientConfig::new("box");
    let t = target(&[(443, true, true), (61443, true, false)]);
    let conn = pool.get(&t, &config).await.unwrap();
    assert_eq!(conn.transport(), Transport::Quic);
    assert_eq!(fake.log(), [(Transport::Quic, 60443, 0), (Transport::Quic, 443, 300)]);
    // The blocked primary port times out later: QUIC worked, so QUIC is not marked
    tokio::time::sleep(S(9)).await;
    let e = entry(&pool, NET);
    assert_eq!(e.transport(Transport::Quic).unwrap().port, Some(443));
    assert!(e.transport(Transport::Quic).unwrap().fail.is_none(), "{e:?}");
    close(&conn).await;
    fake.restart_log();
    pool.get(&t, &config).await.unwrap();
    assert_eq!(fake.log(), [(Transport::Quic, 443, 0)]);
}

/// No poisoning: when every attempt fails (the network is down), nothing is marked; a
/// failure is recorded only when another transport works from the same network within a
/// minute.
#[tokio::test(start_paused = true)]
async fn when_everything_fails_nothing_is_marked() {
    let fake = Fake::new();
    fake.set(Transport::Ssh, 0, Behaviour::Fail(MS(10), io::ErrorKind::Other));
    let net = network(NET);
    let pool = pool(&fake, &net);
    let config = ClientConfig::new("box");
    assert!(pool.get(&target(&[]), &config).await.is_err());
    assert!(pool.volatile.entry(HOST, NET).is_none());
    // More than a minute later QUIC works: the old TLS timeout says nothing any more
    tokio::time::sleep(S(61)).await;
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(50)));
    pool.get(&target(&[]), &config).await.unwrap();
    assert!(!entry(&pool, NET).blocked(Transport::Tls, paths::now()));

    // Within the minute it does
    let fake = Fake::new();
    fake.set(Transport::Ssh, 0, Behaviour::Fail(MS(10), io::ErrorKind::Other));
    let pool = super::tests::pool(&fake, &net);
    assert!(pool.get(&target(&[]), &config).await.is_err());
    tokio::time::sleep(S(5)).await;
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(50)));
    pool.get(&target(&[]), &config).await.unwrap();
    let e = entry(&pool, NET);
    assert!(e.blocked(Transport::Tls, paths::now()));
    assert!(!e.blocked(Transport::Quic, paths::now()));
}

/// m2.md 3.6: while connected, a blocked transport whose retry time came is probed in the
/// background (back-off on failure); once it works again the sessions move to it.
#[tokio::test(start_paused = true)]
async fn blocked_transports_are_probed_with_back_off_and_the_sessions_move_back() {
    let fake = Fake::new();
    fake.set(Transport::Tls, 60443, Behaviour::Connect(MS(100)));
    let net = network(NET);
    let pool = pool(&fake, &net);
    let config = ClientConfig::new("box");
    let conn = pool.get(&target(&[]), &config).await.unwrap();
    // A session attached on it
    let session = conn.clone();
    tokio::time::sleep(S(9)).await;
    assert!(entry(&pool, NET).blocked(Transport::Quic, paths::now()));
    let due = |pool: &Pool| {
        pool.volatile.update(HOST, NET, paths::now(), |e| {
            let quic = e.transports.quic.as_mut().unwrap();
            quic.fail.as_mut().unwrap().retry = paths::now() - 1;
        })
    };
    // Its retry time comes: one probe, which fails again; the next one is 5 minutes away
    fake.restart_log();
    due(&pool);
    tokio::time::sleep(S(10)).await;
    assert_eq!(fake.log(), [(Transport::Quic, 60443, 0)]);
    let e = entry(&pool, NET);
    let fail = e.transport(Transport::Quic).unwrap().fail.clone().unwrap();
    assert_eq!(fail.n, 2);
    assert!((295..=305).contains(&(fail.retry - paths::now())), "{fail:?}");
    tokio::time::sleep(S(10)).await;
    assert_eq!(fake.log().len(), 1, "no probe before the retry time");
    // UDP comes back: the next probe works, and the sessions move to QUIC
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(50)));
    due(&pool);
    tokio::time::sleep(S(2)).await;
    let e = entry(&pool, NET);
    assert!(e.transport(Transport::Quic).unwrap().fail.is_none(), "{e:?}");
    assert!(session.retiring(), "the old connection takes no new attachments");
    let connections = pool.connections();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].1, Transport::Quic);
    let moved = pool.get(&target(&[]), &config).await.unwrap();
    assert_eq!(moved.transport(), Transport::Quic);
    // Once its sessions are gone, the old connection is closed
    let old = Arc::downgrade(&conn);
    drop((conn, session));
    tokio::time::sleep(S(1)).await;
    assert!(old.upgrade().is_none());
}

fn path_info(sequence: u64, port: u16) -> Message {
    Message::PathInfo {
        sequence,
        address: Some(IpAddr::from([198, 51, 100, 7])),
        port,
    }
}

/// m2.md 4.2 and 4.3 through the pool: PATH_INFO reports a new address after the client was
/// idle for K: a NAT timed out, K halves (saved, and in effect at once through PING); not
/// while traffic flows, not within a minute of the last step, not right after the client
/// moved itself.
#[tokio::test(start_paused = true)]
async fn a_nat_rebinding_halves_the_keepalive_down_to_the_floor() {
    let fake = Fake::new();
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(10)));
    let net = network(NET);
    let pool = pool(&fake, &net);
    let conn = pool.get(&target(&[]), &ClientConfig::new("box")).await.unwrap();
    assert_eq!(conn.keepalive(), Some(S(20)));
    let pinged_long_ago = std::time::Instant::now() - S(30);
    assert!(!conn.ping_due(pinged_long_ago), "the QUIC keep-alive holds the NAT");
    fake.push(path_info(0, 40000));
    tokio::time::sleep(S(21)).await;
    fake.push(path_info(1, 40001));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(entry(&pool, NET).keepalive(), Some(S(10)));
    assert_eq!(conn.keepalive(), Some(S(10)));
    assert!(
        conn.ping_due(pinged_long_ago),
        "PING every 10 s now, below the 20 s of QUIC"
    );
    // Within a minute of that step: nothing
    tokio::time::sleep(S(20)).await;
    fake.push(path_info(2, 40002));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(conn.keepalive(), Some(S(10)));
    // While the client sends (input, acknowledgements): a NAT doing something else
    tokio::time::sleep(S(45)).await;
    for _ in 0..30 {
        conn.sent();
        tokio::time::sleep(MS(500)).await;
    }
    fake.push(path_info(3, 40003));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(conn.keepalive(), Some(S(10)));
    // Idle again for longer than K: 5 s, the floor
    tokio::time::sleep(S(11)).await;
    fake.push(path_info(4, 40004));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(conn.keepalive(), Some(S(5)));
    tokio::time::sleep(S(70)).await;
    fake.push(path_info(5, 40005));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(entry(&pool, NET).keepalive(), Some(S(5)));
    // Another network: its own interval; a change right after the move is the client's own
    *net.lock().unwrap() = OTHER_NET.to_vec();
    pool.network_changed();
    tokio::time::sleep(S(2)).await;
    assert_eq!(conn.keepalive(), Some(S(20)));
    fake.push(path_info(6, 40006));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(conn.keepalive(), Some(S(20)));
    assert!(pool
        .volatile
        .entry(HOST, OTHER_NET)
        .and_then(|e| e.keepalive())
        .is_none());
    // The configured interval: no learning
    let fake = Fake::new();
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(10)));
    let pool = super::tests::pool(&fake, &network(NET));
    let mut config = ClientConfig::new("box");
    config.keepalive = Keepalive::Every(S(30));
    let conn = pool.get(&target(&[]), &config).await.unwrap();
    assert_eq!(conn.keepalive(), Some(S(30)));
    fake.push(path_info(0, 1));
    tokio::time::sleep(S(31)).await;
    fake.push(path_info(1, 2));
    tokio::time::sleep(MS(100)).await;
    assert_eq!(conn.keepalive(), Some(S(30)));
}

/// QUIC liveness (m2.md 4.4): no PING, and dead only after max(45 s, 3 K) without a datagram;
/// TLS and the pipe keep the PING every 15 s.
#[tokio::test(start_paused = true)]
async fn liveness_rules_per_transport() {
    let fake = Fake::new();
    fake.set(Transport::Tls, 60443, Behaviour::Connect(MS(10)));
    let pool = pool(&fake, &network(NET));
    let mut config = ClientConfig::new("box");
    config.race.quic = None;
    let tls = pool.get(&target(&[]), &config).await.unwrap();
    assert_eq!(tls.keepalive(), None);
    assert!(tls.ping_due(std::time::Instant::now() - S(15)));
    assert!(!tls.ping_due(std::time::Instant::now() - S(14)));
    let fake = Fake::new();
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(10)));
    let pool = super::tests::pool(&fake, &network(NET));
    let mut config = ClientConfig::new("box");
    config.keepalive = Keepalive::Every(S(25));
    let quic = pool.get(&target(&[]), &config).await.unwrap();
    assert!(!quic.ping_due(std::time::Instant::now() - S(60)));
    assert!(quic.dead().is_none());
    // The fake far end sends nothing by itself: dead after 3 × 25 s, not 45 s
    tokio::time::sleep(S(50)).await;
    assert!(quic.dead().is_none());
    tokio::time::sleep(S(26)).await;
    assert_eq!(quic.dead().as_deref(), Some("nothing received for 75 s"));
}

/// A QUIC attempt marked as failing because a slower transport won the race is cleared at
/// once when its answer comes after all.
#[tokio::test(start_paused = true)]
async fn a_late_answer_clears_the_mark_of_a_lost_race() {
    let fake = Fake::new();
    fake.set(Transport::Quic, 60443, Behaviour::Connect(S(1)));
    fake.set(Transport::Tls, 60443, Behaviour::Connect(MS(100)));
    let pool = pool(&fake, &network(NET));
    let conn = pool.get(&target(&[]), &ClientConfig::new("box")).await.unwrap();
    assert_eq!(conn.transport(), Transport::Tls);
    assert!(entry(&pool, NET).blocked(Transport::Quic, paths::now()));
    tokio::time::sleep(S(2)).await;
    let e = entry(&pool, NET);
    assert!(!e.blocked(Transport::Quic, paths::now()), "{e:?}");
    assert!(e.transport(Transport::Quic).unwrap().ok.is_some());
    // TLS won the last race: on the same day it goes first next time
    assert_eq!(e.last(), Some(Transport::Tls));
}

/// The chaos scenario `udp-blocked-memory` (S1), exactly: a session over QUIC; UDP is blocked
/// mid-session and the connection dies; the reconnect wins on TLS while its QUIC attempt is
/// still unanswered; the client is killed a second later (no orderly end, QUIC's own 8 s
/// timeout never fires); a new process on the same network (`qsh attach`) starts TLS at once
/// and leaves QUIC out.
#[tokio::test(start_paused = true)]
async fn after_udp_is_blocked_mid_session_the_next_process_starts_tls_at_once() {
    let dir = std::env::temp_dir().join(format!("qsh-pool-s1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let file = dir.join("state/paths.json");
    let process = |fake: &Arc<Fake>| {
        let net = network(NET);
        Pool::build(
            Arc::new(QuicClient::new()),
            Arc::new(FakeConnector(fake.clone())),
            Some(PathMemory::open(&file)),
            Box::new(move || net.lock().unwrap().clone()),
        )
    };
    let config = ClientConfig::new("box");
    // A crossborder path: QUIC answers in 1 RTT, TLS in 2
    let fake = Fake::new();
    fake.set(Transport::Quic, 60443, Behaviour::Connect(MS(270)));
    fake.set(Transport::Tls, 60443, Behaviour::Connect(MS(540)));
    let first = process(&fake);
    let conn = first.get(&target(&[]), &config).await.unwrap();
    assert_eq!(conn.transport(), Transport::Quic);
    // UDP blocked mid-session: the connection dies, QUIC handshakes get no answer
    fake.set(Transport::Quic, 60443, Behaviour::Fail(S(8), io::ErrorKind::TimedOut));
    close(&conn).await;
    fake.restart_log();
    let conn = first.get(&target(&[]), &config).await.unwrap();
    assert_eq!(conn.transport(), Transport::Tls);
    // The remembered winner QUIC first, TLS 1.5 × its 270 ms handshake later
    assert_eq!(fake.log(), [(Transport::Quic, 60443, 0), (Transport::Tls, 60443, 405)]);
    // What the next process needs is on disk at once (written on a blocking thread)
    let on_disk = || PathMemory::open(&file).entry(HOST, NET);
    for _ in 0..500 {
        if on_disk().is_some_and(|e| e.blocked(Transport::Quic, paths::now())) {
            break;
        }
        std::thread::sleep(MS(10));
    }
    let e = on_disk().expect("written");
    assert!(e.blocked(Transport::Quic, paths::now()), "{e:?}");
    assert_eq!(e.last(), Some(Transport::Tls));
    // Killed: no Drop of the pool, nothing more written
    std::mem::forget(first);
    std::mem::forget(conn);

    // `qsh attach` in a new process, on the same network, UDP still blocked
    let fake = Fake::new();
    fake.set(Transport::Tls, 60443, Behaviour::Connect(MS(540)));
    let second = process(&fake);
    let started = Instant::now();
    let conn = second.get(&target(&[]), &config).await.unwrap();
    assert_eq!(conn.transport(), Transport::Tls);
    assert_eq!(fake.log(), [(Transport::Tls, 60443, 0)]);
    assert_eq!(started.elapsed(), MS(540), "one TLS handshake, nothing waited for");
    let planned = paths::plan(Some(&e), &target(&[]), &config.race, paths::now());
    assert_eq!(planned.skipped, [Transport::Quic]);
    assert_eq!(
        (planned.plan.attempts[0].transport, planned.plan.attempts[0].delay),
        (Transport::Tls, Duration::ZERO)
    );
    drop((conn, second));
    let _ = std::fs::remove_dir_all(&dir);
}
