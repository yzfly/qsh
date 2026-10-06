//! Faults stay local (protocol.md 7.8.4 and 7.8.7): against the daemon in this process, with
//! faults injected by the `test-hooks` feature (`qsh_core::fault::test_hooks`), each on data
//! that contains its own marker, so that the tests do not disturb each other:
//!
//! - a session whose screen model panics goes on, byte for byte, without snapshots; another
//!   session of the same daemon keeps its model; the daemon keeps serving;
//! - a panic of the zstd encoder sends that output uncompressed;
//! - a panic of the client's zstd decoder breaks the connection; the second one turns
//!   compression off for that server, and the session ends normally;
//! - a snapshot that fails the content profile is refused once, and the session attaches again
//!   without snapshots, without a reconnect loop.
//!
//! Every attachment is throttled to 300 kB/s (`QSH_TEST_THROTTLE`), so that the daemon
//! compresses; the outputs are small enough that no backlog builds up where it must not.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qsh_core::client::store::SavedSession;
use qsh_core::client::{ClientConfig, Input, Pool, Session, Status, Terminal};
use qsh_core::codec;
use qsh_core::config::Catchup;
use qsh_core::crypto::{Fingerprint, SessionKey};
use qsh_core::fault::test_hooks::{panic_on, Hook};
use qsh_core::proto::bootstrap::{parse_reply, Credentials, Op, Reply};
use qsh_core::proto::message::{ATTACH_ACCEPT_SNAPSHOT, ATTACH_FRESH, LATEST, MAX_CONTROL, MAX_HELLO, MAX_TERMINAL};
use qsh_core::proto::zstd::MAX_ZSTD_CONTENT;
use qsh_core::proto::{read_message, write_message, Message, WindowSize};
use qsh_core::server::{Daemon, DaemonLauncher, ServerConfig};
use qsh_core::transport::{tls, Connection, RecvStream, SendStream};
use qsh_core::Paths;
use tokio::io::BufReader;
use tokio::sync::{mpsc, oneshot};

const STARTUP: Duration = Duration::from_secs(30);

struct TestDaemon {
    paths: Paths,
    dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl TestDaemon {
    async fn start(name: &str) -> TestDaemon {
        // Read by each attachment when it starts (builds with the `test-hooks` feature)
        std::env::set_var("QSH_TEST_THROTTLE", "300000");
        let dir = PathBuf::from(format!("/tmp/qf-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::under(&dir);
        let mut config = ServerConfig::new(paths.clone());
        config.ports = 0..=0;
        config.shell = Some("/bin/sh".into());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            Daemon::run_until(config, async {
                let _ = stopped.await;
            })
            .await
            .map_err(|e| e.to_string())
        });
        let deadline = tokio::time::Instant::now() + STARTUP;
        loop {
            if let Ok(Some(_)) = paths.connect_private(&paths.control_socket()).await {
                break;
            }
            assert!(!task.is_finished(), "the daemon {name} ended before it was ready");
            assert!(tokio::time::Instant::now() < deadline, "the daemon {name} is not ready");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        TestDaemon {
            paths,
            dir,
            stop: Some(stop),
            task,
        }
    }

    /// A tty session running `command`, 80 × 24.
    async fn tty(&self, command: &str) -> Credentials {
        let command = command.replace('\\', "\\\\").replace('"', "\\\"");
        let request = format!(r#"{{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"{command}"}}"#);
        let launcher = DaemonLauncher {
            program: "/bin/false".into(),
            args: vec![],
        };
        let mut out = Vec::new();
        let line = format!("{request}\n");
        qsh_core::server::bootstrap(&self.paths, &launcher, line.as_bytes(), &mut out)
            .await
            .unwrap();
        match parse_reply(&out, Op::New).unwrap() {
            Reply::Credentials(c) => c,
            other => panic!("{other:?}"),
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A protocol-level client: one connection after the hello.
struct Client {
    conn: Connection,
    nonce: [u8; 32],
    _ctl_send: SendStream,
    _ctl_recv: BufReader<RecvStream>,
}

async fn hello(c: &Credentials, offer: &[&str]) -> Client {
    let pin = Fingerprint::from_hex(&c.cert_sha256).unwrap();
    let conn = Connection::tls_client(tls::connect("127.0.0.1", c.tcp, pin).await.unwrap());
    let (_, mut ctl_send, r) = conn.open().await.unwrap();
    write_message(
        &mut ctl_send,
        &Message::ClientHello {
            versions: vec![1],
            capabilities: offer.iter().map(|s| s.to_string()).collect(),
            implementation: "test".into(),
        },
    )
    .await
    .unwrap();
    let mut ctl_recv = BufReader::new(r);
    let Some(Message::ServerHello {
        nonce, capabilities, ..
    }) = read_message(&mut ctl_recv, MAX_HELLO).await.unwrap()
    else {
        panic!("no SERVER_HELLO")
    };
    assert_eq!(capabilities.len(), offer.len(), "{capabilities:?}");
    Client {
        conn,
        nonce,
        _ctl_send: ctl_send,
        _ctl_recv: ctl_recv,
    }
}

struct Channel {
    send: SendStream,
    recv: BufReader<RecvStream>,
}

/// Attach; the channel and the output offset it starts at.
async fn attach(client: &Client, c: &Credentials, output_received: u64, flags: u64) -> (Channel, u64) {
    let session: [u8; 16] = qsh_core::crypto::unhex(&c.session).unwrap();
    let key = SessionKey::from_hex(&c.key).unwrap();
    let (_, mut send, recv) = client.conn.open().await.unwrap();
    let cb = client.conn.channel_binding(&session, &client.nonce).unwrap();
    write_message(
        &mut send,
        &Message::Attach {
            session,
            proof: key.proof(&cb),
            output_received,
            size: WindowSize::new(80, 24),
            flags,
            error_received: None,
        },
    )
    .await
    .unwrap();
    let mut recv = BufReader::new(recv);
    match tokio::time::timeout(Duration::from_secs(10), read_message(&mut recv, MAX_TERMINAL)).await {
        Ok(Ok(Some(Message::Attached { output_start, .. }))) => (Channel { send, recv }, output_start),
        other => panic!("not attached: {other:?}"),
    }
}

/// What a client keeps of the output stream, offsets checked.
#[derive(Default)]
struct Stream {
    received: u64,
    out: Vec<u8>,
    gaps: u64,
    snapshots: u64,
    /// OUTPUT_ZSTD frames.
    frames: u64,
    /// OUTPUT messages (uncompressed), as received.
    plain: Vec<Vec<u8>>,
}

impl Stream {
    /// Take one message; the ACK to send.
    fn take(&mut self, m: Message) -> Option<Message> {
        match m {
            Message::Output { offset, data } => {
                assert_eq!(offset, self.received, "OUTPUT offset");
                self.received += data.len() as u64;
                self.out.extend_from_slice(&data);
                self.plain.push(data);
            }
            Message::OutputZstd { offset, frame } => {
                assert_eq!(offset, self.received, "OUTPUT_ZSTD offset");
                let data = codec::decompress(&frame, MAX_ZSTD_CONTENT).expect("a valid frame");
                self.frames += 1;
                self.received += data.len() as u64;
                self.out.extend(data);
            }
            Message::OutputGap { from, to } => {
                assert_eq!(from, self.received, "OUTPUT_GAP from");
                self.gaps += 1;
                self.received = to;
            }
            Message::Snapshot { offset, flags, .. } => {
                // Whole snapshots only count; the screen is not kept
                if flags & qsh_core::proto::message::SNAPSHOT_FINAL != 0 {
                    self.snapshots += 1;
                    self.received = offset;
                }
                return None;
            }
            Message::Ack { .. } => return None,
            other => panic!("unexpected {other:?}"),
        }
        Some(Message::Ack {
            received: self.received,
            error_received: None,
        })
    }

    fn shows(&self, needle: &str) -> bool {
        self.out.windows(needle.len()).any(|w| w == needle.as_bytes())
    }
}

/// Read and acknowledge until `done`; panics after `limit`.
async fn pump(ch: &mut Channel, s: &mut Stream, limit: Duration, mut done: impl FnMut(&Stream) -> bool) {
    let start = Instant::now();
    while !done(s) {
        let left = limit.checked_sub(start.elapsed()).unwrap_or_default();
        assert!(!left.is_zero(), "not done within {limit:?}");
        match tokio::time::timeout(left, read_message(&mut ch.recv, MAX_TERMINAL)).await {
            Ok(Ok(Some(m))) => {
                if let Some(ack) = s.take(m) {
                    write_message(&mut ch.send, &ack).await.unwrap();
                }
            }
            Ok(other) => panic!("the channel ended: {other:?}"),
            Err(_) => panic!("not done within {limit:?}"),
        }
    }
}

/// Read for `time`, acknowledging, whatever comes.
async fn pump_for(ch: &mut Channel, s: &mut Stream, time: Duration) {
    let until = tokio::time::Instant::now() + time;
    while let Ok(Ok(Some(m))) = tokio::time::timeout_at(until, read_message(&mut ch.recv, MAX_TERMINAL)).await {
        if let Some(ack) = s.take(m) {
            write_message(&mut ch.send, &ack).await.unwrap();
        }
    }
}

/// `seq FROM TO` as a terminal shows it.
fn seq(from: u32, to: u32) -> String {
    (from..=to).map(|i| format!("{i}\r\n")).collect()
}

/// A session whose screen model panics goes on without its model: every byte of its output
/// arrives, in order; where a snapshot would have been sent there is none; it still takes
/// input. Another session on the same daemon keeps its model (an attach at LATEST gets its
/// resync snapshot), and the daemon starts new sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_screen_model_costs_only_its_sessions_snapshots() {
    panic_on(Hook::Model, b"MODEL-FAULT-MARKER");
    let d = TestDaemon::start("model").await;
    // The marker comes in two pieces, so that the command line itself never shows it
    let faulty = d
        .tty("read x; printf '%s%s\\n' MODEL-FAULT- MARKER; seq 1 8000; echo A-DONE; read y; echo got-$y; exec sleep 600")
        .await;
    let healthy = d.tty("read x; seq 1 8000; echo B-DONE; exec sleep 600").await;
    let client = hello(&faulty, &["snapshot"]).await;
    for (c, done) in [(&faulty, "A-DONE"), (&healthy, "B-DONE")] {
        let (mut ch, _) = attach(&client, c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
        write_message(
            &mut ch.send,
            &Message::Input {
                offset: 0,
                data: b"go\n".to_vec(),
            },
        )
        .await
        .unwrap();
        let mut s = Stream::default();
        pump(&mut ch, &mut s, Duration::from_secs(30), |s| s.shows(done)).await;
        assert_eq!((s.gaps, s.snapshots), (0, 0), "{done}: nothing skipped");
        let text = String::from_utf8_lossy(&s.out);
        assert!(
            text.contains(&format!("{}{done}\r\n", seq(1, 8000))),
            "{done}: every byte"
        );
    }
    // An attach at LATEST: a resync snapshot from a model, none without (a redraw instead)
    let (mut ch, start) = attach(&client, &healthy, LATEST, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let mut s = Stream {
        received: start,
        ..Stream::default()
    };
    pump(&mut ch, &mut s, Duration::from_secs(10), |s| s.snapshots == 1).await;
    let (mut ch, start) = attach(&client, &faulty, LATEST, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let mut s = Stream {
        received: start,
        ..Stream::default()
    };
    pump_for(&mut ch, &mut s, Duration::from_secs(2)).await;
    assert_eq!(s.snapshots, 0, "no snapshot from a session whose model failed");
    // It still takes input and shows the output
    write_message(
        &mut ch.send,
        &Message::Input {
            offset: 3,
            data: b"yes\n".to_vec(),
        },
    )
    .await
    .unwrap();
    pump(&mut ch, &mut s, Duration::from_secs(10), |s| s.shows("got-yes")).await;
    assert_eq!(s.snapshots, 0);
    // The daemon serves on
    let other = d.tty("echo C-OK; exec sleep 600").await;
    let client = hello(&other, &["snapshot"]).await;
    let (mut ch, _) = attach(&client, &other, 0, ATTACH_FRESH).await;
    let mut s = Stream::default();
    pump(&mut ch, &mut s, Duration::from_secs(10), |s| s.shows("C-OK")).await;
    assert!(!d.task.is_finished());
}

/// A screen model busy with output (here: stalled for 3 s by the test hook, as one could be
/// with output that is expensive to emulate) holds up neither the daemon nor its own
/// attachment: its reader thread does not hold the output buffer while it feeds the model, and
/// the attachments reach the model on blocking threads. On a runtime of one worker, a RESIZE
/// meanwhile (which resizes the model) and a PING are answered at once; before, the RESIZE
/// waited for the buffer on the only worker, and the PONG with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_busy_screen_model_holds_up_nothing_else() {
    panic_on(Hook::Stall, b"STALL-MODEL-MARKER");
    let d = TestDaemon::start("stall").await;
    let c = d
        .tty("read x; printf '%s%s\\n' STALL-MODEL- MARKER; read y; echo got-$y; exec sleep 600")
        .await;
    let mut client = hello(&c, &["snapshot"]).await;
    let (mut ch, _) = attach(&client, &c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let input = |offset: u64, data: &[u8]| Message::Input {
        offset,
        data: data.to_vec(),
    };
    let start = Instant::now();
    write_message(&mut ch.send, &input(0, b"go\n")).await.unwrap();
    let mut s = Stream::default();
    // The model is stalled from when the marker arrives: well within this (the test's own
    // tasks run on the one worker too, so the time is measured from before the stall)
    pump_for(&mut ch, &mut s, Duration::from_millis(500)).await;
    write_message(&mut ch.send, &Message::Resize(WindowSize::new(100, 30)))
        .await
        .unwrap();
    write_message(&mut client._ctl_send, &Message::Ping { data: 7 })
        .await
        .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match read_message(&mut client._ctl_recv, MAX_CONTROL).await {
                Ok(Some(Message::Pong { data })) => return data,
                Ok(Some(_)) => {}
                other => panic!("the control stream ended: {other:?}"),
            }
        }
    })
    .await
    .expect("a PONG");
    let took = start.elapsed();
    assert_eq!(pong, 7);
    assert!(
        took < Duration::from_millis(2000),
        "the PONG came {took:?} after the input"
    );
    // The session goes on, the model too once it is done
    pump(&mut ch, &mut s, Duration::from_secs(10), |s| {
        s.shows("STALL-MODEL-MARKER")
    })
    .await;
    write_message(&mut ch.send, &input(3, b"yes\n")).await.unwrap();
    pump(&mut ch, &mut s, Duration::from_secs(10), |s| s.shows("got-yes")).await;
}

/// A panic of the zstd encoder sends that output uncompressed; the rest of the output is
/// compressed as usual, and every byte arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_encoder_sends_the_output_uncompressed() {
    panic_on(Hook::Encoder, b"ENCODER-FAULT-MARKER");
    let d = TestDaemon::start("encoder").await;
    let lines = "sed 's|.*|   Compiling crate-& v0.1.0 (/home/user/src/project/crates/crate-&)|'";
    let c = d
        .tty(&format!(
            "read x; seq 1 6000 | {lines}; printf '%s%s\\n' ENCODER-FAULT- MARKER; seq 6001 12000 | {lines}; echo E-DONE; exec sleep 600"
        ))
        .await;
    let client = hello(&c, &["zstd"]).await;
    let (mut ch, _) = attach(&client, &c, 0, ATTACH_FRESH).await;
    write_message(
        &mut ch.send,
        &Message::Input {
            offset: 0,
            data: b"go\n".to_vec(),
        },
    )
    .await
    .unwrap();
    let mut s = Stream::default();
    pump(&mut ch, &mut s, Duration::from_secs(60), |s| s.shows("E-DONE")).await;
    let log = |from: u32, to: u32| -> String {
        (from..=to)
            .map(|i| format!("   Compiling crate-{i} v0.1.0 (/home/user/src/project/crates/crate-{i})\r\n"))
            .collect()
    };
    let expected = format!("{}ENCODER-FAULT-MARKER\r\n{}E-DONE\r\n", log(1, 6000), log(6001, 12000));
    assert!(
        String::from_utf8_lossy(&s.out).contains(&expected),
        "every byte, in order"
    );
    assert!(s.frames > 0, "the rest was compressed");
    let marker = b"ENCODER-FAULT-MARKER";
    assert!(
        s.plain.iter().any(|m| m.windows(marker.len()).any(|w| w == marker)),
        "the output the encoder failed on went uncompressed"
    );
}

fn saved(c: &Credentials) -> SavedSession {
    SavedSession {
        destination: "test-host".into(),
        ssh_options: Vec::new(),
        host: "127.0.0.1".into(),
        udp: c.udp,
        tcp: c.tcp,
        fingerprint: Fingerprint::from_hex(&c.cert_sha256).unwrap(),
        session: qsh_core::crypto::unhex::<16>(&c.session).unwrap(),
        key: SessionKey::from_hex(&c.key).unwrap(),
        pipe: false,
        name: None,
        command: None,
        created: 0,
        extra_ports: Vec::new(),
    }
}

/// The library client (`Session`) on a saved session, its output collected.
struct Running {
    input: mpsc::Sender<Input>,
    output: mpsc::Receiver<Vec<u8>>,
    status: Arc<std::sync::Mutex<Status>>,
    seen: Vec<u8>,
}

impl Running {
    fn start(config: ClientConfig, saved: SavedSession) -> Running {
        let (input, input_rx) = mpsc::channel(16);
        let (output_tx, output) = mpsc::channel(256);
        let session = Session::with_pool(config, Pool::new());
        let status = session.status();
        tokio::spawn(async move {
            let terminal = Terminal {
                input: input_rx,
                output: output_tx,
                errors: None,
                events: None,
            };
            let _ = session.attach_saved(saved, terminal).await;
        });
        Running {
            input,
            output,
            status,
            seen: Vec::new(),
        }
    }

    /// Wait until the output shows `needle`.
    async fn wait_for(&mut self, needle: &str, within: Duration) {
        let found = tokio::time::timeout(within, async {
            while !self.seen.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                match self.output.recv().await {
                    Some(bytes) => self.seen.extend_from_slice(&bytes),
                    None => return false,
                }
            }
            true
        })
        .await;
        assert_eq!(
            found.ok(),
            Some(true),
            "{needle} not shown; status {:?}",
            self.status.lock().unwrap()
        );
    }
}

/// A client without the ssh pipe: these tests never start ssh.
fn config() -> ClientConfig {
    let mut config = ClientConfig::new("test-host");
    config.race.ssh = None;
    config
}

/// A panic of the client's zstd decoder breaks the connection; after the second on output from
/// the same server the client offers it no compression, gets the output uncompressed, and the
/// session goes on to its end: no loop, nothing lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_decoder_ends_with_compression_off_for_that_server() {
    panic_on(Hook::Decoder, b"DECODER-FAULT-MARKER");
    let d = TestDaemon::start("decoder").await;
    let c = d
        .tty("read x; seq 1 30000 | sed 's|.*|line & DECODER-FAULT-MARKER of a long and compressible build log|'; echo D-DONE; exec sleep 600")
        .await;
    let mut config = config();
    config.catchup = Catchup::Off;
    config.replay_on_attach = true;
    let mut running = Running::start(config, saved(&c));
    running.input.send(Input::Data(b"go\n".to_vec())).await.unwrap();
    running.wait_for("D-DONE", Duration::from_secs(90)).await;
    let expected: String = (1..=30000)
        .map(|i| format!("line {i} DECODER-FAULT-MARKER of a long and compressible build log\r\n"))
        .collect();
    assert!(
        String::from_utf8_lossy(&running.seen).contains(&format!("{expected}D-DONE\r\n")),
        "every byte, in order"
    );
    let status = running.status.lock().unwrap().clone();
    assert_eq!(status.frames_refused, 2, "{status:?}");
    assert_eq!(status.reconnects, 2, "{status:?}");
    assert_eq!(status.compressed.0, 0, "{status:?}");
}

/// A snapshot that fails the content profile (a server whose encoder went wrong) is refused
/// once; the session attaches again at once, without snapshots, and goes on: no reconnect, no
/// loop, and nothing of the refused snapshot reaches the terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_snapshot_turns_snapshots_off_for_the_session() {
    panic_on(Hook::Snapshot, b"SNAPSHOT-FAULT-MARKER");
    let d = TestDaemon::start("snapshot").await;
    let c = d
        .tty("printf '%s%s\\n' SNAPSHOT-FAULT- MARKER; while read line; do echo got-$line; done")
        .await;
    // Attached at LATEST once the marker is on the screen: a resync snapshot (spoiled)
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut config = config();
    config.replay_on_attach = false;
    let mut running = Running::start(config, saved(&c));
    let deadline = Instant::now() + Duration::from_secs(20);
    while running.status.lock().unwrap().snapshots_refused == 0 {
        assert!(Instant::now() < deadline, "no snapshot refused");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    running.input.send(Input::Data(b"one\n".to_vec())).await.unwrap();
    running.wait_for("got-one", Duration::from_secs(20)).await;
    running.input.send(Input::Data(b"two\n".to_vec())).await.unwrap();
    running.wait_for("got-two", Duration::from_secs(20)).await;
    let status = running.status.lock().unwrap().clone();
    assert_eq!(status.snapshots_refused, 1, "{status:?}");
    assert_eq!(status.reconnects, 0, "{status:?}");
    assert!(
        !running.seen.windows(4).any(|w| w == b"\x1b[6n"),
        "the refused snapshot was written"
    );
}
