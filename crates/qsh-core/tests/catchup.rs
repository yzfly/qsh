//! Smart catch-up and compression at the protocol level (m2.md sections 6 and 7), against the
//! daemon in this process over a link the daemon throttles (`QSH_TEST_THROTTLE`, a test hook):
//! a flood replaced by snapshots, Ctrl-C answered quickly, exact bookkeeping of offsets and
//! acknowledgements, pipe sessions that never skip, compression byte for byte, the bounded
//! replay of an attach, and peers without the capabilities.
//!
//! Each test has its own directories under /tmp and its own ports (port 0); the floods run one
//! at a time.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use qsh_core::codec;
use qsh_core::crypto::{Fingerprint, SessionKey};
use qsh_core::proto::bootstrap::{parse_reply, Credentials, Op, Reply};
use qsh_core::proto::message::{
    ATTACH_ACCEPT_SNAPSHOT, ATTACH_FRESH, MAX_HELLO, MAX_SNAPSHOT, MAX_TERMINAL, SNAPSHOT_FINAL, SNAPSHOT_ZSTD,
};
use qsh_core::proto::zstd::MAX_ZSTD_CONTENT;
use qsh_core::proto::{read_message, write_message, Message, WindowSize};
use qsh_core::screen::snapshot::check_profile;
use qsh_core::server::{Daemon, DaemonLauncher, ServerConfig};
use qsh_core::transport::{tls, Connection, RecvStream, SendStream};
use qsh_core::Paths;
use tokio::io::BufReader;
use tokio::sync::oneshot;

const STARTUP: Duration = Duration::from_secs(30);
/// The test link: 300 kB/s.
const THROTTLE: &str = "300000";

/// One flood at a time: they take a core each.
static FLOODS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestDaemon {
    paths: Paths,
    dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
}

impl TestDaemon {
    async fn start(name: &str, configure: impl FnOnce(&mut ServerConfig)) -> TestDaemon {
        // Read by each attachment when it starts (builds with the `test-hooks` feature)
        std::env::set_var("QSH_TEST_THROTTLE", THROTTLE);
        let dir = PathBuf::from(format!("/tmp/qc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::under(&dir);
        let mut config = ServerConfig::new(paths.clone());
        config.ports = 0..=0;
        config.shell = Some("/bin/sh".into());
        config.output_replay = 8 << 20;
        configure(&mut config);
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
        }
    }

    async fn boot(&self, request: &str) -> Credentials {
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

    /// A tty session running `command`, 80 × 24.
    async fn tty(&self, command: &str) -> Credentials {
        let command = command.replace('\\', "\\\\").replace('"', "\\\"");
        self.boot(&format!(
            r#"{{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"{command}"}}"#
        ))
        .await
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

struct Client {
    conn: Connection,
    nonce: [u8; 32],
    _ctl_send: SendStream,
    _ctl_recv: BufReader<RecvStream>,
    capabilities: Vec<String>,
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
    Client {
        conn,
        nonce,
        _ctl_send: ctl_send,
        _ctl_recv: ctl_recv,
        capabilities,
    }
}

struct Channel {
    send: SendStream,
    recv: BufReader<RecvStream>,
}

impl Channel {
    async fn next(&mut self, within: Duration) -> Option<Message> {
        match tokio::time::timeout(within, read_message(&mut self.recv, MAX_TERMINAL)).await {
            Ok(m) => m.unwrap(),
            Err(_) => panic!("no message within {within:?}"),
        }
    }

    async fn send(&mut self, m: Message) {
        write_message(&mut self.send, &m).await.unwrap();
    }
}

async fn attach(client: &Client, c: &Credentials, output_received: u64, flags: u64) -> Channel {
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
            error_received: c.pipe().then_some(0),
        },
    )
    .await
    .unwrap();
    let mut ch = Channel {
        send,
        recv: BufReader::new(recv),
    };
    match ch.next(Duration::from_secs(10)).await {
        Some(Message::Attached { .. }) => ch,
        other => panic!("not attached: {other:?}"),
    }
}

/// What a client keeps of the output stream: every rule of protocol.md 7.4 to 7.8 and 7.12
/// checked on the way.
#[derive(Default)]
struct Stream {
    pipe: bool,
    received: u64,
    error_received: u64,
    /// The bytes of OUTPUT (decompressed), in order (gaps and snapshots leave holes).
    out: Vec<u8>,
    gaps: u64,
    gap_bytes: u64,
    /// Snapshots: (offset, skipped bytes, data).
    snapshots: Vec<(u64, u64, Vec<u8>)>,
    assembly: Option<(u64, Vec<u8>)>,
    frames: usize,
    frame_bytes: u64,
    compressed_bytes: u64,
    exited: bool,
}

impl Stream {
    /// Take one message; the ACK to send, if any.
    fn take(&mut self, m: Message) -> Option<Message> {
        let output = matches!(
            m,
            Message::Output { .. } | Message::OutputZstd { .. } | Message::OutputGap { .. } | Message::Exit { .. }
        );
        assert!(
            !(output && self.assembly.is_some()),
            "output between the parts of a snapshot"
        );
        match m {
            Message::Output { offset, data } => {
                assert_eq!(offset, self.received, "OUTPUT offset");
                assert!(!data.is_empty());
                self.received += data.len() as u64;
                self.out.extend(data);
            }
            Message::OutputZstd { offset, frame } => {
                assert_eq!(offset, self.received, "OUTPUT_ZSTD offset");
                let data = codec::decompress(&frame, MAX_ZSTD_CONTENT).expect("a valid frame");
                self.frames += 1;
                self.frame_bytes += frame.len() as u64;
                self.compressed_bytes += data.len() as u64;
                self.received += data.len() as u64;
                self.out.extend(data);
            }
            Message::ErrorOutput { offset, data } => {
                assert!(self.pipe);
                assert_eq!(offset, self.error_received);
                self.error_received += data.len() as u64;
            }
            Message::OutputGap { from, to } => {
                assert!(!self.pipe, "a gap on a pipe session");
                assert_eq!(from, self.received, "OUTPUT_GAP from");
                assert!(to > from);
                self.gaps += 1;
                self.gap_bytes += to - from;
                self.received = to;
            }
            Message::Snapshot {
                offset,
                flags,
                cols,
                rows,
                data,
            } => {
                assert!(!self.pipe, "a snapshot on a pipe session");
                assert!(offset >= self.received, "SNAPSHOT offset below the expected one");
                assert_eq!((cols, rows), (80, 24));
                let part = if flags & SNAPSHOT_ZSTD != 0 {
                    codec::decompress(&data, MAX_ZSTD_CONTENT).expect("a valid snapshot frame")
                } else {
                    data
                };
                let (at, all) = self.assembly.get_or_insert((offset, Vec::new()));
                assert_eq!(*at, offset, "the parts of a snapshot share their offset");
                all.extend(part);
                assert!(all.len() <= MAX_SNAPSHOT);
                if flags & SNAPSHOT_FINAL != 0 {
                    let (_, data) = self.assembly.take().unwrap();
                    check_profile(&data).unwrap();
                    self.snapshots.push((offset, offset - self.received, data));
                    self.received = offset;
                }
            }
            Message::Exit {
                output_end, error_end, ..
            } => {
                assert_eq!(output_end, self.received);
                if self.pipe {
                    assert_eq!(error_end, Some(self.error_received));
                }
                self.exited = true;
            }
            Message::Ack { .. } => return None,
            Message::Error { code, message } => panic!("ERROR {code} {message}"),
            other => panic!("unexpected {other:?}"),
        }
        // Acknowledge everything at once: more often than 7.5 asks, which is allowed
        Some(Message::Ack {
            received: self.received,
            error_received: self.pipe.then_some(self.error_received),
        })
    }

    fn skip_snapshots(&self) -> usize {
        self.snapshots.iter().filter(|s| s.1 > 0).count()
    }

    /// Whether `needle` arrived, in output or on a snapshot's screen.
    fn shows(&self, needle: &str) -> bool {
        let n = needle.as_bytes();
        self.out.windows(n.len()).any(|w| w == n) || self.snapshots.iter().any(|s| s.2.windows(n.len()).any(|w| w == n))
    }
}

/// Read and acknowledge until `done` or `limit`; the time it took.
async fn pump(ch: &mut Channel, s: &mut Stream, limit: Duration, mut done: impl FnMut(&Stream) -> bool) -> Duration {
    let start = Instant::now();
    while !done(s) {
        let left = limit.checked_sub(start.elapsed()).unwrap_or_default();
        assert!(!left.is_zero(), "not done within {limit:?}");
        match tokio::time::timeout(left, read_message(&mut ch.recv, MAX_TERMINAL)).await {
            Ok(Ok(Some(m))) => {
                if let Some(ack) = s.take(m) {
                    ch.send(ack).await;
                }
            }
            Ok(other) => panic!("the channel ended: {other:?}"),
            Err(_) => panic!("not done within {limit:?}"),
        }
    }
    start.elapsed()
}

/// A flood on a slow link is replaced by snapshots (the backlog trigger), every byte delivered
/// or skipped exactly; Ctrl-C typed during it shows the program's reaction at once (the input
/// trigger), instead of after the megabytes in the replay buffer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_gives_way_to_snapshots_and_ctrl_c_answers_at_once() {
    let _flood = FLOODS.lock().await;
    let d = TestDaemon::start("flood", |_| {}).await;
    let c = d
        .tty("trap 'echo PROMPT-BACK; exec sleep 600' INT; yes catch-up-test-line")
        .await;
    let client = hello(&c, &["snapshot"]).await;
    assert_eq!(client.capabilities, vec!["snapshot".to_string()]);
    let mut ch = attach(&client, &c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let mut s = Stream::default();
    // The backlog trigger needs a second of rate samples, then a backlog of 2 s of the rate
    pump(&mut ch, &mut s, Duration::from_secs(30), |s| s.skip_snapshots() >= 2).await;
    assert!(s.snapshots.iter().all(|x| x.2.starts_with(b"\x1b[!p")));
    let skipped: u64 = s.snapshots.iter().map(|x| x.1).sum();
    eprintln!(
        "flood: {} bytes delivered, {} skipped by {} snapshots",
        s.out.len(),
        skipped,
        s.skip_snapshots()
    );
    // Ctrl-C
    ch.send(Message::Input {
        offset: 0,
        data: vec![3],
    })
    .await;
    let took = pump(&mut ch, &mut s, Duration::from_secs(20), |s| s.shows("PROMPT-BACK")).await;
    eprintln!("Ctrl-C to its effect on the client: {took:?} (link {THROTTLE} B/s)");
    assert!(took < Duration::from_secs(3), "Ctrl-C took {took:?}");
    ch.send(Message::Hangup).await;
}

/// Output of a pipe session is data: never a snapshot or a gap, every byte, even when the
/// client would accept snapshots and the link is slow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_session_never_skips() {
    let _flood = FLOODS.lock().await;
    let d = TestDaemon::start("pipe", |_| {}).await;
    let c = d
        .boot(r#"{"qsh":1,"versions":[1],"tty":false,"command":"head -c 1500000 /dev/zero | tr '\\0' y"}"#)
        .await;
    assert!(c.pipe());
    let client = hello(&c, &["snapshot", "zstd"]).await;
    let mut ch = attach(&client, &c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let mut s = Stream {
        pipe: true,
        ..Stream::default()
    };
    pump(&mut ch, &mut s, Duration::from_secs(60), |s| s.exited).await;
    assert_eq!(s.out.len(), 1_500_000);
    assert!(s.out.iter().all(|&b| b == b'y'));
    assert_eq!((s.gaps, s.snapshots.len()), (0, 0));
}

/// What `LOG_COMMAND` writes: lines like a build log.
fn build_log(n: u32) -> Vec<u8> {
    (1..=n)
        .flat_map(|i| format!("   Compiling crate-{i} v0.1.0 (/home/user/src/project/crates/crate-{i})\n").into_bytes())
        .collect()
}

const LOG_COMMAND: &str =
    "seq 1 20000 | sed 's|.*|   Compiling crate-& v0.1.0 (/home/user/src/project/crates/crate-&)|'";

/// Compression on a slow link (m2.md 7): OUTPUT_ZSTD frames that decompress to exactly the
/// program's output, which is the same with and without compression; a build-log-like stream
/// takes a fraction of the bytes on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compressed_output_is_byte_exact() {
    let _flood = FLOODS.lock().await;
    let d = TestDaemon::start("zstd", |_| {}).await;
    let expected = build_log(20_000);
    let mut results = Vec::new();
    for offer in [&["zstd"][..], &[][..]] {
        let c = d
            .boot(&format!(
                r#"{{"qsh":1,"versions":[1],"tty":false,"command":"{}"}}"#,
                LOG_COMMAND.replace('\\', "\\\\")
            ))
            .await;
        let client = hello(&c, offer).await;
        let mut ch = attach(&client, &c, 0, ATTACH_FRESH).await;
        let mut s = Stream {
            pipe: true,
            ..Stream::default()
        };
        let took = pump(&mut ch, &mut s, Duration::from_secs(60), |s| s.exited).await;
        assert!(s.out == expected, "the output differs (offer {offer:?})");
        eprintln!(
            "offer {offer:?}: {} bytes in {took:?}; {} frames carried {} bytes in {} (ratio {:.3})",
            s.out.len(),
            s.frames,
            s.compressed_bytes,
            s.frame_bytes,
            s.frame_bytes as f64 / s.compressed_bytes.max(1) as f64
        );
        results.push((s.frames, took));
    }
    let ((frames, with), (none, without)) = (results[0], results[1]);
    assert!(frames > 0 && none == 0);
    // S5 on this link: less than 40 % of the time without compression
    assert!(
        with.as_secs_f64() < 0.4 * without.as_secs_f64(),
        "{with:?} vs {without:?}"
    );
}

/// An attach whose backlog the path cannot carry in about two seconds (m2.md 6.5): the newest
/// part of the output from just after a line end, then a resync snapshot that skips nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_replays_what_the_path_carries_then_resyncs() {
    let _flood = FLOODS.lock().await;
    let d = TestDaemon::start("attach", |_| {}).await;
    let marker = d.dir.join("written");
    // About 3.3 MiB of lines, more than 2 s of the initial 1 MiB/s estimate on TLS
    let c = d
        .tty(&format!("seq 1 500000; touch {}; exec sleep 600", marker.display()))
        .await;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "seq did not finish");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let client = hello(&c, &["snapshot"]).await;
    let mut ch = attach(&client, &c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let first = ch.next(Duration::from_secs(10)).await.unwrap();
    let Message::OutputGap { from: 0, to: cut } = first else {
        panic!("not a gap first: {first:?}")
    };
    let mut s = Stream {
        received: cut,
        gaps: 1,
        gap_bytes: cut,
        ..Stream::default()
    };
    ch.send(Message::Ack {
        received: cut,
        error_received: None,
    })
    .await;
    pump(&mut ch, &mut s, Duration::from_secs(60), |s| !s.snapshots.is_empty()).await;
    // At most the budget, from the start of a line; then a snapshot (a resync one when the
    // link carried the replay within the budget; on this slower link the backlog trigger
    // replaced the rest first)
    let budget = 2 * 1024 * 1024 + 4096;
    assert!(s.out.len() <= budget, "{} bytes replayed", s.out.len());
    assert!(s.out.first().is_some_and(|b| b.is_ascii_digit()), "{:?}", &s.out[..20]);
    let (offset, _, data) = s.snapshots.last().unwrap();
    assert!(String::from_utf8_lossy(data).contains("500000"));
    ch.send(Message::Hangup).await;
    let _ = offset;
}

/// An attach at LATEST that takes snapshots gets the current screen at once: a resync snapshot
/// at the output's end, which skips nothing, instead of a SIGWINCH to the program.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_at_latest_gets_the_screen() {
    let d = TestDaemon::start("latest", |_| {}).await;
    let marker = d.dir.join("written");
    let c = d
        .tty(&format!(
            "printf 'one\\ntwo\\n'; touch {}; exec sleep 600",
            marker.display()
        ))
        .await;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "printf did not finish");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let client = hello(&c, &["snapshot", "zstd"]).await;
    let session: [u8; 16] = qsh_core::crypto::unhex(&c.session).unwrap();
    let key = SessionKey::from_hex(&c.key).unwrap();
    let (_, mut send, recv) = client.conn.open().await.unwrap();
    let cb = client.conn.channel_binding(&session, &client.nonce).unwrap();
    write_message(
        &mut send,
        &Message::Attach {
            session,
            proof: key.proof(&cb),
            output_received: qsh_core::proto::message::LATEST,
            size: WindowSize::new(80, 24),
            flags: ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT,
            error_received: None,
        },
    )
    .await
    .unwrap();
    let mut ch = Channel {
        send,
        recv: BufReader::new(recv),
    };
    let Some(Message::Attached { output_start, .. }) = ch.next(Duration::from_secs(10)).await else {
        panic!("not attached")
    };
    let mut s = Stream {
        received: output_start,
        ..Stream::default()
    };
    pump(&mut ch, &mut s, Duration::from_secs(10), |s| !s.snapshots.is_empty()).await;
    let (offset, skipped, data) = &s.snapshots[0];
    assert_eq!((*offset, *skipped), (output_start, 0));
    let text = String::from_utf8_lossy(data);
    assert!(text.contains("one") && text.contains("two"), "{text:?}");
    ch.send(Message::Hangup).await;
}

/// Without the capabilities (an old client, or a daemon configured without them) nothing
/// changes: no SNAPSHOT, no OUTPUT_ZSTD, however slow the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peers_without_the_capabilities_see_no_change() {
    let _flood = FLOODS.lock().await;
    let d = TestDaemon::start("old", |_| {}).await;
    let c = d.tty("yes old-client-line").await;
    let client = hello(&c, &[]).await;
    assert!(client.capabilities.is_empty());
    // ACCEPT_SNAPSHOT without the capability is ignored (7.2)
    let mut ch = attach(&client, &c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    let mut s = Stream::default();
    let start = Instant::now();
    pump(&mut ch, &mut s, Duration::from_secs(30), |_| {
        start.elapsed() > Duration::from_secs(3)
    })
    .await;
    assert_eq!((s.snapshots.len(), s.frames), (0, 0));
    assert!(s.out.len() > 100_000);
    ch.send(Message::Hangup).await;
    drop(d);

    let d = TestDaemon::start("off", |config| {
        config.snapshot = false;
        config.compression = false;
    })
    .await;
    let c = d.tty("sleep 600").await;
    let client = hello(&c, &["snapshot", "zstd"]).await;
    assert!(client.capabilities.is_empty());
    let mut ch = attach(&client, &c, 0, ATTACH_FRESH | ATTACH_ACCEPT_SNAPSHOT).await;
    ch.send(Message::Hangup).await;
}

/// Output that falls out of the replay buffer while the window is full is skipped with one
/// OUTPUT_GAP right before the output after it, not with a gap each time the buffer's base
/// moves: a flood once sent a gap per chunk the program wrote while the client was behind,
/// thousands of tiny packets a second that filled the queues of a slow path ahead of an
/// interrupt (m2.md 6.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_window_sends_no_gaps() {
    let _flood = FLOODS.lock().await;
    let d = TestDaemon::start("gaps", |c| c.output_replay = 1 << 20).await;
    let c = d.tty("yes gap-test-line").await;
    let client = hello(&c, &[]).await;
    let mut ch = attach(&client, &c, 0, ATTACH_FRESH).await;
    let mut s = Stream::default();
    // No ACK for 3 s: the window fills (at the test link's pace, with a gap before each chunk
    // when the buffer's base passed it meanwhile) and then stays full while the program
    // overflows the buffer many times over: from then on, nothing at all
    let start = Instant::now();
    let quiet = start + Duration::from_secs(3);
    let mut last_output = start;
    let mut gaps_after = 0;
    while let Ok(m) = tokio::time::timeout_at(quiet.into(), read_message(&mut ch.recv, MAX_TERMINAL)).await {
        let m = m.unwrap().expect("the channel ended");
        match m {
            Message::Output { .. } | Message::OutputZstd { .. } => {
                last_output = Instant::now();
                gaps_after = 0;
            }
            Message::OutputGap { .. } => gaps_after += 1,
            _ => {}
        }
        let _ = s.take(m);
    }
    assert!(s.received > 0, "nothing was sent");
    assert!(
        last_output < start + Duration::from_millis(2500),
        "the window was not full for half a second: {:?}",
        last_output - start
    );
    assert_eq!(gaps_after, 0, "gaps while the window was full");
    // Acknowledged: the output goes on from the buffer's base after a gap (and after another
    // whenever the base passes what is being sent at the test link's pace), until the window is
    // full again
    let gaps = s.gaps;
    ch.send(Message::Ack {
        received: s.received,
        error_received: None,
    })
    .await;
    let quiet = Instant::now() + Duration::from_millis(1500);
    while let Ok(m) = tokio::time::timeout_at(quiet.into(), read_message(&mut ch.recv, MAX_TERMINAL)).await {
        let _ = s.take(m.unwrap().expect("the channel ended"));
    }
    let more = s.gaps - gaps;
    assert!((1..=40).contains(&more), "{more} gaps for the window the ACK opened");
    ch.send(Message::Hangup).await;
}
