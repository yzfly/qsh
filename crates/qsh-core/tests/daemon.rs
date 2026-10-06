//! The daemon in this process, driven at the protocol level: regression tests from the review
//! (H1, H2, M1, M2, L1, L9, L10) and pipe sessions. Each test has its own directories under
//! /tmp and its own ports (port 0).

use std::path::PathBuf;
use std::time::Duration;

use qsh_core::crypto::{Fingerprint, SessionKey};
use qsh_core::proto::bootstrap::{parse_reply, Credentials, Op, Reply};
use qsh_core::proto::message::{ATTACH_FRESH, LATEST, MAX_CONTROL, MAX_HELLO, MAX_TERMINAL};
use qsh_core::proto::{read_message, write_message, ErrorCode, ExitStatus, Message, WindowSize};
use qsh_core::server::{Daemon, DaemonLauncher, ServerConfig};
use qsh_core::transport::{tls, Connection, RecvStream, SendStream};
use qsh_core::Paths;
use tokio::io::BufReader;
use tokio::sync::oneshot;

/// How long a daemon may take to start: generous, for slow and emulated builders.
const STARTUP: Duration = Duration::from_secs(30);

struct TestDaemon {
    paths: Paths,
    dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}

impl TestDaemon {
    async fn start(name: &str, replay: usize) -> TestDaemon {
        let dir = PathBuf::from(format!("/tmp/qd-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::under(&dir);
        let mut config = ServerConfig::new(paths.clone());
        config.ports = 0..=0;
        config.shell = Some("/bin/sh".into());
        config.output_replay = replay;
        // The tests cause AUTH_FAILED on purpose, all from 127.0.0.1
        config.preauth.failure_burst = 1000;
        let (stop, stopped) = oneshot::channel::<()>();
        let mut task = tokio::spawn(async move {
            Daemon::run_until(config, async {
                let _ = stopped.await;
            })
            .await
            .map_err(|e| e.to_string())
        });
        // Ready once its control socket accepts connections (it is bound after the ports and
        // the certificate, which a slow or emulated machine takes a while to make). The daemon
        // runs in this process: its log is this test's captured stderr
        let deadline = tokio::time::Instant::now() + STARTUP;
        loop {
            if let Ok(Some(_)) = paths.connect_private(&paths.control_socket()).await {
                break;
            }
            if task.is_finished() {
                let ended = (&mut task).await;
                panic!("the daemon {name} ended before it was ready: {ended:?}");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon {name} is not ready after {STARTUP:?}: nothing accepts on {}",
                paths.control_socket().display()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        TestDaemon {
            paths,
            dir,
            stop: Some(stop),
            task: Some(task),
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

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            tokio::time::timeout(STARTUP, task)
                .await
                .expect("the daemon stops")
                .unwrap()
                .unwrap();
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

struct Client {
    conn: Connection,
    nonce: [u8; 32],
    /// Kept open: finishing the control stream is a connection error
    _ctl_send: SendStream,
    ctl_recv: BufReader<RecvStream>,
}

async fn hello(port: u16, pin: Fingerprint) -> Client {
    let conn = Connection::tls_client(tls::connect("127.0.0.1", port, pin).await.unwrap());
    let (_, mut ctl_send, r) = conn.open().await.unwrap();
    write_message(
        &mut ctl_send,
        &Message::ClientHello {
            versions: vec![1],
            capabilities: vec![],
            implementation: "test".into(),
        },
    )
    .await
    .unwrap();
    let mut ctl_recv = BufReader::new(r);
    let Some(Message::ServerHello { nonce, .. }) = read_message(&mut ctl_recv, MAX_HELLO).await.unwrap() else {
        panic!("no SERVER_HELLO")
    };
    Client {
        conn,
        nonce,
        _ctl_send: ctl_send,
        ctl_recv,
    }
}

struct Channel {
    send: SendStream,
    recv: BufReader<RecvStream>,
}

impl Channel {
    async fn next(&mut self) -> Option<Message> {
        tokio::time::timeout(Duration::from_secs(60), read_message(&mut self.recv, MAX_TERMINAL))
            .await
            .expect("a message in time")
            .unwrap()
    }

    async fn send(&mut self, m: Message) {
        write_message(&mut self.send, &m).await.unwrap();
    }
}

async fn attach(c: &Client, creds: &Credentials, key: &SessionKey, output_received: u64, flags: u64) -> Channel {
    let session: [u8; 16] = qsh_core::crypto::unhex(&creds.session).unwrap();
    let (_, mut send, recv) = c.conn.open().await.unwrap();
    let cb = c.conn.channel_binding(&session, &c.nonce).unwrap();
    write_message(
        &mut send,
        &Message::Attach {
            session,
            proof: key.proof(&cb),
            output_received,
            size: WindowSize::new(80, 24),
            flags,
            error_received: creds.pipe().then_some(0),
        },
    )
    .await
    .unwrap();
    Channel {
        send,
        recv: BufReader::new(recv),
    }
}

fn key(c: &Credentials) -> SessionKey {
    SessionKey::from_hex(&c.key).unwrap()
}

fn pin(c: &Credentials) -> Fingerprint {
    Fingerprint::from_hex(&c.cert_sha256).unwrap()
}

/// Wait until `path` exists: a session program's sign that it got somewhere. Generous, for
/// slow and emulated builders.
async fn wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no {} after 60 s",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A program that writes `mib` MiB to its terminal in large writes, whatever the speed of the
/// system's `yes` (busybox's writes a line at a time), then creates `marker`.
fn big_writer(mib: u32, marker: &std::path::Path) -> String {
    format!(
        "head -c {} /dev/zero | tr '\\\\0' y; touch {}",
        mib << 20,
        marker.display()
    )
}

/// Review H2: an ACK the client sent before an OUTPUT_GAP reached it is valid (protocol.md
/// 7.5); the attachment goes on. It used to fail with SEQUENCE_ERROR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ack_in_flight_across_a_gap_is_accepted() {
    let d = TestDaemon::start("gap", 64 * 1024).await;
    // 1 MiB at once overflows the 64 KiB replay buffer while the client does not read; then
    // output that goes on for good
    let marker = d.dir.join("written");
    let command = format!(
        "{}; while :; do head -c 1048576 /dev/zero | tr '\\\\0' y; done",
        big_writer(1, &marker)
    );
    let c = d
        .boot(&format!(
            r#"{{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"{command}"}}"#
        ))
        .await;
    let client = hello(c.tcp, pin(&c)).await;
    let mut ch = attach(&client, &c, &key(&c), 0, ATTACH_FRESH).await;
    assert!(matches!(ch.next().await, Some(Message::Attached { .. })));
    let mut received = 0u64;
    let mut outputs = 0;
    let mut gap_acked = false;
    // Once the gap's stale ACK was sent: a good while more of output, and no ERROR
    let mut after = 0u64;
    while after < 2 << 20 {
        match ch.next().await.expect("the channel goes on") {
            Message::Output { offset, data } => {
                assert_eq!(offset, received);
                received += data.len() as u64;
                outputs += 1;
                if gap_acked {
                    after += data.len() as u64;
                    ch.send(Message::Ack {
                        received,
                        error_received: None,
                    })
                    .await;
                }
                if outputs == 1 {
                    // A slow reader: the program overflows the replay buffer meanwhile
                    wait_for_file(&marker).await;
                }
            }
            Message::OutputGap { from, to } if outputs > 0 && !gap_acked => {
                assert_eq!(from, received);
                // What a real client had already sent before the GAP arrived
                ch.send(Message::Ack {
                    received,
                    error_received: None,
                })
                .await;
                received = to;
                gap_acked = true;
            }
            Message::OutputGap { from, to } => {
                assert_eq!(from, received);
                received = to;
            }
            Message::Error { code, .. } => panic!("ERROR {code}"),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(gap_acked);
}

/// Review M2: a KEY_CONFIRM that arrives late, on an attachment that was taken over, must not
/// promote the newer attach's key and drop the still valid current one. KEY_CONFIRM names its
/// key now (6.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_key_confirm_never_promotes_another_attachs_key() {
    let d = TestDaemon::start("kc", 1 << 20).await;
    let c = d
        .boot(r#"{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"sleep 1000"}"#)
        .await;
    let (mut lost, mut kept) = (0, 0);
    for _ in 0..20 {
        // A fresh K1 over "ssh"
        let r = d
            .boot(&format!(
                r#"{{"qsh":1,"op":"attach","session":"{}","versions":[1],"cols":80,"rows":24}}"#,
                c.session
            ))
            .await;
        let k1 = key(&r);
        let a = hello(c.tcp, pin(&c)).await;
        let b = hello(c.tcp, pin(&c)).await;
        let mut ach = attach(&a, &c, &k1, LATEST, ATTACH_FRESH).await;
        let Some(Message::Attached { next_key: k2, .. }) = ach.next().await else {
            panic!("A not attached")
        };
        // B attaches with K1 (still current) while A confirms K2
        let mut bch = attach(&b, &c, &k1, LATEST, ATTACH_FRESH).await;
        ach.send(Message::KeyConfirm { key_id: k2.id() }).await;
        let b_got = bch.next().await;
        if !matches!(b_got, Some(Message::Attached { .. })) {
            // A's confirmation came first: K1 is gone, correctly
            continue;
        }
        // B's ATTACHED was "lost" before it could confirm: K1 must still be valid
        let cc = hello(c.tcp, pin(&c)).await;
        let mut cch = attach(&cc, &c, &k1, LATEST, ATTACH_FRESH).await;
        match cch.next().await {
            Some(Message::Attached { .. }) => kept += 1,
            other => {
                eprintln!("K1 rejected: {other:?}");
                lost += 1
            }
        }
    }
    eprintln!("K1 kept {kept}, lost {lost}");
    assert_eq!(lost, 0);
}

/// Review M1: connections that never finish their TLS handshake are counted from acceptance
/// and capped per source (8); the others are closed at once, before any TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_handshakes_are_capped_per_source() {
    let d = TestDaemon::start("fd", 1 << 20).await;
    let c = d
        .boot(r#"{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"sleep 1000"}"#)
        .await;
    let mut held = Vec::new();
    for _ in 0..40 {
        held.push(tokio::net::TcpStream::connect(("127.0.0.1", c.tcp)).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let status = qsh_core::server::request_status(&d.paths).await.unwrap().unwrap();
    let pending = status["stats"]["unauthenticated"].as_u64().unwrap();
    assert!(pending <= 8, "{status}");
    // The refused ones were closed at once: reading gives the end. Read all of them together,
    // the 8 admitted ones (which say nothing) until the deadline: a slow machine needs a while
    // to get to all 40
    let mut reads = tokio::task::JoinSet::new();
    for mut s in held {
        reads.spawn(async move {
            let mut b = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut s, &mut b));
            (matches!(read.await, Ok(Ok(0))), s)
        });
    }
    let mut closed = 0;
    let mut held = Vec::new();
    while let Some(read) = reads.join_next().await {
        let (eof, s) = read.unwrap();
        closed += usize::from(eof);
        held.push(s);
    }
    assert!(closed >= 32, "{closed} closed");
    // Once they go, a real client gets in, when the daemon has seen them go
    drop(held);
    let deadline = tokio::time::Instant::now() + STARTUP;
    loop {
        let status = qsh_core::server::request_status(&d.paths).await.unwrap().unwrap();
        if status["stats"]["unauthenticated"].as_u64() == Some(0) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{status}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let client = hello(c.tcp, pin(&c)).await;
    let mut ch = attach(&client, &c, &key(&c), LATEST, ATTACH_FRESH).await;
    assert!(matches!(ch.next().await, Some(Message::Attached { .. })));
}

/// Review L9: only AUTH_FAILED counts as a failed ATTACH, and a connection that carries an
/// attachment is not closed for failures of other sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_auth_failures_count_and_never_against_an_attached_connection() {
    let d = TestDaemon::start("fail", 1 << 20).await;
    let c = d
        .boot(r#"{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"sleep 1000"}"#)
        .await;
    let mut gone = c.clone();
    gone.session = "00".repeat(16);
    let wrong = SessionKey([7; 32]);
    // SESSION_UNKNOWN three times (four channels at most before authentication): the
    // connection stays usable
    let client = hello(c.tcp, pin(&c)).await;
    for _ in 0..3 {
        let mut ch = attach(&client, &gone, &key(&c), LATEST, ATTACH_FRESH).await;
        assert!(matches!(ch.next().await, Some(Message::Error { code, .. }) if code == ErrorCode::SESSION_UNKNOWN));
    }
    // An attachment, then AUTH_FAILED three times on the same connection: it stays up
    let mut ch = attach(&client, &c, &key(&c), LATEST, ATTACH_FRESH).await;
    assert!(matches!(ch.next().await, Some(Message::Attached { .. })));
    for _ in 0..3 {
        let mut bad = attach(&client, &c, &wrong, LATEST, ATTACH_FRESH).await;
        assert!(matches!(bad.next().await, Some(Message::Error { code, .. }) if code == ErrorCode::AUTH_FAILED));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!client.conn.is_closed());
    // Without an attachment, the third AUTH_FAILED closes the connection
    let other = hello(c.tcp, pin(&c)).await;
    for _ in 0..3 {
        let mut bad = attach(&other, &c, &wrong, LATEST, ATTACH_FRESH).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), read_message(&mut bad.recv, MAX_TERMINAL)).await;
    }
    tokio::time::timeout(Duration::from_secs(30), other.conn.closed())
        .await
        .expect("closed after three failures");
}

/// Review L10: HANGUP with much output pending still ends the attachment with EXIT, after an
/// OUTPUT_GAP that announces what was not sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hangup_with_much_pending_output_ends_with_gap_and_exit() {
    let d = TestDaemon::start("hup", 8 << 20).await;
    // 6 MiB: far more than the pacing window (512 KiB) and the messages sent after a hangup
    // (64 of 16 KiB) together, within the replay buffer; then a program SIGHUP ends
    let marker = d.dir.join("written");
    let command = format!("{}; exec sleep 1000", big_writer(6, &marker));
    let c = d
        .boot(&format!(
            r#"{{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"{command}"}}"#
        ))
        .await;
    let client = hello(c.tcp, pin(&c)).await;
    let mut ch = attach(&client, &c, &key(&c), 0, ATTACH_FRESH).await;
    assert!(matches!(ch.next().await, Some(Message::Attached { .. })));
    // Never acknowledge: pacing holds the server back while the program fills the replay
    // buffer. Once it is done, the server has it all but what is still in the terminal
    wait_for_file(&marker).await;
    ch.send(Message::Hangup).await;
    let mut received = 0u64;
    let mut gap = false;
    loop {
        match ch.next().await {
            Some(Message::Output { offset, data }) => {
                assert_eq!(offset, received);
                received += data.len() as u64;
            }
            Some(Message::OutputGap { from, to }) => {
                assert_eq!(from, received);
                received = to;
                gap = true;
            }
            Some(Message::Exit { output_end, status, .. }) => {
                assert_eq!(output_end, received);
                assert!(gap, "a gap announced the output not sent ({status:?})");
                break;
            }
            Some(Message::Error { code, .. }) => {
                assert_eq!(code, ErrorCode::SESSION_ENDED);
                break;
            }
            other => panic!("the attachment ended without EXIT or SESSION_ENDED: {other:?}"),
        }
    }
}

/// Review L1: when the daemon stops, every attachment gets its final EXIT (or SESSION_ENDED)
/// before GOAWAY (SHUTDOWN) and the close (protocol.md 7.13).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_the_daemon_ends_attachments_before_the_goaway() {
    let mut d = TestDaemon::start("stop", 1 << 20).await;
    let c = d
        .boot(r#"{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"echo ready; exec sleep 1000"}"#)
        .await;
    let mut client = hello(c.tcp, pin(&c)).await;
    let mut ch = attach(&client, &c, &key(&c), 0, ATTACH_FRESH).await;
    assert!(matches!(ch.next().await, Some(Message::Attached { .. })));
    let mut stop = Box::pin(d.stop());
    let mut last = None;
    // Messages on the terminal channel until its end, while the daemon stops
    let channel = async {
        while let Some(m) = ch.next().await {
            let end = matches!(m, Message::Exit { .. } | Message::Error { .. });
            last = Some(m);
            if end {
                break;
            }
        }
    };
    tokio::select! {
        _ = channel => {}
        _ = &mut stop => panic!("stopped before the attachment ended"),
    }
    match &last {
        Some(Message::Exit { status, .. }) => assert_eq!(
            status,
            &ExitStatus::Signaled {
                signal: "HUP".into(),
                core_dumped: false
            }
        ),
        other => panic!("no EXIT: {other:?}"),
    }
    // Then GOAWAY (SHUTDOWN) on the control stream
    let goaway = loop {
        match read_message(&mut client.ctl_recv, MAX_CONTROL).await {
            Ok(Some(Message::GoAway { code, .. })) => break code,
            Ok(Some(_)) => continue,
            other => panic!("no GOAWAY: {other:?}"),
        }
    };
    assert_eq!(goaway, ErrorCode::SHUTDOWN);
    stop.await;
    drop(client);
}

/// Review M3 at the protocol level: a pipe session carries every byte value exactly, stderr
/// apart, and INPUT_EOF closes the program's stdin; EXIT carries both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_session_round_trip() {
    let d = TestDaemon::start("pipe", 1 << 20).await;
    let c = d
        .boot(r#"{"qsh":1,"versions":[1],"tty":false,"command":"cat; echo done >&2"}"#)
        .await;
    assert!(c.pipe());
    let client = hello(c.tcp, pin(&c)).await;
    let mut ch = attach(&client, &c, &key(&c), 0, ATTACH_FRESH).await;
    let Some(Message::Attached {
        error_start, next_key, ..
    }) = ch.next().await
    else {
        panic!("not attached")
    };
    assert_eq!(error_start, Some(0));
    ch.send(Message::KeyConfirm { key_id: next_key.id() }).await;
    let data: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    for (i, chunk) in data.chunks(16384).enumerate() {
        ch.send(Message::Input {
            offset: (i * 16384) as u64,
            data: chunk.to_vec(),
        })
        .await;
    }
    ch.send(Message::InputEof {
        offset: data.len() as u64,
    })
    .await;
    // Repeated: ignored
    ch.send(Message::InputEof {
        offset: data.len() as u64,
    })
    .await;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        match ch.next().await.expect("EXIT") {
            Message::Output { offset, data } => {
                assert_eq!(offset, out.len() as u64);
                out.extend(data);
                ch.send(Message::Ack {
                    received: out.len() as u64,
                    error_received: Some(err.len() as u64),
                })
                .await;
            }
            Message::ErrorOutput { offset, data } => {
                assert_eq!(offset, err.len() as u64);
                err.extend(data);
            }
            Message::Ack { .. } => {}
            Message::Exit {
                output_end,
                status,
                error_end,
            } => {
                assert_eq!(output_end, out.len() as u64);
                assert_eq!(error_end, Some(err.len() as u64));
                assert_eq!(status, ExitStatus::Exited(0));
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(out == data, "stdout differs");
    assert_eq!(err, b"done\n");
}

/// Review H1: `qsh-server bootstrap` refuses a runtime directory others may use, instead of
/// talking to whatever listens there; and it does not change the directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_refuses_an_open_runtime_dir() {
    use std::os::unix::fs::PermissionsExt;
    let dir = PathBuf::from(format!("/tmp/qd-{}-sock", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("run")).unwrap();
    // As another user could leave it: world-writable
    std::fs::set_permissions(dir.join("run"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let paths = Paths::under(&dir);
    let listener = tokio::net::UnixListener::bind(paths.control_socket()).unwrap();
    let (got, mut got_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let _ = got.send(());
            drop(s);
        }
    });
    let launcher = DaemonLauncher {
        program: "/bin/false".into(),
        args: vec![],
    };
    let mut out = Vec::new();
    let req = b"{\"qsh\":1,\"versions\":[1],\"cols\":80,\"rows\":24}\n";
    let ok = qsh_core::server::bootstrap(&paths, &launcher, &req[..], &mut out)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(!ok, "{text}");
    assert!(text.contains("accessible to other users"), "{text}");
    assert!(got_rx.try_recv().is_err(), "it connected to the socket");
    assert_eq!(
        std::fs::metadata(dir.join("run")).unwrap().permissions().mode() & 0o777,
        0o777
    );
    // The status command checks the same
    assert!(qsh_core::server::request_status(&paths).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
