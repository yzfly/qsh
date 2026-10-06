//! The daemon's lifecycle, in this process: extra ports (m2.md section 5), the status of the
//! control socket's version 2 (protocol.md 10.6), and the upgrade refused by a daemon that is
//! embedded in another program. Each test has its own directories under /tmp and its own
//! ports. The upgrade itself replaces the process, so it is tested end to end with the real
//! `qsh-server` (crates/qsh-cli/tests/upgrade.rs).

use std::path::PathBuf;
use std::time::Duration;

use qsh_core::crypto::{Fingerprint, SessionKey};
use qsh_core::proto::bootstrap::{parse_reply, Credentials, ExtraPort, Op, Reply};
use qsh_core::proto::message::{ATTACH_FRESH, MAX_HELLO, MAX_TERMINAL};
use qsh_core::proto::{read_message, write_message, Message, WindowSize};
use qsh_core::server::{Daemon, DaemonLauncher, ServerConfig};
use qsh_core::transport::{tls, Connection, RecvStream};
use qsh_core::Paths;
use tokio::io::BufReader;

const STARTUP: Duration = Duration::from_secs(30);

struct TestDaemon {
    paths: Paths,
    dir: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TestDaemon {
    async fn start(name: &str, extra_ports: Vec<u16>) -> TestDaemon {
        let dir = PathBuf::from(format!("/tmp/ql-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::under(&dir);
        let mut config = ServerConfig::new(paths.clone());
        config.ports = 0..=0;
        config.shell = Some("/bin/sh".into());
        config.extra_ports = extra_ports;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let result = Daemon::run_until(config, async {
                let _ = stopped.await;
            })
            .await;
            assert!(result.is_ok(), "{result:?}");
        });
        let deadline = tokio::time::Instant::now() + STARTUP;
        while !matches!(paths.connect_private(&paths.control_socket()).await, Ok(Some(_))) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon {name} did not start"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        TestDaemon {
            paths,
            dir,
            stop: Some(stop),
        }
    }

    async fn boot(&self) -> Credentials {
        let launcher = DaemonLauncher {
            program: "/bin/false".into(),
            args: vec![],
        };
        let mut out = Vec::new();
        let request =
            "{\"qsh\":1,\"versions\":[1],\"cols\":80,\"rows\":24,\"command\":\"echo hello-$QSH_SESSION; sleep 100\"}\n";
        qsh_core::server::bootstrap(&self.paths, &launcher, request.as_bytes(), &mut out)
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

/// A port free on both UDP and TCP, on every address.
fn free_port() -> u16 {
    loop {
        let udp = std::net::UdpSocket::bind("[::]:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        if std::net::TcpListener::bind(("::", port)).is_ok() {
            return port;
        }
    }
}

async fn next(recv: &mut BufReader<RecvStream>) -> Option<Message> {
    tokio::time::timeout(Duration::from_secs(60), read_message(recv, MAX_TERMINAL))
        .await
        .expect("in time")
        .unwrap()
}

/// Attach to the session on `conn` and expect ATTACHED and its output.
async fn attach_works(conn: Connection, creds: &Credentials) {
    let (_, mut ctl_send, ctl_recv) = conn.open().await.unwrap();
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
    let mut ctl_recv = BufReader::new(ctl_recv);
    let Some(Message::ServerHello { nonce, .. }) = read_message(&mut ctl_recv, MAX_HELLO).await.unwrap() else {
        panic!("no SERVER_HELLO")
    };
    let session: [u8; 16] = qsh_core::crypto::unhex(&creds.session).unwrap();
    let key = SessionKey::from_hex(&creds.key).unwrap();
    let (_, mut send, recv) = conn.open().await.unwrap();
    let cb = conn.channel_binding(&session, &nonce).unwrap();
    write_message(
        &mut send,
        &Message::Attach {
            session,
            proof: key.proof(&cb),
            output_received: 0,
            size: WindowSize::new(80, 24),
            flags: ATTACH_FRESH,
            error_received: None,
        },
    )
    .await
    .unwrap();
    let mut recv = BufReader::new(recv);
    assert!(matches!(next(&mut recv).await, Some(Message::Attached { .. })));
    let mut text = String::new();
    while !text.contains(&format!("hello-{}", creds.session)) {
        match next(&mut recv).await {
            Some(Message::Output { data, .. }) => text.push_str(&String::from_utf8_lossy(&data)),
            other => panic!("{other:?} after {text:?}"),
        }
    }
    drop(ctl_send);
}

/// m2.md 5.1 and 5.2: extra ports are bound where they can be, UDP and TCP independently; a
/// port in use is skipped, not fatal; the bootstrap reply and the status announce exactly the
/// ports bound; a client reaches the session through each of them, on QUIC and on TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extra_ports_are_bound_where_possible_announced_and_served() {
    let (both, tcp_only, neither) = (free_port(), free_port(), free_port());
    // Another program holds UDP on one port, and both protocols on another
    let _udp_taken = std::net::UdpSocket::bind(("::", tcp_only)).unwrap();
    let _udp_taken2 = std::net::UdpSocket::bind(("::", neither)).unwrap();
    let _tcp_taken = std::net::TcpListener::bind(("::", neither)).unwrap();
    let d = TestDaemon::start("extra", vec![both, tcp_only, neither]).await;
    let creds = d.boot().await;
    assert_eq!(
        creds.extra_ports,
        vec![
            ExtraPort {
                port: both,
                udp: true,
                tcp: true
            },
            ExtraPort {
                port: tcp_only,
                udp: false,
                tcp: true
            },
        ]
    );
    let pin = Fingerprint::from_hex(&creds.cert_sha256).unwrap();
    // TLS on both extra TCP ports, QUIC on the extra UDP port: the same daemon, the same
    // certificate, the same session
    for port in [both, tcp_only] {
        let conn = Connection::tls_client(tls::connect("127.0.0.1", port, pin).await.unwrap());
        attach_works(conn, &creds).await;
    }
    let quic = qsh_core::transport::quic::QuicClient::new();
    let conn = quic.connect("127.0.0.1", both, pin).await.unwrap();
    attach_works(Connection::quic(conn), &creds).await;

    let status = qsh_core::server::request_status(&d.paths).await.unwrap().unwrap();
    assert_eq!(status["extra_ports"][0]["port"], both, "{status}");
    assert_eq!(status["extra_ports"].as_array().unwrap().len(), 2, "{status}");
    assert_eq!(status["udp"], status["tcp"]);
    assert_eq!(status["cert_sha256"], creds.cert_sha256.as_str());
    assert_eq!(status["session_count"], 1);
    assert_eq!(status["handoff"], serde_json::json!([1]));
    assert_eq!(status["v"], 2);
}

/// An embedded daemon (no program of its own to execute again) refuses to upgrade, says so,
/// and goes on serving; its status says it cannot upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_embedded_daemon_refuses_to_upgrade_and_goes_on() {
    let d = TestDaemon::start("embedded", vec![]).await;
    let creds = d.boot().await;
    let exe = std::env::current_exe().unwrap();
    let answer = qsh_core::server::request_upgrade(&d.paths, &exe, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer["ok"], false, "{answer}");
    assert!(
        answer["error"].as_str().unwrap().contains("cannot upgrade in place"),
        "{answer}"
    );
    let status = qsh_core::server::request_status(&d.paths).await.unwrap().unwrap();
    assert_eq!(status["can_upgrade"], false, "{status}");
    assert_eq!(status["restarts"], 0);
    assert_eq!(status["upgrading"], false);
    let pin = Fingerprint::from_hex(&creds.cert_sha256).unwrap();
    let conn = Connection::tls_client(tls::connect("127.0.0.1", creds.tcp, pin).await.unwrap());
    attach_works(conn, &creds).await;
}
