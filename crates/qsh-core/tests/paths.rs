//! Path intelligence against a real daemon in this process (m2.md sections 3 to 5): a blocked
//! primary UDP port and an extra port, a transport upgrade when UDP comes back, and NAT
//! keepalive learning behind a relay that forgets idle mappings. Each test has its own
//! directories under /tmp, its own ports (port 0) and its own path memory file.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use qsh_core::client::paths::PathMemory;
use qsh_core::client::store::SavedSession;
use qsh_core::client::{ClientConfig, Input, Pool, Session, Status, Terminal};
use qsh_core::config::Keepalive;
use qsh_core::crypto::{Fingerprint, SessionKey};
use qsh_core::netwatch::NetSnapshot;
use qsh_core::proto::bootstrap::{parse_reply, Credentials, ExtraPort, Op, Reply};
use qsh_core::server::{Daemon, DaemonLauncher, ServerConfig};
use qsh_core::transport::quic::QuicClient;
use qsh_core::transport::ssh::SshCommand;
use qsh_core::transport::{FailureKind, Target, Transport};
use qsh_core::Paths;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

/// How long a daemon may take to start: generous, for slow and emulated builders.
const STARTUP: Duration = Duration::from_secs(30);

struct TestDaemon {
    paths: Paths,
    dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
}

impl TestDaemon {
    async fn start(name: &str) -> TestDaemon {
        let dir = PathBuf::from(format!("/tmp/qp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths::under(&dir);
        let mut config = ServerConfig::new(paths.clone());
        config.ports = 0..=0;
        config.shell = Some("/bin/sh".into());
        let (stop, stopped) = oneshot::channel::<()>();
        let mut task = tokio::spawn(async move {
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
            if task.is_finished() {
                let ended = (&mut task).await;
                panic!("the daemon {name} ended before it was ready: {ended:?}");
            }
            assert!(tokio::time::Instant::now() < deadline, "the daemon {name} is not ready");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        TestDaemon {
            paths,
            dir,
            stop: Some(stop),
        }
    }

    async fn boot(&self, command: &str) -> Credentials {
        let launcher = DaemonLauncher {
            program: "/bin/false".into(),
            args: vec![],
        };
        let mut out = Vec::new();
        let line = format!(r#"{{"qsh":1,"versions":[1],"cols":80,"rows":24,"command":"{command}"}}"#) + "\n";
        qsh_core::server::bootstrap(&self.paths, &launcher, line.as_bytes(), &mut out)
            .await
            .unwrap();
        match parse_reply(&out, Op::New).unwrap() {
            Reply::Credentials(c) => c,
            other => panic!("{other:?}"),
        }
    }

    /// Path memory of the client in this test's directory.
    fn memory_path(&self) -> PathBuf {
        self.dir.join("client/paths.json")
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

/// A UDP relay between one client and the daemon, standing in for the network: it can drop
/// everything (UDP blocked), and it can behave like a NAT that forgets a mapping after the
/// client was quiet for a while (the next client packet then leaves from a new port).
struct Relay {
    port: u16,
    blocked: Arc<AtomicBool>,
    /// Times the "NAT" gave the client a new mapping.
    rebinds: Arc<AtomicU32>,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    async fn start(daemon: SocketAddr, nat_timeout: Option<Duration>) -> Relay {
        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = front.local_addr().unwrap().port();
        let blocked = Arc::new(AtomicBool::new(false));
        let rebinds = Arc::new(AtomicU32::new(0));
        let (b, r) = (blocked.clone(), rebinds.clone());
        let task = tokio::spawn(async move {
            let mut up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut client: Option<SocketAddr> = None;
            let mut last = tokio::time::Instant::now();
            let (mut a, mut c) = (vec![0u8; 65536], vec![0u8; 65536]);
            loop {
                tokio::select! {
                    got = front.recv_from(&mut a) => {
                        let Ok((n, from)) = got else { return };
                        if b.load(Ordering::SeqCst) {
                            continue;
                        }
                        if nat_timeout.is_some_and(|t| last.elapsed() > t) && client.is_some() {
                            up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                            r.fetch_add(1, Ordering::SeqCst);
                        }
                        last = tokio::time::Instant::now();
                        client = Some(from);
                        let _ = up.send_to(&a[..n], daemon).await;
                    }
                    got = up.recv_from(&mut c) => {
                        let Ok((n, _)) = got else { return };
                        if b.load(Ordering::SeqCst) {
                            continue;
                        }
                        if let Some(to) = client {
                            let _ = front.send_to(&c[..n], to).await;
                        }
                    }
                }
            }
        });
        Relay {
            port,
            blocked,
            rebinds,
            task,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn saved(c: &Credentials, udp: u16, tcp: u16) -> SavedSession {
    SavedSession {
        destination: "test-host".into(),
        ssh_options: Vec::new(),
        host: "127.0.0.1".into(),
        udp,
        tcp,
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

/// A client without the ssh pipe: these tests never start ssh.
fn config() -> ClientConfig {
    let mut config = ClientConfig::new("test-host");
    config.race.ssh = None;
    config
}

struct Running {
    input: mpsc::Sender<Input>,
    output: mpsc::Receiver<Vec<u8>>,
    status: Arc<std::sync::Mutex<Status>>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    fn start(pool: &Arc<Pool>, config: ClientConfig, saved: SavedSession) -> Running {
        let (input, input_rx) = mpsc::channel(16);
        let (output_tx, output) = mpsc::channel(256);
        let session = Session::with_pool(config, pool.clone());
        let status = session.status();
        let task = tokio::spawn(async move {
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
            task,
        }
    }

    async fn wait_transport(&self, transport: Transport, within: Duration) {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.status.lock().unwrap().transport == Some(transport) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "not attached over {transport} within {within:?}: {:?}",
                self.status.lock().unwrap()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Type `text` and wait for its echo.
    async fn echo(&mut self, text: &str) {
        self.input
            .send(Input::Data(format!("{text}\n").into_bytes()))
            .await
            .unwrap();
        let mut seen = Vec::new();
        let found = tokio::time::timeout(Duration::from_secs(20), async {
            while let Some(bytes) = self.output.recv().await {
                seen.extend_from_slice(&bytes);
                if String::from_utf8_lossy(&seen).contains(text) {
                    return true;
                }
            }
            false
        })
        .await;
        assert_eq!(
            found.ok(),
            Some(true),
            "no echo of {text}: {:?}",
            String::from_utf8_lossy(&seen)
        );
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The network as path memory keys it; None on a machine without a default route, where
/// nothing can be remembered (the tests then check what they can).
fn network() -> Option<Vec<u8>> {
    Some(NetSnapshot::take().path_key()).filter(|k| !k.is_empty())
}

/// m2.md 5.3 with real QUIC: the primary UDP port answers nothing, the extra port 300 ms later
/// connects; the port is remembered and starts the next race.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_falls_back_to_an_extra_port_and_remembers_it() {
    let d = TestDaemon::start("extra").await;
    let c = d.boot("sleep 1000").await;
    let hole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = Target {
        host: "127.0.0.1".into(),
        udp: hole.local_addr().unwrap().port(),
        tcp: 0,
        fingerprint: Fingerprint::from_hex(&c.cert_sha256).unwrap(),
        ssh: SshCommand::new("test-host"),
        extra_ports: vec![ExtraPort {
            port: c.udp,
            udp: true,
            tcp: false,
        }],
    };
    let pool = Pool::with_memory(Arc::new(QuicClient::new()), Some(PathMemory::open(d.memory_path())));
    let started = tokio::time::Instant::now();
    let conn = pool.get(&target, &config()).await.unwrap();
    let took = started.elapsed();
    assert_eq!(conn.transport(), Transport::Quic);
    assert!(took >= Duration::from_millis(300), "{took:?}");
    drop(conn);
    drop(pool);
    let Some(network) = network() else { return };
    let entry = PathMemory::open(d.memory_path()).entry("127.0.0.1", &network).unwrap();
    let quic = entry.transport(Transport::Quic).unwrap();
    assert_eq!(quic.port, Some(c.udp));
    assert!(
        quic.fail.is_none(),
        "the blocked port does not mark QUIC: another port worked"
    );
    let planned = qsh_core::client::paths::plan(Some(&entry), &target, &config().race, qsh_core::client::paths::now());
    assert_eq!(planned.plan.attempts[0].port, c.udp);
    assert_eq!(planned.plan.attempts[0].delay, Duration::ZERO);
}

/// m2.md 3.6: a session on TLS because UDP was blocked moves to QUIC once a background probe
/// finds UDP open again, without a disconnection, and goes on working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_session_moves_to_quic_when_udp_comes_back() {
    let Some(network) = network() else { return };
    let d = TestDaemon::start("upgrade").await;
    let c = d.boot("cat").await;
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], c.udp)), None).await;
    relay.blocked.store(true, Ordering::SeqCst);
    // Remembered: TLS works here, QUIC timed out and is due for a probe in 3 s
    let memory = PathMemory::open(d.memory_path());
    let now = qsh_core::client::paths::now();
    memory.update("127.0.0.1", &network, now, |e| {
        e.succeeded(Transport::Tls, c.tcp, Duration::from_millis(50), now);
        e.failed(Transport::Quic, FailureKind::Timeout, now);
        e.transports.quic.as_mut().unwrap().fail.as_mut().unwrap().retry = now + 3;
    });
    memory.flush().unwrap();
    let pool = Pool::with_memory(Arc::new(QuicClient::new()), Some(PathMemory::open(d.memory_path())));
    let mut s = Running::start(&pool, config(), saved(&c, relay.port, c.tcp));
    s.wait_transport(Transport::Tls, Duration::from_secs(10)).await;
    s.echo("before-the-move").await;
    relay.blocked.store(false, Ordering::SeqCst);
    s.wait_transport(Transport::Quic, Duration::from_secs(30)).await;
    s.echo("after-the-move").await;
    assert_eq!(s.status.lock().unwrap().reconnects, 0, "moved, not reconnected");
    let entry = pool.path_memory().unwrap().entry("127.0.0.1", &network).unwrap();
    assert!(entry.transport(Transport::Quic).unwrap().fail.is_none(), "{entry:?}");
}

/// m2.md 4.2 and 4.3 with real QUIC: behind a "NAT" that forgets a mapping after 6 s of quiet,
/// a learned 8 s keepalive loses the mapping once: the server reports the new address, the
/// interval halves to 5 s (saved), and the PINGs at that interval keep the mapping from then
/// on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nat_that_forgets_idle_mappings_teaches_the_keepalive() {
    let Some(network) = network() else { return };
    let d = TestDaemon::start("nat").await;
    let c = d.boot("cat").await;
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], c.udp)), Some(Duration::from_secs(6))).await;
    let memory = PathMemory::open(d.memory_path());
    let now = qsh_core::client::paths::now();
    memory.update("127.0.0.1", &network, now, |e| e.set_keepalive(Duration::from_secs(8)));
    memory.flush().unwrap();
    let pool = Pool::with_memory(Arc::new(QuicClient::new()), Some(PathMemory::open(d.memory_path())));
    let mut config = config();
    config.race.tls = None;
    assert_eq!(config.keepalive, Keepalive::Auto);
    let mut s = Running::start(&pool, config, saved(&c, relay.port, 0));
    s.wait_transport(Transport::Quic, Duration::from_secs(10)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let learned = PathMemory::open(d.memory_path())
            .entry("127.0.0.1", &network)
            .and_then(|e| e.keepalive());
        if learned == Some(Duration::from_secs(5)) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "not learned: {learned:?}, {} rebinds",
            relay.rebinds.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let rebinds = relay.rebinds.load(Ordering::SeqCst);
    assert!(rebinds >= 1);
    // Idle for longer than the NAT's timeout: the PINGs every 5 s hold the mapping
    tokio::time::sleep(Duration::from_secs(14)).await;
    assert_eq!(relay.rebinds.load(Ordering::SeqCst), rebinds);
    s.echo("still-here").await;
}
