//! `qsh doctor [HOST]` (m2.md 8.5): the client's own checks; with a host, the server's
//! report over the user's ssh (`qsh-server doctor --json --probe`, whose certificate
//! fingerprint is as trustworthy as a bootstrap reply), a probe of every transport and port
//! from here, and a diagnosis that combines both sides.
//!
//! The probes speak qsh/1 up to the hello exchange and close (no ATTACH, no session): QUIC
//! and TLS to every announced port, pinned to the server's certificate, QUIC for 3 s with a
//! 100 ms keep-alive to sample RTT, loss and path MTU; and the ssh pipe to its preface.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use qsh_core::client::paths::{self, PathMemory};
use qsh_core::client::{ClientConfig, Conn};
use qsh_core::config::Keepalive;
use qsh_core::crypto::Fingerprint;
use qsh_core::netwatch::{NetSnapshot, NetWatch};
use qsh_core::proto::bootstrap::ExtraPort;
use qsh_core::proto::ErrorCode;
use qsh_core::transport::quic::{self, QuicClient};
use qsh_core::transport::{self, FailureKind, Target, Transport};
use qsh_core::Paths;

use super::checks::{self, WANTED_BUFFER};
use super::report::{self, Style};
use super::system::{Host, System};
use super::{Check, Fix, Status, SCHEMA};

/// How long the QUIC probes sample the path after the hello.
pub const SAMPLE: Duration = Duration::from_secs(3);
/// QUIC keep-alive while sampling: a sample every 100 ms.
pub const SAMPLE_KEEPALIVE: Duration = Duration::from_millis(100);
/// The hello must come within this long (as in the race, m2.md 3.3 `hello`).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// What `qsh doctor` was asked.
#[derive(Debug, Clone)]
pub struct Options {
    /// `--json`.
    pub json: bool,
    /// `--tune`: run `sudo qsh-server tune --apply` on the host afterwards, over `ssh -t`.
    pub tune: bool,
    /// ssh may ask for passwords on the terminal.
    pub interactive: bool,
    /// `path_memory` of qsh_config(5).
    pub path_memory: bool,
    /// `keepalive` of qsh_config(5).
    pub keepalive: Keepalive,
}

// ---------------------------------------------------------------------------------------
// The client's own checks

fn client_udp_buffers(sys: &dyn System) -> Check {
    if cfg!(target_os = "macos") {
        let max = sys
            .run("sysctl", &["-n", "kern.ipc.maxsockbuf"])
            .and_then(|o| o.stdout.trim().parse::<u64>().ok());
        return match max {
            Some(m) if m >= WANTED_BUFFER => Check::new(
                "udp-buffers",
                Status::Ok,
                format!("socket buffers up to {} MiB", m >> 20),
            ),
            Some(m) => Check::new(
                "udp-buffers",
                Status::Warn,
                format!("kern.ipc.maxsockbuf is {m}; QUIC on long fast paths needs {WANTED_BUFFER}"),
            )
            .fix(Fix::commands(
                true,
                [format!("sudo sysctl -w kern.ipc.maxsockbuf={}", WANTED_BUFFER * 2)],
            )),
            None => Check::new("udp-buffers", Status::Skip, "kern.ipc.maxsockbuf cannot be read"),
        };
    }
    let read = |k: &str| checks::sysctl(sys, k).and_then(|v| v.parse::<u64>().ok());
    match (read("net.core.rmem_max"), read("net.core.wmem_max")) {
        (Some(r), Some(w)) if r >= WANTED_BUFFER && w >= WANTED_BUFFER => {
            Check::new("udp-buffers", Status::Ok, format!("socket buffers up to {} MiB", r.min(w) >> 20))
        }
        (Some(r), Some(w)) => Check::new(
            "udp-buffers",
            Status::Warn,
            format!("net.core.rmem_max is {r}, wmem_max {w}; fast downloads over QUIC need {WANTED_BUFFER}"),
        )
        .fix(
            Fix::commands(
                true,
                [
                    format!("sudo sysctl -w net.core.rmem_max={WANTED_BUFFER} net.core.wmem_max={WANTED_BUFFER}"),
                    format!("printf 'net.core.rmem_max = {WANTED_BUFFER}\\nnet.core.wmem_max = {WANTED_BUFFER}\\n' | sudo tee /etc/sysctl.d/90-qsh.conf"),
                ],
            ),
        ),
        _ => Check::new("udp-buffers", Status::Skip, "the socket buffer limits cannot be read"),
    }
}

fn describe_route(r: &qsh_core::netwatch::DefaultRoute) -> String {
    match r.gateway {
        Some(g) => format!("{} ({} via {g})", r.interface, r.source),
        None => format!("{} ({})", r.interface, r.source),
    }
}

/// How the client sees its network: the default routes and how changes are noticed.
fn network(snapshot: &NetSnapshot) -> Check {
    let mechanism = NetWatch::spawn()
        .map(|w| w.mechanism().to_string())
        .unwrap_or_else(|_| "polling".into());
    let routes: Vec<String> = [("IPv4", &snapshot.ipv4), ("IPv6", &snapshot.ipv6)]
        .iter()
        .filter_map(|(fam, r)| r.as_ref().map(|r| format!("{fam} {}", describe_route(r))))
        .collect();
    if routes.is_empty() {
        return Check::new("network", Status::Fail, "offline: no default route").fact("watch", mechanism);
    }
    let status = if mechanism == "polling" {
        Status::Info
    } else {
        Status::Ok
    };
    let how = if mechanism == "polling" {
        "changes noticed by polling every 5 s".to_string()
    } else {
        format!("changes seen at once ({mechanism})")
    };
    Check::new("network", status, format!("{}; {how}", routes.join(", "))).fact("watch", mechanism)
}

fn ssh_check(sys: &dyn System, program: &str) -> Check {
    match sys.run(program, &["-V"]) {
        Some(o) => {
            // OpenSSH prints its version on stderr; another ssh may not know -V
            let v = o
                .stderr
                .lines()
                .chain(o.stdout.lines())
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let summary = if o.ok() && !v.is_empty() {
                v.clone()
            } else {
                program.to_string()
            };
            Check::new("ssh", Status::Ok, summary).fact("version", if o.ok() { v } else { String::new() })
        }
        None => Check::new(
            "ssh",
            Status::Fail,
            format!("{program} is not installed: qsh needs it for the first contact"),
        )
        .fix(Fix::commands(
            false,
            ["install the OpenSSH client (openssh-client, openssh)".to_string()],
        )),
    }
}

fn day_text(day: Option<u64>, today: u64) -> String {
    match day.map(|d| today.saturating_sub(d)) {
        Some(0) => "today".into(),
        Some(1) => "yesterday".into(),
        Some(n) => format!("{n} days ago"),
        None => "never".into(),
    }
}

/// The path memory entry of `host` on this network, for people and for JSON.
fn memory_check(
    opts: &Options,
    memory: Option<&PathMemory>,
    host: Option<&str>,
    entry: Option<&paths::Entry>,
) -> Check {
    if !opts.path_memory {
        return Check::new(
            "path-memory",
            Status::Info,
            "off (path_memory = false): every reconnect races all transports",
        );
    }
    let file = memory
        .and_then(|m| m.path())
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let Some(host) = host else {
        return Check::new(
            "path-memory",
            Status::Ok,
            format!("on, in {file}; qsh doctor HOST shows what it knows about HOST here"),
        )
        .fact("file", file);
    };
    let (k, auto) = paths::keepalive_for(opts.keepalive, entry);
    let learned = auto && entry.and_then(paths::Entry::keepalive).is_some();
    let ka = format!(
        "keepalive {} s ({})",
        k.as_secs(),
        match (auto, learned) {
            (false, _) => "configured",
            (true, true) => "learned on this network",
            (true, false) => "default",
        }
    );
    let Some(e) = entry else {
        return Check::new(
            "path-memory",
            Status::Info,
            format!("nothing remembered about {host} on this network yet; {ka}"),
        )
        .fact("file", file)
        .fact("keepalive_s", k.as_secs());
    };
    let now = paths::now();
    let today = now / 86400;
    let mut parts = Vec::new();
    for t in [Transport::Quic, Transport::Tls, Transport::Ssh] {
        if let Some(r) = e.transport(t) {
            if e.blocked(t, now) {
                let kind = r.fail.as_ref().map(|f| f.kind.clone()).unwrap_or_default();
                parts.push(format!("{t} blocked ({kind})"));
            } else if r.ok.is_some() {
                parts.push(format!("{t} worked {}", day_text(r.ok, today)));
            }
        }
    }
    if parts.is_empty() {
        parts.push("no outcome yet".into());
    }
    let mut c = Check::new("path-memory", Status::Info, format!("{}; {ka}", parts.join(", ")))
        .fact("file", file)
        .fact("entry", serde_json::to_value(e).unwrap_or(Value::Null))
        .fact("keepalive_s", k.as_secs());
    if e.blocked_now(now).is_empty() {
        c.status = Status::Ok;
    }
    c
}

// ---------------------------------------------------------------------------------------
// The server's report over ssh

/// What running `qsh-server doctor --json --probe` over ssh gave.
#[derive(Debug, Clone, PartialEq)]
pub enum Remote {
    /// The report.
    Report(Value),
    /// The host has no qsh-server (42, 127).
    NoServer,
    /// The host's qsh-server has no doctor (before 0.5.0).
    Old,
    /// ssh failed, or the output was not a report.
    Error(String),
}

/// The most of the remote report's output read (the rest is dropped).
pub const MAX_REMOTE_OUTPUT: u64 = 1 << 20;

/// How long `qsh-server doctor --json --probe` over ssh may take, logins included.
pub const REMOTE_TIMEOUT: Duration = Duration::from_secs(60);

/// The longest string of a remote report kept.
const MAX_REMOTE_STRING: usize = 1024;

/// Every string in `v`, made text only and bounded (security.md 4.6): the report is the
/// server's, and its summaries, fixes and notes are printed on the user's terminal.
fn sanitize_strings(v: &mut Value) {
    match v {
        Value::String(text) => *text = qsh_core::text::sanitize(text, MAX_REMOTE_STRING),
        Value::Array(items) => items.iter_mut().for_each(sanitize_strings),
        Value::Object(members) => {
            let clean: serde_json::Map<String, Value> = std::mem::take(members)
                .into_iter()
                .map(|(k, mut v)| {
                    sanitize_strings(&mut v);
                    (qsh_core::text::sanitize(&k, 64), v)
                })
                .collect();
            *members = clean;
        }
        _ => {}
    }
}

/// Find the report in the output of the remote command: the last line that is a JSON object
/// with `"doctor"` (login scripts may print before it). Every string of it, and of the
/// errors made from ssh's output, is text only ([`qsh_core::text::sanitize`]).
pub fn parse_remote(status: Option<i32>, stdout: &str, stderr: &str) -> Remote {
    let stderr = qsh_core::text::sanitize(stderr.trim(), MAX_REMOTE_STRING);
    let report = stdout
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .find(|v| v.get("doctor").is_some())
        .or_else(|| {
            serde_json::from_str::<Value>(stdout.trim())
                .ok()
                .filter(|v| v.get("doctor").is_some())
        });
    if let Some(mut r) = report {
        sanitize_strings(&mut r);
        return Remote::Report(r);
    }
    match status {
        Some(42) | Some(127) => Remote::NoServer,
        Some(2) if stderr.contains("doctor") || stderr.contains("unrecognized subcommand") => Remote::Old,
        Some(126) => Remote::Error("qsh-server on the host cannot be executed (another architecture?)".into()),
        Some(255) => Remote::Error(format!("ssh failed: {stderr}")),
        Some(s) => Remote::Error(format!("qsh-server doctor exited with status {s}: {stderr}")),
        None => Remote::Error("ssh was killed".into()),
    }
}

/// `qsh-server doctor --json --probe` over ssh, within [`REMOTE_TIMEOUT`] and
/// [`MAX_REMOTE_OUTPUT`] bytes.
async fn remote_report(config: &ClientConfig, interactive: bool) -> Remote {
    let ssh = config.ssh.clone();
    let result = tokio::task::spawn_blocking(move || {
        let cmd = ssh.one_off(&ssh.remote_command("doctor --json --probe"), !interactive);
        super::system::run_capped(cmd, REMOTE_TIMEOUT, MAX_REMOTE_OUTPUT, 64 << 10)
    })
    .await;
    match result {
        Ok(Some(out)) if out.status == -1 => Remote::Error(format!(
            "qsh-server doctor over ssh gave no report within {REMOTE_TIMEOUT:?}"
        )),
        Ok(Some(out)) => parse_remote(Some(out.status), &out.stdout, &out.stderr),
        Ok(None) => Remote::Error("cannot run ssh".into()),
        Err(e) => Remote::Error(e.to_string()),
    }
}

// ---------------------------------------------------------------------------------------
// Probes

/// How one transport and port fared.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    /// The transport.
    pub transport: Transport,
    /// The port (0 for the ssh pipe).
    pub port: u16,
    /// None when it worked; else the failure.
    pub failure: Option<(FailureKind, String)>,
    /// Handshake time (QUIC, TLS: to the end of the TLS handshake; pipe: to the preface).
    pub handshake: Option<Duration>,
    /// Round-trip time (QUIC: quinn's estimate after sampling; TLS: the hello exchange).
    pub rtt: Option<Duration>,
    /// QUIC loss ratio while sampling.
    pub loss: Option<f64>,
    /// QUIC path MTU (PLPMTUD).
    pub mtu: Option<u16>,
    /// The client's address as the server saw it (PATH_INFO).
    pub observed: Option<std::net::SocketAddr>,
    /// The local port of the client's UDP socket (QUIC).
    pub local_port: Option<u16>,
}

impl Probe {
    fn failed(transport: Transport, port: u16, error: &std::io::Error) -> Probe {
        Probe {
            transport,
            port,
            failure: Some((FailureKind::of(error), error.to_string())),
            ..Probe::ok(transport, port)
        }
    }

    fn ok(transport: Transport, port: u16) -> Probe {
        Probe {
            transport,
            port,
            failure: None,
            handshake: None,
            rtt: None,
            loss: None,
            mtu: None,
            observed: None,
            local_port: None,
        }
    }

    /// True when it worked.
    pub fn works(&self) -> bool {
        self.failure.is_none()
    }

    /// The JSON form.
    pub fn to_json(&self) -> Value {
        let ms = |d: Option<Duration>| d.map(|d| d.as_millis() as u64);
        json!({
            "transport": match self.transport {
                Transport::Quic => "quic",
                Transport::Tls => "tls",
                Transport::Ssh => "ssh",
            },
            "port": self.port,
            "outcome": match &self.failure {
                None => "ok",
                Some((FailureKind::Refused, _)) => "refused",
                Some((kind, _)) => kind.as_str(),
            },
            "error": self.failure.as_ref().map(|f| f.1.clone()),
            "handshake_ms": ms(self.handshake),
            "rtt_ms": ms(self.rtt),
            "loss": self.loss,
            "mtu": self.mtu,
            "observed": self.observed.map(|a| a.to_string()),
        })
    }
}

async fn hello(connection: transport::Connection) -> std::io::Result<Arc<Conn>> {
    match tokio::time::timeout(HELLO_TIMEOUT, Conn::hello(connection)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no SERVER_HELLO within 5 s",
        )),
    }
}

async fn probe_quic(client: Arc<QuicClient>, host: String, port: u16, pin: Fingerprint) -> Probe {
    let started = Instant::now();
    let options = quic::Options {
        keep_alive: SAMPLE_KEEPALIVE,
        ..quic::Options::default()
    };
    let connection = match client.connect_with(&host, port, pin, &options).await {
        Ok(c) => c,
        Err(e) => return Probe::failed(Transport::Quic, port, &e),
    };
    let handshake = started.elapsed();
    // A second handle on the same connection, for quinn's path statistics
    let stats = connection.clone();
    let conn = match hello(transport::Connection::quic(connection)).await {
        Ok(c) => c,
        Err(e) => {
            let mut p = Probe::failed(Transport::Quic, port, &e);
            if p.failure.as_ref().is_some_and(|f| f.0 == FailureKind::Timeout) {
                p.failure = Some((FailureKind::Hello, e.to_string()));
            }
            return p;
        }
    };
    tokio::time::sleep(SAMPLE).await;
    let mut p = Probe::ok(Transport::Quic, port);
    p.handshake = Some(handshake);
    p.loss = conn.loss();
    p.observed = conn.observed();
    p.local_port = client.local_addr().map(|a| a.port());
    let path = stats.stats().path;
    p.rtt = Some(path.rtt);
    p.mtu = Some(path.current_mtu);
    conn.close(ErrorCode::NO_ERROR, "doctor");
    p
}

async fn probe_tls(host: String, port: u16, pin: Fingerprint) -> Probe {
    let started = Instant::now();
    let tls = match transport::tls::connect(&host, port, pin).await {
        Ok(t) => t,
        Err(e) => return Probe::failed(Transport::Tls, port, &e),
    };
    let handshake = started.elapsed();
    let hello_started = Instant::now();
    let conn = match hello(transport::Connection::tls_client(tls)).await {
        Ok(c) => c,
        Err(e) => {
            let mut p = Probe::failed(Transport::Tls, port, &e);
            if p.failure.as_ref().is_some_and(|f| f.0 == FailureKind::Timeout) {
                p.failure = Some((FailureKind::Hello, e.to_string()));
            }
            return p;
        }
    };
    let mut p = Probe::ok(Transport::Tls, port);
    p.handshake = Some(handshake);
    // The hello exchange is one round trip
    p.rtt = Some(hello_started.elapsed());
    p.observed = conn.observed();
    conn.close(ErrorCode::NO_ERROR, "doctor");
    p
}

async fn probe_pipe(ssh: qsh_core::transport::ssh::SshCommand) -> Probe {
    let started = Instant::now();
    match transport::connect_pipe(&ssh).await {
        Ok(connection) => {
            let handshake = started.elapsed();
            match hello(connection).await {
                Ok(conn) => {
                    conn.close(ErrorCode::NO_ERROR, "doctor");
                    let mut p = Probe::ok(Transport::Ssh, 0);
                    p.handshake = Some(handshake);
                    p
                }
                Err(e) => Probe::failed(Transport::Ssh, 0, &e),
            }
        }
        Err(e) => Probe::failed(Transport::Ssh, 0, &e),
    }
}

/// The daemon as the server's report announced it.
fn target_of(config: &ClientConfig, host: &str, report: &Value) -> Option<Target> {
    let d = &report["daemon"];
    let pin = Fingerprint::from_hex(d["cert_sha256"].as_str()?)?;
    let port = |k: &str| d[k].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(0);
    Some(Target {
        host: host.to_string(),
        udp: port("udp"),
        tcp: port("tcp"),
        fingerprint: pin,
        ssh: config.ssh.clone(),
        extra_ports: ExtraPort::list_from_json(&d["extra_ports"]),
    })
}

/// The most QUIC and TLS probes open at once. Each is an unauthenticated connection for about
/// 3 s, and the daemon admits at most `MAX_PREAUTH_PER_SOURCE` (8) of those per source address
/// (protocol.md 6.6): more would be refused by the daemon's own limit, and recorded as the
/// network blocking the transport (review M5). Two stay free for a real client of the same
/// address meanwhile.
pub const PROBES_AT_ONCE: usize = qsh_core::proto::limits::MAX_PREAUTH_PER_SOURCE - 2;
const _: () = assert!(PROBES_AT_ONCE >= 1 && PROBES_AT_ONCE < qsh_core::proto::limits::MAX_PREAUTH_PER_SOURCE);

/// Run `jobs` with at most `at_once` of them at a time; their results in the order given.
pub async fn at_most<T: Send + 'static>(
    jobs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>>,
    at_once: usize,
) -> Vec<T> {
    let permits = Arc::new(tokio::sync::Semaphore::new(at_once.max(1)));
    let tasks: Vec<_> = jobs
        .into_iter()
        .map(|job| {
            let permits = permits.clone();
            tokio::spawn(async move {
                let _permit = permits.acquire_owned().await;
                job.await
            })
        })
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        if let Ok(v) = t.await {
            out.push(v);
        }
    }
    out
}

/// Probe every transport and port of `target` (when there is one), at most
/// [`PROBES_AT_ONCE`] at a time, and the ssh pipe meanwhile.
async fn probe_all(target: Option<&Target>, config: &ClientConfig) -> Vec<Probe> {
    type Job = std::pin::Pin<Box<dyn std::future::Future<Output = Probe> + Send>>;
    let mut jobs: Vec<Job> = Vec::new();
    if let Some(t) = target {
        let client = Arc::new(QuicClient::new());
        for port in t.candidates(Transport::Quic, None) {
            jobs.push(Box::pin(probe_quic(
                client.clone(),
                t.host.clone(),
                port,
                t.fingerprint,
            )));
        }
        for port in t.candidates(Transport::Tls, None) {
            jobs.push(Box::pin(probe_tls(t.host.clone(), port, t.fingerprint)));
        }
    }
    let pipe = tokio::spawn(probe_pipe(config.ssh.clone()));
    let mut probes = at_most(jobs, PROBES_AT_ONCE).await;
    if let Ok(p) = pipe.await {
        probes.push(p);
    }
    probes
}

/// Record what the probes showed into path memory, as a race would (no poisoning: a
/// failure is recorded only when another transport reached the server).
fn record(memory: &PathMemory, host: &str, network: &[u8], probes: &[Probe]) {
    let now = paths::now();
    let worked: Vec<&Probe> = probes.iter().filter(|p| p.works()).collect();
    if worked.is_empty() {
        return;
    }
    memory.update(host, network, now, |e| {
        for t in [Transport::Quic, Transport::Tls, Transport::Ssh] {
            let mine: Vec<&Probe> = probes.iter().filter(|p| p.transport == t).collect();
            if let Some(ok) = mine.iter().filter(|p| p.works()).min_by_key(|p| p.handshake) {
                e.succeeded(t, ok.port, ok.handshake.unwrap_or_default(), now);
                if t == Transport::Quic {
                    e.measured(ok.rtt, ok.loss);
                }
            } else if t != Transport::Ssh {
                if let Some(kind) = mine
                    .iter()
                    .filter_map(|p| p.failure.as_ref().map(|f| f.0))
                    .find(|k| k.recorded())
                {
                    e.failed(t, kind, now);
                }
            }
        }
    });
    let _ = memory.flush();
}

// ---------------------------------------------------------------------------------------
// Diagnosis

fn server_check<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    report["checks"].as_array()?.iter().find(|c| c["id"] == id)
}

fn cloud_name(id: &str) -> Option<(&'static str, &'static str)> {
    Some(match id {
        "aws" => ("Amazon EC2", "security group"),
        "gcp" => ("Google Compute Engine", "VPC firewall"),
        "azure" => ("Microsoft Azure", "network security group"),
        "alibaba" => ("Alibaba Cloud", "security group (安全组)"),
        "tencent" => ("Tencent Cloud", "security group (安全组)"),
        "oracle" => ("Oracle Cloud", "security list"),
        "hetzner" | "digitalocean" | "vultr" => ("the cloud provider", "cloud firewall"),
        _ => return None,
    })
}

/// What the probes and the server's report mean together (m2.md 8.5 step 4).
pub fn diagnose(host: &str, probes: &[Probe], remote: &Remote) -> Vec<String> {
    let mut out = Vec::new();
    let works = |t: Transport| probes.iter().any(|p| p.transport == t && p.works());
    let tried = |t: Transport| probes.iter().any(|p| p.transport == t);
    let first_fail = |t: Transport| probes.iter().find(|p| p.transport == t && !p.works());
    let report = match remote {
        Remote::Report(r) => Some(r),
        Remote::NoServer => {
            out.push(format!(
                "{host} has no qsh-server: install it (qsh install {host}, or the distribution's package)"
            ));
            None
        }
        Remote::Old => {
            out.push(format!(
                "qsh-server on {host} has no doctor (before 0.5.0): upgrade it for a full report; only the ssh pipe could be tested"
            ));
            None
        }
        Remote::Error(e) => {
            out.push(format!("the server's report is missing: {e}"));
            None
        }
    };
    let firewall = report.and_then(|r| server_check(r, "firewall"));
    let fw_status = firewall.and_then(|f| f["status"].as_str()).unwrap_or("");
    let fw_fix = firewall
        .and_then(|f| f["fix"]["commands"].as_array())
        .map(|c| c.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" && "))
        .unwrap_or_default();
    let cloud = report.and_then(|r| r["host"]["cloud"].as_str()).and_then(cloud_name);
    let quic_port = first_fail(Transport::Quic).map(|p| p.port);
    if tried(Transport::Quic) {
        if works(Transport::Quic) {
            if let Some(p) = first_fail(Transport::Quic) {
                out.push(format!(
                    "QUIC works, but not on port {}: {}",
                    p.port,
                    p.failure.as_ref().map(|f| f.1.as_str()).unwrap_or("")
                ));
            } else {
                out.push("QUIC works from here: qsh uses it, and keeps sessions across address changes".into());
            }
        } else {
            let p = quic_port.unwrap_or(0);
            let kind = first_fail(Transport::Quic)
                .and_then(|p| p.failure.as_ref())
                .map(|f| f.0);
            match kind {
                Some(FailureKind::Refused) => out.push(format!(
                    "nothing answers on UDP {p} of {host}: the daemon does not listen there (qsh-server stop, then connect again)"
                )),
                Some(FailureKind::PinMismatch) => out.push(format!(
                    "the daemon on UDP {p} presented another certificate than the report: run qsh doctor {host} again"
                )),
                _ if fw_status == "fail" => out.push(format!(
                    "UDP {p} times out from here, and the server's firewall blocks it: {fw_fix}"
                )),
                _ if fw_status == "skip" => out.push(format!(
                    "UDP {p} times out from here; the server's firewall rules need root to read: run sudo qsh-server doctor on {host}"
                )),
                _ if cloud.is_some() => {
                    let (name, group) = cloud.unwrap_or_default();
                    out.push(format!(
                        "UDP {p} times out from here, the server's firewall allows it, and the server is on {name}: the {group} most likely blocks UDP {p}"
                    ));
                }
                _ if works(Transport::Tls) => out.push(
                    "nothing on the server blocks UDP, and TLS works: your network blocks UDP; qsh will use TLS on this network (remembered)"
                        .into(),
                ),
                _ => out.push(format!(
                    "UDP {p} times out from here although nothing on the server blocks it: a firewall in between (the server's network or yours) drops it"
                )),
            }
        }
    }
    if tried(Transport::Tls) && !works(Transport::Tls) {
        let p = first_fail(Transport::Tls).map(|p| p.port).unwrap_or(0);
        let why = first_fail(Transport::Tls)
            .and_then(|p| p.failure.as_ref())
            .map(|f| f.1.clone())
            .unwrap_or_default();
        if works(Transport::Quic) {
            out.push(format!(
                "TLS on TCP {p} fails ({why}): only matters where UDP is blocked, where it is the fallback"
            ));
        } else if fw_status != "fail" {
            out.push(format!(
                "TLS on TCP {p} fails too ({why}): qsh falls back to the ssh pipe"
            ));
        }
    }
    match probes.iter().find(|p| p.transport == Transport::Ssh) {
        Some(p) if !p.works() => {
            let why = p.failure.as_ref().map(|f| f.1.as_str()).unwrap_or("");
            out.push(format!(
                "the ssh pipe fails ({why}): it needs ssh without prompts (a key or agent); it is the last fallback"
            ));
        }
        _ => {}
    }
    if let Some(loss) = probes
        .iter()
        .filter(|p| p.transport == Transport::Quic)
        .filter_map(|p| p.loss)
        .reduce(f64::max)
    {
        if loss >= 0.05 {
            out.push(format!(
                "{:.0} % of packets are lost on this path: qsh recovers, but output arrives in bursts",
                loss * 100.0
            ));
        }
    }
    if let Some(r) = report {
        let problems = r["checks"]
            .as_array()
            .map(|c| {
                c.iter()
                    .filter(|c| c["status"] == "fail" || c["status"] == "warn")
                    .filter(|c| c["id"] != "firewall")
                    .count()
            })
            .unwrap_or(0);
        if problems > 0 {
            out.push(format!(
                "{host} has {problems} more problem{} above; qsh doctor {host} --tune applies what tune can",
                if problems == 1 { "" } else { "s" }
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Rendering and the command

fn ms(d: Duration) -> String {
    if d >= Duration::from_secs(10) {
        format!("{:.0} s", d.as_secs_f64())
    } else if d >= Duration::from_secs(1) {
        format!("{:.1} s", d.as_secs_f64())
    } else {
        format!("{} ms", d.as_millis())
    }
}

fn probe_line(p: &Probe) -> (Status, String, String) {
    let label = match p.transport {
        Transport::Ssh => "ssh pipe".to_string(),
        t => format!("{t} {}", p.port),
    };
    let Some((kind, why)) = &p.failure else {
        let mut parts = Vec::new();
        if let Some(h) = p.handshake {
            parts.push(if p.transport == Transport::Ssh {
                format!("{} to the preface", ms(h))
            } else {
                format!("handshake {}", ms(h))
            });
        }
        if let Some(r) = p.rtt {
            parts.push(format!("RTT {}", ms(r)));
        }
        if let Some(l) = p.loss {
            parts.push(format!("loss {:.1} %", l * 100.0));
        }
        if let Some(m) = p.mtu {
            parts.push(format!("MTU {m}"));
        }
        return (Status::Ok, label, parts.join(", "));
    };
    let text = match kind {
        FailureKind::Timeout => "timeout".to_string(),
        FailureKind::Refused => "refused".to_string(),
        FailureKind::Reset => format!("reset: {why}"),
        FailureKind::Hello => "no SERVER_HELLO (something in between interferes)".to_string(),
        _ => why.clone(),
    };
    (Status::Fail, label, text)
}

/// The local address the kernel uses towards `host`:`port` (a connected UDP socket; nothing
/// is sent).
fn source_for(host: &str, port: u16) -> Option<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    let server = (host, port).to_socket_addrs().ok()?.next()?;
    let any: std::net::SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(any).ok()?;
    socket.connect(server).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// NAT: whether the server sees another address than the one this client sends from, and
/// whether the NAT kept the port.
fn nat_line(probes: &[Probe], source: Option<std::net::IpAddr>) -> Option<(Status, String)> {
    let p = probes
        .iter()
        .find(|p| p.transport == Transport::Quic && p.observed.is_some())?;
    let observed = p.observed?;
    let ip = match observed.ip() {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(observed.ip()),
        ip => ip,
    };
    if source == Some(ip) {
        return Some((Status::Ok, format!("no NAT: the server sees {ip} as this machine")));
    }
    let port = match p.local_port {
        Some(l) if l == observed.port() => "port kept",
        Some(_) => "port changed",
        None => "port unknown",
    };
    Some((
        Status::Info,
        format!("behind a NAT: the server sees {observed} ({port}); qsh learns how long it keeps mappings"),
    ))
}

fn describe_remote_host(h: &Value) -> String {
    let mut parts = vec![h["os_name"].as_str().unwrap_or("Linux").to_string()];
    if let Some(v) = h["systemd"].as_str() {
        parts.push(format!("systemd {v}"));
    }
    if let Some(k) = h["kernel"].as_str().filter(|k| !k.is_empty()) {
        parts.push(format!("kernel {}", k.split(['-', '+']).next().unwrap_or(k)));
    }
    if let Some(c) = h["container"].as_str() {
        parts.push(format!("in a {c} container"));
    }
    if let Some((name, _)) = h["cloud"].as_str().and_then(cloud_name) {
        parts.push(name.to_string());
    }
    parts.join(", ")
}

fn status_of(s: &str) -> Status {
    match s {
        "ok" => Status::Ok,
        "info" => Status::Info,
        "warn" => Status::Warn,
        "fail" => Status::Fail,
        _ => Status::Skip,
    }
}

/// A check of the server's JSON report as a line.
fn remote_line(c: &Value, style: &Style, width: usize) -> String {
    let fix = c.get("fix").map(|f| Fix {
        root: f["root"] == true,
        tune: f["tune"].as_str().map(|_| "remote"),
        tune_flags: f["tune_flags"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        commands: f["commands"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        note: f["note"].as_str().map(String::from),
    });
    report::line(
        status_of(c["status"].as_str().unwrap_or("")),
        c["id"].as_str().unwrap_or("?"),
        c["summary"].as_str().unwrap_or(""),
        fix.as_ref(),
        style,
        width,
    )
}

/// The whole of `qsh doctor` (with or without a host). Returns the exit status: 0 when
/// nothing failed, 1 when something did, 2 when doctor could not run.
pub async fn run(config: Option<ClientConfig>, opts: Options) -> i32 {
    let sys = Host::default();
    let paths = Paths::from_env();
    let memory = opts.path_memory.then(|| PathMemory::standard(&paths));
    let snapshot = NetSnapshot::take();
    let network_key = snapshot.path_key();
    let mut client = vec![network(&snapshot), client_udp_buffers(&sys)];
    let ssh_program = config
        .as_ref()
        .map(|c| c.ssh.program.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ssh".into());
    client.push(ssh_check(&sys, &ssh_program));
    let style = Style::for_stdout();

    let Some(config) = config else {
        client.push(memory_check(&opts, memory.as_ref(), None, None));
        if opts.json {
            let out = json!({
                "doctor": SCHEMA,
                "client": {"checks": client.iter().map(Check::to_json).collect::<Vec<_>>()},
            });
            println!("{out:#}");
        } else {
            let w = report::id_width(&client);
            let mut out = String::from("qsh doctor: this machine\n\n");
            for c in &client {
                out.push_str(&report::check_lines(c, &style, w));
            }
            print!("{out}");
        }
        return i32::from(super::exit_status(&client));
    };

    let destination = config.ssh.destination.clone();
    // The host the client dials, as a session would (ssh -G, else the host part)
    let host = match config.ssh.resolve_host().await {
        Some(h) => h,
        None => destination.rsplit('@').next().unwrap_or(&destination).to_string(),
    };
    let entry = memory.as_ref().and_then(|m| m.entry(&host, &network_key));
    client.push(memory_check(&opts, memory.as_ref(), Some(&host), entry.as_ref()));

    if !opts.json {
        eprintln!("qsh: asking {destination} (qsh-server doctor over ssh), then probing every transport…");
    }
    let remote = remote_report(&config, opts.interactive).await;
    let target = match &remote {
        Remote::Report(r) => target_of(&config, &host, r),
        _ => None,
    };
    let probes = probe_all(target.as_ref(), &config).await;
    if let Some(m) = &memory {
        record(m, &host, &network_key, &probes);
    }
    let diagnosis = diagnose(&destination, &probes, &remote);
    let source = target.as_ref().and_then(|t| source_for(&t.host, t.udp.max(t.tcp)));
    let nat = nat_line(&probes, source);
    let direct_failed = target.is_some() && !probes.iter().any(|p| p.transport != Transport::Ssh && p.works());
    let server_failed = matches!(&remote, Remote::Report(r) if r["checks"].as_array().is_some_and(|c| c.iter().any(|c| c["status"] == "fail")));
    let no_report = !matches!(remote, Remote::Report(_));
    let mut code = i32::from(direct_failed || server_failed || no_report || super::exit_status(&client) == 1);
    if no_report && !probes.iter().any(Probe::works) {
        code = 2;
    }

    if opts.json {
        let out = json!({
            "doctor": SCHEMA,
            "destination": destination,
            "client": {
                "checks": client.iter().map(Check::to_json).collect::<Vec<_>>(),
                "nat": nat.as_ref().map(|n| n.1.clone()),
            },
            "server": match &remote { Remote::Report(r) => r.clone(), _ => Value::Null },
            "server_error": match &remote {
                Remote::Report(_) => Value::Null,
                Remote::NoServer => json!("no qsh-server"),
                Remote::Old => json!("qsh-server without doctor"),
                Remote::Error(e) => json!(e),
            },
            "probes": probes.iter().map(Probe::to_json).collect::<Vec<_>>(),
            "diagnosis": diagnosis,
        });
        println!("{out:#}");
    } else {
        let mut lines: Vec<(Status, String, String)> = probes.iter().map(probe_line).collect();
        if let Some((s, text)) = &nat {
            lines.push((*s, "nat".into(), text.clone()));
        }
        let remote_checks: Vec<Value> = match &remote {
            Remote::Report(r) => r["checks"].as_array().cloned().unwrap_or_default(),
            _ => Vec::new(),
        };
        let width = client
            .iter()
            .map(|c| c.id.len())
            .chain(lines.iter().map(|l| l.1.len()))
            .chain(remote_checks.iter().map(|c| c["id"].as_str().unwrap_or("").len()))
            .max()
            .unwrap_or(12)
            .max(13)
            + 1;
        let mut out = format!("qsh doctor: {destination}\n\nThis machine\n");
        for c in &client {
            out.push_str(&report::check_lines(c, &style, width));
        }
        let _ = writeln!(out, "\nFrom here to {destination}");
        for (s, label, text) in &lines {
            out.push_str(&report::line(*s, label, text, None, &style, width));
        }
        if let Remote::Report(r) = &remote {
            let _ = writeln!(
                out,
                "\nOn {} — {}",
                r["host"]["name"].as_str().unwrap_or(&destination),
                describe_remote_host(&r["host"])
            );
            for c in &remote_checks {
                out.push_str(&remote_line(c, &style, width));
            }
        }
        if !diagnosis.is_empty() {
            out.push_str("\nDiagnosis\n");
            let room = style.width.saturating_sub(4).max(40);
            for d in &diagnosis {
                for (i, l) in report::wrap(d, room).iter().enumerate() {
                    let lead = if i == 0 { "  " } else { "    " };
                    let _ = writeln!(out, "{lead}{l}");
                }
            }
        }
        print!("{out}");
    }

    if opts.tune {
        return tune_over_ssh(&config);
    }
    code
}

/// The remote program of `qsh doctor HOST --tune`: the discovery of protocol.md 10.2, but
/// sudo runs only a qsh-server that root owns and nobody else can change, in directories
/// nobody else can change (review L2: `~/.local/bin/qsh-server` is the user's to replace, and
/// sudo would run it as root). Its real path is what sudo runs. Exit 42: no qsh-server; 43:
/// one that is not installed for root (it says how to install it).
pub const TUNE_REMOTE: &str = "sh -c 'safe() { set -- $(ls -lnd -- \"$1\" 2>/dev/null); case \"$1\" in ?????w*|????????w*) return 1;; esac; [ \"$3\" = 0 ]; }; for p in \"$(command -v qsh-server)\" \"$HOME/.local/bin/qsh-server\"; do [ -n \"$p\" ] && [ -x \"$p\" ] || continue; r=$(readlink -f -- \"$p\") || continue; d=$r; ok=1; while :; do safe \"$d\" || { ok=0; break; }; [ \"$d\" = / ] && break; d=$(dirname -- \"$d\"); done; if [ $ok = 1 ]; then exec sudo -- \"$r\" tune --apply; fi; echo \"qsh: $p is not owned by root, or root does not own a directory above it: sudo does not run it\" >&2; echo \"qsh: install qsh-server for the whole system (a package, or the install script as root), then: sudo qsh-server tune --apply\" >&2; exit 43; done; exit 42'";

/// `ssh -t HOST sudo qsh-server tune --apply`, in front of the user: the plan, the
/// confirmation and sudo's password prompt happen on this terminal (security.md 4.9). With
/// the forwarding options of every ssh qsh runs (security.md 4.6).
fn tune_over_ssh(config: &ClientConfig) -> i32 {
    let ssh = &config.ssh;
    eprintln!(
        "\nqsh: running sudo qsh-server tune --apply on {} (ssh -t): it shows its plan and asks before changing anything",
        ssh.destination
    );
    let status = ssh.with_terminal(TUNE_REMOTE).status();
    match status {
        Ok(s) => s.code().unwrap_or(qsh_core::client::EXIT_ERROR),
        Err(e) => {
            eprintln!("qsh: cannot run ssh: {e}");
            qsh_core::client::EXIT_ERROR
        }
    }
}
