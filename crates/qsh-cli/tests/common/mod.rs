//! The test world shared by the end-to-end tests: a fake `ssh` that runs the remote command
//! locally, the real `qsh-server` started on demand by the bootstrap (in its own directories,
//! on its own port), and helpers to drive `qsh` on pipes or a pseudo terminal.
//!
//! Every world has its own HOME, XDG directories and port, and cleans up by pid: the daemon it
//! started, then any session process still working in its home directory.

#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

pub const QSH: &str = env!("CARGO_BIN_EXE_qsh");
pub const QSH_SERVER: &str = env!("CARGO_BIN_EXE_qsh-server");

/// ssh for tests: runs the remote command on this machine. Destinations containing `nosrv`
/// have no qsh-server. FAKE_SSH_UDP / FAKE_SSH_TCP rewrite the ports in the bootstrap reply,
/// to send the client to a port that is blocked.
pub const FAKE_SSH: &str = r#"#!/bin/sh
if [ "$1" = -G ]; then echo "hostname 127.0.0.1"; exit 0; fi
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-p|-l|-i|-J|-F|-E|-b|-c|-m) shift 2 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
dest=$1; shift
cmd="$*"
case "$dest" in
  *nosrv*) exec env PATH=/usr/bin:/bin HOME=/nonexistent sh -c "$cmd" ;;
esac
case "$cmd" in
  *" bootstrap;"*)
    if [ -n "$FAKE_SSH_UDP$FAKE_SSH_TCP" ]; then
      out=$(sh -c "$cmd"); status=$?
      [ -n "$FAKE_SSH_UDP" ] && out=$(printf '%s' "$out" | sed "s/\"udp\":[0-9]*/\"udp\":$FAKE_SSH_UDP/")
      [ -n "$FAKE_SSH_TCP" ] && out=$(printf '%s' "$out" | sed "s/\"tcp\":[0-9]*/\"tcp\":$FAKE_SSH_TCP/")
      printf '%s\n' "$out"; exit $status
    fi ;;
esac
exec sh -c "$cmd"
"#;

/// A test world: its own HOME and XDG directories, a port range of one free port.
pub struct World {
    pub dir: PathBuf,
    pub port: u16,
    pub env: Vec<(String, String)>,
    /// UDP sockets that swallow everything: a "blocked" UDP port.
    _blackholes: Vec<std::net::UdpSocket>,
}

impl World {
    pub fn new(name: &str) -> World {
        // What this test inherited (like the lock of `flock ... cargo test`) must not reach the
        // daemon and the sessions: they would hold it after the test
        qsh_core::sys::cloexec_from(3);
        // Short: unix socket paths are limited to about 100 bytes
        let dir = PathBuf::from(format!("/tmp/qsht-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["bin", "home", "run", "state", "config"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        let ssh = dir.join("bin/ssh");
        fs::write(&ssh, FAKE_SSH).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let port = free_port();
        let bin_dir = Path::new(QSH_SERVER).parent().unwrap().to_path_buf();
        let env = vec![
            ("HOME".into(), dir.join("home").display().to_string()),
            ("XDG_RUNTIME_DIR".into(), dir.join("run").display().to_string()),
            ("XDG_STATE_HOME".into(), dir.join("state").display().to_string()),
            ("XDG_CONFIG_HOME".into(), dir.join("config").display().to_string()),
            ("QSH_SERVER_PORTS".into(), format!("{port}-{port}")),
            (
                "PATH".into(),
                format!("{}:{}:/usr/bin:/bin", dir.join("bin").display(), bin_dir.display()),
            ),
        ];
        World {
            dir,
            port,
            env,
            _blackholes: Vec::new(),
        }
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.into(), value.into()));
    }

    /// Make the client's QUIC attempts go to a UDP port that swallows everything.
    pub fn block_udp(&mut self) {
        let hole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = hole.local_addr().unwrap().port();
        self._blackholes.push(hole);
        self.set("FAKE_SSH_UDP", port.to_string());
    }

    /// Make the client's TLS attempts go to a TCP port where nothing listens.
    pub fn block_tcp(&mut self) {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        self.set("FAKE_SSH_TCP", port.to_string());
    }

    pub fn command(&self, program: &str, args: &[&str]) -> Command {
        let mut c = Command::new(program);
        c.args(args)
            .env_clear()
            .env("TERM", "xterm-256color")
            .env("LANG", "C.UTF-8");
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c.current_dir(&self.dir);
        c
    }

    pub fn qsh(&self, args: &[&str]) -> Command {
        self.command(QSH, args)
    }

    /// The daemon's status, None when none runs.
    pub fn status(&self) -> Option<Value> {
        let out = self.command(QSH_SERVER, &["status"]).output().unwrap();
        out.status
            .success()
            .then(|| serde_json::from_slice(&out.stdout).unwrap())
    }

    pub fn stats(&self) -> Value {
        self.status().expect("a daemon")["stats"].clone()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let pid = self.status().and_then(|s| s["pid"].as_u64());
        let _ = self.command(QSH_SERVER, &["stop"]).output();
        if let Some(pid) = pid {
            wait_until(
                Duration::from_secs(5),
                || !alive(pid as i32),
                "the daemon to stop",
                false,
            );
            kill(pid as i32);
        }
        // The sessions' programs get SIGHUP when the daemon stops; kill what is left
        let home = self.dir.join("home");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut left = processes_in(&home);
        while !left.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            left = processes_in(&home);
        }
        for pid in &left {
            kill(*pid);
        }
        if std::thread::panicking() || std::env::var_os("QSH_TEST_LOGS").is_some() {
            eprintln!("--- {} (port {})", self.dir.display(), self.port);
            if let Ok(text) = fs::read_to_string(self.dir.join("state/qsh/daemon.log")) {
                eprintln!("--- daemon.log\n{text}");
            }
        }
        if !std::thread::panicking() {
            let _ = fs::remove_dir_all(&self.dir);
            assert!(left.is_empty(), "session processes {left:?} outlived the daemon");
        }
    }
}

pub fn alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.contains(") Z "))
}

pub fn kill(pid: i32) {
    let _ = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .stderr(Stdio::null())
        .status();
}

/// Processes working in `dir` (sessions start in HOME).
pub fn processes_in(dir: &Path) -> Vec<i32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| fs::read_link(format!("/proc/{pid}/cwd")).is_ok_and(|cwd| cwd.starts_with(dir)))
        .filter(|pid| alive(*pid))
        .collect()
}

/// Descendants of `ancestor` whose command line contains `needle`.
pub fn descendants(ancestor: u32, needle: &str) -> Vec<i32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let parent_of = |pid: i32| -> Option<i32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit(") ").next()?.split(' ').nth(1)?.parse().ok()
    };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            let mut p = *pid;
            let mut descends = false;
            while let Some(parent) = parent_of(p).filter(|p| *p > 1) {
                if parent == ancestor as i32 {
                    descends = true;
                    break;
                }
                p = parent;
            }
            let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            // Arguments are separated by NUL bytes
            descends && String::from_utf8_lossy(&cmdline).replace('\0', " ").contains(needle)
        })
        .collect()
}

pub fn free_port() -> u16 {
    loop {
        let udp = std::net::UdpSocket::bind("[::]:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        if std::net::TcpListener::bind(("::", port)).is_ok() {
            return port;
        }
    }
}

pub fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool, what: &str, must: bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        if Instant::now() >= deadline {
            assert!(!must, "timed out waiting for {what}");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// qsh on a pseudo terminal, like a user's interactive session.
pub struct Tty {
    pub child: Child,
    pub master: fs::File,
    pub out: Arc<Mutex<Vec<u8>>>,
}

impl Tty {
    pub fn spawn(mut command: Command) -> Tty {
        let (master, slave) = qsh_core::sys::openpty(100, 30).unwrap();
        let slave = fs::File::from(slave);
        command
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        let child = command.spawn().unwrap();
        let master = fs::File::from(master);
        let mut reader = master.try_clone().unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let sink = out.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Tty { child, master, out }
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
    }

    pub fn wait_for(&self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.text().contains(needle) {
            assert!(Instant::now() < deadline, "no {needle:?} in {:?}", self.text());
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
    }

    pub fn exit_code(&mut self, timeout: Duration) -> i32 {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(Instant::now() < deadline, "qsh did not exit; output {:?}", self.text());
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The numbers of the complete `tick-N` lines, in order.
pub fn ticks(text: &str) -> Vec<u64> {
    text.split("tick-")
        .skip(1)
        .filter_map(|s| {
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            matches!(s[digits.len()..].chars().next(), Some('\r') | Some('\n'))
                .then(|| digits.parse().ok())
                .flatten()
        })
        .collect()
}

pub const TICKER: &str = "i=0; while [ $i -lt 100000 ]; do i=$((i+1)); echo tick-$i; sleep 0.05; done";
