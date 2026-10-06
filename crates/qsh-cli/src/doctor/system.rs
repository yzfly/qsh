//! What doctor reads and tune changes, behind one trait: files (under a root directory that
//! stands for `/`), commands, the environment and a few system calls. [`Host`] is the real
//! one; the tests use fixture trees (`fixtures.rs`) and temporary roots with a directory of
//! stub commands (`--root DIR --commands DIR`).

use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long a status command may take (a firewall daemon that does not answer on D-Bus must
/// not hang doctor).
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// What a command printed, and its exit status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit status; -1 when it was killed (by a signal, or after [`COMMAND_TIMEOUT`]).
    pub status: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl Output {
    /// True for exit status 0.
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// What binding a port on the wildcard address shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    /// The port can be bound.
    Free,
    /// `EADDRINUSE`: something holds it.
    InUse,
    /// `EACCES`: below `net.ipv4.ip_unprivileged_port_start` for this user.
    Denied,
    /// Another error.
    Error(String),
}

/// `lstat` of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    /// A directory (not through a symbolic link).
    pub dir: bool,
    /// A symbolic link.
    pub symlink: bool,
}

/// Everything doctor reads and tune changes. Paths are absolute paths of the system
/// (`/etc/os-release`); an implementation may map them under a root directory.
pub trait System {
    /// The content of a file, None when it cannot be read.
    fn read(&self, path: &str) -> Option<String>;
    /// True when `path` exists (without following a final symbolic link).
    fn exists(&self, path: &str) -> bool;
    /// The names in a directory, sorted; empty when it cannot be read.
    fn list(&self, dir: &str) -> Vec<String>;
    /// `lstat`.
    fn meta(&self, path: &str) -> Option<Meta>;
    /// Run `program` (looked up in `PATH`) with `args`, stdin closed, `LC_ALL=C`. None when
    /// the program does not exist or cannot be started.
    fn run(&self, program: &str, args: &[&str]) -> Option<Output>;
    /// An environment variable of this process.
    fn env(&self, name: &str) -> Option<String>;
    /// The effective user id.
    fn euid(&self) -> u32;
    /// Try to bind `port` on the wildcard address, UDP or TCP, and let it go at once.
    fn bind(&self, port: u16, udp: bool) -> Bind;
    /// UDP GSO and GRO segments a socket gets ([`qsh_core::transport::quic::udp_offload`]).
    fn udp_offload(&self) -> Option<(usize, usize)>;
    /// Whether the kernel reports the clock synchronized.
    fn clock_synchronized(&self) -> Option<bool>;
    /// The source address of the IPv4 default route (no packet is sent).
    fn source_v4(&self) -> Option<IpAddr>;

    /// Write `content` to `path` with `mode` and, when given, `owner` (uid, gid): a temporary
    /// file next to it, then renamed. A symbolic link is never followed.
    fn write(&self, path: &str, content: &[u8], mode: u32, owner: Option<(u32, u32)>) -> io::Result<()>;
    /// Overwrite an existing file in place (a sysctl under /proc/sys).
    fn set(&self, path: &str, content: &str) -> io::Result<()>;
    /// Remove a file.
    fn remove(&self, path: &str) -> io::Result<()>;
    /// Create a directory (not its parents) with `mode`.
    fn mkdir(&self, path: &str, mode: u32) -> io::Result<()>;
    /// Remove an empty directory.
    fn rmdir(&self, path: &str) -> io::Result<()>;
}

/// The `PATH` commands are looked up in when doctor or tune runs as root: the system's
/// directories only, never the one of whoever ran sudo (security.md 4.9).
pub const ROOT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// The real system, or a directory standing in for `/` (`--root DIR`, tests only).
///
/// On the real system files are read as their paths say (`/etc/os-release` is often a link),
/// while everything tune changes is reached without following a symbolic link (an `openat`
/// walk, [`qsh_core::sys::Beneath`]). Commands are looked up in [`ROOT_PATH`] when running as
/// root, in the inherited `PATH` otherwise.
///
/// Under a stand-in root every file is reached without following any link and nothing can
/// lead outside it; and no command of the host runs: only the stub programs of the
/// `commands` directory, by name. Without one, no command runs at all.
#[derive(Debug)]
pub struct Host {
    root: PathBuf,
    beneath: Option<qsh_core::sys::Beneath>,
    commands: Option<PathBuf>,
}

impl Default for Host {
    fn default() -> Self {
        Host::real()
    }
}

impl Host {
    /// The real system.
    pub fn real() -> Host {
        Host {
            root: PathBuf::from("/"),
            beneath: qsh_core::sys::Beneath::open(Path::new("/")).ok(),
            commands: None,
        }
    }

    /// The system whose `/` is the directory `root`, with the stub programs of `commands` as
    /// its only commands (tests).
    pub fn stand_in(root: &Path, commands: Option<&Path>) -> io::Result<Host> {
        Ok(Host {
            root: root.to_path_buf(),
            beneath: Some(qsh_core::sys::Beneath::open(root)?),
            commands: commands.map(Path::to_path_buf),
        })
    }

    /// True when this is the real system.
    pub fn is_real(&self) -> bool {
        self.root == Path::new("/")
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn beneath(&self) -> io::Result<&qsh_core::sys::Beneath> {
        self.beneath
            .as_ref()
            .ok_or_else(|| io::Error::other(format!("cannot open {}", self.root.display())))
    }

    /// The program to run for `program`, and the `PATH` it gets; None when there is none.
    fn program(&self, program: &str) -> Option<(PathBuf, Option<String>)> {
        if program.is_empty() || program.contains('/') {
            return None;
        }
        if !self.is_real() {
            let dir = self.commands.as_ref()?;
            let path = dir.join(program);
            return path
                .is_file()
                .then(|| (path, Some(format!("{}:{ROOT_PATH}", dir.display()))));
        }
        if qsh_core::sys::euid() != 0 {
            return Some((PathBuf::from(program), None));
        }
        ROOT_PATH
            .split(':')
            .map(|d| Path::new(d).join(program))
            .find(|p| p.is_file())
            .map(|p| (p, Some(ROOT_PATH.to_string())))
    }
}

/// Run a command with a timeout; None when it cannot be started.
pub fn run_command(program: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut command = Command::new(program);
    command.args(args);
    run_capped(command, timeout, 16 << 20, 1 << 20)
}

/// Run `command` (stdin closed, `LC_ALL=C`) for at most `timeout`, keeping at most `out_limit`
/// bytes of its standard output and `err_limit` of its standard error (the rest is read and
/// dropped, so that it never blocks on a full pipe). None when it cannot be started.
pub fn run_capped(mut command: Command, timeout: Duration, out_limit: u64, err_limit: u64) -> Option<Output> {
    let mut child = command
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    // Read both pipes on threads: a full pipe would block the command forever
    fn reader(mut pipe: impl io::Read + Send + 'static, limit: u64) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = (&mut pipe).take(limit).read_to_end(&mut text);
            let _ = io::copy(&mut pipe, &mut io::sink());
            String::from_utf8_lossy(&text).into_owned()
        })
    }
    let out_thread = reader(child.stdout.take()?, out_limit);
    let err_thread = reader(child.stderr.take()?, err_limit);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break -1;
            }
        }
    };
    Some(Output {
        status,
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
    })
}

/// Most bytes doctor reads of one file.
const READ_LIMIT: u64 = 16 << 20;

impl System for Host {
    fn read(&self, path: &str) -> Option<String> {
        let bytes = if self.is_real() {
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(READ_LIMIT)
                .read_to_end(&mut bytes)
                .ok()?;
            bytes
        } else {
            self.beneath().ok()?.read(path, READ_LIMIT).ok()?
        };
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn exists(&self, path: &str) -> bool {
        self.meta(path).is_some()
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let mut names: Vec<String> = if self.is_real() {
            std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            self.beneath().and_then(|b| b.list(dir)).unwrap_or_default()
        };
        names.sort();
        names
    }

    fn meta(&self, path: &str) -> Option<Meta> {
        use std::os::unix::fs::MetadataExt;
        if self.is_real() {
            let m = std::fs::symlink_metadata(path).ok()?;
            return Some(Meta {
                uid: m.uid(),
                gid: m.gid(),
                mode: m.mode() & 0o7777,
                dir: m.is_dir(),
                symlink: m.file_type().is_symlink(),
            });
        }
        let st = self.beneath().ok()?.stat(path).ok()?;
        Some(Meta {
            uid: st.uid,
            gid: st.gid,
            mode: st.mode & 0o7777,
            dir: st.is_dir(),
            symlink: st.is_symlink(),
        })
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<Output> {
        let (path, search) = self.program(program)?;
        let mut command = Command::new(path);
        command.args(args);
        if let Some(search) = search {
            command.env("PATH", search);
        }
        run_capped(command, COMMAND_TIMEOUT, 16 << 20, 1 << 20)
    }

    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn euid(&self) -> u32 {
        qsh_core::sys::euid()
    }

    fn bind(&self, port: u16, udp: bool) -> Bind {
        let result = if udp {
            qsh_core::sys::udp_any(port).map(drop)
        } else {
            std::net::TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port))
                .or_else(|e| match e.kind() {
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => Err(e),
                    // No IPv6 on this host
                    _ => std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)),
                })
                .map(drop)
        };
        match result {
            Ok(()) => Bind::Free,
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => Bind::InUse,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Bind::Denied,
            Err(e) => Bind::Error(e.to_string()),
        }
    }

    fn udp_offload(&self) -> Option<(usize, usize)> {
        qsh_core::transport::quic::udp_offload().ok()
    }

    fn clock_synchronized(&self) -> Option<bool> {
        qsh_core::sys::clock_synchronized()
    }

    fn source_v4(&self) -> Option<IpAddr> {
        qsh_core::netwatch::NetSnapshot::take().ipv4.map(|r| r.source)
    }

    fn write(&self, path: &str, content: &[u8], mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
        self.beneath()?.write(path, content, mode, owner)
    }

    fn set(&self, path: &str, content: &str) -> io::Result<()> {
        self.beneath()?.set(path, content.as_bytes())
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        self.beneath()?.remove(path)
    }

    fn mkdir(&self, path: &str, mode: u32) -> io::Result<()> {
        self.beneath()?.mkdir(path, mode)
    }

    fn rmdir(&self, path: &str) -> io::Result<()> {
        self.beneath()?.rmdir(path)
    }
}
