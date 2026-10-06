//! What doctor reads and tune changes, behind one trait: files (under a root directory that
//! stands for `/`), commands, the environment and a few system calls. [`Host`] is the real
//! one; the tests use fixture trees (`fixtures.rs`) and temporary roots with stub
//! commands on `PATH`.

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

    /// Write `content` to `path` with `mode`: a temporary file next to it, then renamed.
    fn write(&self, path: &str, content: &[u8], mode: u32) -> io::Result<()>;
    /// Overwrite an existing file in place (a sysctl under /proc/sys).
    fn set(&self, path: &str, content: &str) -> io::Result<()>;
    /// Remove a file.
    fn remove(&self, path: &str) -> io::Result<()>;
    /// Create a directory (not its parents) with mode 0755.
    fn mkdir(&self, path: &str) -> io::Result<()>;
    /// Remove an empty directory.
    fn rmdir(&self, path: &str) -> io::Result<()>;
}

/// The real system, or a directory standing in for `/` (`--root`). Files are read and written
/// under the root; commands, the environment and the system calls are the host's.
#[derive(Debug, Clone)]
pub struct Host {
    root: PathBuf,
}

impl Default for Host {
    fn default() -> Self {
        Host::new("/")
    }
}

impl Host {
    /// The system whose `/` is `root`.
    pub fn new(root: impl Into<PathBuf>) -> Host {
        Host { root: root.into() }
    }

    /// True when the root is the real `/`.
    pub fn is_real_root(&self) -> bool {
        self.root.canonicalize().map(|p| p == Path::new("/")).unwrap_or(false)
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where `path` of the system is on this host.
    pub fn path(&self, path: &str) -> PathBuf {
        if self.root == Path::new("/") {
            PathBuf::from(path)
        } else {
            self.root.join(path.trim_start_matches('/'))
        }
    }
}

/// Run a command with a timeout; None when it cannot be started.
pub fn run_command(program: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    // Read both pipes on threads: a full pipe would block the command forever
    fn reader(pipe: impl io::Read + Send + 'static, limit: u64) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = pipe.take(limit).read_to_end(&mut text);
            String::from_utf8_lossy(&text).into_owned()
        })
    }
    let out_thread = reader(child.stdout.take()?, 16 << 20);
    let err_thread = reader(child.stderr.take()?, 1 << 20);
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

impl System for Host {
    fn read(&self, path: &str) -> Option<String> {
        let bytes = std::fs::read(self.path(path)).ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(self.path(path)).is_ok()
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.path(dir))
            .map(|entries| {
                entries
                    .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn meta(&self, path: &str) -> Option<Meta> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(self.path(path)).ok()?;
        Some(Meta {
            uid: m.uid(),
            mode: m.mode() & 0o7777,
            dir: m.is_dir(),
            symlink: m.file_type().is_symlink(),
        })
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<Output> {
        run_command(program, args, COMMAND_TIMEOUT)
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

    fn write(&self, path: &str, content: &[u8], mode: u32) -> io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let target = self.path(path);
        let name = target
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
            .to_string_lossy()
            .into_owned();
        let tmp = target.with_file_name(format!(".{name}.qsh-tune-{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)?;
            file.write_all(content)?;
            file.sync_all()?;
            // The umask may have taken bits away
            std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
            std::fs::rename(&tmp, &target)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    fn set(&self, path: &str, content: &str) -> io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.path(path))?;
        file.write_all(content.as_bytes())
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        std::fs::remove_file(self.path(path))
    }

    fn mkdir(&self, path: &str) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o755).create(self.path(path))
    }

    fn rmdir(&self, path: &str) -> io::Result<()> {
        std::fs::remove_dir(self.path(path))
    }
}
