//! Where qsh keeps its files (docs/DESIGN.md section 3, FHS and XDG).
//!
//! | what | default |
//! |---|---|
//! | configuration | `$XDG_CONFIG_HOME/qsh`, else `~/.config/qsh` |
//! | state (daemon identity, saved sessions in `sessions/`, logs of on-demand daemons) | `$XDG_STATE_HOME/qsh`, else `~/.local/state/qsh` |
//! | runtime (control socket, daemon lock) | `$XDG_RUNTIME_DIR/qsh`, else `/tmp/qsh-$UID` |
//!
//! Every field is public: an embedder (TokenSSH keeps everything under its own directory)
//! builds a [`Paths`] of its own instead of [`Paths::from_env`].

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use tokio::net::UnixStream;

use crate::sys;

/// The directories qsh uses. Nothing is created until a `ensure_*` method or a component that
/// needs the directory asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The user's home directory: where sessions start.
    pub home: PathBuf,
    /// Configuration (`config` file, M1).
    pub config: PathBuf,
    /// Persistent state: the daemon's certificate, saved session credentials.
    pub state: PathBuf,
    /// Runtime files: the daemon's control socket and lock. Must be private to the user.
    pub runtime: PathBuf,
}

impl Paths {
    /// The standard locations from the environment (`HOME`, `XDG_*`), falling back to the
    /// password database for the home directory.
    pub fn from_env() -> Paths {
        let env_dir = |name: &str| std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute());
        let home = env_dir("HOME")
            .or_else(|| sys::passwd_entry().map(|u| u.home))
            .unwrap_or_else(|| PathBuf::from("/"));
        let config = env_dir("XDG_CONFIG_HOME")
            .unwrap_or_else(|| home.join(".config"))
            .join("qsh");
        let state = env_dir("XDG_STATE_HOME")
            .unwrap_or_else(|| home.join(".local/state"))
            .join("qsh");
        let runtime = match env_dir("XDG_RUNTIME_DIR") {
            Some(dir) => dir.join("qsh"),
            // Not $TMPDIR: every qsh-server of the user must find the same socket
            None => PathBuf::from(format!("/tmp/qsh-{}", sys::euid())),
        };
        Paths {
            home,
            config,
            state,
            runtime,
        }
    }

    /// All directories under one root, for tests and embedders that keep everything together.
    pub fn under(root: &Path) -> Paths {
        Paths {
            home: root.to_path_buf(),
            config: root.join("config"),
            state: root.join("state"),
            runtime: root.join("run"),
        }
    }

    /// The daemon's unix control socket, used by `qsh-server bootstrap` and `pipe`.
    pub fn control_socket(&self) -> PathBuf {
        self.runtime.join("control.sock")
    }

    /// The lock the daemon holds while it runs: one daemon per user.
    pub fn daemon_lock(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    /// The directory with the daemon's certificate and key.
    pub fn identity_dir(&self) -> PathBuf {
        self.state.join("daemon")
    }

    /// Where a daemon started on demand (by a bootstrap) writes its log.
    pub fn daemon_log(&self) -> PathBuf {
        self.state.join("daemon.log")
    }

    /// Where `qsh` keeps the credentials of its sessions (`qsh attach`, `qsh ls`): one file per
    /// session, mode 0600, in a directory of mode 0700 ([`crate::client::store`]).
    pub fn sessions_dir(&self) -> PathBuf {
        self.state.join("sessions")
    }

    /// The hub's unix socket (feature `hub`).
    pub fn hub_socket(&self) -> PathBuf {
        self.runtime.join("hub.sock")
    }

    /// The runtime directory, created with mode 0700 if missing. Refused when it belongs to
    /// someone else or others may use it: in a shared `/tmp`, anyone could have created it
    /// first to intercept the control socket.
    pub fn ensure_runtime(&self) -> io::Result<&Path> {
        ensure_private_dir(&self.runtime)?;
        Ok(&self.runtime)
    }

    /// Check the runtime directory before connecting to a socket in it, without creating it:
    /// false when it does not exist (so nothing can listen there), an error when it is not a
    /// private directory of this user ([`check_private_dir`]).
    pub fn check_runtime(&self) -> io::Result<bool> {
        match check_private_dir(&self.runtime) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Connect to `socket`, a unix socket in the runtime directory (the daemon's control socket,
    /// the hub's socket), checking first that the directory is private to this user
    /// ([`Paths::check_runtime`]) and then that the process at the other end runs as this user
    /// ([`check_peer`]). None when the directory does not exist or nothing listens on the
    /// socket; an error when either check fails, since then someone else may be listening.
    pub async fn connect_private(&self, socket: &Path) -> io::Result<Option<UnixStream>> {
        if !self.check_runtime()? {
            return Ok(None);
        }
        let stream = match UnixStream::connect(socket).await {
            Ok(stream) => stream,
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        check_peer(&stream)?;
        Ok(Some(stream))
    }

    /// The state directory, created with mode 0700 if missing.
    pub fn ensure_state(&self) -> io::Result<&Path> {
        ensure_private_dir(&self.state)?;
        Ok(&self.state)
    }
}

/// Create `dir` (and its parents) with mode 0700 if missing, then check it with
/// [`check_private_dir`]. An existing directory that is too open is refused, not changed:
/// whoever made it so may already have used it.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().recursive(true).mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    check_private_dir(dir)
}

/// Check that `dir` is a directory (not a symbolic link to one) that belongs to the effective
/// user and that nobody else may enter or change (no group or other permission bits). Nothing is
/// changed; a directory that fails is refused with an error saying why.
///
/// A socket found in such a directory was put there by this user: nobody else can create,
/// replace or rename entries in it. The directory itself cannot be swapped either: its parent is
/// the user's own `XDG_RUNTIME_DIR`, or `/tmp`, where the sticky bit stops others from renaming
/// what the user created.
pub fn check_private_dir(dir: &Path) -> io::Result<()> {
    // symlink_metadata: a symbolic link planted in /tmp must not redirect us elsewhere
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if meta.uid() != sys::euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} belongs to another user (uid {}); refusing to use it",
                dir.display(),
                meta.uid()
            ),
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible to other users (mode {:o}); refusing to use it (chmod 700 it, or remove it)",
                dir.display(),
                meta.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

/// Check that the process at the other end of a unix socket runs as the effective user
/// (`SO_PEERCRED` on Linux, `getpeereid` on the BSDs and macOS).
pub fn check_peer(stream: &UnixStream) -> io::Result<()> {
    let cred = stream.peer_cred()?;
    if cred.uid() != sys::euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the process behind the socket runs as uid {}, not as this user; refusing to talk to it",
                cred.uid()
            ),
        ));
    }
    Ok(())
}

/// Write a file only the user may read, atomically and durably: a temporary file of mode 0600
/// in the same directory, written and synced, renamed into place, then the directory synced, so
/// that a crash leaves either the old or the new content, never a truncated file.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // The rename itself is durable once the directory is: best effort, some file systems
    // cannot sync a directory
    if let Some(dir) = path.parent() {
        if let Ok(dir) = fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qsh-paths-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Review L5: a directory that is too open is refused, never quietly tightened.
    #[test]
    fn private_dir_is_created_0700_and_a_too_open_one_is_refused() {
        let root = scratch("private");
        let dir = root.join("a/b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        for mode in [0o755, 0o710, 0o701, 0o777] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            let e = ensure_private_dir(&dir).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            assert!(e.to_string().contains("accessible to other users"), "{e}");
            // Left as it was
            assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, mode);
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = Paths {
            runtime: dir.clone(),
            ..Paths::under(&root)
        };
        assert!(paths.check_runtime().unwrap());
        let missing = Paths::under(&root.join("missing"));
        assert!(!missing.check_runtime().unwrap());
        assert!(!root.join("missing").exists(), "check_runtime creates nothing");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_symlink_is_not_a_private_dir() {
        let root = scratch("link");
        fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        assert!(ensure_private_dir(&root.join("link")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn under_keeps_everything_together() {
        let p = Paths::under(Path::new("/x"));
        assert_eq!(p.control_socket(), Path::new("/x/run/control.sock"));
        assert_eq!(p.identity_dir(), Path::new("/x/state/daemon"));
    }

    #[test]
    fn private_files_are_0600() {
        let root = scratch("file");
        ensure_private_dir(&root).unwrap();
        let f = root.join("secret");
        write_private(&f, b"x").unwrap();
        assert_eq!(fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(root).unwrap();
    }
}
