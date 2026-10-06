//! Where qsh keeps its files (docs/DESIGN.md section 3, FHS and XDG).
//!
//! | what | default |
//! |---|---|
//! | configuration | `$XDG_CONFIG_HOME/qsh`, else `~/.config/qsh` |
//! | state (daemon identity, saved sessions, logs of on-demand daemons) | `$XDG_STATE_HOME/qsh`, else `~/.local/state/qsh` |
//! | runtime (control socket, daemon lock) | `$XDG_RUNTIME_DIR/qsh`, else `/tmp/qsh-$UID` |
//!
//! Every field is public: an embedder (TokenSSH keeps everything under its own directory)
//! builds a [`Paths`] of its own instead of [`Paths::from_env`].

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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

    /// The state directory, created with mode 0700 if missing.
    pub fn ensure_state(&self) -> io::Result<&Path> {
        ensure_private_dir(&self.state)?;
        Ok(&self.state)
    }
}

/// Create `dir` (and its parents) with mode 0700 if missing; check that the user owns it and
/// nobody else may use it.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().recursive(true).mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // symlink_metadata: a symbolic link planted in /tmp must not redirect us elsewhere
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if meta.uid() != sys::euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} belongs to another user (uid {})", dir.display(), meta.uid()),
        ));
    }
    if meta.mode() & 0o077 != 0 {
        // Ours, just too open (an older umask): tighten it
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a file only the user may read, atomically (a temporary file renamed into place).
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
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qsh-paths-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn private_dir_is_created_0700_and_tightened() {
        let root = scratch("private");
        let dir = root.join("a/b");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
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
