//! Saved session credentials: what `qsh attach` needs to reach a session again after the client
//! process is gone, without ssh (docs/security.md, "Session state files").
//!
//! One file per session in `$XDG_STATE_HOME/qsh/sessions/` ([`crate::Paths::sessions_dir`]):
//! the directory has mode 0700, every file 0600, both created with explicit modes; a directory
//! or file that others may read is refused, never quietly tightened. Files are written
//! atomically (a temporary file renamed into place, [`crate::paths::write_private`]), so a crash
//! leaves the old key or the new one, never a truncated file. The client stores every rotated
//! key here *before* it confirms it to the server (protocol.md 6.5).
//!
//! A file holds the destination and ssh options, the daemon's host, ports and certificate
//! fingerprint, the session id, its kind, and the session key. Next to it a `.lock` file is
//! locked (`flock`) by the `qsh` process that runs the session, so others can tell a session in
//! use here from one that is detached or whose client died.
//!
//! ```json
//! {"qsh":1,"destination":"alice@build","ssh_options":["-p","2222"],"host":"203.0.113.5",
//!  "udp":60443,"tcp":60443,"cert_sha256":"…","session":"…","key":"…","name":null,
//!  "command":"make","created":1791200000}
//! ```

use std::fmt;
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, Fingerprint, SessionKey};
use crate::paths::{self, Paths};
use crate::sys;

/// The format version of a state file, member `"qsh"`.
pub const FORMAT: u64 = 1;

/// The largest state file read; real ones are well under 1 KiB.
const MAX_FILE: u64 = 64 * 1024;

/// Temporary files older than this are left over from a crash and removed.
const STALE_TMP: Duration = Duration::from_secs(60);

/// The credentials of one session, as saved.
#[derive(Clone)]
pub struct SavedSession {
    /// `[user@]host` as given to `qsh`.
    pub destination: String,
    /// The ssh options the session was started with (`-p`, `-l`, `-i`, …): used again for the
    /// ssh pipe and for re-issuing the key over ssh.
    pub ssh_options: Vec<String>,
    /// Host name or address of the daemon for QUIC and TLS.
    pub host: String,
    /// QUIC port, 0 when the daemon does not listen on UDP.
    pub udp: u16,
    /// TLS port, 0 when the daemon does not listen on TCP.
    pub tcp: u16,
    /// The daemon's pinned certificate.
    pub fingerprint: Fingerprint,
    /// The session id.
    pub session: [u8; 16],
    /// The session key. Secret: not shown by `Debug`, wiped from memory when dropped.
    pub key: SessionKey,
    /// A pipe session (protocol.md 7.14).
    pub pipe: bool,
    /// The session's name, if it has one.
    pub name: Option<String>,
    /// The remote command; None for a login shell.
    pub command: Option<String>,
    /// When the session was created, in seconds since the Unix epoch.
    pub created: u64,
}

impl SavedSession {
    /// The session id in lowercase hex.
    pub fn id(&self) -> String {
        crypto::hex(&self.session)
    }
}

impl fmt::Debug for SavedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavedSession")
            .field("destination", &self.destination)
            .field("ssh_options", &self.ssh_options)
            .field("host", &self.host)
            .field("udp", &self.udp)
            .field("tcp", &self.tcp)
            .field("fingerprint", &self.fingerprint)
            .field("session", &self.id())
            .field("key", &"..")
            .field("pipe", &self.pipe)
            .field("name", &self.name)
            .field("command", &self.command)
            .field("created", &self.created)
            .finish()
    }
}

/// The file format. The key is wiped from memory on drop.
#[derive(Serialize, Deserialize)]
struct FileFormat {
    qsh: u64,
    destination: String,
    #[serde(default)]
    ssh_options: Vec<String>,
    host: String,
    udp: u16,
    tcp: u16,
    cert_sha256: String,
    session: String,
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tty: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    created: u64,
}

impl Drop for FileFormat {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

impl FileFormat {
    fn of(s: &SavedSession) -> FileFormat {
        FileFormat {
            qsh: FORMAT,
            destination: s.destination.clone(),
            ssh_options: s.ssh_options.clone(),
            host: s.host.clone(),
            udp: s.udp,
            tcp: s.tcp,
            cert_sha256: s.fingerprint.to_hex(),
            session: s.id(),
            key: s.key.to_hex(),
            tty: s.pipe.then_some(false),
            name: s.name.clone(),
            command: s.command.clone(),
            created: s.created,
        }
    }

    fn parse(&self) -> Result<SavedSession, String> {
        if self.qsh != FORMAT {
            return Err(format!("unknown format {}", self.qsh));
        }
        Ok(SavedSession {
            destination: self.destination.clone(),
            ssh_options: self.ssh_options.clone(),
            host: self.host.clone(),
            udp: self.udp,
            tcp: self.tcp,
            fingerprint: Fingerprint::from_hex(&self.cert_sha256).ok_or("malformed cert_sha256")?,
            session: crypto::unhex::<16>(&self.session).ok_or("malformed session")?,
            key: SessionKey::from_hex(&self.key).ok_or("malformed key")?,
            pipe: self.tty == Some(false),
            name: self.name.clone(),
            command: self.command.clone(),
            created: self.created,
        })
    }
}

/// A state file that could not be used, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unusable {
    /// The file.
    pub path: PathBuf,
    /// Why it was skipped.
    pub why: String,
}

/// Every saved session, and the files that could not be read.
#[derive(Debug, Default)]
pub struct Listing {
    /// Sessions, oldest first.
    pub sessions: Vec<SavedSession>,
    /// Files skipped: corrupted, of an unknown format, or readable by others.
    pub unusable: Vec<Unusable>,
}

/// The lock a running `qsh` holds on a session it uses; released when dropped (or when the
/// process ends, however it ends).
#[derive(Debug)]
pub struct SessionLock {
    _file: fs::File,
}

/// The directory of saved sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStore {
    dir: PathBuf,
}

impl SessionStore {
    /// The sessions in `dir`; nothing is created until the first save.
    pub fn new(dir: impl Into<PathBuf>) -> SessionStore {
        SessionStore { dir: dir.into() }
    }

    /// The standard location, [`Paths::sessions_dir`].
    pub fn from_paths(paths: &Paths) -> SessionStore {
        SessionStore::new(paths.sessions_dir())
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file name of a session: its id, and a hash of the destination so that two hosts can
    /// never overwrite each other's files, whatever ids their servers choose.
    fn stem(destination: &str, session: &[u8; 16]) -> String {
        let tag = crypto::sha256(destination.as_bytes());
        format!("{}-{}", crypto::hex(session), crypto::hex(&tag[..4]))
    }

    fn path(&self, destination: &str, session: &[u8; 16]) -> PathBuf {
        self.dir.join(format!("{}.json", Self::stem(destination, session)))
    }

    fn lock_path(&self, destination: &str, session: &[u8; 16]) -> PathBuf {
        self.dir.join(format!("{}.lock", Self::stem(destination, session)))
    }

    /// Save `session`, replacing its previous file atomically. When this returns Ok, the
    /// content is on disk (the file and the directory are synced).
    pub fn save(&self, session: &SavedSession) -> io::Result<()> {
        paths::ensure_private_dir(&self.dir)?;
        let mut bytes = serde_json::to_vec(&FileFormat::of(session)).map_err(io::Error::other)?;
        bytes.push(b'\n');
        let result = paths::write_private(&self.path(&session.destination, &session.session), &bytes);
        zeroize::Zeroize::zeroize(&mut bytes);
        result
    }

    /// The saved session `session` of `destination`, None when there is none. A file that
    /// cannot be used is an error saying why.
    pub fn load(&self, destination: &str, session: &[u8; 16]) -> io::Result<Option<SavedSession>> {
        match self.check_dir() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
        let path = self.path(destination, session);
        match read_file(&path) {
            Ok(saved) => Ok(Some(saved)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Every saved session, oldest first, with the files that were skipped. Temporary files
    /// left over from a crash are removed.
    pub fn list(&self) -> io::Result<Listing> {
        let mut listing = Listing::default();
        match self.check_dir() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(listing),
            Err(e) => return Err(e),
        }
        let mut names: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let path = self.dir.join(&name);
            if name.contains(".tmp") {
                // A crash between writing and renaming: it may hold a key, and nobody needs it
                let stale = fs::symlink_metadata(&path)
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t.elapsed().unwrap_or_default() > STALE_TMP);
                if stale {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            if !name.ends_with(".json") {
                continue;
            }
            match read_file(&path) {
                Ok(saved) => listing.sessions.push(saved),
                Err(e) => listing.unusable.push(Unusable {
                    path,
                    why: e.to_string(),
                }),
            }
        }
        listing.sessions.sort_by_key(|s| s.created);
        Ok(listing)
    }

    /// Forget a session: its file and its lock file. Not an error when there is none.
    pub fn remove(&self, destination: &str, session: &[u8; 16]) -> io::Result<()> {
        for path in [self.path(destination, session), self.lock_path(destination, session)] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Lock the session for this process. None when another process holds the lock.
    pub fn lock(&self, destination: &str, session: &[u8; 16]) -> io::Result<Option<SessionLock>> {
        paths::ensure_private_dir(&self.dir)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.lock_path(destination, session))?;
        Ok(sys::try_lock(&file)?.then_some(SessionLock { _file: file }))
    }

    /// True when a running `qsh` (this process included) holds the session's lock.
    pub fn in_use(&self, destination: &str, session: &[u8; 16]) -> bool {
        let Ok(file) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.lock_path(destination, session))
        else {
            return false;
        };
        // Taken (and released at once) when nobody holds it
        matches!(sys::try_lock(&file), Ok(false))
    }

    /// Refuse a directory others may use: a session key in it could have been read, or a file
    /// planted ([`paths::check_private_dir`]).
    fn check_dir(&self) -> io::Result<()> {
        paths::check_private_dir(&self.dir)
    }
}

/// Read one state file: a regular file of this user that nobody else may read or write.
fn read_file(path: &Path) -> io::Result<SavedSession> {
    let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {why}", path.display()));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(invalid("not a regular file".into()));
    }
    if meta.uid() != sys::euid() {
        return Err(invalid(format!("belongs to another user (uid {})", meta.uid())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "accessible to other users (mode {:o}); refusing to use it (chmod 600 it, or remove it)",
            meta.mode() & 0o7777
        )));
    }
    if meta.len() > MAX_FILE {
        return Err(invalid("too large".into()));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    (&mut file).take(MAX_FILE).read_to_end(&mut bytes)?;
    let parsed = serde_json::from_slice::<FileFormat>(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    let format = parsed.map_err(|e| invalid(format!("corrupted ({e})")))?;
    format.parse().map_err(invalid)
}

/// Seconds since the Unix epoch, now.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qsh-store-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn saved(destination: &str, id: u8, key: u8) -> SavedSession {
        SavedSession {
            destination: destination.into(),
            ssh_options: vec!["-p".into(), "2222".into()],
            host: "203.0.113.5".into(),
            udp: 60443,
            tcp: 60444,
            fingerprint: Fingerprint([7; 32]),
            session: [id; 16],
            key: SessionKey([key; 32]),
            pipe: id % 2 == 0,
            name: Some("build".into()),
            command: None,
            created: 1_791_200_000 + u64::from(id),
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn saved_sessions_round_trip_in_private_files() {
        let root = scratch("roundtrip");
        let store = SessionStore::new(root.join("state/sessions"));
        assert!(
            store.list().unwrap().sessions.is_empty(),
            "nothing before the first save"
        );
        assert!(store.load("h", &[1; 16]).unwrap().is_none());
        store.save(&saved("alice@h", 1, 0x11)).unwrap();
        store.save(&saved("h", 2, 0x22)).unwrap();
        assert_eq!(mode(store.dir()), 0o700);
        let files: Vec<_> = fs::read_dir(store.dir()).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(files.len(), 2, "{files:?}");
        for f in &files {
            assert_eq!(mode(f), 0o600, "{f:?}");
        }
        let s = store.load("alice@h", &[1; 16]).unwrap().unwrap();
        assert_eq!(s.key.0, [0x11; 32]);
        assert_eq!(s.ssh_options, ["-p", "2222"]);
        assert_eq!((s.udp, s.tcp, s.pipe), (60443, 60444, false));
        assert_eq!(s.fingerprint, Fingerprint([7; 32]));
        // Another destination with the same id is another file
        assert!(store.load("h", &[1; 16]).unwrap().is_none());
        // A new key replaces the old one
        store.save(&saved("alice@h", 1, 0x33)).unwrap();
        assert_eq!(store.load("alice@h", &[1; 16]).unwrap().unwrap().key.0, [0x33; 32]);
        let listing = store.list().unwrap();
        assert_eq!(listing.sessions.len(), 2);
        assert!(listing.unusable.is_empty());
        assert!(
            listing.sessions[0].created < listing.sessions[1].created,
            "oldest first"
        );
        store.remove("alice@h", &[1; 16]).unwrap();
        store.remove("alice@h", &[1; 16]).unwrap();
        assert_eq!(store.list().unwrap().sessions.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    /// The key never shows in debug output.
    #[test]
    fn debug_hides_the_key() {
        let text = format!("{:?}", saved("h", 1, 0x5e));
        assert!(text.contains(&"01".repeat(16)), "{text}");
        assert!(!text.contains("5e5e") && !text.contains("94, 94"), "{text}");
    }

    #[test]
    fn corrupted_and_foreign_files_are_skipped_and_reported() {
        let root = scratch("corrupt");
        let store = SessionStore::new(root.join("sessions"));
        store.save(&saved("h", 1, 1)).unwrap();
        let good = store.path("h", &[1; 16]);
        // Truncated, not JSON, unknown format, malformed key
        let write = |name: &str, text: &[u8]| {
            let p = store.dir().join(name);
            fs::write(&p, text).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        };
        let full = fs::read(&good).unwrap();
        write("truncated.json", &full[..full.len() / 2]);
        write("garbage.json", b"\x00\xffnot json");
        write(
            "future.json",
            String::from_utf8_lossy(&full)
                .replace("\"qsh\":1", "\"qsh\":9")
                .as_bytes(),
        );
        write(
            "badkey.json",
            String::from_utf8_lossy(&full)
                .replace(&"01".repeat(32), "zz")
                .as_bytes(),
        );
        // Readable by others: refused, and left as it is
        write("open.json", &full);
        fs::set_permissions(store.dir().join("open.json"), fs::Permissions::from_mode(0o644)).unwrap();
        // Not ours to read: anything that is not a .json file
        write("notes.txt", b"hello");
        let listing = store.list().unwrap();
        assert_eq!(listing.sessions.len(), 1, "{listing:?}");
        let mut why: Vec<_> = listing
            .unusable
            .iter()
            .map(|u| {
                (
                    u.path.file_name().unwrap().to_string_lossy().into_owned(),
                    u.why.clone(),
                )
            })
            .collect();
        why.sort();
        assert_eq!(why.len(), 5, "{why:?}");
        assert!(
            why[0].0 == "badkey.json" && why[0].1.contains("malformed key"),
            "{why:?}"
        );
        assert!(
            why[1].0 == "future.json" && why[1].1.contains("unknown format"),
            "{why:?}"
        );
        assert!(why[2].0 == "garbage.json" && why[2].1.contains("corrupted"), "{why:?}");
        assert!(
            why[3].0 == "open.json" && why[3].1.contains("accessible to other users"),
            "{why:?}"
        );
        assert!(
            why[4].0 == "truncated.json" && why[4].1.contains("corrupted"),
            "{why:?}"
        );
        assert_eq!(mode(&store.dir().join("open.json")), 0o644, "never changed");
        // load of a corrupted file is an error, not "no session"
        fs::write(&good, b"{").unwrap();
        assert_eq!(
            store.load("h", &[1; 16]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_directory_others_can_use_is_refused() {
        let root = scratch("opendir");
        let store = SessionStore::new(root.join("sessions"));
        store.save(&saved("h", 1, 1)).unwrap();
        fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755)).unwrap();
        let e = store.list().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(store.load("h", &[1; 16]).is_err());
        assert!(store.save(&saved("h", 1, 2)).is_err());
        assert_eq!(mode(store.dir()), 0o755, "never changed");
        fs::remove_dir_all(root).unwrap();
    }

    /// Atomic replacement: a crash before the rename leaves the old file intact, and the
    /// temporary file it left behind is cleaned up once stale; it never counts as a session.
    #[test]
    fn writes_are_atomic_and_leftovers_are_cleaned_up() {
        let root = scratch("atomic");
        let store = SessionStore::new(root.join("sessions"));
        store.save(&saved("h", 1, 1)).unwrap();
        let path = store.path("h", &[1; 16]);
        // What a crash between write and rename leaves
        let tmp = path.with_extension("tmp999999");
        fs::write(&tmp, b"{\"half\":").unwrap();
        let listing = store.list().unwrap();
        assert_eq!(listing.sessions.len(), 1);
        assert!(listing.unusable.is_empty(), "{listing:?}");
        assert!(tmp.exists(), "a fresh temporary file may belong to a running write");
        let old = SystemTime::now() - Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&tmp)
            .unwrap()
            .set_modified(old)
            .unwrap();
        store.list().unwrap();
        assert!(!tmp.exists(), "a stale one is removed");
        // Every save goes through a temporary file: the old content stays until the rename
        for key in 2..20u8 {
            store.save(&saved("h", 1, key)).unwrap();
            assert_eq!(store.load("h", &[1; 16]).unwrap().unwrap().key.0, [key; 32]);
        }
        let left: Vec<_> = fs::read_dir(store.dir()).unwrap().collect();
        assert_eq!(left.len(), 1, "no temporary files left: {left:?}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_lock_tells_a_session_in_use() {
        let root = scratch("lock");
        let store = SessionStore::new(root.join("sessions"));
        store.save(&saved("h", 1, 1)).unwrap();
        assert!(!store.in_use("h", &[1; 16]));
        let lock = store.lock("h", &[1; 16]).unwrap().expect("free");
        assert!(store.in_use("h", &[1; 16]));
        assert!(store.lock("h", &[1; 16]).unwrap().is_none(), "held");
        assert_eq!(mode(&store.lock_path("h", &[1; 16])), 0o600);
        drop(lock);
        assert!(!store.in_use("h", &[1; 16]));
        store.remove("h", &[1; 16]).unwrap();
        assert!(!store.lock_path("h", &[1; 16]).exists());
        fs::remove_dir_all(root).unwrap();
    }
}
