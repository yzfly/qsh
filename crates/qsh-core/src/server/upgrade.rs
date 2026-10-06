//! The upgrade in place (m2.md section 10, security.md 4.8): deciding to upgrade (a newer
//! requester, `qsh-server upgrade`, or a replaced executable while idle), quiescing,
//! serializing, executing the new program in this process, and, in the new image, resuming
//! from the state, or executing the old image again when that fails (Linux).
//!
//! ```text
//! old image A                                   new image B (same pid)
//! validate + probe P ─▶ {"restarting":true}
//! stop accepting, GOAWAY (RESTART), close
//! stop the session threads (≤ 2 s)
//! state ─▶ sealed anonymous file, key ─▶ pipe
//! clear close-on-exec on exactly those fds
//! execve(P, daemon --resume …) ───────────────▶ read key, open + check state, fstat every fd
//!   (returns only on failure: resume as A)         ├─ fails before commit: fexecve(A) (Linux)
//!                                                  └─ commit: adopt, start threads, serve
//! ```

use std::collections::{HashSet, VecDeque};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::handoff::{self, Listener, ListenerKind, SessionFds, State, NO_FD};
use super::pty::{Adopted, AdoptedFds, PtySession};
use super::{adopt, fd_number, serve, version, Listeners, Resume, Runtime, ServerConfig, Shared, StartError};
use crate::config::Upgrade;
use crate::crypto::{self, Identity, StateKey, STATE_KEY_LEN};
use crate::log;
use crate::proto::ErrorCode;
use crate::sys;

/// The test hook that makes a program report another version (see [`super::version`]).
pub(crate) const TEST_VERSION: &str = "QSH_TEST_VERSION";

/// A test hook (unstable): a comma-separated list of faults, one per upgrade attempt, in
/// order: `stop` (the session threads do not stop), `serialize` (the state cannot be
/// written), `exec` (execve fails), `restore` (the new image cannot resume; Linux falls back
/// to the old one), `none` (this attempt has no fault). Read when the daemon starts, only in
/// builds with the cargo feature `test-hooks`.
pub(crate) const TEST_FAULT: &str = "QSH_TEST_HANDOFF_FAULT";

/// GOAWAY (RESTART) has this long to reach the clients before their connections close.
const GOAWAY_FLUSH: Duration = Duration::from_millis(500);

/// The session threads have this long to stop (m2.md 10.3 step 3).
const STOP_THREADS: Duration = Duration::from_secs(2);

/// A fault of the test hook [`TEST_FAULT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    None,
    Stop,
    Serialize,
    Exec,
    Restore,
}

impl Fault {
    fn name(self) -> &'static str {
        match self {
            Fault::None => "none",
            Fault::Stop => "stop",
            Fault::Serialize => "serialize",
            Fault::Exec => "exec",
            Fault::Restore => "restore",
        }
    }
}

fn faults_from_env() -> VecDeque<Fault> {
    if !cfg!(feature = "test-hooks") {
        return VecDeque::new();
    }
    let Ok(text) = std::env::var(TEST_FAULT) else {
        return VecDeque::new();
    };
    text.split(',')
        .filter_map(|f| match f.trim() {
            "none" => Some(Fault::None),
            "stop" => Some(Fault::Stop),
            "serialize" => Some(Fault::Serialize),
            "exec" => Some(Fault::Exec),
            "restore" => Some(Fault::Restore),
            _ => None,
        })
        .collect()
}

/// An upgrade decided on: the program to execute.
#[derive(Debug)]
pub(crate) struct Plan {
    pub exe: PathBuf,
    pub version: String,
    pub why: String,
}

/// Why an upgrade was not started.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub message: String,
    /// The program is not newer than the daemon (nothing to do, rather than a failure).
    pub not_newer: bool,
}

impl Refusal {
    fn new(message: impl Into<String>) -> Refusal {
        Refusal {
            message: message.into(),
            not_newer: false,
        }
    }
}

/// The daemon's upgrade state.
#[derive(Debug)]
pub(crate) struct UpgradeState {
    tx: mpsc::UnboundedSender<Plan>,
    /// One upgrade (its probe, then its attempt) at a time.
    busy: AtomicBool,
    /// The daemon is stopping for an upgrade: control requests get `{"restarting":true}`.
    quiescing: AtomicBool,
    /// Held (shared) by control requests that change sessions, taken (exclusive) by the
    /// upgrade before it collects them: no session is created or changed behind its back.
    pub gate: RwLock<()>,
    restarts: AtomicU32,
    failures: AtomicU32,
    last_error: Mutex<Option<String>>,
    /// The version this image was upgraded from.
    upgraded_from: Option<String>,
    /// Programs (device, inode) whose probe said no: not probed again unless forced.
    refused: Mutex<HashSet<(u64, u64)>>,
    /// The executable this image was started from, and its identity then.
    exe: Option<PathBuf>,
    exe_id: Option<(u64, u64)>,
    /// This image's executable, open (Linux): the fallback of the next upgrade (m2.md 10.4).
    fallback_exe: Option<File>,
    faults: Mutex<VecDeque<Fault>>,
}

impl UpgradeState {
    /// The state of a daemon that starts (`from`: None) or resumes from `from`.
    pub fn new(config: &ServerConfig, from: Option<(&State, bool)>) -> (UpgradeState, mpsc::UnboundedReceiver<Plan>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let able = config.reexec.is_some();
        let exe = able.then(|| std::env::current_exe().ok()).flatten();
        let exe_id = exe.as_deref().and_then(handoff::file_identity);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let fallback_exe = able.then(|| File::open("/proc/self/exe").ok()).flatten();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let fallback_exe = None;
        let (mut restarts, mut failures, mut last_error, mut upgraded_from) = (0, 0, None, None);
        if let Some((state, fell_back)) = from {
            restarts = state.restarts;
            failures = state.failures;
            if fell_back {
                failures += 1;
                last_error = Some("the new program could not resume the sessions; the previous one took over again (see the daemon log)".to_string());
            } else {
                restarts += 1;
                upgraded_from = Some(state.writer.trim_start_matches("qsh-server/").to_string());
            }
        }
        let state = UpgradeState {
            tx,
            busy: AtomicBool::new(false),
            quiescing: AtomicBool::new(false),
            gate: RwLock::new(()),
            restarts: AtomicU32::new(restarts),
            failures: AtomicU32::new(failures),
            last_error: Mutex::new(last_error),
            upgraded_from,
            refused: Mutex::new(HashSet::new()),
            exe,
            exe_id,
            fallback_exe,
            faults: Mutex::new(if able { faults_from_env() } else { VecDeque::new() }),
        };
        (state, rx)
    }

    /// True while the daemon stops for an upgrade: control requests are answered with
    /// `{"restarting":true}`, and the requester asks again (protocol.md 10.6).
    pub fn restarting(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// An upgrade attempt failed; the daemon goes on as it was.
    pub fn failed(&self, error: &str) {
        log::info(format_args!(
            "upgrade failed: {error}; the daemon goes on with its sessions"
        ));
        self.failures.fetch_add(1, Ordering::SeqCst);
        *self.last_error.lock().unwrap() = Some(error.to_string());
        self.quiescing.store(false, Ordering::SeqCst);
        self.busy.store(false, Ordering::SeqCst);
    }

    /// Start the upgrade `plan` (prepared by [`prepare`]).
    pub fn start(&self, plan: Plan) {
        if self.tx.send(plan).is_err() {
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    /// The members of `qsh-server status` about upgrades (protocol.md 10.6).
    pub fn status(&self, config: &ServerConfig) -> Value {
        json!({
            "upgrade": match config.upgrade { Upgrade::Auto => "auto", Upgrade::Manual => "manual" },
            "can_upgrade": config.reexec.is_some(),
            "handoff": handoff::FORMATS,
            "restarts": self.restarts.load(Ordering::SeqCst),
            "upgrade_failures": self.failures.load(Ordering::SeqCst),
            "upgrade_error": *self.last_error.lock().unwrap(),
            "upgrading": self.busy.load(Ordering::SeqCst) || self.restarting(),
            "upgraded_from": self.upgraded_from,
        })
    }
}

/// Decide whether to upgrade to `exe` (m2.md 10.3 steps 1 and 2): this daemon can upgrade,
/// no other upgrade runs, `exe` is safe to execute, its probe answers with a state format this
/// daemon writes and a newer version (unless `force`). On success the daemon is reserved for
/// this upgrade: pass the plan to [`UpgradeState::start`].
pub(crate) async fn prepare(shared: &Shared, exe: &Path, force: bool, why: &str) -> Result<Plan, Refusal> {
    if shared.config.reexec.is_none() {
        return Err(Refusal::new(
            "this daemon cannot upgrade in place (it runs inside another program)",
        ));
    }
    let state = &shared.upgrade;
    if state.busy.swap(true, Ordering::SeqCst) {
        return Err(Refusal::new("an upgrade is already in progress"));
    }
    let result = async {
        let id = handoff::file_identity(exe);
        if !force && id.is_some_and(|id| state.refused.lock().unwrap().contains(&id)) {
            return Err(Refusal {
                message: format!("{} was already found unsuitable", exe.display()),
                not_newer: true,
            });
        }
        handoff::validate_exe(exe).map_err(Refusal::new)?;
        let probe = handoff::probe(exe).await.map_err(Refusal::new)?;
        let refuse = |message: String, not_newer: bool| {
            if let Some(id) = id {
                state.refused.lock().unwrap().insert(id);
            }
            Err(Refusal { message, not_newer })
        };
        if !probe.formats.contains(&handoff::FORMAT) {
            return refuse(
                format!(
                    "{} reads state formats {:?}; this daemon writes {}",
                    exe.display(),
                    probe.formats,
                    handoff::FORMAT
                ),
                false,
            );
        }
        if !force && !handoff::newer(&probe.version, version()) {
            return refuse(
                format!(
                    "{} is version {}, not newer than the daemon's {}",
                    exe.display(),
                    probe.version,
                    version()
                ),
                true,
            );
        }
        Ok(Plan {
            exe: exe.to_path_buf(),
            version: probe.version,
            why: why.to_string(),
        })
    }
    .await;
    if result.is_err() {
        state.busy.store(false, Ordering::SeqCst);
    }
    result
}

/// A control request from a newer `qsh-server` (`"version"`, `"exe"`; protocol.md 10.6): when
/// this daemon upgrades by itself and the requester's program checks out, start the upgrade.
/// True when it started: answer `{"restarting":true}`.
pub(crate) async fn upgrade_for(shared: &Shared, request: &Value) -> bool {
    if shared.config.upgrade != Upgrade::Auto || shared.config.reexec.is_none() {
        return false;
    }
    let (Some(theirs), Some(exe)) = (request["version"].as_str(), request["exe"].as_str()) else {
        return false;
    };
    if !handoff::newer(theirs, version()) {
        return false;
    }
    let why = format!("a qsh-server {theirs} asked");
    match prepare(shared, Path::new(exe), false, &why).await {
        Ok(plan) => {
            shared.upgrade.start(plan);
            true
        }
        Err(refusal) => {
            log::debug(format_args!("no upgrade to {exe}: {}", refusal.message));
            false
        }
    }
}

/// Upgrade by itself when idle (m2.md 10.2): when the executable this image was started from
/// was replaced (another inode at its path) and no session is attached, probe it and upgrade
/// if it is newer.
pub(crate) async fn watch_exe(shared: Arc<Shared>) {
    let Some(reexec) = shared.config.reexec.clone() else {
        return;
    };
    let (Some(path), Some(started)) = (shared.upgrade.exe.clone(), shared.upgrade.exe_id) else {
        return;
    };
    loop {
        tokio::time::sleep(reexec.check_every).await;
        if shared.config.upgrade != Upgrade::Auto {
            continue;
        }
        if handoff::file_identity(&path).is_none_or(|now| now == started) {
            continue;
        }
        if shared.sessions.all().iter().any(|s| s.attached() > 0) {
            continue;
        }
        match prepare(&shared, &path, false, "its program was replaced").await {
            Ok(plan) => shared.upgrade.start(plan),
            Err(refusal) => log::debug(format_args!("no upgrade to {}: {}", path.display(), refusal.message)),
        }
    }
}

/// What the new image is handed besides the descriptors of the state.
struct Handoff {
    /// The sealed state.
    file: File,
    /// The read end of the key's pipe.
    key: OwnedFd,
    /// Every descriptor the state names.
    fds: Vec<RawFd>,
}

/// Carry out `plan` (m2.md 10.3 steps 3 to 6). Returns only when the upgrade failed, with the
/// reason, after everything was resumed: the caller starts the tasks again.
pub(crate) async fn run(shared: &Arc<Shared>, runtime: &mut Runtime, plan: Plan) -> String {
    let fault = shared.upgrade.faults.lock().unwrap().pop_front().unwrap_or(Fault::None);
    log::info(format_args!(
        "upgrading in place to {} {} ({})",
        plan.exe.display(),
        plan.version,
        plan.why
    ));
    // 3. Quiesce: no new control requests change sessions, nothing is accepted, every
    //    connection gets GOAWAY (RESTART) and is closed
    shared.upgrade.quiescing.store(true, Ordering::SeqCst);
    loop {
        // Control requests that change sessions are short and never wait while holding it
        if let Ok(guard) = shared.upgrade.gate.try_write() {
            drop(guard);
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    runtime.stop();
    serve::goaway_all(shared, ErrorCode::RESTART);
    tokio::time::sleep(GOAWAY_FLUSH).await;
    serve::close_all(shared, ErrorCode::RESTART);
    // The CONNECTION_CLOSE frames go out
    tokio::time::sleep(Duration::from_millis(100)).await;
    if let Err(e) = runtime.detach_endpoints() {
        return resume_here(runtime, &[], format!("cannot stop QUIC: {e}")).await;
    }
    let sessions = shared.sessions.all();
    for s in &sessions {
        s.request_pause();
    }
    let deadline = tokio::time::Instant::now() + STOP_THREADS;
    while fault == Fault::Stop || sessions.iter().any(|s| s.threads_running() > 0) {
        if tokio::time::Instant::now() >= deadline {
            return resume_here(
                runtime,
                &sessions,
                format!("the threads of a session did not stop within {STOP_THREADS:?}"),
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // 4. Serialize
    let handoff = match serialize(shared, runtime, &sessions, fault) {
        Ok(h) => h,
        Err(e) => return resume_here(runtime, &sessions, format!("cannot write the state: {e}")).await,
    };
    // 5. Execute; returns only when that failed
    let error = exec(shared, &plan, &handoff, fault);
    // 6. Nothing was lost: resume
    resume_here(runtime, &sessions, error).await
}

/// m2.md 10.3 step 6: back to serving as before the attempt (the caller restarts the tasks).
async fn resume_here(runtime: &Runtime, sessions: &[Arc<PtySession>], error: String) -> String {
    if let Err(e) = runtime.attach_endpoints() {
        log::info(format_args!("cannot resume QUIC after the failed upgrade: {e}"));
    }
    // A thread that was late to stop parks its descriptor when it does: wait for that, so that
    // it is started again with the others (a thread that never stops is not waited for long)
    let deadline = tokio::time::Instant::now() + STOP_THREADS * 5;
    while sessions.iter().any(|s| s.threads_running() > 0) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for s in sessions {
        if let Err(e) = s.resume_threads() {
            log::info(format_args!("session {}: cannot resume: {e}", &s.id.to_hex()[..8]));
            s.hang_up();
        }
    }
    error
}

/// m2.md 10.3 step 4: the state, sealed into an anonymous file; the key in a pipe.
fn serialize(shared: &Shared, runtime: &Runtime, sessions: &[Arc<PtySession>], fault: Fault) -> io::Result<Handoff> {
    if fault == Fault::Serialize {
        return Err(io::Error::other("test fault"));
    }
    let l = &runtime.listeners;
    let mut listeners = Vec::new();
    for (port, socket) in &l.udp {
        listeners.push(Listener {
            kind: ListenerKind::Udp,
            fd: fd_number(socket),
            port: *port,
        });
    }
    for (port, listener) in &l.tcp {
        listeners.push(Listener {
            kind: ListenerKind::Tcp,
            fd: fd_number(listener),
            port: *port,
        });
    }
    listeners.push(Listener {
        kind: ListenerKind::Control,
        fd: fd_number(&l.control),
        port: 0,
    });
    listeners.push(Listener {
        kind: ListenerKind::Lock,
        fd: fd_number(&l.lock),
        port: 0,
    });
    let state = State {
        writer: format!("qsh-server/{}", version()),
        started_ms: shared
            .started
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        restarts: shared.upgrade.restarts.load(Ordering::SeqCst),
        failures: shared.upgrade.failures.load(Ordering::SeqCst),
        port: shared.port,
        listeners,
        sessions: sessions.iter().filter_map(|s| s.export()).collect(),
    };
    let fds = state.descriptors().into_iter().map(|fd| fd as RawFd).collect();
    let bytes = handoff::encode(&state).map_err(io::Error::other)?;
    drop(state);
    let (sealed, key) = crypto::seal_state(bytes)?;
    let runtime_dir = shared.config.paths.ensure_runtime()?.to_path_buf();
    let mut file = sys::anonymous_file(&runtime_dir)?;
    file.write_all(&sealed)?;
    // 32 bytes always fit in a pipe's buffer
    let (read, write) = sys::pipe()?;
    File::from(write).write_all(&key[..])?;
    Ok(Handoff { file, key: read, fds })
}

/// The environment of the next image: this one's, without the test hooks that must not pass
/// on, with the remaining test faults.
fn next_environment(faults: Option<String>) -> Vec<CString> {
    let mut env: Vec<CString> = std::env::vars_os()
        .filter(|(k, _)| k != TEST_VERSION && k != TEST_FAULT)
        .filter_map(|(k, v)| {
            let mut entry = k.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(v.as_bytes());
            CString::new(entry).ok()
        })
        .collect();
    if let Some(faults) = faults.filter(|f| !f.is_empty()) {
        env.extend(CString::new(format!("{TEST_FAULT}={faults}")).ok());
    }
    env
}

fn faults_text<'a>(faults: impl Iterator<Item = &'a Fault>) -> String {
    faults.map(|f| f.name()).collect::<Vec<_>>().join(",")
}

/// `qsh-server daemon --resume …` and this daemon's own options.
fn resume_arguments(
    config: &ServerConfig,
    state_fd: RawFd,
    key_fd: RawFd,
    fallback: Option<RawFd>,
    fell_back: bool,
) -> Vec<CString> {
    let mut args = vec![
        "qsh-server".to_string(),
        "daemon".into(),
        "--resume".into(),
        format!("--state-fd={state_fd}"),
        format!("--key-fd={key_fd}"),
    ];
    if let Some(fd) = fallback {
        args.push(format!("--fallback-exe-fd={fd}"));
    }
    if fell_back {
        args.push("--fell-back".into());
    }
    let mut args: Vec<CString> = args.into_iter().filter_map(|a| CString::new(a).ok()).collect();
    if let Some(reexec) = &config.reexec {
        args.extend(reexec.args.iter().filter_map(|a| CString::new(a.as_bytes()).ok()));
    }
    args
}

/// m2.md 10.3 step 5: clear close-on-exec on exactly the descriptors the new image adopts, and
/// execute it. Returns only when that failed, with close-on-exec set again.
fn exec(shared: &Shared, plan: &Plan, handoff: &Handoff, fault: Fault) -> String {
    let fallback = shared
        .upgrade
        .fallback_exe
        .as_ref()
        .map(fd_number)
        .map(|fd| fd as RawFd);
    let mut inherit = handoff.fds.clone();
    inherit.push(fd_number(&handoff.file) as RawFd);
    inherit.push(fd_number(&handoff.key) as RawFd);
    inherit.extend(fallback);
    let path = match CString::new(plan.exe.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return format!("{} is not a usable path", plan.exe.display()),
    };
    let args = resume_arguments(
        &shared.config,
        fd_number(&handoff.file) as RawFd,
        fd_number(&handoff.key) as RawFd,
        fallback,
        false,
    );
    // The faults left for the next image: a `restore` fault is its own
    let faults = {
        let remaining = shared.upgrade.faults.lock().unwrap();
        let mine = (fault == Fault::Restore).then_some(&Fault::Restore);
        faults_text(mine.into_iter().chain(remaining.iter()))
    };
    let env = next_environment(Some(faults));
    let mut set = Vec::new();
    let mut error = None;
    for fd in &inherit {
        match sys::set_inheritable(fd, true) {
            Ok(()) => set.push(*fd),
            Err(e) => {
                error = Some(format!("cannot pass descriptor {fd}: {e}"));
                break;
            }
        }
    }
    let error = error.unwrap_or_else(|| {
        // The next image raises the limit again, and so learns the one its programs get
        let _ = sys::restore_nofile_limit();
        let e = if fault == Fault::Exec {
            io::Error::other("test fault")
        } else {
            sys::execve(&path, &args, &env)
        };
        let _ = sys::raise_nofile_limit();
        format!("cannot execute {}: {e}", plan.exe.display())
    });
    for fd in &set {
        let _ = sys::set_inheritable(fd, false);
    }
    error
}

// ---------------------------------------------------------------------------------------------
// The new image

/// Use descriptor `fd` (inherited, not owned yet) for a moment, leaving it open whatever
/// happens: before the commit, the old image may need it again.
fn peek<T>(fd: u32, f: impl FnOnce(&File) -> io::Result<T>) -> io::Result<T> {
    let file = File::from(adopt::<OwnedFd>(fd)?);
    let result = f(&file);
    let _ = file.into_raw_fd();
    result
}

/// Check that `fd` is of `kind`, and owned by this user unless `any_owner`.
fn expect(file: &File, kind: sys::FdKind, any_owner: bool, what: &str) -> io::Result<()> {
    let info = sys::fd_info(file)?;
    if info.kind != kind || (!any_owner && info.uid != sys::euid()) {
        return Err(io::Error::other(format!(
            "descriptor {} is not this user's {what} ({info:?})",
            fd_number(file)
        )));
    }
    Ok(())
}

/// m2.md 10.3 step 7: every descriptor the state names is open, of the recorded type and
/// owned by this user. Changes nothing.
fn check_descriptors(state: &State) -> io::Result<()> {
    use sys::FdKind;
    for l in &state.listeners {
        peek(l.fd, |f| match l.kind {
            ListenerKind::Udp | ListenerKind::Tcp => {
                expect(f, FdKind::Socket, false, "socket")?;
                let datagram = l.kind == ListenerKind::Udp;
                let wanted = if datagram { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
                if sys::socket_type(f)? != wanted {
                    return Err(io::Error::other(format!(
                        "descriptor {} has the wrong socket type",
                        l.fd
                    )));
                }
                let dup = OwnedFd::from(f.try_clone()?);
                let port = if datagram {
                    std::net::UdpSocket::from(dup).local_addr()?.port()
                } else {
                    std::net::TcpListener::from(dup).local_addr()?.port()
                };
                if port != l.port {
                    return Err(io::Error::other(format!("descriptor {} is not port {}", l.fd, l.port)));
                }
                Ok(())
            }
            ListenerKind::Control => {
                expect(f, FdKind::Socket, false, "control socket")?;
                if sys::socket_type(f)? != libc::SOCK_STREAM {
                    return Err(io::Error::other("the control socket has the wrong type"));
                }
                Ok(())
            }
            ListenerKind::Lock => {
                expect(f, FdKind::Regular, false, "lock")?;
                // flock on the same open file: succeeds when it is the lock this daemon holds
                if !sys::try_lock(f)? {
                    return Err(io::Error::other("the lock is not held"));
                }
                Ok(())
            }
        })?;
    }
    for s in &state.sessions {
        match s.fds {
            SessionFds::Tty { master } => peek(master, |f| {
                // A master belongs to the owner of the multiplexer (root): its kind says it
                expect(f, FdKind::CharDevice, true, "terminal")?;
                if !sys::is_pty_master(f) {
                    return Err(io::Error::other(format!(
                        "descriptor {master} is not a terminal master"
                    )));
                }
                Ok(())
            })?,
            SessionFds::Pipe { stdin, stdout, stderr } => {
                for fd in [stdin, stdout, stderr].into_iter().filter(|fd| *fd != NO_FD) {
                    peek(fd, |f| expect(f, FdKind::Fifo, false, "pipe"))?;
                }
            }
        }
    }
    Ok(())
}

/// Read the state's key from its pipe (and close it).
fn read_key(fd: RawFd) -> io::Result<StateKey> {
    use std::io::Read;
    let mut pipe = File::from(adopt::<OwnedFd>(fd as u32)?);
    let mut key = StateKey::new([0u8; STATE_KEY_LEN]);
    pipe.read_exact(&mut key[..])?;
    Ok(key)
}

/// Everything checked, nothing changed (before the commit).
struct Checked {
    state: State,
    identity: Identity,
}

/// m2.md 10.3 step 7: read and check everything, change nothing.
fn check(config: &ServerConfig, resume: &Resume, key: &StateKey, fault: bool) -> io::Result<Checked> {
    let state = peek(resume.state_fd as u32, |f| handoff::read_sealed(f, key))?;
    if fault {
        return Err(io::Error::other("test fault"));
    }
    check_descriptors(&state)?;
    let paths = &config.paths;
    paths.ensure_runtime()?;
    paths.ensure_state()?;
    let identity = Identity::load_or_create(&paths.identity_dir())?;
    Ok(Checked { state, identity })
}

/// The new image: from the inherited state to a serving daemon (m2.md 10.3 steps 7 to 9).
pub(crate) async fn resume(
    config: ServerConfig,
    resume: Resume,
) -> Result<(Arc<Shared>, Runtime, mpsc::UnboundedReceiver<Plan>), StartError> {
    let mut faults = faults_from_env();
    let fault = faults.front() == Some(&Fault::Restore);
    if fault {
        faults.pop_front();
    }
    // As a daemon that starts (section 6.6); the previous image put the limit back
    if let Err(e) = sys::raise_nofile_limit() {
        log::info(format_args!("cannot raise the limit of open files: {e}"));
    }
    let key = read_key(resume.key_fd)?;
    fallback::arm(&config, &resume, &key, faults_text(faults.iter()));
    let checked = match check(&config, &resume, &key, fault) {
        Ok(c) => c,
        Err(e) => {
            log::info(format_args!("cannot resume from the previous image: {e}"));
            fallback::run(&format!("{e}"));
            return Err(e.into());
        }
    };
    fallback::disarm();
    drop(key);
    // Committed: from here on this image owns the descriptors and the sessions
    commit(config, resume, checked)
}

/// Adopt the descriptors and the sessions; start nothing yet but the session threads.
fn commit(
    config: ServerConfig,
    resume: Resume,
    checked: Checked,
) -> Result<(Arc<Shared>, Runtime, mpsc::UnboundedReceiver<Plan>), StartError> {
    let Checked { mut state, identity } = checked;
    let (mut udp, mut tcp, mut control, mut lock) = (Vec::new(), Vec::new(), None, None);
    for l in &state.listeners {
        match l.kind {
            ListenerKind::Udp => udp.push((l.port, adopt::<std::net::UdpSocket>(l.fd)?)),
            ListenerKind::Tcp => tcp.push((l.port, adopt::<std::net::TcpListener>(l.fd)?)),
            ListenerKind::Control => control = Some(adopt::<UnixListener>(l.fd)?),
            ListenerKind::Lock => lock = Some(adopt::<File>(l.fd)?),
        }
    }
    // The primary port first
    let primary = state.port;
    udp.sort_by_key(|(port, _)| *port != primary);
    tcp.sort_by_key(|(port, _)| *port != primary);
    // The state and the old image's executable are not needed any more
    drop(adopt::<File>(resume.state_fd as u32));
    if let Some(fd) = resume.fallback_exe_fd {
        drop(adopt::<File>(fd as u32));
    }
    let sessions = std::mem::take(&mut state.sessions);
    let mut adopted: Vec<Adopted> = Vec::new();
    for s in sessions {
        let id = crypto::hex(&s.id[..4]);
        let mut fds = AdoptedFds::default();
        let take = |fd: u32| (fd != NO_FD).then(|| adopt::<File>(fd)).transpose();
        let taken = match s.fds {
            SessionFds::Tty { master } => take(master).map(|m| fds.master = m),
            SessionFds::Pipe { stdin, stdout, stderr } => (|| {
                fds.stdin = take(stdin)?;
                fds.stdout = take(stdout)?;
                fds.stderr = take(stderr)?;
                Ok(())
            })(),
        };
        match taken.and_then(|()| PtySession::adopt(s, fds)) {
            Ok(a) => adopted.push(a),
            Err(e) => log::info(format_args!("session {id}: cannot adopt it: {e}")),
        }
    }
    // Everything this image needs is adopted; nothing else may reach a program it starts
    sys::cloexec_from(3);
    let control = control.ok_or_else(|| io::Error::other("no control socket"))?;
    control.set_nonblocking(true)?;
    for (_, socket) in &udp {
        socket.set_nonblocking(true)?;
    }
    for (_, listener) in &tcp {
        listener.set_nonblocking(true)?;
    }
    let listeners = Listeners {
        udp,
        tcp,
        control,
        lock: lock.ok_or_else(|| io::Error::other("no lock"))?,
    };
    let (upgrade, plans) = UpgradeState::new(&config, Some((&state, resume.fell_back)));
    let paths = config.paths.clone();
    let shared = Arc::new(Shared {
        extra_ports: listeners.extra_ports(primary),
        account: super::pty::account(&paths.home, config.shell.as_deref()),
        gate: Arc::new(super::gate::Gate::new(config.preauth)),
        config,
        connections: serve::Registry::default(),
        sessions: super::SessionTable::default(),
        port: primary,
        fingerprint: identity.fingerprint(),
        stats: super::Stats::default(),
        shutdown: tokio::sync::Notify::new(),
        started: std::time::UNIX_EPOCH + Duration::from_millis(state.started_ms),
        upgrade,
    });
    let runtime = Runtime::new(&identity, listeners)?;
    let mut kept = 0;
    for a in adopted {
        match a.start() {
            Ok(session) => {
                shared.sessions.insert(session);
                kept += 1;
            }
            Err(e) => log::info(format_args!("a session could not be resumed: {e}")),
        }
    }
    if resume.fell_back {
        eprintln!(
            "qsh-server {}: daemon pid {}: the upgrade failed, resumed {} with {kept} session(s)",
            version(),
            std::process::id(),
            state.writer
        );
    } else {
        eprintln!(
            "qsh-server {}: daemon pid {}: upgraded in place from {}, {kept} session(s) kept",
            version(),
            std::process::id(),
            state.writer
        );
    }
    Ok((shared, runtime, plans))
}

/// m2.md 10.4: when the new image cannot resume, it executes the old one again (Linux, which
/// can execute an open file: the old executable was kept open since that image started, so a
/// package upgrade that replaced the file does not matter). A panic before the commit does
/// the same, from the panic hook (release builds abort on panic).
mod fallback {
    use super::*;

    /// What it takes to execute the old image again.
    // Read by `exec_old`, which only Linux has
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    struct Plan {
        exe: RawFd,
        state: RawFd,
        key: StateKey,
        faults: String,
        config: ServerConfig,
    }

    static PLAN: Mutex<Option<Plan>> = Mutex::new(None);

    /// Prepare the fallback, if this system and the old image allow one.
    pub(super) fn arm(config: &ServerConfig, resume: &Resume, key: &StateKey, faults: String) {
        let Some(exe) = resume.fallback_exe_fd else { return };
        if !cfg!(any(target_os = "linux", target_os = "android")) {
            return;
        }
        *PLAN.lock().unwrap_or_else(|e| e.into_inner()) = Some(Plan {
            exe,
            state: resume.state_fd,
            key: key.clone(),
            faults,
            config: config.clone(),
        });
        static HOOK: std::sync::Once = std::sync::Once::new();
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                previous(info);
                run("a panic");
            }));
        });
    }

    /// The commit: no fallback any more.
    pub(super) fn disarm() {
        PLAN.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// Execute the old image with the same state, if armed. Returns when that is not possible.
    pub(super) fn run(why: &str) {
        let Some(plan) = PLAN.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        if let Err(e) = exec_old(&plan, why) {
            log::info(format_args!("cannot execute the previous program again: {e}"));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn exec_old(plan: &Plan, why: &str) -> io::Result<()> {
        let (read, write) = sys::pipe()?;
        File::from(write).write_all(&plan.key[..])?;
        sys::set_inheritable(&read, true)?;
        let args = resume_arguments(&plan.config, plan.state, fd_number(&read) as RawFd, None, true);
        let env = next_environment(Some(plan.faults.clone()));
        log::info(format_args!(
            "could not resume ({why}); executing the previous program again"
        ));
        let _ = sys::restore_nofile_limit();
        let e = sys::fexecve(&plan.exe, &args, &env);
        let _ = sys::raise_nofile_limit();
        Err(e)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn exec_old(_plan: &Plan, _why: &str) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
