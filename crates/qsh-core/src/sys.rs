//! The operating system calls the rest of qsh needs and the standard library does not offer:
//! pseudo terminals, terminal modes, process groups, file locks, a dual-stack UDP socket, the
//! addresses of network interfaces and the kernel's notifications of network changes.
//!
//! This is the only module of qsh with `unsafe` code. Every block is a plain libc call with
//! arguments that are valid for the duration of the call; each one says why it is sound.
//! Everything public here is a safe interface.

// The crate forbids unsafe code everywhere else (lib.rs); this module is the exception the
// design allows (docs/DESIGN.md section 3), each block justified below.
#![allow(unsafe_code)]

use std::ffi::{CStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// The effective user id of this process.
pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// True when `fd` is a terminal.
pub fn is_tty(fd: &impl AsRawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor; an invalid one yields 0.
    unsafe { libc::isatty(fd.as_raw_fd()) == 1 }
}

/// The size of the terminal on `fd` as (columns, rows), or None when it is not a terminal or
/// reports no size.
pub fn window_size(fd: &impl AsRawFd) -> Option<(u16, u16)> {
    // SAFETY: winsize is plain old data; all zeroes is a valid value.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one winsize into the pointer, which lives across the call.
    let ok = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) } == 0;
    (ok && ws.ws_col > 0 && ws.ws_row > 0).then_some((ws.ws_col, ws.ws_row))
}

/// Set the size of the terminal on `fd` (the pty master of a session): the kernel sends
/// SIGWINCH to the terminal's foreground process group.
pub fn set_window_size(fd: &impl AsRawFd, cols: u16, rows: u16) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize from the pointer, which lives across the call.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A new pseudo terminal of the given size: (master, slave), both close-on-exec.
pub fn openpty(cols: u16, rows: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty writes two descriptors into the pointers; the name pointer may be null,
    // termios null means default modes, and the winsize pointer is valid for the call.
    let r = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            // null_mut: macOS declares termp mutable, Linux const (mut coerces to const)
            std::ptr::null_mut(),
            &ws as *const libc::winsize as *mut libc::winsize,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty succeeded, so both are open descriptors this process now owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // Not inherited by the programs of other sessions: a leaked master keeps that session's
    // terminal open after the session ended
    set_cloexec(master.as_raw_fd())?;
    set_cloexec(slave.as_raw_fd())?;
    Ok((master, slave))
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl F_SETFD on a descriptor has no memory effects.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mark every descriptor from `first` up close-on-exec, so programs this process starts do not
/// inherit them (a lock file of whoever started us, another session's pty).
pub fn cloexec_from(first: RawFd) {
    for fd in first..open_max() {
        // SAFETY: as in set_cloexec; descriptors that are not open just fail with EBADF.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
}

fn open_max() -> RawFd {
    // SAFETY: sysconf has no preconditions.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    // A huge limit (systemd sets 524288) would make the loop slow; few programs go that high
    if max <= 0 {
        4096
    } else {
        max.min(65536) as RawFd
    }
}

/// Make `command` start in a new session whose controlling terminal is its stdin (the pty
/// slave), with nothing but stdin, stdout and stderr inherited, and every signal at its
/// default disposition and unblocked: the daemon ignores SIGHUP, and an ignored signal would
/// otherwise stay ignored in the session's programs (a hangup would not end them).
pub fn spawn_on_pty(command: &mut Command) {
    spawn_session(command, true);
}

/// Make `command` start like [`spawn_on_pty`], but without a controlling terminal: the program
/// of a pipe session, whose stdin, stdout and stderr are pipes.
pub fn spawn_with_pipes(command: &mut Command) {
    spawn_session(command, false);
}

fn spawn_session(command: &mut Command, controlling_tty: bool) {
    let max = open_max();
    let nofile = ORIGINAL_NOFILE.get().copied();
    // SAFETY: the closure runs between fork and exec and calls only async-signal-safe
    // functions (signal, sigemptyset, sigprocmask, setsid, ioctl, fcntl, setrlimit) on local
    // data, allocating nothing.
    unsafe {
        command.pre_exec(move || {
            for signal in 1..32 {
                if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                    libc::signal(signal, libc::SIG_DFL);
                }
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if controlling_tty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            // The daemon raised its own descriptor limit (raise_nofile_limit); programs get the
            // limit the daemon started with, as select()-based ones expect
            if let Some(limit) = nofile {
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
            for fd in 3..max {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
}

/// The descriptor limit the process started with, before [`raise_nofile_limit`].
static ORIGINAL_NOFILE: std::sync::OnceLock<libc::rlimit> = std::sync::OnceLock::new();

/// Raise the soft limit of open descriptors to the hard limit (protocol.md 6.6: the daemon's
/// own connection limits, not the descriptor table, should decide when connections are
/// refused). Programs started afterwards with [`spawn_on_pty`] or [`spawn_with_pipes`] get the
/// original limit back. Returns the new soft limit.
// rlim_t is u32 on some 32-bit targets: the casts are not always no-ops
#[allow(clippy::unnecessary_cast)]
pub fn raise_nofile_limit() -> io::Result<u64> {
    // SAFETY: rlimit is plain old data; all zeroes is a valid value.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: getrlimit writes one rlimit into the pointer, valid across the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = ORIGINAL_NOFILE.set(limit);
    let mut raised = limit;
    raised.rlim_cur = limit.rlim_max;
    // macOS refuses RLIM_INFINITY and values above OPEN_MAX (10240, <sys/syslimits.h>) for
    // the soft limit
    #[cfg(target_vendor = "apple")]
    {
        raised.rlim_cur = raised.rlim_cur.min(10240);
    }
    if raised.rlim_cur > limit.rlim_cur {
        // SAFETY: setrlimit reads one rlimit from the pointer, valid across the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(raised.rlim_cur as u64);
    }
    Ok(limit.rlim_cur as u64)
}

/// Put the soft limit of open descriptors back to what it was before
/// [`raise_nofile_limit`], if that raised it: right before an upgrade in place executes the
/// next image (m2.md 10.3 step 5), which raises it again and so learns the limit its session
/// programs must get. Calling [`raise_nofile_limit`] again undoes it.
pub fn restore_nofile_limit() -> io::Result<()> {
    if let Some(original) = ORIGINAL_NOFILE.get() {
        // SAFETY: setrlimit reads one rlimit from the pointer, valid across the call.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, original) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Make `fd` non-blocking (for [`wait_fd`] loops).
pub fn set_nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    let fd = fd.as_raw_fd();
    // SAFETY: fcntl F_GETFL / F_SETFL on a descriptor have no memory effects.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A way to wake every thread waiting in [`wait_fd`]: a pipe whose write end is closed by
/// [`Cancel::cancel`] (or when the `Cancel` is dropped), which makes its read end readable for
/// good.
#[derive(Debug)]
pub struct Cancel {
    read: OwnedFd,
    write: std::sync::Mutex<Option<OwnedFd>>,
}

impl Cancel {
    /// A new, not yet cancelled, cancel pipe.
    pub fn new() -> io::Result<Cancel> {
        let mut fds = [-1 as libc::c_int; 2];
        // SAFETY: pipe writes two descriptors into the array, which lives across the call.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe succeeded: both are open descriptors this process now owns.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        set_cloexec(read.as_raw_fd())?;
        set_cloexec(write.as_raw_fd())?;
        Ok(Cancel {
            read,
            write: std::sync::Mutex::new(Some(write)),
        })
    }

    /// Wake every waiter, now and from now on.
    pub fn cancel(&self) {
        self.write.lock().unwrap().take();
    }

    /// True once cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.write.lock().unwrap().is_none()
    }
}

/// What [`wait_fd`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ready {
    /// The descriptor is ready (or failed, or reached its end: the next read or write says).
    Fd,
    /// The [`Cancel`] was cancelled.
    Cancelled,
    /// The timeout passed.
    TimedOut,
}

/// Wait until `fd` is readable (or writable, with `write`), `cancel` is cancelled, or
/// `timeout` passed. Used with non-blocking descriptors, so that a thread blocked on a
/// session's terminal or pipe can always be told to let go of it.
pub fn wait_fd(
    fd: &impl AsRawFd,
    write: bool,
    cancel: &Cancel,
    timeout: Option<std::time::Duration>,
) -> io::Result<Ready> {
    wait_raw(fd.as_raw_fd(), write, cancel.read.as_raw_fd(), timeout)
}

#[cfg(not(target_vendor = "apple"))]
fn wait_raw(fd: RawFd, write: bool, cancel: RawFd, timeout: Option<std::time::Duration>) -> io::Result<Ready> {
    let events = if write { libc::POLLOUT } else { libc::POLLIN };
    let mut fds = [
        libc::pollfd { fd, events, revents: 0 },
        libc::pollfd {
            fd: cancel,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let ms = timeout.map_or(-1, |t| t.as_millis().min(i32::MAX as u128) as libc::c_int);
    loop {
        // SAFETY: poll reads and writes the two pollfd entries of the array, valid for the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[1].revents != 0 {
            return Ok(Ready::Cancelled);
        }
        if fds[0].revents != 0 {
            return Ok(Ready::Fd);
        }
        return Ok(Ready::TimedOut);
    }
}

/// macOS: poll() and kqueue do not work on terminal devices, select() does. Descriptors beyond
/// FD_SETSIZE cannot be put in an fd_set; for those, short sleeps stand in for the wait (the
/// callers retry their non-blocking reads and writes).
#[cfg(target_vendor = "apple")]
fn wait_raw(fd: RawFd, write: bool, cancel: RawFd, timeout: Option<std::time::Duration>) -> io::Result<Ready> {
    let limit = libc::FD_SETSIZE as RawFd;
    if fd >= limit || cancel >= limit {
        let nap = std::time::Duration::from_millis(20);
        std::thread::sleep(timeout.map_or(nap, |t| t.min(nap)));
        return Ok(Ready::Fd);
    }
    loop {
        // SAFETY: fd_set is plain old data; all zeroes is an empty set.
        let mut readable: libc::fd_set = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut writable: libc::fd_set = unsafe { std::mem::zeroed() };
        // SAFETY: both descriptors are below FD_SETSIZE (checked above); the sets are local.
        unsafe {
            libc::FD_SET(cancel, &mut readable);
            if write {
                libc::FD_SET(fd, &mut writable);
            } else {
                libc::FD_SET(fd, &mut readable);
            }
        }
        let mut tv = timeout.map(|t| libc::timeval {
            tv_sec: t.as_secs() as libc::time_t,
            tv_usec: t.subsec_micros() as libc::suseconds_t,
        });
        let tvp = tv.as_mut().map_or(std::ptr::null_mut(), |t| t as *mut libc::timeval);
        // SAFETY: select reads and writes the local sets and timeval, valid for the call.
        let n = unsafe {
            libc::select(
                fd.max(cancel) + 1,
                &mut readable,
                &mut writable,
                std::ptr::null_mut(),
                tvp,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        // SAFETY: FD_ISSET only reads the local sets, with descriptors below FD_SETSIZE.
        unsafe {
            if libc::FD_ISSET(cancel, &readable) {
                return Ok(Ready::Cancelled);
            }
            if libc::FD_ISSET(fd, &readable) || libc::FD_ISSET(fd, &writable) {
                return Ok(Ready::Fd);
            }
        }
        return Ok(Ready::TimedOut);
    }
}

/// Wait until child process `pid` has ended, without reaping it: its pid (and so its process
/// group id) stays reserved until the caller reaps it, so the process group can still be
/// signalled safely in between.
pub fn wait_exit_no_reap(pid: u32) -> io::Result<()> {
    let id = libc::id_t::from(pid);
    loop {
        // SAFETY: siginfo_t is plain old data; all zeroes is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid writes one siginfo_t into the pointer, valid across the call.
        let r = unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if r == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// How a reaped child ended (see [`reap`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildExit {
    /// The exit code, when it exited.
    pub code: Option<i32>,
    /// The signal that ended it, when one did.
    pub signal: Option<i32>,
    /// A core dump was written.
    pub core_dumped: bool,
}

/// Wait for child process `pid` to end and reap it. The daemon uses this rather than
/// `std::process::Child::wait`, because after an upgrade in place (m2.md section 10) the
/// session programs are still its children, but no `Child` value exists for them any more.
pub fn reap(pid: u32) -> io::Result<ChildExit> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pid <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid writes one c_int into the pointer, valid across the call; pid > 0
        // names a single child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            let exited = libc::WIFEXITED(status);
            let signaled = libc::WIFSIGNALED(status);
            return Ok(ChildExit {
                code: exited.then(|| libc::WEXITSTATUS(status)),
                signal: signaled.then(|| libc::WTERMSIG(status)),
                core_dumped: signaled && libc::WCOREDUMP(status),
            });
        }
        let e = io::Error::last_os_error();
        if r < 0 && e.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(e);
    }
}

/// Mark `fd` inherited by programs this process executes (`inherit`), or close-on-exec. The
/// upgrade in place clears close-on-exec on exactly the descriptors the new image adopts, and
/// on nothing else (security.md 4.8).
pub fn set_inheritable(fd: &impl AsRawFd, inherit: bool) -> io::Result<()> {
    let flags = if inherit { 0 } else { libc::FD_CLOEXEC };
    // SAFETY: fcntl F_SETFD on a descriptor has no memory effects.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Take ownership of descriptor number `fd`, inherited from the previous image of this process
/// across an upgrade in place. None when no descriptor with that number is open. The caller
/// must have been told the number by that image (the handoff state, m2.md 10.5), must take each
/// number at most once, and must not hold another owner of it.
pub fn adopt_fd(fd: RawFd) -> Option<OwnedFd> {
    if fd < 0 {
        return None;
    }
    // SAFETY: fcntl F_GETFD only checks that the number is an open descriptor.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    // SAFETY: the descriptor is open (checked above) and, by the caller's contract, owned by
    // nothing else in this process: it was inherited across execve for exactly this owner.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The kind of file a descriptor refers to ([`fd_info`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// A socket.
    Socket,
    /// A character device (a pseudo-terminal master).
    CharDevice,
    /// A pipe.
    Fifo,
    /// A regular file (including an anonymous memory file).
    Regular,
    /// Anything else.
    Other,
}

/// What `fstat` says about a descriptor: its kind and the user that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdInfo {
    /// The kind of file.
    pub kind: FdKind,
    /// The owner's user id.
    pub uid: u32,
}

/// The kind and owner of the file `fd` refers to.
pub fn fd_info(fd: &impl AsRawFd) -> io::Result<FdInfo> {
    // SAFETY: stat is plain old data; all zeroes is a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes one stat into the pointer, valid across the call.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => FdKind::Socket,
        libc::S_IFCHR => FdKind::CharDevice,
        libc::S_IFIFO => FdKind::Fifo,
        libc::S_IFREG => FdKind::Regular,
        _ => FdKind::Other,
    };
    Ok(FdInfo { kind, uid: st.st_uid })
}

/// True when `fd` is the master side of a pseudo terminal. (A master belongs to root, the
/// owner of the multiplexer device: its owner says nothing about who opened it.)
pub fn is_pty_master(fd: &impl AsRawFd) -> bool {
    #[cfg(target_os = "linux")]
    {
        let mut number: libc::c_uint = 0;
        // SAFETY: TIOCGPTN writes the slave's number into the c_uint, valid across the call;
        // it succeeds only on a master.
        unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGPTN as _, &mut number) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: isatty only inspects the descriptor.
        unsafe { libc::isatty(fd.as_raw_fd()) == 1 }
    }
}

/// The socket type (`SOCK_STREAM`, `SOCK_DGRAM`, ...) of socket `fd`.
pub fn socket_type(fd: &impl AsRawFd) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into the c_int and updates `len`, both
    // valid across the call.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// A pipe, both ends close-on-exec: (read end, write end).
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as libc::c_int; 2];
    // SAFETY: pipe writes two descriptors into the array, which lives across the call.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe succeeded: both are open descriptors this process now owns.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    set_cloexec(read.as_raw_fd())?;
    set_cloexec(write.as_raw_fd())?;
    Ok((read, write))
}

/// An anonymous file for secrets that must cross an `execve` (the upgrade's state, m2.md 10.3
/// step 4): a memory file (`memfd_create`) on Linux; elsewhere, or where that fails, a file
/// created with mode 0600 in `dir` (a private directory) and unlinked at once. Close-on-exec.
pub fn anonymous_file(dir: &std::path::Path) -> io::Result<File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let name = c"qsh-handoff";
        // SAFETY: memfd_create reads the NUL-terminated name, valid across the call.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd >= 0 {
            // SAFETY: memfd_create succeeded: a new descriptor this process now owns.
            return Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }));
        }
    }
    use std::os::unix::fs::OpenOptionsExt;
    for _ in 0..16 {
        let path = dir.join(format!(
            ".handoff-{}",
            crate::crypto::hex(&crate::crypto::random::<8>())
        ));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                std::fs::remove_file(&path)?;
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("cannot create a private temporary file"))
}

/// Pointers to the strings, NUL-terminated, for execve's argv and envp.
fn exec_pointers(strings: &[std::ffi::CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

/// Replace this process's program with `path` (`execve`), keeping its process id, its
/// children and every descriptor not marked close-on-exec. Returns only when that fails.
pub fn execve(path: &std::ffi::CStr, argv: &[std::ffi::CString], envp: &[std::ffi::CString]) -> io::Error {
    let args = exec_pointers(argv);
    let env = exec_pointers(envp);
    // SAFETY: the path and every string are NUL-terminated and alive across the call; both
    // arrays end with a null pointer. On success the call does not return.
    unsafe { libc::execve(path.as_ptr(), args.as_ptr(), env.as_ptr()) };
    io::Error::last_os_error()
}

/// Replace this process's program with the executable open on `fd` (`fexecve`; the old
/// image of an upgrade, m2.md 10.4). Returns only when that fails.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn fexecve(fd: &impl AsRawFd, argv: &[std::ffi::CString], envp: &[std::ffi::CString]) -> io::Error {
    let args = exec_pointers(argv);
    let env = exec_pointers(envp);
    // SAFETY: every string is NUL-terminated and alive across the call; both arrays end with a
    // null pointer; fd is an open descriptor. On success the call does not return.
    unsafe { libc::fexecve(fd.as_raw_fd(), args.as_ptr(), env.as_ptr()) };
    io::Error::last_os_error()
}

/// Ask for `bytes` of receive and send buffer on a UDP socket (the kernel caps the request
/// at `net.core.rmem_max` / `wmem_max`, m2.md 8.2 `udp-buffers`). Returns the sizes the kernel
/// granted (Linux reports twice the usable size).
pub fn set_socket_buffers(fd: &impl AsRawFd, bytes: usize) -> io::Result<(usize, usize)> {
    let value = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
    let mut granted = [0usize; 2];
    for (i, option) in [libc::SO_RCVBUF, libc::SO_SNDBUF].into_iter().enumerate() {
        // SAFETY: the option value points to a c_int that lives across the call, with its size.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut now: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into the c_int and updates `len`.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                &mut now as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if r == 0 {
            granted[i] = usize::try_from(now).unwrap_or(0);
        }
    }
    Ok((granted[0], granted[1]))
}

/// Use congestion control `name` (`bbr`) on TCP socket `fd`; on a listening socket the
/// connections it accepts inherit it. Linux only, and only when the administrator allows the
/// algorithm for unprivileged users (`net.ipv4.tcp_allowed_congestion_control`, m2.md 8.4).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_tcp_congestion(fd: &impl AsRawFd, name: &str) -> io::Result<()> {
    // SAFETY: the option value points to `name`'s bytes, valid across the call, with its length.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Congestion control cannot be chosen per socket on this system.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn set_tcp_congestion(_fd: &impl AsRawFd, _name: &str) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Make `command` a daemon: a grandchild in a session of its own (so the ssh session that
/// started it can end without taking it along), ignoring SIGHUP, with nothing but stdin,
/// stdout and stderr inherited. `spawn` returns once the intermediate process exited, and the
/// returned child is that intermediate process: wait for it.
pub fn spawn_detached(command: &mut Command) {
    let max = open_max();
    // SAFETY: the closure runs between fork and exec and calls only async-signal-safe
    // functions (fork, _exit, setsid, signal, fcntl), allocating nothing.
    unsafe {
        command.pre_exec(move || {
            match libc::fork() {
                -1 => return Err(io::Error::last_os_error()),
                0 => {}
                _ => libc::_exit(0),
            }
            libc::setsid();
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            for fd in 3..max {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
}

/// Signals qsh sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// The terminal hung up: what a session's programs get when the session is closed.
    Hangup,
    /// Terminate politely.
    Terminate,
    /// Kill.
    Kill,
}

impl Signal {
    fn number(self) -> libc::c_int {
        match self {
            Signal::Hangup => libc::SIGHUP,
            Signal::Terminate => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        }
    }
}

/// Send `signal` to process `pid`.
pub fn kill(pid: u32, signal: Signal) -> io::Result<()> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pid <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: kill has no memory effects; pid is a positive single process.
    if unsafe { libc::kill(pid, signal.number()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send `signal` to every process of process group `pgid` (a session's programs).
pub fn kill_group(pgid: u32, signal: Signal) -> io::Result<()> {
    let pgid = libc::pid_t::try_from(pgid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pgid <= 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: killpg has no memory effects; pgid > 1 never means "every process".
    if unsafe { libc::killpg(pgid, signal.number()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True when process `pid` exists (and may be signalled by us).
pub fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks for existence and permission.
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

/// Take an exclusive lock on `file` without waiting. False when another process holds it.
/// The lock lasts as long as the file stays open.
pub fn try_lock(file: &File) -> io::Result<bool> {
    // SAFETY: flock has no memory effects.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// The effective user in the password database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Login name.
    pub name: String,
    /// Login shell.
    pub shell: PathBuf,
    /// Home directory.
    pub home: PathBuf,
}

/// Whether the kernel considers the system clock synchronized (an NTP daemon disciplines
/// it): `adjtimex` without changing anything. None where it cannot tell (not Linux).
/// For `qsh-server doctor` (m2.md 8.2, `clock`).
#[cfg(target_os = "linux")]
pub fn clock_synchronized() -> Option<bool> {
    // SAFETY: timex is plain old data; all zeroes is a valid value, and modes = 0 makes the
    // call read only.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: adjtimex fills in the timex the pointer refers to, valid across the call.
    let state = unsafe { libc::adjtimex(&mut tx) };
    if state < 0 {
        return None;
    }
    Some(state != libc::TIME_ERROR && tx.status & libc::STA_UNSYNC == 0)
}

/// Whether the kernel considers the system clock synchronized: unknown on this system.
#[cfg(not(target_os = "linux"))]
pub fn clock_synchronized() -> Option<bool> {
    None
}

/// The effective user's entry in the password database.
pub fn passwd_entry() -> Option<User> {
    // SAFETY: passwd is plain old data; all zeroes is a valid value.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16384];
    // SAFETY: getpwuid_r writes the entry into `entry` with strings in `buf`, both valid and
    // sized as passed, and sets `result` to `&entry` on success.
    let r = unsafe { libc::getpwuid_r(euid(), &mut entry, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
    if r != 0 || result.is_null() || entry.pw_shell.is_null() || entry.pw_dir.is_null() || entry.pw_name.is_null() {
        return None;
    }
    // SAFETY: on success all three point to NUL-terminated strings inside `buf`, alive here.
    let (name, shell, dir) = unsafe {
        (
            CStr::from_ptr(entry.pw_name),
            CStr::from_ptr(entry.pw_shell),
            CStr::from_ptr(entry.pw_dir),
        )
    };
    let os = |s: &CStr| PathBuf::from(OsString::from_vec(s.to_bytes().to_vec()));
    Some(User {
        name: name.to_string_lossy().into_owned(),
        shell: os(shell),
        home: os(dir),
    })
}

/// The name of signal `number` without "SIG", as in RFC 4254 section 6.10 ("HUP", "TERM", …).
pub fn signal_name(number: i32) -> String {
    let name = match number {
        libc::SIGABRT => "ABRT",
        libc::SIGALRM => "ALRM",
        libc::SIGFPE => "FPE",
        libc::SIGHUP => "HUP",
        libc::SIGILL => "ILL",
        libc::SIGINT => "INT",
        libc::SIGKILL => "KILL",
        libc::SIGPIPE => "PIPE",
        libc::SIGQUIT => "QUIT",
        libc::SIGSEGV => "SEGV",
        libc::SIGTERM => "TERM",
        libc::SIGUSR1 => "USR1",
        libc::SIGUSR2 => "USR2",
        libc::SIGBUS => "BUS",
        libc::SIGSYS => "SYS",
        libc::SIGTRAP => "TRAP",
        libc::SIGXCPU => "XCPU",
        libc::SIGXFSZ => "XFSZ",
        _ => return format!("{number}"),
    };
    name.to_string()
}

/// The number of a signal named as by [`signal_name`] on this system, if it has one.
pub fn signal_number(name: &str) -> Option<i32> {
    (1..65).find(|n| signal_name(*n) == name).or_else(|| name.parse().ok())
}

/// A UDP socket bound to `port` on all addresses: IPv6 and IPv4 on one socket where the host
/// has IPv6, IPv4 only otherwise. Non-blocking, close-on-exec.
pub fn udp_any(port: u16) -> io::Result<std::net::UdpSocket> {
    let socket = match udp_dual_stack(port) {
        Ok(s) => s,
        Err(e) if e.raw_os_error() == Some(libc::EADDRINUSE) => return Err(e),
        Err(_) => std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port))?,
    };
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn udp_dual_stack(port: u16) -> io::Result<std::net::UdpSocket> {
    // SAFETY: socket has no memory effects; the result is checked below.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    // SAFETY: as above. No SOCK_CLOEXEC on macOS: close-on-exec is set right after, before the
    // daemon (single threaded at bind time) can spawn a session.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    // SAFETY: fd is the descriptor just created; F_SETFD has no memory effects.
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    // SAFETY: fd is a new descriptor this process owns; the socket closes it on drop.
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let off: libc::c_int = 0;
    // SAFETY: the option value points to a c_int that lives across the call, with its size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_in6 is plain old data; all zeroes is the unspecified address.
    let mut any: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    any.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    any.sin6_port = port.to_be();
    // SAFETY: the address points to a sockaddr_in6 that lives across the call, with its size.
    let r = unsafe {
        libc::bind(
            fd,
            &any as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// The rtnetlink multicast groups [`route_socket`] joins (`RTMGRP_*` of linux/rtnetlink.h,
/// kernel ABI; spelled out because the libc crate has them for Linux but not for Android):
/// links, IPv4 and IPv6 addresses, IPv4 and IPv6 routes.
#[cfg(any(target_os = "linux", target_os = "android"))]
const RTNETLINK_GROUPS: u32 = 0x1 | 0x10 | 0x40 | 0x100 | 0x400;

/// A socket on which the kernel announces changes of network interfaces, addresses and
/// routes: rtnetlink (`NETLINK_ROUTE`) on Linux and Android, a routing socket (`PF_ROUTE`) on
/// macOS; `Unsupported` elsewhere. Non-blocking and close-on-exec; each read(2) returns one
/// datagram of messages (see [`crate::netwatch`] for what is read from them).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn route_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket has no memory effects; the result is checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a new descriptor this process owns; the OwnedFd closes it on every path.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_nl is plain old data; all zeroes is valid (port id 0: the kernel picks).
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address.nl_groups = RTNETLINK_GROUPS;
    // SAFETY: the address points to a sockaddr_nl that lives across the call, with its size.
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// A socket on which the kernel announces changes of network interfaces, addresses and
/// routes: a routing socket (`PF_ROUTE`). Non-blocking and close-on-exec; each read(2)
/// returns one routing message (see [`crate::netwatch`] for what is read from them).
#[cfg(target_os = "macos")]
pub fn route_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket has no memory effects; the result is checked below. AF_UNSPEC as the
    // protocol: messages about every address family.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a new descriptor this process owns; the OwnedFd closes it on every path.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // No SOCK_CLOEXEC on macOS: set right after; a program spawned in between by another
    // thread could only inherit a socket that reads routing messages.
    set_cloexec(fd.as_raw_fd())?;
    set_nonblocking(&fd)?;
    Ok(fd)
}

/// Kernel notifications of network changes are not implemented on this system: always
/// `Unsupported` ([`crate::netwatch`] polls instead).
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn route_socket() -> io::Result<OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no route change notifications on this system",
    ))
}

/// An IPv4 or IPv6 address of a network interface, from getifaddrs(3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddress {
    /// The interface's name (`eth0`, `wlan0`, `en0`).
    pub interface: String,
    /// The address.
    pub address: std::net::IpAddr,
    /// The interface is up and running (`IFF_UP` and `IFF_RUNNING`).
    pub up: bool,
    /// The interface is a loopback interface.
    pub loopback: bool,
}

/// The IPv4 and IPv6 addresses of every network interface.
pub fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs stores a pointer to a list it allocated into `head`, which lives
    // across the call; the list is freed below with freeifaddrs, once.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let up = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_uint;
    let loopback = libc::IFF_LOOPBACK as libc::c_uint;
    let mut addresses = Vec::new();
    let mut node = head;
    while !node.is_null() {
        // SAFETY: `node` is an element of the list getifaddrs returned, which stays valid
        // until freeifaddrs below; nothing borrowed from it outlives this loop.
        let entry = unsafe { &*node };
        node = entry.ifa_next;
        // SAFETY: ifa_addr is null or points to a complete socket address of the list.
        let Some(address) = (unsafe { socket_address_ip(entry.ifa_addr) }) else {
            continue;
        };
        if entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string of the list (above).
        let interface = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy().into_owned();
        addresses.push(InterfaceAddress {
            interface,
            address,
            up: entry.ifa_flags & up == up,
            loopback: entry.ifa_flags & loopback != 0,
        });
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once; no reference into the
    // list is left (the loop above copied what it needed).
    unsafe { libc::freeifaddrs(head) };
    Ok(addresses)
}

/// The IP address in a socket address; None for other families (link layer, …).
///
/// # Safety
///
/// `address` must be null or point to a valid socket address whose structure for its family
/// is complete (getifaddrs gives complete `sockaddr_in` and `sockaddr_in6`).
unsafe fn socket_address_ip(address: *const libc::sockaddr) -> Option<std::net::IpAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: non-null, and valid by the caller's promise; sa_family is in every sockaddr.
    // (sa_family_t is u16 on Linux, u8 on macOS: i32::from takes both.)
    let family = i32::from(unsafe { (*address).sa_family });
    match family {
        libc::AF_INET => {
            // SAFETY: an AF_INET address is a complete sockaddr_in (caller's promise);
            // read_unaligned makes no assumption about its alignment.
            let v4 = unsafe { std::ptr::read_unaligned(address as *const libc::sockaddr_in) };
            // s_addr is in network byte order: its bytes in memory are the address
            Some(std::net::Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()).into())
        }
        libc::AF_INET6 => {
            // SAFETY: as above, for an AF_INET6 address and sockaddr_in6.
            let v6 = unsafe { std::ptr::read_unaligned(address as *const libc::sockaddr_in6) };
            Some(std::net::Ipv6Addr::from(v6.sin6_addr.s6_addr).into())
        }
        _ => None,
    }
}

/// The terminal mode of stdin before [`RawMode::enable`], for [`restore_terminal`].
static SAVED_TERMIOS: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

/// Put stdin's terminal back into the mode it had before [`RawMode::enable`], if raw mode is on.
/// For the paths on which [`RawMode`]'s drop never runs, or not soon enough: a panic (from
/// the panic hook, before the unwinding, which may end only a task), and signals that end the
/// process. Safe to call more than once.
pub fn restore_terminal() {
    let saved = match SAVED_TERMIOS.try_lock() {
        Ok(mut guard) => guard.take(),
        // Poisoned by a panic while it was held: the value is still good
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner().take(),
        // Held right now by another thread: it is restoring or saving; leave it alone
        Err(std::sync::TryLockError::WouldBlock) => None,
    };
    if let Some(original) = saved {
        // SAFETY: tcsetattr reads the saved termios the pointer refers to.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &original) };
    }
}

/// True when the terminal on `fd` echoes input and edits lines (canonical mode): not raw.
pub fn terminal_is_cooked(fd: &impl AsRawFd) -> Option<bool> {
    // SAFETY: termios is plain old data; all zeroes is a valid value.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr fills the termios the pointer refers to, valid across the call.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut t) } != 0 {
        return None;
    }
    Some(t.c_lflag & libc::ICANON != 0 && t.c_lflag & libc::ECHO != 0)
}

/// The terminal on stdin in raw mode (no echo, no line editing, no signals from keys) for as
/// long as this value lives; the previous mode comes back when it is dropped (and from
/// [`restore_terminal`], for exits that skip drops).
#[derive(Debug)]
pub struct RawMode {
    original: Option<libc::termios>,
}

impl RawMode {
    /// Put the terminal on stdin into raw mode. Does nothing when stdin is not a terminal.
    pub fn enable() -> RawMode {
        let fd = libc::STDIN_FILENO;
        // SAFETY: termios is plain old data; all zeroes is a valid value.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr fills the termios the pointer refers to, valid across the call.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return RawMode { original: None };
        }
        let mut raw = original;
        // SAFETY: cfmakeraw only modifies the termios the pointer refers to.
        unsafe { libc::cfmakeraw(&mut raw) };
        *SAVED_TERMIOS.lock().unwrap_or_else(|e| e.into_inner()) = Some(original);
        // SAFETY: tcsetattr reads the termios the pointer refers to.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            SAVED_TERMIOS.lock().unwrap_or_else(|e| e.into_inner()).take();
            return RawMode { original: None };
        }
        RawMode {
            original: Some(original),
        }
    }

    /// True when the terminal was put into raw mode.
    pub fn active(&self) -> bool {
        self.original.is_some()
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if self.original.is_some() {
            restore_terminal();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_has_the_requested_size() {
        let (master, slave) = openpty(100, 30).unwrap();
        assert_eq!(window_size(&slave), Some((100, 30)));
        set_window_size(&master, 120, 40).unwrap();
        assert_eq!(window_size(&slave), Some((120, 40)));
        assert!(is_tty(&slave));
    }

    #[test]
    fn signals_refuse_dangerous_pids() {
        assert!(kill(0, Signal::Hangup).is_err());
        assert!(kill_group(1, Signal::Hangup).is_err());
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = std::env::temp_dir().join(format!("qsh-sys-lock-{}", std::process::id()));
        let a = File::create(&dir).unwrap();
        let b = File::open(&dir).unwrap();
        assert!(try_lock(&a).unwrap());
        assert!(!try_lock(&b).unwrap());
        drop(a);
        assert!(try_lock(&b).unwrap());
        let _ = std::fs::remove_file(dir);
    }

    #[test]
    fn cancel_wakes_a_waiting_reader() {
        let (master, _slave) = openpty(80, 24).unwrap();
        set_nonblocking(&master).unwrap();
        let cancel = std::sync::Arc::new(Cancel::new().unwrap());
        assert_eq!(
            wait_fd(&master, false, &cancel, Some(std::time::Duration::from_millis(50))).unwrap(),
            Ready::TimedOut
        );
        let c = cancel.clone();
        let waiter = std::thread::spawn(move || wait_fd(&master, false, &c, None).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(50));
        cancel.cancel();
        assert_eq!(waiter.join().unwrap(), Ready::Cancelled);
        assert!(cancel.is_cancelled());
    }

    #[test]
    #[allow(clippy::unnecessary_cast)]
    fn nofile_limit_is_raised_and_given_back_to_programs() {
        let raised = raise_nofile_limit().unwrap();
        let original = ORIGINAL_NOFILE.get().unwrap().rlim_cur as u64;
        assert!(raised >= original);
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "ulimit -n"]).stdout(std::process::Stdio::piped());
        spawn_with_pipes(&mut cmd);
        let out = cmd.output().unwrap();
        let shown = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if original != libc::RLIM_INFINITY as u64 {
            assert_eq!(shown, original.to_string());
        }
    }

    #[test]
    fn udp_socket_binds_an_ephemeral_port() {
        let s = udp_any(0).unwrap();
        assert_ne!(s.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn interface_addresses_include_loopback() {
        let addresses = interface_addresses().unwrap();
        assert!(
            addresses.iter().any(|a| a.loopback && a.address.is_loopback()),
            "{addresses:?}"
        );
    }

    #[test]
    // Reaped by pid with `reap`, which is what is tested, not with Child::wait
    #[allow(clippy::zombie_processes)]
    fn a_child_is_reaped_with_its_status() {
        let child = Command::new("/bin/sh").args(["-c", "exit 7"]).spawn().unwrap();
        let exit = reap(child.id()).unwrap();
        assert_eq!((exit.code, exit.signal), (Some(7), None));
        let child = Command::new("/bin/sh").args(["-c", "kill -TERM $$"]).spawn().unwrap();
        let exit = reap(child.id()).unwrap();
        assert_eq!((exit.code, exit.signal), (None, Some(libc::SIGTERM)));
        assert!(reap(0).is_err());
    }

    #[test]
    fn descriptors_are_classified_and_inheritance_is_switched() {
        let (master, slave) = openpty(80, 24).unwrap();
        assert_eq!(fd_info(&master).unwrap().kind, FdKind::CharDevice);
        assert!(is_pty_master(&master));
        #[cfg(target_os = "linux")]
        assert!(!is_pty_master(&slave));
        let (r, _w) = pipe().unwrap();
        assert_eq!(
            fd_info(&r).unwrap(),
            FdInfo {
                kind: FdKind::Fifo,
                uid: euid()
            }
        );
        let udp = udp_any(0).unwrap();
        assert_eq!(fd_info(&udp).unwrap().kind, FdKind::Socket);
        assert_eq!(socket_type(&udp).unwrap(), libc::SOCK_DGRAM);
        let file = anonymous_file(&std::env::temp_dir()).unwrap();
        assert_eq!(
            fd_info(&file).unwrap(),
            FdInfo {
                kind: FdKind::Regular,
                uid: euid()
            }
        );
        // SAFETY: F_GETFD only reads the descriptor's flags.
        let cloexec = |fd: &OwnedFd| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0;
        assert!(cloexec(&r));
        set_inheritable(&r, true).unwrap();
        assert!(!cloexec(&r));
        set_inheritable(&r, false).unwrap();
        assert!(cloexec(&r));
        // A number that is not open is not adopted
        let number = r.as_raw_fd();
        drop(r);
        assert!(adopt_fd(number).is_none());
        drop(slave);
    }

    #[test]
    fn udp_buffers_are_raised_as_far_as_the_kernel_allows() {
        let udp = udp_any(0).unwrap();
        let (rcv, snd) = set_socket_buffers(&udp, 4 << 20).unwrap();
        assert!(rcv > 0 && snd > 0);
        // BBR may not be allowed here: either way the call is harmless
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _ = set_tcp_congestion(&tcp, "bbr");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn route_socket_opens() {
        // No root needed for either kind of socket; a sandbox may forbid them, then polling is
        // what netwatch falls back to
        match route_socket() {
            Ok(fd) => assert!(fd.as_raw_fd() >= 0),
            Err(e) => eprintln!("route socket unavailable here: {e}"),
        }
    }
}
