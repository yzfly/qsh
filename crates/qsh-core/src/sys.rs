//! The operating system calls the rest of qsh needs and the standard library does not offer:
//! pseudo terminals, terminal modes, process groups, file locks and a dual-stack UDP socket.
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
            std::ptr::null(),
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
    let max = open_max();
    // SAFETY: the closure runs between fork and exec and calls only async-signal-safe
    // functions (signal, sigemptyset, sigprocmask, setsid, ioctl, fcntl) on local data,
    // allocating nothing.
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
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in 3..max {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
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

/// Make the terminal on `fd` a plain byte pipe for a program whose client is not a terminal:
/// no echo of input and no `\n` to `\r\n` translation of output. Line editing stays on, so
/// Ctrl-D still means end of input.
pub fn plain_terminal(fd: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: termios is plain old data; all zeroes is a valid value.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr fills the termios the pointer refers to, valid across the call.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    t.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::ECHOCTL);
    t.c_oflag &= !libc::ONLCR;
    // SAFETY: tcsetattr reads the termios the pointer refers to.
    if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
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

/// The terminal on stdin in raw mode (no echo, no line editing, no signals from keys) for as
/// long as this value lives; the previous mode comes back when it is dropped.
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
        // SAFETY: tcsetattr reads the termios the pointer refers to.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
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
        if let Some(original) = &self.original {
            // SAFETY: tcsetattr reads the saved termios the pointer refers to.
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, original) };
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
    fn udp_socket_binds_an_ephemeral_port() {
        let s = udp_any(0).unwrap();
        assert_ne!(s.local_addr().unwrap().port(), 0);
    }
}
