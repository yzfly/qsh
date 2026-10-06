#!/usr/bin/env python3
"""qsh end to end against a real, private, unprivileged OpenSSH sshd (scripts/local-test.sh).

No root and nothing outside one temporary directory: sshd runs as the current user on
127.0.0.1 and a free high port, with its own host key, its own authorized_keys (a fresh key)
and `SetEnv` giving every login a temporary HOME and XDG directories, so the server side of qsh
(qsh-server in ~/.local/bin, the daemon's state, its control socket) never touches the real
home. The client gets its own HOME and XDG directories and an ssh config (-F) with its own
known_hosts. Cleanup is by pid: sshd, the daemon, and any process whose environment points into
the temporary directory.

Each check appends a line `STATUS<TAB>STEP<TAB>NAME<TAB>SECONDS<TAB>DETAIL` to --results
(STATUS: PASS, FAIL, SKIP, WARN). Exits 1 when a check failed.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

STEP = "sshd"
HOST = "qshtest"
TICKER = "i=0; while :; do i=$((i+1)); echo tick-$i; sleep 0.05; done"
SHELL = "env 'PS1=QPMARK$ ' bash --norc --noprofile -i"
PROMPT = b"QPMARK$ "


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} sshd-e2e: {msg}", file=sys.stderr, flush=True)


class Results:
    def __init__(self, path):
        self.path = path
        self.failed = 0

    def add(self, status, name, seconds, detail=""):
        detail = " ".join(str(detail).split())[:400]
        if status == "FAIL":
            self.failed += 1
        log(f"{status} {name} ({seconds:.1f} s) {detail}")
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(f"{status}\t{STEP}\t{name}\t{seconds:.1f}\t{detail}\n")


class Check(Exception):
    """A failed check: the scenario stops with this message."""


def need(cond, msg):
    if not cond:
        raise Check(msg)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)


def port_free(port):
    """Free on TCP and UDP, IPv4 and IPv6 wildcard: where the daemon binds."""
    socks = []
    try:
        for family, kind, addr in (
            (socket.AF_INET, socket.SOCK_STREAM, "0.0.0.0"),
            (socket.AF_INET, socket.SOCK_DGRAM, "0.0.0.0"),
            (socket.AF_INET6, socket.SOCK_STREAM, "::"),
            (socket.AF_INET6, socket.SOCK_DGRAM, "::"),
        ):
            s = socket.socket(family, kind)
            socks.append(s)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((addr, port))
        return True
    except OSError:
        return False
    finally:
        for s in socks:
            s.close()


def free_port(avoid=()):
    for _ in range(200):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port not in avoid and port > 20000 and port_free(port):
            return port
    raise RuntimeError("no free port")


# ---------------------------------------------------------------------------------------------
# A program on a pseudo terminal (its controlling terminal), read by a thread


class Term:
    def __init__(self, argv, env, cwd, log_path, rows=30, cols=100):
        self.master, slave = os.openpty()
        self.resize(rows, cols)
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.eof = False
        stderr = open(log_path, "ab")  # qsh's own messages go to stderr: keep them apart

        def ctty():
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=stderr,
            env=env,
            cwd=cwd,
            start_new_session=True,
            preexec_fn=ctty,  # noqa: PLW1509 (no threads of ours touch the child's state)
        )
        os.close(slave)
        stderr.close()
        self.log_path = log_path
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                data = b""
            if not data:
                with self.lock:
                    self.eof = True
                return
            with self.lock:
                self.buf.extend(data)

    def resize(self, rows, cols):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def pos(self):
        with self.lock:
            return len(self.buf)

    def text(self, start=0):
        with self.lock:
            return bytes(self.buf[start:])

    def send(self, data, pause=0.0):
        os.write(self.master, data)
        if pause:
            time.sleep(pause)

    def expect(self, pattern, start=0, timeout=30.0):
        """Wait for regex `pattern` (bytes) at or after offset `start`; the match or None."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                m = rx.search(bytes(self.buf), start)
                eof = self.eof
            if m:
                return m
            if eof or time.monotonic() > deadline:
                return None
            time.sleep(0.02)

    def wait(self, timeout):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stderr_text(self):
        try:
            with open(self.log_path, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        try:
            os.close(self.master)
        except OSError:
            pass


def ticks(data):
    return [int(m) for m in re.findall(rb"tick-(\d+)\r", data)]


def contiguous(seq):
    return bool(seq) and seq == list(range(seq[0], seq[0] + len(seq)))


# ---------------------------------------------------------------------------------------------
# The world: binaries, sshd, client and server directories


class World:
    def __init__(self, root, qsh, server, keep, copy=True, trust_root=False):
        self.root = root
        self.keep = keep
        self.trust_root = trust_root
        self.sshd = None
        self.started = time.time()
        for d in (
            "bin",
            "data",
            "logs",
            "sshd",
            "ssh",
            "cli/home",
            "cli/run",
            "cli/state",
            "cli/config/qsh",
            "srv/home",
            "srv/run",
            "srv/state",
            "srv/config",
        ):
            os.makedirs(os.path.join(root, d), mode=0o700, exist_ok=True)
        for d in ("cli/run", "srv/run"):
            os.chmod(os.path.join(root, d), 0o700)
        # Copies (unless the caller made them): another build replacing target/debug/* under a
        # running test changes nothing
        self.qsh = os.path.join(root, "bin/qsh")
        self.server = os.path.join(root, "bin/qsh-server")
        if copy:
            shutil.copyfile(qsh, self.qsh)
            shutil.copyfile(server, self.server)
            os.chmod(self.qsh, 0o755)
            os.chmod(self.server, 0o755)
        else:
            self.qsh, self.server = os.path.abspath(qsh), os.path.abspath(server)
        self.ssh_port = free_port()
        self.daemon_port = free_port(avoid=(self.ssh_port,))
        self.srv_home = os.path.join(root, "srv/home")
        self.installed = os.path.join(self.srv_home, ".local/bin/qsh-server")
        self.ssh_config = os.path.join(root, "ssh/config")
        self._shell_files()

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def _shell_files(self):
        # The login shell (whatever the user's is) gets a known prompt, and no first-run wizard
        for name in (".zshrc", ".bashrc", ".bash_profile", ".profile"):
            with open(os.path.join(self.srv_home, name), "w") as f:
                f.write("PS1='QLOGIN> '\nPROMPT='QLOGIN> '\n")

    def server_env_words(self):
        return {
            "HOME": self.srv_home,
            "XDG_RUNTIME_DIR": self.p("srv/run"),
            "XDG_STATE_HOME": self.p("srv/state"),
            "XDG_CONFIG_HOME": self.p("srv/config"),
            "QSH_SERVER_PORTS": f"{self.daemon_port}-{self.daemon_port}",
            # Test hook: the daemon upgrade checks no directory above the run's (--trust-root)
            **({"QSH_TEST_TRUSTED_DIR": self.root} if self.trust_root else {}),
        }

    def server_env(self, extra=None):
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "QSHL_ROOT": self.root}
        env.update(self.server_env_words())
        env.update(extra or {})
        return env

    def client_env(self, extra=None):
        env = {
            "HOME": self.p("cli/home"),
            "XDG_RUNTIME_DIR": self.p("cli/run"),
            "XDG_STATE_HOME": self.p("cli/state"),
            "XDG_CONFIG_HOME": self.p("cli/config"),
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "QSHL_ROOT": self.root,
        }
        env.update(extra or {})
        return env

    def start_sshd(self):
        sshd_dir = self.p("sshd")
        ssh_dir = self.p("ssh")
        user = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        for path, comment in ((f"{sshd_dir}/host_ed25519", "qshl-host"), (f"{ssh_dir}/id_ed25519", "qshl")):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path], check=True)
        shutil.copyfile(f"{ssh_dir}/id_ed25519.pub", f"{sshd_dir}/authorized_keys")
        os.chmod(f"{sshd_dir}/authorized_keys", 0o600)
        setenv = " ".join(f"{k}={v}" for k, v in self.server_env_words().items())
        with open(f"{sshd_dir}/sshd_config", "w") as f:
            f.write(
                f"""Port {self.ssh_port}
ListenAddress 127.0.0.1
HostKey {sshd_dir}/host_ed25519
PidFile {sshd_dir}/sshd.pid
AuthorizedKeysFile {sshd_dir}/authorized_keys
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers {user}
PermitUserRC no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
AcceptEnv LANG LC_* QSH_TEST_*
SetEnv {setenv}
PrintMotd no
PrintLastLog no
MaxStartups 100
MaxSessions 100
LogLevel VERBOSE
"""
            )
        host_pub = open(f"{sshd_dir}/host_ed25519.pub").read().split()
        with open(f"{ssh_dir}/known_hosts", "w") as f:
            f.write(f"[127.0.0.1]:{self.ssh_port} {host_pub[0]} {host_pub[1]}\n")
        with open(self.ssh_config, "w") as f:
            f.write(
                f"""Host {HOST}
  HostName 127.0.0.1
  Port {self.ssh_port}
  User {user}
  IdentityFile {ssh_dir}/id_ed25519
  IdentitiesOnly yes
  IdentityAgent none
  BatchMode yes
  StrictHostKeyChecking yes
  UserKnownHostsFile {ssh_dir}/known_hosts
  GlobalKnownHostsFile /dev/null
  ControlMaster no
  ControlPath none
  LogLevel ERROR
  ConnectTimeout 20
"""
            )
        os.chmod(self.ssh_config, 0o600)
        # -D: in the foreground, so its pid is the one we kill
        self.sshd = subprocess.Popen(
            ["/usr/sbin/sshd", "-D", "-f", f"{sshd_dir}/sshd_config", "-E", f"{sshd_dir}/sshd.log"],
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "QSHL_ROOT": self.root},
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.sshd.poll() is not None:
                break
            r = self.ssh(["true"], timeout=20)
            if r.returncode == 0:
                return
            time.sleep(0.3)
        raise RuntimeError("private sshd does not answer: " + self.tail(f"{sshd_dir}/sshd.log"))

    def ssh(self, remote, timeout=60, stdin=subprocess.DEVNULL):
        return subprocess.run(
            ["ssh", "-F", self.ssh_config, HOST, *remote],
            stdin=stdin,
            capture_output=True,
            env=self.client_env(),
            timeout=timeout,
        )

    def qsh_argv(self, args, ssh_opts=()):
        return [self.qsh, "-F", self.ssh_config, *ssh_opts, *args]

    def qsh_run(self, args, stdin=subprocess.DEVNULL, timeout=120, env=None, ssh_opts=(), input_bytes=None):
        """Run qsh without a terminal: (code, stdout, stderr); code None after the timeout."""
        try:
            r = subprocess.run(
                self.qsh_argv(args, ssh_opts),
                stdin=None if input_bytes is not None else stdin,
                input=input_bytes,
                capture_output=True,
                env=self.client_env(env),
                cwd=self.p("cli/home"),
                timeout=timeout,
            )
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            return None, e.stdout or b"", e.stderr or b""

    def term(self, args, name, env=None, ssh_opts=()):
        return Term(self.qsh_argv(args, ssh_opts), self.client_env(env), self.p("cli/home"), self.p("logs", name + ".log"))

    def server_cmd(self, args, extra=None, timeout=30):
        r = subprocess.run(
            [self.server, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=self.server_env(extra),
            timeout=timeout,
        )
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")

    def status(self, as_version=None):
        extra = {"QSH_TEST_VERSION": as_version} if as_version else None
        code, out, _ = self.server_cmd(["status"], extra)
        if code != 0:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return None

    def stop_daemon(self):
        st = self.status()
        self.server_cmd(["stop"])
        pid = st and st.get("pid")
        if pid:
            deadline = time.monotonic() + 10
            while alive(pid) and time.monotonic() < deadline:
                time.sleep(0.1)
            if alive(pid) and is_ours(pid, self.root):
                os.kill(pid, signal.SIGKILL)

    def random_file(self, mib):
        path = self.p("data", f"random-{mib}M")
        if not os.path.exists(path):
            with open("/dev/urandom", "rb") as src, open(path, "wb") as dst:
                for _ in range(mib):
                    dst.write(src.read(1 << 20))
        return path

    @staticmethod
    def tail(path, n=2000):
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - n))
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def daemon_log(self):
        return self.tail(self.p("srv/state/qsh/daemon.log"))

    def cleanup(self):
        try:
            self.stop_daemon()
        except Exception as e:  # noqa: BLE001 (cleanup goes on)
            log(f"cleanup: stopping the daemon: {e}")
        if self.sshd and self.sshd.poll() is None:
            self.sshd.terminate()
            try:
                self.sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.sshd.kill()
                self.sshd.wait()
        left = sweep(self.root)
        if left:
            log(f"cleanup: killed {len(left)} leftover process(es) of this run: {left}")
        return left


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def is_ours(pid, root):
    """Is `pid` a process of this run: one of our user's whose environment points into `root`?"""
    try:
        if os.stat(f"/proc/{pid}").st_uid != os.getuid():
            return False
        with open(f"/proc/{pid}/environ", "rb") as f:
            env = f.read().split(b"\0")
    except OSError:
        return False
    needle = root.encode()
    return any(b"=" in e and e.split(b"=", 1)[1].startswith(needle) for e in env)


def sweep(root):
    """Kill every process of this run that is still there (by pid; never by name)."""
    me = os.getpid()
    ancestors = set()
    pid = me
    while pid > 1:
        ancestors.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    killed = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in ancestors or not is_ours(pid, root):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except OSError:
            pass
    return killed


# ---------------------------------------------------------------------------------------------
# Scenarios


class Suite:
    def __init__(self, world, results, args):
        self.w = world
        self.r = results
        self.a = args

    def run(self, name, fn):
        start = time.monotonic()
        try:
            out = fn()
            status, detail = out if isinstance(out, tuple) else ("PASS", out or "")
        except Check as e:
            status, detail = "FAIL", str(e)
        except Exception as e:  # noqa: BLE001 (a crashed scenario is a failed check)
            status, detail = "FAIL", f"{type(e).__name__}: {e}"
        self.r.add(status, name, time.monotonic() - start, detail)
        return status

    # -- discovery and install

    def no_server(self):
        found = self.w.ssh(["command -v qsh-server || true"]).stdout.decode().strip()
        if found:
            return "SKIP", f"a qsh-server is in the remote PATH ({found}); 42 not testable"
        code, _, err = self.w.qsh_run([HOST, "--", "true"])
        need(code == 42, f"exit {code}, want 42 (no qsh-server): {err[-300:]!r}")
        return "exit 42 and an install hint" if b"install" in err else "exit 42"

    def server_command(self):
        cfg = self.w.p("cli/config/qsh/config")
        with open(cfg, "w") as f:
            f.write(f'[defaults]\nserver_command = "{self.w.server}"\n')
        os.chmod(cfg, 0o600)
        try:
            code, out, err = self.w.qsh_run([HOST, "--", "echo via-server-command"])
            need(code == 0 and out == b"via-server-command\n", f"exit {code} out {out!r} err {err[-300:]!r}")
        finally:
            os.unlink(cfg)
            self.w.stop_daemon()
        return "server_command reaches a qsh-server outside PATH and ~/.local/bin"

    def install(self):
        os.makedirs(os.path.dirname(self.w.installed), exist_ok=True)
        if not self.a.self_install:
            shutil.copyfile(self.w.server, self.w.installed)
            os.chmod(self.w.installed, 0o755)
            return "SKIP", "built without self-install; copied qsh-server by hand"
        code, out, err = self.w.qsh_run(["install", HOST, "--from", self.w.server], timeout=300)
        ok = code == 0 and os.path.exists(self.w.installed)
        if not ok:
            # The other scenarios still need a server
            shutil.copyfile(self.w.server, self.w.installed)
            os.chmod(self.w.installed, 0o755)
            raise Check(f"qsh install exit {code}: {out[-200:]!r} {err[-300:]!r}")
        need(sha256_file(self.w.installed) == sha256_file(self.w.server), "installed file differs")
        mode = os.stat(self.w.installed).st_mode & 0o777
        need(mode & 0o022 == 0, f"installed mode {mode:o} is writable by others")
        code, out, err = self.w.qsh_run([HOST, "--", "echo installed-ok"])
        need(code == 0 and out == b"installed-ok\n", f"after install: exit {code} {out!r} {err[-300:]!r}")
        return f"into the test HOME's ~/.local/bin (mode {mode:o}), then found by discovery"

    # -- command mode

    def exit_codes(self):
        cases = [("true", 0), ("exit 7", 7), ("kill -TERM $$", 143), ("qshl-no-such-command-xyz", 127)]
        got = []
        for cmd, want in cases:
            code, _, err = self.w.qsh_run([HOST, "--", cmd])
            got.append(f"{cmd!r}={code}")
            need(code == want, f"{cmd!r}: exit {code}, want {want}: {err[-300:]!r}")
        return ", ".join(got)

    def stdio_exact(self):
        code, out, err = self.w.qsh_run([HOST, "--", r"printf 'o\000ut\377\n'; printf 'e\000rr\376' >&2; exit 3"])
        need(code == 3, f"exit {code}, want 3")
        need(out == b"o\x00ut\xff\n", f"stdout {out!r}")
        need(err == b"e\x00rr\xfe", f"stderr {err!r} (qsh's own messages must not mix in)")
        blob = os.urandom(1 << 20)
        code, out, err = self.w.qsh_run([HOST, "--", "cat"], input_bytes=blob)
        need(code == 0 and out == blob, f"1 MiB stdin->stdout: exit {code}, {len(out)} bytes, equal {out == blob}")
        code, out, err = self.w.qsh_run([HOST, "--", "cat >&2"], input_bytes=blob)
        need(code == 0 and err == blob and out == b"", f"stdin->stderr: exit {code}, {len(err)} bytes on stderr")
        code, out, err = self.w.qsh_run([HOST, "--", "cat"])
        need(code == 0 and out == b"", f"empty stdin: exit {code}, {out!r}")
        # The program ends while stdin keeps coming: qsh ends too
        yes = subprocess.Popen(["yes"], stdout=subprocess.PIPE)
        try:
            code, out, err = self.w.qsh_run([HOST, "--", "head -c 100000"], stdin=yes.stdout, timeout=60)
        finally:
            yes.kill()
            yes.wait()
        need(code == 0 and len(out) == 100000, f"`yes | qsh host head -c 100000`: exit {code}, {len(out)} bytes")
        # A big stdout with no stdin
        path = self.w.random_file(20)
        code, out, err = self.w.qsh_run([HOST, "--", f"cat {path}"], timeout=300)
        need(code == 0 and hashlib.sha256(out).hexdigest() == sha256_file(path), f"20 MiB stdout: exit {code}")
        return "exit status, binary stdout/stderr apart, stdin->stdout/stderr, EOF, early exit, 20 MiB out"

    def pipe(self, mib, runs, transports=None, label=None):
        """`qsh host -- cat` with `mib` MiB in and out, `runs` times; a stall (no output for
        --stall seconds) or a run over --pipe-timeout fails."""
        path = self.w.random_file(mib)
        want = sha256_file(path)
        size = os.path.getsize(path)
        env = {"QSH_TRANSPORTS": transports} if transports else None
        times, bad = [], []
        for i in range(runs):
            ok, secs, detail = self.pipe_once(path, size, want, env, f"{label or 'pipe'}-{i}")
            times.append(secs)
            if not ok:
                bad.append(f"run {i + 1}: {detail}")
                log(f"pipe {label}: run {i + 1}/{runs} FAILED: {detail}")
                if len(bad) >= 3 and self.a.pipe_stop_early:
                    break
            else:
                log(f"pipe {label}: run {i + 1}/{runs} ok in {secs:.1f} s")
        done = len(times)
        rate = 2 * mib / statistics.median(times) if times else 0
        summary = (
            f"{done - len(bad)}/{runs} exact ({mib} MiB each way); median {statistics.median(times):.1f} s, "
            f"max {max(times):.1f} s, ~{rate:.0f} MiB/s both ways"
        )
        if bad:
            raise Check(summary + "; " + "; ".join(bad[:3]))
        return summary

    def pipe_once(self, path, size, want, env, name):
        logf = self.w.p("logs", name + ".log")
        start = time.monotonic()
        with open(path, "rb") as src, open(logf, "wb") as err:
            p = subprocess.Popen(
                self.w.qsh_argv([HOST, "--", "cat"]),
                stdin=src,
                stdout=subprocess.PIPE,
                stderr=err,
                env=self.w.client_env(env),
                cwd=self.w.p("cli/home"),
            )
            h = hashlib.sha256()
            n = 0
            last = time.monotonic()
            fd = p.stdout.fileno()
            why = None
            while True:
                ready, _, _ = select.select([fd], [], [], 1.0)
                now = time.monotonic()
                if ready:
                    data = os.read(fd, 1 << 20)
                    if not data:
                        break
                    h.update(data)
                    n += len(data)
                    last = now
                if now - last > self.a.stall:
                    why = f"stalled: no output for {self.a.stall:.0f} s at {n}/{size} bytes"
                    break
                if now - start > self.a.pipe_timeout:
                    why = f"over {self.a.pipe_timeout:.0f} s at {n}/{size} bytes"
                    break
            if why:
                p.kill()
            try:
                code = p.wait(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
                code = p.wait()
                why = why or f"no exit 60 s after EOF ({n} bytes)"
            p.stdout.close()
        secs = time.monotonic() - start
        if why:
            return False, secs, why + f"; stderr {self.w.tail(logf, 200)!r}"
        if code != 0:
            return False, secs, f"exit {code}, {n} bytes; stderr {self.w.tail(logf, 200)!r}"
        if n != size or h.hexdigest() != want:
            return False, secs, f"output differs: {n}/{size} bytes"
        return True, secs, ""

    def transport(self, name):
        t = self.w.p("cli", f"transcript-{name}.jsonl")
        env = {"QSH_TRANSPORTS": name, "QSH_TRANSCRIPT": t}
        blob = os.urandom(5 << 20)
        start = time.monotonic()
        code, out, err = self.w.qsh_run([HOST, "--", "cat; exit 5"], input_bytes=blob, env=env, timeout=300)
        secs = time.monotonic() - start
        need(code == 5, f"exit {code}, want 5: {err[-300:]!r}")
        need(out == blob, f"5 MiB not exact: {len(out)} bytes")
        connected = []
        try:
            for line in open(t, encoding="utf-8"):
                rec = json.loads(line)
                if rec.get("ev") == "connected":
                    connected.append(str(rec.get("transport", "?")).lower())
        except OSError:
            pass
        need(connected and all(c == name for c in connected), f"connected over {connected}, want only {name}")
        return f"5 MiB exact, exit 5, over {connected[0]} ({secs:.1f} s)"

    # -- terminal sessions

    def tty(self):
        term = self.w.term([HOST, "--", SHELL], "tty")
        try:
            need(term.expect(re.escape(PROMPT), 0, 60), f"no prompt: {term.text()[-300:]!r} {term.stderr_text()[-300:]!r}")
            pos = term.pos()
            term.send(b"echo $((6*7)); tty; stty size\r")
            # (bash may wrap its output in bracketed-paste switches)
            m = term.expect(rb"42\r\n(/dev/pts/\d+)\r\n30 100\r\n", pos, 20)
            need(m, f"echo/tty/stty: {term.text(pos)[-300:]!r}")
            # A window change reaches the remote terminal
            term.resize(40, 120)
            os.killpg(term.proc.pid, signal.SIGWINCH)
            time.sleep(1)
            pos = term.pos()
            term.send(b"stty size\r")
            need(term.expect(rb"40 120\r\n", pos, 20), f"after resize: {term.text(pos)[-200:]!r}")
            # Ctrl-C interrupts the remote program, not qsh
            pos = term.pos()
            term.send(b"sleep 100\r", 0.5)
            term.send(b"\x03")
            need(term.expect(re.escape(PROMPT), pos + 1, 20), "Ctrl-C did not bring the prompt back")
            term.send(b"exit 3\r")
            code = term.wait(30)
            need(code == 3, f"exit {code}, want 3")
        finally:
            term.close()
        return "prompt, tty, size, SIGWINCH resize, Ctrl-C, exit status 3"

    def login_shell(self):
        term = self.w.term([HOST], "login")
        try:
            need(term.expect(rb"QLOGIN> ", 0, 60), f"no login prompt: {term.text()[-400:]!r} {term.stderr_text()[-300:]!r}")
            pos = term.pos()
            term.send(b'echo "H=$HOME"\r')
            want = f"H={self.w.srv_home}".encode()
            need(term.expect(re.escape(want), pos, 20), f"HOME of the session: {term.text(pos)[-300:]!r}")
            term.send(b"exit\r")
            code = term.wait(30)
            need(code == 0, f"exit {code}")
        finally:
            term.close()
        return "login shell with the test HOME, exit 0"

    def detach_attach(self):
        # Start from no session (an earlier scenario that failed may have left one)
        self.w.qsh_run(["kill", HOST, "--all"])
        term = self.w.term([HOST, "--", TICKER], "detach")
        try:
            need(term.expect(rb"tick-12\r", 0, 60), f"no ticks: {term.text()[-300:]!r} {term.stderr_text()[-300:]!r}")
            term.send(b"\r~d")
            code = term.wait(20)
            need(code == 0, f"~d: exit {code}: {term.stderr_text()[-300:]!r}")
            need(b"detached" in term.text() + term.stderr_text().encode(), "no 'detached' message")
            seen = ticks(term.text())
        finally:
            term.close()
        code, out, _ = self.w.qsh_run(["ls", "--json"])
        need(code == 0, f"qsh ls --json: exit {code}")
        local = json.loads(out)["sessions"]
        need(len(local) == 1, f"saved sessions: {local}")
        code, out, err = self.w.qsh_run(["ls", "--json", HOST])
        need(code == 0, f"qsh ls --json {HOST}: exit {code} {err[-200:]!r}")
        remote = json.loads(out)["sessions"]
        need(len(remote) == 1 and remote[0].get("attached") is False, f"remote sessions: {remote}")
        sid = remote[0]["session"]
        time.sleep(1)
        term = self.w.term(["attach", HOST], "attach")
        try:
            target = (seen[-1] if seen else 0) + 30
            need(term.expect(f"tick-{target}\r".encode(), 0, 60), f"attach: {term.stderr_text()[-300:]!r}")
            got = ticks(term.text())
            need(got[0] == 1 and contiguous(got), f"replayed ticks not 1..N: first {got[:3]} ({len(got)})")
            # The client dies (SIGKILL): attach again, nothing lost
            term.proc.kill()
            term.wait(5)
        finally:
            term.close()
        time.sleep(2)
        term = self.w.term(["attach", HOST], "attach2")
        try:
            need(term.expect(rb"tick-\d+\r", 0, 60), f"attach after SIGKILL: {term.stderr_text()[-300:]!r}")
            time.sleep(2)
            got = ticks(term.text())
            need(contiguous(got) and got[0] == 1, f"after SIGKILL: ticks not 1..N ({got[:3]}..{got[-3:]})")
            term.send(b"\r~d")
            need(term.wait(20) == 0, "second ~d")
        finally:
            term.close()
        # A second session, then kill one by id prefix and the rest with --all
        t2 = self.w.term([HOST, "--", "sleep 300"], "second")
        try:
            time.sleep(3)
            t2.send(b"\r~d")
            need(t2.wait(20) == 0, "~d of the second session")
        finally:
            t2.close()
        code, out, err = self.w.qsh_run(["ls", "--json", HOST])
        ids = [s["session"] for s in json.loads(out)["sessions"]]
        need(len(ids) == 2 and sid in ids, f"two sessions expected: {ids}")
        code, out, err = self.w.qsh_run(["kill", HOST, sid[:8]])
        need(code == 0 and f"ended session {sid[:8]}".encode() in out, f"qsh kill: exit {code} {out!r} {err[-200:]!r}")
        code, out, _ = self.w.qsh_run(["ls", "--json", HOST])
        left = [s["session"] for s in json.loads(out)["sessions"]]
        need(sid not in left and len(left) == 1, f"after kill: {left}")
        code, out, err = self.w.qsh_run(["kill", HOST, "--all"])
        need(code == 0, f"qsh kill --all: exit {code} {err[-200:]!r}")
        code, out, _ = self.w.qsh_run(["ls", "--json", HOST])
        need(json.loads(out)["sessions"] == [], f"after kill --all: {out!r}")
        code, out, _ = self.w.qsh_run(["ls", "--json"])
        need(json.loads(out)["sessions"] == [], f"saved sessions after kill --all: {out!r}")
        return "~d, ls (local and remote), attach replays 1..N, attach after SIGKILL, kill by prefix, kill --all"

    # -- the daemon

    def upgrade(self):
        if not self.a.test_hooks:
            return "SKIP", "needs a --features test-hooks build"
        self.w.stop_daemon()
        old = "0.0.1"
        as_old = ("-o", f"SetEnv=QSH_TEST_VERSION={old}")
        term = self.w.term([HOST, "--", TICKER], "upgrade", ssh_opts=as_old)
        pipe = None
        try:
            need(term.expect(rb"tick-5\r", 0, 60), f"no ticks: {term.stderr_text()[-300:]!r}")
            plog = open(self.w.p("logs/upgrade-pipe.log"), "wb")
            pipe = subprocess.Popen(
                self.w.qsh_argv([HOST, "--", "sleep 8; exit 7"], as_old),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=plog,
                env=self.w.client_env(),
                cwd=self.w.p("cli/home"),
            )
            plog.close()
            time.sleep(2)
            before = self.w.status(as_version=old)
            need(before and before.get("version") == old, f"daemon before: {before}")
            # A bootstrap of the newer program upgrades the older daemon in place
            upgraded_at = time.monotonic()
            code, _, err = self.w.qsh_run([HOST, "--", "true"])
            need(code == 0, f"bootstrap after the upgrade: exit {code} {err[-300:]!r}")
            try:
                pcode = pipe.wait(timeout=60)
            except subprocess.TimeoutExpired:
                pcode = None
            need(pcode == 7, f"the pipe session across the upgrade: exit {pcode}")
            pos = term.pos()
            need(term.expect(rb"tick-\d+\r", pos, 30), "no output after the upgrade")
            time.sleep(2)
            after = self.w.status()
            need(after and after.get("pid") == before.get("pid"), f"pid {before.get('pid')} -> {after and after.get('pid')}")
            need(after.get("version") != old, f"version after: {after.get('version')}")
            got = ticks(term.text())
            need(contiguous(got), f"ticks lost or repeated across the upgrade ({len(got)} ticks)")
            # `qsh-server upgrade --force`: in place again
            code, out, err = self.w.server_cmd(["upgrade", "--force"], timeout=60)
            need(code == 0 and "upgraded in place" in out, f"upgrade --force: {code} {out!r} {err!r}")
            again = self.w.status()
            need(again and again.get("pid") == before.get("pid"), f"pid after --force: {again}")
            pos = term.pos()
            need(term.expect(rb"tick-\d+\r", pos, 30), "no output after upgrade --force")
            time.sleep(1)
            got = ticks(term.text())
            need(contiguous(got), "ticks lost or repeated across upgrade --force")
            detail = (
                f"pid {before['pid']} kept, {old} -> {after.get('version')}, pipe exit 7, "
                f"{len(got)} ticks contiguous ({time.monotonic() - upgraded_at:.1f} s)"
            )
        finally:
            if pipe and pipe.poll() is None:
                pipe.kill()
                pipe.wait()
            term.close()
        return detail

    def server_stop(self):
        term = self.w.term([HOST, "--", TICKER], "stop")
        try:
            need(term.expect(rb"tick-3\r", 0, 60), "no session")
            st = self.w.status()
            need(st and st.get("pid"), f"no daemon: {st}")
            code, out, err = self.w.server_cmd(["stop"])
            need(code == 0, f"qsh-server stop: exit {code} {err!r}")
            deadline = time.monotonic() + 10
            while alive(st["pid"]) and time.monotonic() < deadline:
                time.sleep(0.1)
            need(not alive(st["pid"]), "the daemon still runs 10 s after stop")
            code, _, _ = self.w.server_cmd(["status"])
            need(code == 3, f"status after stop: exit {code}, want 3")
            ccode = term.wait(60)
            need(ccode is not None, "the client still runs 60 s after its session ended")
        finally:
            term.close()
        return f"daemon gone, status exit 3, the client ended with exit {ccode}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--qsh", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--results", help="append result lines here")
    ap.add_argument("--tmp", default="/tmp", help="parent of the run's directory (keep it short: unix sockets)")
    ap.add_argument("--keep", action="store_true", help="keep the run's directory")
    ap.add_argument("--no-copy", action="store_true", help="use the binaries where they are (the caller copied them)")
    ap.add_argument("--pipe-mib", type=int, default=50)
    ap.add_argument("--pipe-runs", type=int, default=20)
    ap.add_argument("--pipe-runs-other", type=int, default=2, help="runs over tls and ssh each")
    ap.add_argument("--pipe-timeout", type=float, default=300.0)
    ap.add_argument("--stall", type=float, default=30.0, help="seconds without output that count as a stall")
    ap.add_argument("--pipe-stop-early", action="store_true", help="stop the pipe runs after 3 failures")
    ap.add_argument("--self-install", action="store_true", help="the build has the self-install feature")
    ap.add_argument("--test-hooks", action="store_true", help="the build has the test-hooks feature")
    ap.add_argument(
        "--trust-root",
        action="store_true",
        help="the run's directory is below one others can write (/tmp): tell the daemons not to check "
        "the directories above it for an upgrade (test hook QSH_TEST_TRUSTED_DIR, needs --test-hooks)",
    )
    ap.add_argument("--only", default="", help="comma-separated scenario names")
    a = ap.parse_args()

    results = Results(a.results)
    root = tempfile.mkdtemp(prefix="qshl-", dir=a.tmp)
    os.chmod(root, 0o700)
    log(f"directory {root}")
    world = World(root, a.qsh, a.server, a.keep, copy=not a.no_copy, trust_root=a.trust_root)

    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)
    interrupted = False
    try:
        start = time.monotonic()
        try:
            world.start_sshd()
        except Exception as e:  # noqa: BLE001
            results.add("FAIL", "private sshd", time.monotonic() - start, str(e))
            return 1
        ver = subprocess.run(["ssh", "-V"], capture_output=True, text=True).stderr.strip()
        where = f"127.0.0.1:{world.ssh_port} as {os.environ.get('USER')}"
        results.add("PASS", "private sshd", time.monotonic() - start, f"{where}, {ver}")
        s = Suite(world, results, a)
        pipe_label = f"pipe {a.pipe_mib} MiB x{a.pipe_runs}"
        scenarios = [
            ("no qsh-server: exit 42", s.no_server),
            ("server_command", s.server_command),
            ("qsh install --from", s.install),
            ("exit codes", s.exit_codes),
            ("stdio exactness", s.stdio_exact),
            (pipe_label, lambda: s.pipe(a.pipe_mib, a.pipe_runs, label="default")),
            ("transport quic", lambda: s.transport("quic")),
            ("transport tls", lambda: s.transport("tls")),
            ("transport ssh", lambda: s.transport("ssh")),
            (f"pipe {a.pipe_mib} MiB tls x{a.pipe_runs_other}", lambda: s.pipe(a.pipe_mib, a.pipe_runs_other, "tls", "tls")),
            (f"pipe {a.pipe_mib} MiB ssh x{a.pipe_runs_other}", lambda: s.pipe(a.pipe_mib, a.pipe_runs_other, "ssh", "ssh")),
            ("tty session", s.tty),
            ("login shell", s.login_shell),
            ("detach/attach/ls/kill", s.detach_attach),
            ("daemon upgrade in place", s.upgrade),
            ("qsh-server stop", s.server_stop),
        ]
        only = [o.strip() for o in a.only.split(",") if o.strip()]
        for name, fn in scenarios:
            # The first three set the host up: always
            setup = fn in (s.no_server, s.server_command, s.install)
            if only and not setup and not any(o in name for o in only):
                continue
            if a.pipe_runs_other == 0 and name.startswith("pipe") and ("tls" in name or "ssh" in name):
                continue
            status = s.run(name, fn)
            if status == "FAIL":
                dl = world.daemon_log()
                if dl:
                    log("daemon log tail:\n" + dl[-1500:])
    except KeyboardInterrupt as e:
        interrupted = True
        results.add("FAIL", "interrupted", 0, str(e))
    finally:
        start = time.monotonic()
        left = world.cleanup()
        results.add(
            "PASS" if not interrupted else "WARN",
            "cleanup",
            time.monotonic() - start,
            f"sshd and daemon stopped by pid; {len(left)} leftover process(es) killed",
        )
        if a.keep or results.failed:
            log(f"kept {root} (logs in {root}/logs, sshd log in {root}/sshd)")
            # Drop the big data files, keep the logs
            shutil.rmtree(world.p("data"), ignore_errors=True)
            shutil.rmtree(world.p("bin"), ignore_errors=True)
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 1 if results.failed else 0


if __name__ == "__main__":
    sys.exit(main())
