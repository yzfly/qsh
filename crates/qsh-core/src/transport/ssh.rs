//! The user's own `ssh`: for the bootstrap, and as the transport of last resort (the ssh
//! pipe, `ssh host qsh-server pipe`), which works wherever ssh works.

use std::ffi::OsString;
use std::io;
use std::process::Stdio;

use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// How to run ssh to one destination: the program, the options passed through from the
/// command line (`-p`, `-l`, `-i`, `-J`, `-F`, `-o`, `-4`, `-6`, `-v`) and the destination.
#[derive(Debug, Clone)]
pub struct SshCommand {
    /// The ssh program, `ssh` from `PATH` by default.
    pub program: OsString,
    /// Options for ssh, before the destination.
    pub options: Vec<OsString>,
    /// `[user@]host`, or an alias from `~/.ssh/config`.
    pub destination: String,
    /// The server program on the remote host. It is looked up in the remote `PATH`, then in
    /// `~/.local/bin` (where `qsh install` puts it).
    pub server_program: String,
}

/// The exit code of a remote shell that did not find the command.
pub const EXIT_COMMAND_NOT_FOUND: i32 = 127;

/// The exit code of a remote shell that found the command but could not execute it.
pub const EXIT_CANNOT_EXECUTE: i32 = 126;

impl SshCommand {
    /// ssh to `destination` with no extra options.
    pub fn new(destination: impl Into<String>) -> SshCommand {
        SshCommand {
            program: OsString::from("ssh"),
            options: Vec::new(),
            destination: destination.into(),
            server_program: "qsh-server".into(),
        }
    }

    /// The remote command that runs `qsh-server <subcommand>` (protocol.md 10.2): it goes
    /// through the user's login shell, whatever that is, so it is one single-quoted `sh -c`
    /// program without `!`, backslashes, newlines or inner single quotes. It looks for the
    /// server in `PATH`, then in `~/.local/bin`, and exits with 42 when there is none.
    pub fn remote_command(&self, subcommand: &str) -> String {
        let program = &self.server_program;
        // A custom program name must keep the properties above; anything odd falls back
        let program = if program
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
            && !program.is_empty()
        {
            program.as_str()
        } else {
            "qsh-server"
        };
        let local = if program.contains('/') {
            program.to_string()
        } else {
            format!("$HOME/.local/bin/{program}")
        };
        format!(
            "sh -c 'for p in \"$(command -v {program})\" \"{local}\"; do if [ -n \"$p\" ] && [ -x \"$p\" ]; then exec \"$p\" {subcommand}; fi; done; exit 42'"
        )
    }

    /// Options qsh adds to every ssh it runs (protocol.md 10.1): no pty, and none of the
    /// forwardings configured for interactive logins.
    const COMMON: [&'static str; 7] = [
        "-T",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
    ];

    fn common(cmd: &mut Command) {
        cmd.args(Self::COMMON);
    }

    /// `ssh -T … destination <remote>`, a one-off remote command (`qsh install`) as a blocking
    /// command, with the options of [`SshCommand::bootstrap`]: interactive unless `batch`. The
    /// caller sets up stdin, stdout and stderr. `remote` goes through the user's login shell,
    /// whatever it is: a single-quoted `sh -c` program with the properties of protocol.md 10.2.
    pub fn one_off(&self, remote: &str, batch: bool) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.program);
        cmd.args(Self::COMMON);
        if batch {
            cmd.args(["-o", "BatchMode=yes"]);
        }
        cmd.args(&self.options).arg("--").arg(&self.destination).arg(remote);
        cmd
    }

    /// `ssh -t … destination <remote>` with a terminal, in front of the user (`qsh doctor HOST
    /// --tune`), and without any forwarding, like every ssh qsh runs (security.md 4.6). The
    /// caller sets up stdin, stdout and stderr (inherited by default).
    pub fn with_terminal(&self, remote: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.program);
        cmd.arg("-t").args(&Self::COMMON[1..]);
        cmd.args(&self.options).arg("--").arg(&self.destination).arg(remote);
        cmd
    }

    /// `ssh -T … destination '<discovery> bootstrap'`, interactive: ssh asks for passwords and
    /// second factors on the terminal as usual (no BatchMode). stdin and stdout are pipes (the
    /// request goes on stdin, never in argv where `ps` shows it); stderr is the user's.
    pub fn bootstrap(&self, batch: bool) -> io::Result<Child> {
        let mut cmd = Command::new(&self.program);
        Self::common(&mut cmd);
        if batch {
            cmd.args(["-o", "BatchMode=yes"]);
        }
        cmd.args(&self.options);
        cmd.arg("--")
            .arg(&self.destination)
            .arg(self.remote_command("bootstrap"));
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        cmd.spawn()
    }

    /// The ssh pipe transport (protocol.md 10.5): `ssh -T -o BatchMode=yes … destination
    /// '<discovery> pipe --version 1'`. Never interactive (it runs during reconnects); without
    /// a key or agent it fails and the other transports carry the session.
    pub fn pipe(&self) -> io::Result<(Child, ChildStdout, ChildStdin)> {
        let mut cmd = Command::new(&self.program);
        Self::common(&mut cmd);
        // ssh takes the first value given for an option: BatchMode before the user's options
        cmd.args(["-o", "BatchMode=yes"]).args(&self.options);
        // ConnectTimeout: on a network that drops packets ssh would otherwise wait minutes for
        // the TCP connect while new attempts start, one ssh process each
        cmd.args([
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
        ]);
        let sub = format!("pipe --version {}", crate::proto::VERSION);
        cmd.arg("--").arg(&self.destination).arg(self.remote_command(&sub));
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("ssh without stdout"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("ssh without stdin"))?;
        Ok((child, stdout, stdin))
    }

    /// The host name ssh connects to for this destination (`ssh -G`), with the user's
    /// configuration and options applied: where the daemon's QUIC and TLS ports are.
    pub async fn resolve_host(&self) -> Option<String> {
        let output = Command::new(&self.program)
            .arg("-G")
            .args(&self.options)
            .arg("--")
            .arg(&self.destination)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("hostname ").map(|h| h.trim().to_string()))
            .filter(|h| !h.is_empty())
    }
}

/// Quote `text` for a POSIX shell: single quotes, with `'` written as `'\''`.
pub fn sh_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@%+,".contains(&b))
    {
        return text.to_string();
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("qsh-server"), "qsh-server");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn remote_command_is_the_discovery_command() {
        let ssh = SshCommand::new("host");
        let cmd = ssh.remote_command("bootstrap");
        assert_eq!(
            cmd,
            "sh -c 'for p in \"$(command -v qsh-server)\" \"$HOME/.local/bin/qsh-server\"; do if [ -n \"$p\" ] && [ -x \"$p\" ]; then exec \"$p\" bootstrap; fi; done; exit 42'"
        );
        assert!(!cmd.contains('!') && !cmd.contains('\\') && !cmd.contains('\n'));
        // Run by a local sh with an empty PATH and HOME: nothing found, 42
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(42));
    }
}
