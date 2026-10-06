//! The command lines of `qsh` and `qsh-server`, as clap definitions shared by the binaries and
//! by `cargo xtask gen` (man pages and shell completions).

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

const QSH_AFTER: &str = "\
Escapes (after Enter): ~. end the session, ~d detach, ~s status, ~? help, ~~ a literal ~.

Exit status: the remote program's status (128 + N when it was killed by signal N); 255 when
qsh or ssh failed; 42 when the host has no qsh-server.";

/// qsh: a remote shell over QUIC. If you can `ssh host`, you can `qsh host`, and it never
/// drops.
#[derive(Debug, Parser)]
#[command(
    name = "qsh",
    version,
    about = "Remote shell over QUIC: sessions survive network changes, sleep and roaming",
    long_about = "qsh starts a session on HOST through your own ssh (keys, agent, ~/.ssh/config, \
                  passwords and second factors all work), then keeps it alive over QUIC, TLS or \
                  an ssh pipe, whichever works, reconnecting and replaying missed output as the \
                  network comes and goes.",
    after_help = QSH_AFTER
)]
pub struct QshArgs {
    /// Port of the ssh server (ssh -p)
    #[arg(short = 'p', value_name = "PORT")]
    pub port: Option<String>,
    /// User to log in as (ssh -l)
    #[arg(short = 'l', value_name = "USER")]
    pub login: Option<String>,
    /// Identity file (ssh -i); may be repeated
    #[arg(short = 'i', value_name = "FILE", action = ArgAction::Append)]
    pub identity: Vec<PathBuf>,
    /// Jump hosts (ssh -J)
    #[arg(short = 'J', value_name = "DESTINATION")]
    pub jump: Option<String>,
    /// ssh configuration file (ssh -F)
    #[arg(short = 'F', value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// ssh option (ssh -o); may be repeated
    #[arg(short = 'o', value_name = "OPTION", action = ArgAction::Append)]
    pub options: Vec<String>,
    /// Use IPv4 addresses only (ssh -4)
    #[arg(short = '4')]
    pub ipv4: bool,
    /// Use IPv6 addresses only (ssh -6)
    #[arg(short = '6')]
    pub ipv6: bool,
    /// Verbose: qsh's own messages, and ssh -v; may be repeated
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,
    /// [user@]host, or a host alias from ~/.ssh/config
    #[arg(value_name = "DESTINATION")]
    pub destination: String,
    /// Command to run instead of a login shell
    #[arg(value_name = "COMMAND", trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl QshArgs {
    /// The ssh options these arguments stand for, in ssh's syntax.
    pub fn ssh_options(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = &self.port {
            out.extend(["-p".to_string(), p.clone()]);
        }
        if let Some(l) = &self.login {
            out.extend(["-l".to_string(), l.clone()]);
        }
        for i in &self.identity {
            out.extend(["-i".to_string(), i.display().to_string()]);
        }
        if let Some(j) = &self.jump {
            out.extend(["-J".to_string(), j.clone()]);
        }
        if let Some(f) = &self.config {
            out.extend(["-F".to_string(), f.display().to_string()]);
        }
        for o in &self.options {
            out.extend(["-o".to_string(), o.clone()]);
        }
        if self.ipv4 {
            out.push("-4".into());
        }
        if self.ipv6 {
            out.push("-6".into());
        }
        for _ in 0..self.verbose {
            out.push("-v".into());
        }
        out
    }

    /// The remote command as ssh would send it: the words joined by spaces.
    pub fn remote_command(&self) -> Option<String> {
        (!self.command.is_empty()).then(|| self.command.join(" "))
    }
}

/// Subcommand names reserved for later milestones: `qsh ls` means the subcommand, `qsh -- ls`
/// a host named ls.
pub const RESERVED: &[&str] = &["attach", "ls", "kill", "install", "doctor"];

/// qsh-server: the server side of qsh, run over ssh by the client, and the per-user daemon.
#[derive(Debug, Parser)]
#[command(
    name = "qsh-server",
    version,
    about = "Server side of qsh: the per-user daemon, and the commands qsh runs over ssh",
    long_about = "qsh-server needs no root and no configuration: `qsh HOST` runs \
                  `qsh-server bootstrap` over ssh, which starts the per-user daemon on demand. \
                  The daemon listens on the first port of 60443-60542 free on both UDP and TCP.",
    after_help = "Environment: QSH_SERVER_PORTS=FIRST-LAST sets the port range of daemons \
                  started on demand."
)]
pub struct ServerArgs {
    /// Log more (repeat for more)
    #[arg(short = 'v', action = ArgAction::Count, global = true)]
    pub verbose: u8,
    /// What to do
    #[command(subcommand)]
    pub command: ServerCommand,
}

/// The subcommands of qsh-server.
#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Create a session for the client (run over ssh; request on stdin, reply on stdout)
    Bootstrap,
    /// Carry a connection over ssh's stdin and stdout (run over ssh by the client)
    Pipe {
        /// Protocol version
        #[arg(long, value_name = "N", default_value_t = 1)]
        version: u32,
    },
    /// Run the per-user daemon (started on demand by bootstrap otherwise)
    Daemon(DaemonArgs),
    /// Show the running daemon and its sessions (JSON)
    Status,
    /// Stop the running daemon; its sessions end
    Stop,
}

/// Options of `qsh-server daemon`.
#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Stay in the foreground (for service managers); otherwise start in the background
    #[arg(long)]
    pub foreground: bool,
    /// Ports to try, FIRST-LAST; the first free on both UDP and TCP is used
    #[arg(long, value_name = "FIRST-LAST", env = "QSH_SERVER_PORTS")]
    pub ports: Option<String>,
    /// Exit after an hour without sessions (set when started on demand)
    #[arg(long, hide = true)]
    pub on_demand: bool,
}

/// Parse `FIRST-LAST` (or a single port).
pub fn parse_ports(text: &str) -> Option<std::ops::RangeInclusive<u16>> {
    let (a, b) = text.split_once('-').unwrap_or((text, text));
    let (a, b): (u16, u16) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (a <= b).then_some(a..=b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn definitions_are_consistent() {
        QshArgs::command().debug_assert();
        ServerArgs::command().debug_assert();
    }

    #[test]
    fn ssh_options_pass_through_and_the_command_keeps_its_dashes() {
        let a = QshArgs::try_parse_from([
            "qsh", "-p", "2222", "-o", "A=b", "-v", "-i", "k", "u@h", "ls", "-l", "/",
        ])
        .unwrap();
        assert_eq!(a.ssh_options(), ["-p", "2222", "-i", "k", "-o", "A=b", "-v"]);
        assert_eq!(a.destination, "u@h");
        assert_eq!(a.remote_command().as_deref(), Some("ls -l /"));
        let a = QshArgs::try_parse_from(["qsh", "h", "--", "echo", "hi"]).unwrap();
        assert_eq!(a.remote_command().as_deref(), Some("echo hi"));
        let a = QshArgs::try_parse_from(["qsh", "--", "ls"]).unwrap();
        assert_eq!(a.destination, "ls");
    }

    #[test]
    fn port_ranges() {
        assert_eq!(parse_ports("60443-60542"), Some(60443..=60542));
        assert_eq!(parse_ports("7000"), Some(7000..=7000));
        assert_eq!(parse_ports("9-1"), None);
        assert_eq!(parse_ports("x"), None);
    }
}
