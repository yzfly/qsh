//! The command lines of `qsh` and `qsh-server`, as clap definitions shared by the binaries and
//! by `cargo xtask gen` (man pages and shell completions).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};

const QSH_AFTER: &str = "\
Escapes (after Enter): ~. end the session, ~d detach, ~s status, ~? help, ~~ a literal ~.

Exit status: the remote program's status (128 + N when it was killed by signal N); 255 when
qsh or ssh failed; 42 when the host has no qsh-server.

A host named like a subcommand: qsh -- ls";

const QSH_ABOUT: &str = "Remote shell over QUIC: sessions survive network changes, sleep and roaming";

const QSH_LONG_ABOUT: &str = "qsh starts a session on HOST through your own ssh (keys, agent, \
    ~/.ssh/config, passwords and second factors all work), then keeps it alive over QUIC, TLS or \
    an ssh pipe, whichever works, reconnecting and replaying missed output as the network comes \
    and goes. Detached sessions keep running: qsh ls lists them, qsh attach takes you back.";

/// qsh: a remote shell over QUIC. If you can `ssh host`, you can `qsh host`, and it never
/// drops.
#[derive(Debug, Parser)]
#[command(
    name = "qsh",
    version,
    about = QSH_ABOUT,
    long_about = QSH_LONG_ABOUT,
    after_help = QSH_AFTER
)]
pub struct QshArgs {
    /// ssh options
    #[command(flatten)]
    pub ssh: SshArgs,
    /// Where to connect: user@host or host, or a host alias from ~/.ssh/config
    #[arg(value_name = "DESTINATION", help = "[user@]host, or a host alias from ~/.ssh/config")]
    pub destination: String,
    /// Command to run instead of a login shell
    #[arg(value_name = "COMMAND", trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// `qsh [ssh options] SUBCOMMAND …`: ssh options may come before or after the subcommand.
#[derive(Debug, Parser)]
#[command(name = "qsh", version, disable_help_subcommand = true)]
pub struct QshSubcommandArgs {
    /// ssh options
    #[command(flatten)]
    pub ssh: SshArgs,
    /// The subcommand
    #[command(subcommand)]
    pub command: QshCommand,
}

/// What a `qsh` command line asks for.
#[derive(Debug)]
pub enum Invocation {
    /// A session on a host: `qsh [options] destination [command…]`.
    Connect(QshArgs),
    /// A subcommand: `qsh [options] attach|ls|kill|install …`.
    Subcommand(SshArgs, QshCommand),
}

/// The names of the subcommands.
pub const SUBCOMMANDS: &[&str] = &["attach", "ls", "kill", "install"];

/// The ssh options of qsh that take a value (`-p 22`, or `-p22`).
const OPTIONS_WITH_VALUES: &[char] = &['p', 'l', 'i', 'J', 'F', 'o'];

/// Parse a `qsh` command line. The first word that is not an option decides: a subcommand
/// name, or a destination; after `--`, always a destination (`qsh -- ls` is a host named ls).
/// After the destination everything is the remote command, options included, as with ssh.
/// `--help` and `--version` describe the whole program ([`qsh_command`]).
pub fn parse_qsh<I, T>(args: I) -> Result<Invocation, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut words = args.iter().skip(1).map(|a| a.to_string_lossy());
    let mut help = false;
    let mut subcommand = false;
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            help |= long == "help" || long == "version";
            continue;
        }
        if let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) {
            for (i, c) in cluster.char_indices() {
                help |= c == 'h' || c == 'V';
                if OPTIONS_WITH_VALUES.contains(&c) {
                    if i + c.len_utf8() == cluster.len() {
                        // The value is the next word
                        words.next();
                    }
                    break;
                }
            }
            continue;
        }
        subcommand = SUBCOMMANDS.contains(&word.as_ref());
        break;
    }
    if help {
        // The error is the help or version text; a mistaken guess parses as usual below
        let _ = qsh_command().try_get_matches_from(&args)?;
    }
    if subcommand {
        let a = QshSubcommandArgs::try_parse_from(&args)?;
        Ok(Invocation::Subcommand(a.ssh, a.command))
    } else {
        QshArgs::try_parse_from(&args).map(Invocation::Connect)
    }
}

/// All of `qsh`, sessions and subcommands, as one definition: for `--help`, the man page and
/// the shell completions. (Parsing goes through [`parse_qsh`].)
pub fn qsh_command() -> clap::Command {
    let cmd = QshArgs::command()
        .subcommand_negates_reqs(true)
        .args_conflicts_with_subcommands(true)
        .subcommand_value_name("SUBCOMMAND")
        .subcommand_help_heading("Subcommands");
    // DESTINATION is required only without a subcommand (subcommand_negates_reqs)
    QshCommand::augment_subcommands(cmd)
        .disable_help_subcommand(true)
        .about(QSH_ABOUT)
        .long_about(QSH_LONG_ABOUT)
}

/// The options passed through to ssh.
#[derive(Debug, Clone, Default, Args)]
pub struct SshArgs {
    /// Port of the ssh server (ssh -p)
    #[arg(short = 'p', value_name = "PORT", global = true)]
    pub port: Option<String>,
    /// User to log in as (ssh -l)
    #[arg(short = 'l', value_name = "USER", global = true)]
    pub login: Option<String>,
    /// Identity file (ssh -i); may be repeated
    #[arg(short = 'i', value_name = "FILE", action = ArgAction::Append, global = true)]
    pub identity: Vec<PathBuf>,
    /// Jump hosts (ssh -J)
    #[arg(short = 'J', value_name = "DESTINATION", global = true)]
    pub jump: Option<String>,
    /// ssh configuration file (ssh -F)
    #[arg(short = 'F', value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,
    /// ssh option (ssh -o); may be repeated
    #[arg(short = 'o', value_name = "OPTION", action = ArgAction::Append, global = true)]
    pub options: Vec<String>,
    /// Use IPv4 addresses only (ssh -4)
    #[arg(short = '4', global = true)]
    pub ipv4: bool,
    /// Use IPv6 addresses only (ssh -6)
    #[arg(short = '6', global = true)]
    pub ipv6: bool,
    /// Verbose: qsh's own messages, and ssh -v; may be repeated
    #[arg(short = 'v', action = ArgAction::Count, global = true)]
    pub verbose: u8,
}

/// The subcommands of qsh.
#[derive(Debug, Subcommand)]
pub enum QshCommand {
    /// Reattach a detached session, replaying the output it produced meanwhile
    #[command(
        long_about = "Reattach a session that is detached (~d), or whose client was lost. With \
                      saved credentials qsh connects straight to the server, without ssh; \
                      otherwise, or when they are no longer valid, it gets new ones over ssh. \
                      Without SESSION: the only detached session, or a choice among them."
    )]
    Attach {
        /// The host the session runs on (user@host or host)
        #[arg(value_name = "DESTINATION", help = "[user@]host the session runs on")]
        destination: String,
        /// Session id (or a unique prefix of it) or name, as qsh ls shows them
        #[arg(value_name = "SESSION")]
        session: Option<String>,
    },
    /// List sessions: on DESTINATION (over ssh), or the saved ones of every host
    Ls {
        /// The host to ask (user@host or host); without it, the sessions saved on this machine
        #[arg(
            value_name = "DESTINATION",
            help = "[user@]host to ask; without it, the sessions saved on this machine (no network)"
        )]
        destination: Option<String>,
        /// Print JSON, for scripts
        #[arg(long)]
        json: bool,
    },
    /// End a session: its programs get SIGHUP
    Kill {
        /// The host the session runs on (user@host or host)
        #[arg(value_name = "DESTINATION", help = "[user@]host the session runs on")]
        destination: String,
        /// Session id (or a unique prefix of it) or name, as qsh ls shows them
        #[arg(value_name = "SESSION", required_unless_present = "all", conflicts_with = "all")]
        session: Option<String>,
        /// End every session on DESTINATION
        #[arg(long)]
        all: bool,
    },
    /// Install qsh-server into ~/.local/bin on DESTINATION (builds with feature self-install)
    #[command(long_about = "Install qsh-server, of this qsh's version, into ~/.local/bin on \
                      DESTINATION; no root needed. qsh finds the host's system over ssh, then \
                      copies a matching qsh-server from this machine, or downloads the release \
                      archive here, checks it against the release's SHA256SUMS and copies it \
                      over; as a last resort it runs the install script on the host. Only in \
                      builds with the cargo feature self-install.")]
    Install {
        /// The host to install on (user@host or host)
        #[arg(value_name = "DESTINATION", help = "[user@]host to install on")]
        destination: String,
        /// Copy this qsh-server binary instead (built for the host's system)
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
}

impl SshArgs {
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
}

impl QshArgs {
    /// The ssh options these arguments stand for, in ssh's syntax.
    pub fn ssh_options(&self) -> Vec<String> {
        self.ssh.ssh_options()
    }

    /// The remote command as ssh would send it: the words joined by spaces.
    pub fn remote_command(&self) -> Option<String> {
        (!self.command.is_empty()).then(|| self.command.join(" "))
    }
}

/// Names that are not hosts unless written after `--`: the subcommands, and those planned
/// for later milestones (`qsh doctor`, M2). `qsh -- doctor` is a host named doctor.
pub const RESERVED: &[&str] = &["doctor"];

/// qsh-server: the server side of qsh, run over ssh by the client, and the per-user daemon.
#[derive(Debug, Parser)]
#[command(
    name = "qsh-server",
    version,
    about = "Server side of qsh: the per-user daemon, and the commands qsh runs over ssh",
    long_about = "qsh-server needs no root and no configuration: qsh HOST runs \
                  qsh-server bootstrap over ssh, which starts the per-user daemon on demand. \
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
    /// Replace the running daemon with a newer qsh-server in place; sessions are kept
    #[command(long_about = "Replace the running daemon with a newer qsh-server in place: the \
                      daemon executes the new program in its own process, keeping its process \
                      id, its ports and every session with its output; clients reconnect \
                      within a second. The program must belong to root or to you, must not be \
                      writable by others, and must report a newer version, unless --force. If \
                      anything goes wrong, the daemon goes on as before. The systemd user unit \
                      runs this on systemctl --user reload qsh-server.")]
    Upgrade {
        /// The qsh-server to run (default: this program)
        #[arg(long, value_name = "PATH")]
        exe: Option<PathBuf>,
        /// Upgrade even to a version that is not newer
        #[arg(long)]
        force: bool,
    },
    /// Print the version and the handoff state formats this program reads (used by upgrades)
    #[command(name = "handoff-probe", hide = true)]
    HandoffProbe,
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
    /// Resume from the state an older image of this daemon handed over (an upgrade in place)
    #[arg(long, hide = true, requires_all = ["state_fd", "key_fd"])]
    pub resume: bool,
    /// The descriptor of the sealed state (with --resume)
    #[arg(long, hide = true, value_name = "FD", requires = "resume")]
    pub state_fd: Option<i32>,
    /// The descriptor of the pipe with the state's key (with --resume)
    #[arg(long, hide = true, value_name = "FD", requires = "resume")]
    pub key_fd: Option<i32>,
    /// The descriptor of the previous program, run again if resuming fails (with --resume)
    #[arg(long, hide = true, value_name = "FD", requires = "resume")]
    pub fallback_exe_fd: Option<i32>,
    /// The new program could not resume; this is the previous one again (with --resume)
    #[arg(long, hide = true, requires = "resume")]
    pub fell_back: bool,
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
        QshSubcommandArgs::command().debug_assert();
        qsh_command().debug_assert();
        ServerArgs::command().debug_assert();
        let names: Vec<_> = qsh_command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        assert_eq!(names, SUBCOMMANDS);
    }

    fn connect(args: &[&str]) -> QshArgs {
        match parse_qsh(args).unwrap() {
            Invocation::Connect(a) => a,
            other => panic!("{args:?}: {other:?}"),
        }
    }

    fn sub(args: &[&str]) -> (SshArgs, QshCommand) {
        match parse_qsh(args).unwrap() {
            Invocation::Subcommand(ssh, c) => (ssh, c),
            other => panic!("{args:?}: {other:?}"),
        }
    }

    #[test]
    fn ssh_options_pass_through_and_the_command_keeps_its_dashes() {
        let a = connect(&[
            "qsh", "-p", "2222", "-o", "A=b", "-v", "-i", "k", "u@h", "ls", "-l", "/",
        ]);
        assert_eq!(a.ssh_options(), ["-p", "2222", "-i", "k", "-o", "A=b", "-v"]);
        assert_eq!(a.destination, "u@h");
        assert_eq!(a.remote_command().as_deref(), Some("ls -l /"));
        let a = connect(&["qsh", "h", "--", "echo", "hi"]);
        assert_eq!(a.remote_command().as_deref(), Some("echo hi"));
        let a = connect(&["qsh", "-p2222", "-vv", "h"]);
        assert_eq!(a.ssh_options(), ["-p", "2222", "-v", "-v"]);
        // A command named like a subcommand is a command
        for word in SUBCOMMANDS {
            let a = connect(&["qsh", "h", word, "x"]);
            assert_eq!(a.remote_command().unwrap(), format!("{word} x"));
        }
    }

    #[test]
    fn subcommands_and_hosts_named_like_them() {
        // `qsh -- ls` is a host named ls
        assert_eq!(connect(&["qsh", "--", "ls"]).destination, "ls");
        let a = connect(&["qsh", "-p", "22", "--", "attach", "uptime"]);
        assert_eq!(a.destination, "attach");
        assert_eq!(a.remote_command().as_deref(), Some("uptime"));
        // An option's value is not a subcommand
        assert_eq!(connect(&["qsh", "-l", "ls", "srv"]).destination, "srv");
        // Subcommands, with ssh options before or after them
        let (_, c) = sub(&["qsh", "ls"]);
        assert!(matches!(
            c,
            QshCommand::Ls {
                destination: None,
                json: false
            }
        ));
        let (ssh, c) = sub(&["qsh", "ls", "--json", "-p", "2222", "srv"]);
        assert!(matches!(&c, QshCommand::Ls { destination: Some(d), json: true } if d == "srv"));
        assert_eq!(ssh.ssh_options(), ["-p", "2222"]);
        let (ssh, c) = sub(&["qsh", "-l", "alice", "attach", "srv", "3f2a"]);
        assert!(
            matches!(&c, QshCommand::Attach { destination, session: Some(s) } if destination == "srv" && s == "3f2a")
        );
        assert_eq!(ssh.ssh_options(), ["-l", "alice"]);
        let (_, c) = sub(&["qsh", "kill", "srv", "--all"]);
        assert!(matches!(
            c,
            QshCommand::Kill {
                all: true,
                session: None,
                ..
            }
        ));
        assert!(parse_qsh(["qsh", "kill", "srv"]).is_err(), "a session or --all");
        assert!(parse_qsh(["qsh", "kill", "srv", "x", "--all"]).is_err());
        let (_, c) = sub(&["qsh", "install", "srv", "--from", "/b/qsh-server"]);
        assert!(matches!(c, QshCommand::Install { from: Some(_), .. }));
        // Nothing at all is an error
        assert!(parse_qsh(["qsh"]).is_err());
        assert!(parse_qsh(["qsh", "-p", "22"]).is_err());
        // Help describes everything
        let help = parse_qsh(["qsh", "--help"]).unwrap_err().to_string();
        assert!(help.contains("attach") && help.contains("DESTINATION"), "{help}");
        let help = parse_qsh(["qsh", "ls", "--help"]).unwrap_err().to_string();
        assert!(help.contains("--json"), "{help}");
    }

    /// What --help, the man pages and the completions show is plain text: no Markdown from doc
    /// comments (backticks), and [user@]host as written.
    #[test]
    fn help_texts_are_plain() {
        fn texts(cmd: &clap::Command, out: &mut Vec<String>) {
            out.extend(
                [cmd.get_about(), cmd.get_long_about(), cmd.get_after_help()]
                    .into_iter()
                    .flatten()
                    .map(|t| t.to_string()),
            );
            for arg in cmd.get_arguments() {
                out.extend(
                    [arg.get_help(), arg.get_long_help()]
                        .into_iter()
                        .flatten()
                        .map(|t| t.to_string()),
                );
            }
            for sub in cmd.get_subcommands() {
                texts(sub, out);
            }
        }
        let mut all = Vec::new();
        texts(&qsh_command(), &mut all);
        texts(&ServerArgs::command(), &mut all);
        for text in &all {
            assert!(!text.contains('`'), "{text:?}");
        }
        let help = parse_qsh(["qsh", "--help"]).unwrap_err().to_string();
        assert!(help.contains("[user@]host, or a host alias"), "{help}");
        let help = parse_qsh(["qsh", "attach", "--help"]).unwrap_err().to_string();
        assert!(help.contains("[user@]host the session runs on"), "{help}");
    }

    #[test]
    fn upgrade_and_resume_arguments() {
        let args =
            ServerArgs::try_parse_from(["qsh-server", "upgrade", "--exe", "/usr/bin/qsh-server", "--force"]).unwrap();
        assert!(matches!(
            args.command,
            ServerCommand::Upgrade {
                exe: Some(_),
                force: true
            }
        ));
        let args = ServerArgs::try_parse_from(["qsh-server", "handoff-probe"]).unwrap();
        assert!(matches!(args.command, ServerCommand::HandoffProbe));
        let args = ServerArgs::try_parse_from([
            "qsh-server",
            "daemon",
            "--resume",
            "--state-fd=5",
            "--key-fd=6",
            "--fallback-exe-fd=7",
            "--foreground",
            "--on-demand",
        ])
        .unwrap();
        let ServerCommand::Daemon(d) = args.command else {
            panic!()
        };
        assert!(d.resume && d.foreground && d.on_demand && !d.fell_back);
        assert_eq!((d.state_fd, d.key_fd, d.fallback_exe_fd), (Some(5), Some(6), Some(7)));
        // The descriptors only with --resume, and --resume only with them
        assert!(ServerArgs::try_parse_from(["qsh-server", "daemon", "--state-fd=5"]).is_err());
        assert!(ServerArgs::try_parse_from(["qsh-server", "daemon", "--resume", "--state-fd=5"]).is_err());
    }

    #[test]
    fn port_ranges() {
        assert_eq!(parse_ports("60443-60542"), Some(60443..=60542));
        assert_eq!(parse_ports("7000"), Some(7000..=7000));
        assert_eq!(parse_ports("9-1"), None);
        assert_eq!(parse_ports("x"), None);
    }
}
