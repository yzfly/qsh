//! Development tasks: `cargo xtask gen [--check]` writes the man pages (`man/`) and the shell
//! completions (`completions/`) from the command line definitions in `qsh_cli::cli`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use clap::CommandFactory;
use clap_complete::Shell;
use qsh_cli::cli::{qsh_command, QshArgs, ServerArgs, SshArgs};

/// Extra sections of qsh(1), in roff.
const QSH_EXTRA: &str = r#".SH SESSIONS
A session lives on the server; the client is a replaceable window on it. Detach with
.BR ~d ,
or lose the client altogether, and the session keeps running: for 6 hours without a client,
1 hour after its program exited.
.B qsh ls
lists the sessions saved on this machine,
.B qsh ls
.I HOST
those on the host;
.B qsh attach
.I HOST
takes you back, with the output produced meanwhile;
.B qsh kill
ends one. Sessions are named by their id, any unique prefix of it, or their name.
.PP
The credentials of every session are saved (see FILES), so
.B qsh attach
reaches it again without ssh, even after the client process died. When they are no longer
valid (another client attached it meanwhile, or the daemon's certificate changed), qsh gets new
ones over ssh.
.SH ESCAPES
Typed right after Enter, as with
.BR ssh (1)
(the escape character is ~ unless
.B escape_char
in
.BR qsh_config (5)
says otherwise):
.TP
.B ~.
End the session: its programs get SIGHUP.
.TP
.B ~d
Detach: the session keeps running on the server.
.TP
.B ~s
Show the connection: transport and address, round-trip time, bytes, how long this attachment
has lasted, reconnects, how each transport fared when the connection was made, and the
session id.
.TP
.B ~?
List the escapes.
.TP
.B ~~
Send a literal ~.
.SH EXIT STATUS
The remote program's exit status, or 128 plus the signal number when a signal killed it;
0 after detaching;
.B 255
when qsh or ssh failed;
.B 42
when the host has no
.B qsh\-server
(on a terminal, builds with
.B qsh install
offer to install it first, unless
.B install = "never"
in
.BR qsh_config (5)).
.SH FILES
.TP
.I $XDG_STATE_HOME/qsh/sessions/
Saved session credentials, one file per session (mode 0600, directory 0700; default
.IR ~/.local/state/qsh/sessions/ ).
Each holds the destination and ssh options, the server's ports and certificate fingerprint,
and the session key: as sensitive as an ssh private key while the session lives. qsh removes a
file when its session ends, and refuses files and directories other users may read.
.TP
.IR $XDG_CONFIG_HOME/qsh/config ", " /etc/qsh/qsh_config
Configuration, see
.BR qsh_config (5).
.SH ENVIRONMENT
.TP
.B QSH_TRANSPORTS
Comma-separated transports to use, of quic, tls and ssh; all when unset.
.TP
.B QSH_SSH
The ssh program to run instead of ssh from PATH.
.TP
.B QSH_DOWNLOAD_URL
Where
.B qsh install
downloads releases from, instead of https://github.com/yzfly/qsh/releases (a mirror;
https:// or file:// only).
.TP
.B QSH_TRANSCRIPT
A file to which qsh appends a line of JSON for every piece of output, gap and reconnect, for
qsh's own tests. Unstable: the format changes without notice.
.TP
.BR LANG ", " LANGUAGE ", " LC_* ", " COLORTERM ", " TERM
Passed to the session.
.SH SEE ALSO
.BR qsh\-server (1),
.BR qsh_config (5),
.BR ssh (1)
"#;

/// Extra sections of qsh-server(1), in roff.
const SERVER_EXTRA: &str = r#".SH FILES
.TP
.I $XDG_RUNTIME_DIR/qsh/control.sock
The daemon's control socket (directory mode 0700;
.I /tmp/qsh\-UID
when XDG_RUNTIME_DIR is unset).
.TP
.I $XDG_STATE_HOME/qsh/daemon/
The daemon's certificate and key.
.TP
.I $XDG_STATE_HOME/qsh/daemon.log
The log of a daemon started on demand.
.SH EXIT STATUS
.B bootstrap
exits 0 after a success reply, 1 after an error reply, 2 when invoked wrongly.
.B status
exits 3 when no daemon runs. Status 42 is never used: it means
"no qsh-server" to clients.
.SH SEE ALSO
.BR qsh (1),
.BR qsh_config (5)
"#;

/// Escape text for roff.
fn roff(text: &str) -> String {
    text.replace('\\', "\\e").replace('-', "\\-").replace('`', "")
}

/// The SUBCOMMANDS section of qsh(1): one page for the program, the subcommands in it (as
/// git's or ip's are not, they are few and small).
fn subcommands_section() -> String {
    let mut out = String::from(".SH SUBCOMMANDS\nssh options may come before or after the subcommand.\n");
    let global: Vec<String> = SshArgs::augment_args(clap::Command::new("ssh"))
        .get_arguments()
        .map(|a| a.get_id().to_string())
        .collect();
    for sub in qsh_command().get_subcommands() {
        let usage = sub
            .clone()
            .bin_name(format!("qsh {}", sub.get_name()))
            .render_usage()
            .to_string();
        let usage = usage.trim_start_matches("Usage: ").trim();
        out.push_str(&format!(".TP\n.B {}\n", roff(usage)));
        let about = sub
            .get_long_about()
            .or(sub.get_about())
            .map(|a| a.to_string())
            .unwrap_or_default();
        out.push_str(&roff(&about));
        out.push('\n');
        for arg in sub.get_arguments() {
            let id = arg.get_id().as_str();
            if global.iter().any(|g| g == id) || id == "help" {
                continue;
            }
            let values = arg.get_value_names().filter(|_| arg.get_action().takes_values());
            let name = match (arg.get_long(), values) {
                (Some(long), Some(values)) => format!("--{long} {}", values[0]),
                (Some(long), None) => format!("--{long}"),
                (None, Some(values)) => values[0].to_string(),
                (None, None) => id.to_string(),
            };
            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
            out.push_str(&format!(".RS\n.TP\n.B {}\n{}\n.RE\n", roff(&name), roff(&help)));
        }
    }
    out
}

fn man_page(cmd: clap::Command, extra: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    clap_mangen::Man::new(cmd).render(&mut out)?;
    out.extend_from_slice(extra.as_bytes());
    Ok(out)
}

fn completion(cmd: &mut clap::Command, shell: Shell, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    clap_complete::generate(shell, cmd, name, &mut out);
    out
}

/// Every generated file: path relative to the repository, content.
fn files() -> io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut files = vec![
        (
            PathBuf::from("man/qsh.1"),
            man_page(QshArgs::command(), &format!("{}{QSH_EXTRA}", subcommands_section()))?,
        ),
        (
            PathBuf::from("man/qsh-server.1"),
            man_page(ServerArgs::command(), SERVER_EXTRA)?,
        ),
        (
            PathBuf::from("man/qsh_config.5"),
            include_bytes!("qsh_config.5").to_vec(),
        ),
    ];
    for (name, mut cmd) in [("qsh", qsh_command()), ("qsh-server", ServerArgs::command())] {
        files.push((
            PathBuf::from(format!("completions/{name}.bash")),
            completion(&mut cmd, Shell::Bash, name),
        ));
        files.push((
            PathBuf::from(format!("completions/_{name}")),
            completion(&mut cmd, Shell::Zsh, name),
        ));
        files.push((
            PathBuf::from(format!("completions/{name}.fish")),
            completion(&mut cmd, Shell::Fish, name),
        ));
    }
    Ok(files)
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is in the repository")
        .to_path_buf()
}

fn gen(check: bool) -> io::Result<bool> {
    let root = root();
    let mut stale = Vec::new();
    for (path, content) in files()? {
        let full = root.join(&path);
        if fs::read(&full).ok().as_deref() == Some(content.as_slice()) {
            continue;
        }
        stale.push(path.clone());
        if !check {
            fs::create_dir_all(full.parent().expect("a directory"))?;
            fs::write(&full, &content)?;
            println!("wrote {}", path.display());
        }
    }
    if check && !stale.is_empty() {
        for path in &stale {
            eprintln!("out of date: {} (run: cargo xtask gen)", path.display());
        }
        return Ok(false);
    }
    Ok(true)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["gen"] => gen(false),
        ["gen", "--check"] => gen(true),
        _ => {
            eprintln!("usage: cargo xtask gen [--check]");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}
