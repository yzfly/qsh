//! Development tasks: `cargo xtask gen [--check]` writes the man pages (`man/`) and the shell
//! completions (`completions/`) from the command line definitions in `qsh_cli::cli`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::CommandFactory;
use clap_complete::Shell;
use qsh_cli::cli::{QshArgs, ServerArgs};

/// Extra sections of qsh(1), in roff.
const QSH_EXTRA: &str = r#".SH ESCAPES
Typed right after Enter, as with
.BR ssh (1):
.TP
.B ~.
End the session: its programs get SIGHUP.
.TP
.B ~d
Detach: the session keeps running on the server.
.TP
.B ~s
Show the connection: transport, round-trip time, bytes, reconnects.
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
.BR qsh\-server .
.SH ENVIRONMENT
.TP
.B QSH_TRANSPORTS
Comma-separated transports to use, of quic, tls and ssh; all when unset.
.TP
.B QSH_SSH
The ssh program to run instead of ssh from PATH.
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
        (PathBuf::from("man/qsh.1"), man_page(QshArgs::command(), QSH_EXTRA)?),
        (
            PathBuf::from("man/qsh-server.1"),
            man_page(ServerArgs::command(), SERVER_EXTRA)?,
        ),
        (
            PathBuf::from("man/qsh_config.5"),
            include_bytes!("qsh_config.5").to_vec(),
        ),
    ];
    for (name, mut cmd) in [("qsh", QshArgs::command()), ("qsh-server", ServerArgs::command())] {
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
