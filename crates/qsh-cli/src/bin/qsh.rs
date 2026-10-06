//! `qsh [ssh options] [user@]host [command…]`: a remote shell over QUIC; and `qsh attach`,
//! `qsh ls`, `qsh kill`, `qsh install`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use qsh_cli::cli::{parse_qsh, Invocation, QshCommand, SshArgs, RESERVED};
use qsh_cli::terminal::{self, Start, TerminalOptions};
use qsh_core::client::store::SessionStore;
use qsh_core::client::{ClientConfig, EXIT_ERROR};
use qsh_core::config::{Config, ConfigPaths, Install};
use qsh_core::proto::bootstrap::accepted_env_name;
use qsh_core::{log, sys, Paths};

fn main() {
    let invocation = match parse_qsh(std::env::args_os()) {
        Ok(i) => i,
        Err(e) => {
            // --help and --version are not errors
            let code = if e.use_stderr() { EXIT_ERROR } else { 0 };
            let _ = e.print();
            std::process::exit(code);
        }
    };
    let code = match invocation {
        Invocation::Connect(args) => {
            // `qsh doctor` is a subcommand to come (M2); `qsh -- doctor` is a host named doctor
            let explicit_host = std::env::args()
                .skip(1)
                .take_while(|a| a != &args.destination)
                .any(|a| a == "--");
            if RESERVED.contains(&args.destination.as_str()) && !explicit_host {
                eprintln!(
                    "qsh: `qsh {}` is not available in this version; to connect to a host of that name: qsh -- {}",
                    args.destination, args.destination
                );
                std::process::exit(EXIT_ERROR);
            }
            match config_for(&args.destination, &args.ssh) {
                Ok((mut config, options)) => {
                    config.command = args.remote_command();
                    block_on(terminal::run(config, Start::New, options))
                }
                Err(code) => code,
            }
        }
        Invocation::Subcommand(ssh, command) => subcommand(ssh, command),
    };
    std::process::exit(code);
}

/// The client configuration for `destination` and how the terminal behaves: the
/// configuration files (qsh_config(5)) for that host, the environment over them, the command
/// line over both. A configuration file qsh cannot use is an error (exit 255), as for ssh.
fn config_for(destination: &str, ssh: &SshArgs) -> Result<(ClientConfig, TerminalOptions), i32> {
    if ssh.verbose > 0 {
        log::set_level(if ssh.verbose > 1 {
            log::Level::Debug
        } else {
            log::Level::Info
        });
    }
    let paths = Paths::from_env();
    let (file, warnings) = Config::load(&ConfigPaths::standard(&paths)).map_err(|e| {
        eprintln!("qsh: {e}");
        EXIT_ERROR
    })?;
    for w in warnings {
        eprintln!("qsh: {w}");
    }
    let options = ssh.ssh_options();
    // `[host."pattern"]` tables may name the HostName that ssh resolves the destination to
    let mut first = file.for_host(destination, None);
    let _ = first.apply_process_env();
    let hostname = ssh_hostname(&first.ssh, &options, destination);
    let mut host = file.for_host(destination, hostname.as_deref());
    for w in host.apply_process_env() {
        eprintln!("qsh: {w}");
    }
    let mut config = ClientConfig::new(destination);
    config.ssh.program = host.ssh.clone();
    // The command line's ssh options first: ssh takes the first value of each
    config.ssh.options = options.iter().chain(&host.ssh_options).map(Into::into).collect();
    if let Some(program) = &host.server_command {
        config.ssh.server_program = program.clone();
    }
    config.race = host.race();
    config.replay_on_attach = host.replay_on_attach;
    config.keepalive = host.keepalive;
    config.path_memory = host.path_memory;
    config.catchup = host.catchup;
    config.compression = host.compression;
    config.term = std::env::var("TERM").ok().filter(|t| !t.is_empty());
    config.env = std::env::vars()
        .filter(|(k, _)| accepted_env_name(k))
        .collect::<BTreeMap<_, _>>();
    config.store = Some(SessionStore::from_paths(&paths));
    let terminal = TerminalOptions {
        escape: host.escape_char,
        status_line: host.status_line,
        offer_install: host.install == Install::Ask,
        verbose: ssh.verbose > 0,
    };
    Ok((config, terminal))
}

/// The host name ssh connects to for `destination` (`ssh -G`), None when ssh cannot say.
fn ssh_hostname(program: &std::ffi::OsStr, options: &[String], destination: &str) -> Option<String> {
    let out = std::process::Command::new(program)
        .arg("-G")
        .args(options)
        .arg("--")
        .arg(destination)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("hostname ").map(|h| h.trim().to_string()))
        .filter(|h| !h.is_empty())
}

fn block_on<F: std::future::Future<Output = i32>>(f: F) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qsh: {e}");
            return EXIT_ERROR;
        }
    };
    let code = runtime.block_on(f);
    // Do not wait for the blocking stdin reader
    runtime.shutdown_background();
    code
}

/// ssh may ask for a password: on a terminal, it can.
fn interactive() -> bool {
    sys::is_tty(&std::io::stdin()) || sys::is_tty(&std::io::stderr())
}

fn subcommand(ssh: SshArgs, command: QshCommand) -> i32 {
    let store = SessionStore::from_paths(&Paths::from_env());
    match command {
        QshCommand::Attach { destination, session } => {
            let (mut config, options) = match config_for(&destination, &ssh) {
                Ok(c) => c,
                Err(code) => return code,
            };
            let given = !ssh.ssh_options().is_empty();
            block_on(async move {
                let tty = sys::is_tty(&std::io::stdin());
                let chosen =
                    qsh_cli::sessions::choose_attach(&config.ssh, &store, session.as_deref(), interactive(), tty).await;
                let start = match chosen {
                    Ok(s) => s,
                    Err(code) => return code,
                };
                // The saved session's ssh options (those it was started with, the configuration
                // files' included), unless others were given now
                if let Start::Saved(saved) = &start {
                    if !given {
                        config.ssh.options = saved.ssh_options.iter().map(Into::into).collect();
                    }
                }
                terminal::run(config, start, options).await
            })
        }
        QshCommand::Ls { destination, json } => match destination {
            Some(destination) => {
                let (config, _) = match config_for(&destination, &ssh) {
                    Ok(c) => c,
                    Err(code) => return code,
                };
                block_on(async move { qsh_cli::sessions::ls_remote(&config.ssh, &store, json, interactive()).await })
            }
            None => qsh_cli::sessions::ls_saved(&store, json),
        },
        QshCommand::Kill {
            destination, session, ..
        } => {
            let (config, _) = match config_for(&destination, &ssh) {
                Ok(c) => c,
                Err(code) => return code,
            };
            block_on(
                async move { qsh_cli::sessions::kill(&config.ssh, &store, session.as_deref(), interactive()).await },
            )
        }
        QshCommand::Install { destination, from } => match config_for(&destination, &ssh) {
            Ok((config, _)) => install(config, from),
            Err(code) => code,
        },
    }
}

#[cfg(feature = "self-install")]
fn install(config: ClientConfig, from: Option<std::path::PathBuf>) -> i32 {
    let options = qsh_cli::install::Options::from_env(from, interactive());
    match qsh_cli::install::install(&config.ssh, &options, &mut |line| eprintln!("qsh: {line}")) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("qsh: {e}");
            EXIT_ERROR
        }
    }
}

#[cfg(not(feature = "self-install"))]
fn install(config: ClientConfig, _from: Option<std::path::PathBuf>) -> i32 {
    eprintln!(
        "qsh: this qsh is built without `qsh install` (cargo feature self-install); install qsh-server on {} with:\n  {}",
        config.ssh.destination,
        terminal::install_hint(&config)
    );
    EXIT_ERROR
}
