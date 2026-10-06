//! `qsh [ssh options] [user@]host [command…]`: a remote shell over QUIC.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use clap::Parser;
use qsh_cli::cli::{QshArgs, RESERVED};
use qsh_core::client::{ClientConfig, EXIT_ERROR};
use qsh_core::log;
use qsh_core::proto::bootstrap::accepted_env_name;
use qsh_core::transport::RaceConfig;

fn main() {
    let args = match QshArgs::try_parse() {
        Ok(a) => a,
        Err(e) => {
            // --help and --version are not errors
            let code = if e.use_stderr() { EXIT_ERROR } else { 0 };
            let _ = e.print();
            std::process::exit(code);
        }
    };
    // `qsh ls` is a subcommand to come (M1); `qsh -- ls` is a host named ls
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
    if args.verbose > 0 {
        log::set_level(if args.verbose > 1 {
            log::Level::Debug
        } else {
            log::Level::Info
        });
    }

    let mut config = ClientConfig::new(args.destination.clone());
    config.ssh.options = args.ssh_options().into_iter().map(Into::into).collect();
    if let Some(program) = std::env::var_os("QSH_SSH") {
        config.ssh.program = program;
    }
    config.command = args.remote_command();
    config.term = std::env::var("TERM").ok().filter(|t| !t.is_empty());
    config.env = std::env::vars()
        .filter(|(k, _)| accepted_env_name(k))
        .collect::<BTreeMap<_, _>>();
    if let Some(race) = race_from_env() {
        config.race = race;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qsh: {e}");
            std::process::exit(EXIT_ERROR);
        }
    };
    let code = runtime.block_on(qsh_cli::terminal::run(config, args.verbose > 0));
    // Do not wait for the blocking stdin reader
    runtime.shutdown_background();
    std::process::exit(code);
}

/// `QSH_TRANSPORTS=quic,tls,ssh`: the transports to try, for debugging a network.
fn race_from_env() -> Option<RaceConfig> {
    let text = std::env::var("QSH_TRANSPORTS").ok()?;
    let mut race = RaceConfig {
        quic: None,
        tls: None,
        ssh: None,
    };
    let default = RaceConfig::default();
    for name in text.split(',').map(str::trim) {
        match name {
            "quic" => race.quic = default.quic,
            "tls" => race.tls = default.tls,
            "ssh" => race.ssh = default.ssh,
            _ => eprintln!("qsh: QSH_TRANSPORTS: unknown transport {name:?} (known: quic, tls, ssh)"),
        }
    }
    Some(race)
}
