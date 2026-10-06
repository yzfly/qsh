//! `qsh-server bootstrap | pipe | daemon | status | stop`: the server side of qsh.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use qsh_cli::cli::{parse_ports, DaemonArgs, ServerArgs, ServerCommand};
use qsh_core::server::{self, Daemon, DaemonLauncher, ServerConfig, StartError, ON_DEMAND_IDLE_EXIT};
use qsh_core::{log, Paths};

fn main() -> ExitCode {
    let args = match ServerArgs::try_parse() {
        Ok(a) => a,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            // Over ssh the client expects a reply line from bootstrap even now (10.4)
            if code == 2 && std::env::args().nth(1).as_deref() == Some("bootstrap") {
                println!("\n{{\"qsh\":1,\"error\":\"bad-request\",\"message\":\"bad qsh-server arguments\"}}");
            }
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    log::set_level(match args.verbose {
        0 => log::Level::Info,
        _ => log::Level::Debug,
    });
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qsh-server: {e}");
            return ExitCode::from(1);
        }
    };
    let code = runtime.block_on(run(args.command));
    runtime.shutdown_background();
    ExitCode::from(code)
}

async fn run(command: ServerCommand) -> u8 {
    let paths = Paths::from_env();
    let launcher = match DaemonLauncher::current_exe() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("qsh-server: cannot find this program: {e}");
            return 1;
        }
    };
    match command {
        ServerCommand::Bootstrap => {
            // Quiet: stdout carries the reply, stderr goes to the user's terminal
            log::set_level(log::Level::Off);
            match server::bootstrap(&paths, &launcher, tokio::io::stdin(), tokio::io::stdout()).await {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(e) => {
                    eprintln!("qsh-server: {e}");
                    1
                }
            }
        }
        ServerCommand::Pipe { version } => {
            if version != qsh_core::proto::VERSION {
                eprintln!("qsh-server: protocol version {version} is not supported (this server speaks 1)");
                return 1;
            }
            log::set_level(log::Level::Off);
            match server::pipe(&paths, &launcher, tokio::io::stdin(), tokio::io::stdout()).await {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("qsh-server: {e}");
                    1
                }
            }
        }
        ServerCommand::Daemon(args) => daemon(paths, launcher, args).await,
        ServerCommand::Status => match server::request_status(&paths).await {
            Ok(Some(status)) => {
                use std::io::Write;
                // Ignore a closed pipe (`qsh-server status | head`)
                let _ = writeln!(std::io::stdout(), "{status:#}");
                0
            }
            Ok(None) => {
                println!("qsh-server: no daemon is running");
                3
            }
            Err(e) => {
                eprintln!("qsh-server: {e}");
                1
            }
        },
        ServerCommand::Stop => match server::request_stop(&paths).await {
            Ok(true) => 0,
            Ok(false) => {
                eprintln!("qsh-server: no daemon is running");
                0
            }
            Err(e) => {
                eprintln!("qsh-server: {e}");
                1
            }
        },
    }
}

async fn daemon(paths: Paths, mut launcher: DaemonLauncher, args: DaemonArgs) -> u8 {
    let mut config = ServerConfig::new(paths.clone());
    if let Some(text) = &args.ports {
        match parse_ports(text) {
            Some(range) => config.ports = range,
            None => {
                eprintln!("qsh-server: bad port range {text:?}; expected FIRST-LAST");
                return 2;
            }
        }
    }
    if !args.foreground {
        if let Some(ports) = &args.ports {
            launcher.args.extend(["--ports".into(), ports.into()]);
        }
        // Start it in the background like a bootstrap would
        return match server::connect_or_start(&paths, &launcher).await {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("qsh-server: {e}");
                1
            }
        };
    }
    if args.on_demand {
        config.idle_exit = Some(ON_DEMAND_IDLE_EXIT);
    }
    match Daemon::run(config).await {
        Ok(()) => 0,
        Err(StartError::AlreadyRunning) => {
            eprintln!("qsh-server: a daemon is already running for this user");
            0
        }
        Err(e) => {
            eprintln!("qsh-server: {e}");
            1
        }
    }
}
