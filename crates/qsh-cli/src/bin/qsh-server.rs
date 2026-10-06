//! `qsh-server bootstrap | pipe | daemon | status | stop | upgrade`: the server side of qsh.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use qsh_cli::cli::{parse_ports, DaemonArgs, ServerArgs, ServerCommand};
use qsh_core::config::{Config, ConfigPaths, ServerSettings};
use qsh_core::server::{self, Daemon, DaemonLauncher, Reexec, Resume, ServerConfig, StartError, ON_DEMAND_IDLE_EXIT};
use qsh_core::{log, Paths};

/// Print what is wrong with the configuration files, for people (`qsh-server status`).
fn report_config(paths: &Paths) {
    match Config::load(&ConfigPaths::standard(paths)) {
        Ok((_, warnings)) => {
            for w in warnings {
                eprintln!("qsh-server: {w}");
            }
        }
        Err(e) => eprintln!("qsh-server: {e}; the daemon uses the defaults"),
    }
}

/// The `[server]` settings of the configuration files, with `QSH_SERVER_PORTS` over them.
/// A file that cannot be used is reported, and the defaults are used: a broken
/// /etc/qsh/qsh_config must not lock users out of their sessions.
fn server_settings(paths: &Paths) -> ServerSettings {
    let mut settings = match Config::load(&ConfigPaths::standard(paths)) {
        Ok((config, warnings)) => {
            for w in warnings {
                log::info(format_args!("{w}"));
            }
            config.server()
        }
        Err(e) => {
            log::info(format_args!("{e}; using the defaults"));
            ServerSettings::default()
        }
    };
    for w in settings.apply_process_env() {
        log::info(format_args!("{w}"));
    }
    settings
}

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
    if let ServerCommand::HandoffProbe = command {
        // What a daemon about to upgrade to this program asks (m2.md 10.3 step 2)
        println!("{}", server::handoff::probe_line(server::version()));
        return 0;
    }
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
        ServerCommand::Status => {
            report_config(&paths);
            status(&paths).await
        }
        ServerCommand::Stop => stop(&paths).await,
        ServerCommand::Upgrade { exe, force } => upgrade(&paths, exe, force).await,
        ServerCommand::HandoffProbe => 0,
    }
}

/// `qsh-server upgrade`: have the running daemon execute `exe` (default: this program) in
/// place, then wait until it runs it, or until it reports that it could not.
async fn upgrade(paths: &Paths, exe: Option<std::path::PathBuf>, force: bool) -> u8 {
    let exe = match exe {
        Some(p) if p.is_absolute() => p,
        Some(p) => match std::env::current_dir() {
            Ok(dir) => dir.join(p),
            Err(e) => {
                eprintln!("qsh-server: {e}");
                return 1;
            }
        },
        None => match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("qsh-server: cannot find this program: {e}");
                return 1;
            }
        },
    };
    let before = match server::request_status(paths).await {
        Ok(Some(status)) => status,
        Ok(None) => {
            eprintln!("qsh-server: no daemon is running");
            return 3;
        }
        Err(e) => {
            eprintln!("qsh-server: {e}");
            return 1;
        }
    };
    let old = before["version"].as_str().unwrap_or("?").to_string();
    if before["can_upgrade"] != true {
        eprintln!(
            "qsh-server: the running daemon ({old}) cannot upgrade in place; it is replaced when \
             its sessions have ended, or now with qsh-server stop (which ends them)"
        );
        return 1;
    }
    let count = |status: &serde_json::Value, key: &str| status[key].as_u64().unwrap_or(0);
    let (restarts, failures) = (count(&before, "restarts"), count(&before, "upgrade_failures"));
    let reply = match server::request_upgrade(paths, &exe, force).await {
        Ok(Some(reply)) => reply,
        Ok(None) => {
            eprintln!("qsh-server: no daemon is running");
            return 3;
        }
        Err(e) => {
            eprintln!("qsh-server: {e}");
            return 1;
        }
    };
    if reply["restarting"] != true {
        let error = reply["error"].as_str().unwrap_or("the daemon refused");
        if reply["not_newer"] == true {
            // Nothing to do: not a failure (systemctl reload after no package change)
            println!("qsh-server: {error}; nothing to do (--force upgrades anyway)");
            return 0;
        }
        eprintln!("qsh-server: {error}");
        return 1;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if let Ok(Some(now)) = server::request_status(paths).await {
            if count(&now, "restarts") > restarts {
                println!(
                    "qsh-server: the daemon (pid {}) runs {} now, upgraded in place from {old}; {} sessions kept",
                    now["pid"],
                    now["version"].as_str().unwrap_or("?"),
                    count(&now, "session_count")
                );
                return 0;
            }
            if count(&now, "upgrade_failures") > failures && now["upgrading"] != true {
                eprintln!(
                    "qsh-server: the upgrade failed: {}; the daemon goes on as before",
                    now["upgrade_error"].as_str().unwrap_or("unknown error")
                );
                return 1;
            }
        }
        if std::time::Instant::now() > deadline {
            eprintln!("qsh-server: the daemon did not finish the upgrade within a minute");
            return 1;
        }
    }
}

async fn status(paths: &Paths) -> u8 {
    match server::request_status(paths).await {
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
    }
}

async fn stop(paths: &Paths) -> u8 {
    match server::request_stop(paths).await {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("qsh-server: no daemon is running");
            0
        }
        Err(e) => {
            eprintln!("qsh-server: {e}");
            1
        }
    }
}

async fn daemon(paths: Paths, mut launcher: DaemonLauncher, args: DaemonArgs) -> u8 {
    let mut config = ServerConfig::new(paths.clone());
    server_settings(&paths).apply(&mut config);
    // A daemon in a program of its own upgrades in place, giving the next image these options
    // again (m2.md 10.3 step 5)
    let mut own: Vec<std::ffi::OsString> = vec!["--foreground".into()];
    if args.on_demand {
        own.push("--on-demand".into());
    }
    if let Some(ports) = &args.ports {
        own.extend(["--ports".into(), ports.into()]);
    }
    let mut reexec = Reexec::new(own);
    // Test hook (feature test-hooks): how often to look for a replaced executable, in ms
    if let Some(ms) = std::env::var("QSH_TEST_UPGRADE_CHECK_MS")
        .ok()
        .filter(|_| cfg!(feature = "test-hooks"))
        .and_then(|ms| ms.parse::<u64>().ok())
        .filter(|ms| *ms >= 10)
    {
        reexec.check_every = std::time::Duration::from_millis(ms);
    }
    config.reexec = Some(reexec);
    // The command line (or QSH_SERVER_PORTS through it) over the files
    if let Some(text) = &args.ports {
        match parse_ports(text) {
            Some(range) => config.ports = range,
            None => {
                eprintln!("qsh-server: bad port range {text:?}; expected FIRST-LAST");
                return 2;
            }
        }
    }
    if !args.foreground && !args.resume {
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
    // SIGTERM (service managers) and SIGINT stop the daemon as `qsh-server stop` does: every
    // session is ended and each attached client gets its final message (protocol.md 7.13)
    let stop = async {
        use tokio::signal::unix::{signal, SignalKind};
        match (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
            }
            _ => std::future::pending::<()>().await,
        }
    };
    let result = match (args.resume, args.state_fd, args.key_fd) {
        (true, Some(state_fd), Some(key_fd)) => {
            let resume = Resume {
                state_fd,
                key_fd,
                fallback_exe_fd: args.fallback_exe_fd,
                fell_back: args.fell_back,
            };
            Daemon::resume_until(config, resume, stop).await
        }
        _ => Daemon::run_until(config, stop).await,
    };
    match result {
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
