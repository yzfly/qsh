//! `qsh-server bootstrap | pipe | daemon | status | stop | upgrade | doctor | tune`: the server
//! side of qsh.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use qsh_cli::cli::{parse_ports, DaemonArgs, DoctorArgs, ServerArgs, ServerCommand, TuneArgs};
use qsh_cli::doctor::{self, checks, report, tune};
use qsh_core::config::{Config, ConfigPaths, ServerSettings};
use qsh_core::server::handoff::DaemonOptions;
use qsh_core::server::{
    self, Daemon, DaemonLauncher, Reexec, Resume, Resuming, ServerConfig, StartError, ON_DEMAND_IDLE_EXIT,
};
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
    // The new image of an upgrade in place: a frozen command line, recognized before anything
    // else, and the fallback to the old image armed first (m2.md 10.3 step 5, 10.4)
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    match Resume::from_args(&argv) {
        Some(Ok(resume)) => return ExitCode::from(resume_daemon(resume)),
        Some(Err(e)) => {
            eprintln!("qsh-server: {e}");
            return ExitCode::from(2);
        }
        None => {}
    }
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
    if let ServerCommand::Tune(args) = command {
        return tune_command(args);
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
        ServerCommand::Doctor(args) => doctor_command(&paths, &launcher, args).await,
        ServerCommand::HandoffProbe | ServerCommand::Tune(_) => 0,
    }
}

/// The daemon's panic hook: one line in its log (stderr: journald or `daemon.log`) with the
/// thread and the location, before the unwinding, so that a panic can be reported. Release
/// builds unwind (workspace `Cargo.toml`): a panic in the screen model or the codec is
/// contained and logged by its caller with the session (`qsh_core::fault`; nothing here then),
/// any other ends its task or thread, not the daemon. The message is left out when it may quote
/// a session's output.
fn log_panics() {
    std::panic::set_hook(Box::new(|info| {
        if qsh_core::fault::hook(info) {
            return;
        }
        eprintln!("qsh-server: {}", qsh_core::fault::report(info));
    }));
}

/// The daemon's port range and extra ports, from the configuration files and
/// `QSH_SERVER_PORTS`, or `--ports`; quietly (`qsh-server status` reports the files'
/// problems).
fn configured_ports(paths: &Paths, ports: Option<&str>) -> Result<(std::ops::RangeInclusive<u16>, Vec<u16>), u8> {
    let mut config = ServerConfig::new(paths.clone());
    let mut settings = Config::load(&ConfigPaths::standard(paths))
        .map(|(c, _)| c.server())
        .unwrap_or_default();
    let _ = settings.apply_process_env();
    settings.apply(&mut config);
    if let Some(text) = ports {
        match parse_ports(text) {
            Some(range) => config.ports = range,
            None => {
                eprintln!("qsh-server: bad port range {text:?}; expected FIRST-LAST");
                return Err(2);
            }
        }
    }
    Ok((config.ports, config.extra_ports))
}

/// The user the per-user checks are about, from the password database for this process.
fn doctor_user(sys: &dyn doctor::System) -> checks::User {
    let own = qsh_core::sys::passwd_entry().map(|u| (u.name, u.home.display().to_string()));
    checks::target_user(sys, own)
}

/// `qsh-server doctor` (m2.md 8.1, 8.2).
/// The system doctor and tune look at: the real one, or (tests) a stand-in root whose only
/// commands are stubs.
fn host(root: Option<&std::path::Path>, commands: Option<&std::path::Path>) -> Result<doctor::system::Host, u8> {
    match root {
        None => Ok(doctor::system::Host::real()),
        Some(root) => doctor::system::Host::stand_in(root, commands).map_err(|e| {
            eprintln!("qsh-server: {}: {e}", root.display());
            2
        }),
    }
}

async fn doctor_command(paths: &Paths, launcher: &DaemonLauncher, args: DoctorArgs) -> u8 {
    let sys = match host(args.root.as_deref(), args.commands.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let (range, extra_ports) = match configured_ports(paths, args.ports.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let user = doctor_user(&sys);
    let daemon = if user.sudo {
        checks::DaemonState::Unreachable(format!(
            "root cannot ask {}'s daemon; run qsh-server doctor as {}",
            user.name, user.name
        ))
    } else {
        // --probe starts it as a bootstrap would, so that its ports and certificate are known
        let started = match args.probe {
            true => server::connect_or_start(paths, launcher).await.map(drop),
            false => Ok(()),
        };
        let socket = paths.control_socket();
        match (started, server::request_status(paths).await) {
            (_, Ok(Some(status))) => checks::DaemonState::Running(status),
            (Err(e), _) => checks::DaemonState::Failed(
                format!("{} ({e})", socket.display()),
                paths.daemon_log().display().to_string(),
            ),
            (Ok(()), Ok(None)) => checks::DaemonState::NotRunning,
            (Ok(()), Err(e)) => checks::DaemonState::Unreachable(format!("{}: {e}", socket.display())),
        }
    };
    let host = checks::HostInfo::read(&sys);
    let ctx = checks::Context {
        version: server::version().to_string(),
        exe: std::env::current_exe().ok().map(|p| p.display().to_string()),
        range,
        extra_ports,
        daemon,
        probe: args.probe,
        user,
    };
    let results = checks::run_all(&sys, &host, &ctx);
    use std::io::Write;
    let mut stdout = std::io::stdout();
    let text = if args.json {
        let value = report::json(&host, &ctx.daemon, ctx.probe, &results);
        // One line for programs (qsh doctor HOST reads it over ssh), indented for people
        if qsh_core::sys::is_tty(&stdout) {
            format!("{value:#}\n")
        } else {
            format!("{value}\n")
        }
    } else {
        report::human(&host, &results, &report::Style::for_stdout())
    };
    if stdout.write_all(text.as_bytes()).and_then(|()| stdout.flush()).is_err() {
        return 2;
    }
    doctor::exit_status(&results)
}

/// `qsh-server tune` (m2.md 8.4).
fn tune_command(args: TuneArgs) -> u8 {
    let paths = Paths::from_env();
    let sys = match host(args.root.as_deref(), args.commands.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let (range, extra) = match configured_ports(&paths, args.ports.as_deref()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let host = checks::HostInfo::read(&sys);
    let user = doctor_user(&sys);
    let ports = doctor::firewall::Ports {
        udp: *range.start(),
        tcp: *range.start(),
        range,
        extra,
    };
    let request = tune::Request {
        apply: args.apply,
        revert: args.revert,
        yes: args.yes,
        options: tune::Options {
            bbr_default: args.bbr_default,
            low_ports: args.allow_low_ports,
            linger: args.linger,
            ports,
        },
    };
    // A stand-in root is the invoking user's own directory, changed with the user's own
    // rights; its commands are stubs (security.md 4.9)
    let needs_root = sys.is_real() && qsh_core::sys::euid() != 0;
    let mut ask = |question: &str| -> Option<bool> {
        use std::io::{BufRead, Write};
        let stdin = std::io::stdin();
        if !qsh_core::sys::is_tty(&stdin) {
            return None;
        }
        print!("{question}");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        stdin.lock().read_line(&mut answer).ok()?;
        Some(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
    };
    tune::command(
        &sys,
        &host,
        &user,
        &request,
        needs_root,
        &mut ask,
        &mut std::io::stdout(),
    )
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
    log_panics();
    let mut config = ServerConfig::new(paths.clone());
    server_settings(&paths).apply(&mut config);
    // The command line (or QSH_SERVER_PORTS through it) over the files
    let ports = match &args.ports {
        Some(text) => match parse_ports(text) {
            Some(range) => Some((*range.start(), *range.end())),
            None => {
                eprintln!("qsh-server: bad port range {text:?}; expected FIRST-LAST");
                return 2;
            }
        },
        None => None,
    };
    // A daemon in a program of its own upgrades in place, handing the next image these options
    // in the state (m2.md 10.3 step 5)
    apply_options(
        &mut config,
        DaemonOptions {
            on_demand: args.on_demand,
            ports,
        },
    );
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
    let result = Daemon::run_until(config, stop_signal()).await;
    daemon_exit(result)
}

/// The daemon's options and the reexec of a daemon that is a program of its own.
fn apply_options(config: &mut ServerConfig, options: DaemonOptions) {
    if let Some((first, last)) = options.ports {
        config.ports = first..=last;
    }
    if options.on_demand {
        config.idle_exit = Some(ON_DEMAND_IDLE_EXIT);
    }
    let mut reexec = Reexec::new(options);
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
}

/// `qsh-server handoff-resume …`: the new image of an upgrade in place (m2.md 10.3 steps 7 to
/// 9). The fallback is armed before anything else; from then on every failure executes the
/// old image again (Linux) instead of losing the sessions.
fn resume_daemon(resume: Resume) -> u8 {
    log::set_level(log::Level::Info);
    log_panics();
    let resuming = match Resuming::begin(resume) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qsh-server: cannot resume: {e}");
            return 1;
        }
    };
    let paths = Paths::from_env();
    let mut config = ServerConfig::new(paths.clone());
    server_settings(&paths).apply(&mut config);
    apply_options(&mut config, resuming.options());
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let e = resuming.fail(&format!("cannot start the async runtime: {e}"));
            eprintln!("qsh-server: {e}");
            return 1;
        }
    };
    let code = runtime.block_on(async { daemon_exit(Daemon::resume_until(config, resuming, stop_signal()).await) });
    runtime.shutdown_background();
    code
}

/// SIGTERM (service managers) and SIGINT stop the daemon as `qsh-server stop` does: every
/// session is ended and each attached client gets its final message (protocol.md 7.13).
async fn stop_signal() {
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
}

fn daemon_exit(result: Result<(), StartError>) -> u8 {
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
