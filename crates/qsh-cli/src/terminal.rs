//! A session on this process's terminal: raw mode, window size changes, escapes and the
//! status line; or, when stdin is not a terminal (a script), a pipe session: stdin, stdout and
//! stderr carried byte for byte, the program's input closed at end of file, as with ssh.

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_core::client::store::SavedSession;
use qsh_core::client::{self, ClientConfig, ClientError, Event, Input, Outcome, Session, Status, Terminal};
use qsh_core::proto::bootstrap::SessionInfo;
use qsh_core::proto::WindowSize;
use qsh_core::sys::{self, RawMode};
use qsh_core::transport::ssh::sh_quote;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::escape::{self, Action, EscapeFilter};
use crate::screen::{self, AltScreen};

/// The install script of the latest release, which `--server-only` turns into a server install.
const INSTALL_URL: &str = "https://github.com/yzfly/qsh/releases/latest/download/install.sh";

/// Tell the user about a lost connection only when it stays lost this long.
const OUTAGE_NOTICE_AFTER: Duration = Duration::from_secs(3);

/// How often the notice on a full-screen program's bottom line is redrawn (its clock).
const NOTICE_REFRESH: Duration = Duration::from_secs(1);

/// How a session starts.
#[derive(Debug, Clone)]
pub enum Start {
    /// A new session (`qsh host [command]`).
    New,
    /// A session whose credentials are saved here (`qsh attach`).
    Saved(Box<SavedSession>),
    /// A session on the host whose credentials are issued over ssh (`qsh attach`).
    Remote {
        /// The session id, 32 hex digits.
        session: String,
        /// What `list` said about it.
        info: Option<SessionInfo>,
    },
}

/// How the terminal side behaves (qsh_config(5)).
#[derive(Debug, Clone)]
pub struct TerminalOptions {
    /// The escape character; None: no escapes (`escape_char`).
    pub escape: Option<u8>,
    /// Tell the user when the connection is lost (`status_line`).
    pub status_line: bool,
    /// On a terminal, offer to install qsh-server on a host that has none (`install = "ask"`;
    /// only in builds with the `self-install` feature).
    pub offer_install: bool,
    /// Say more (`-v`).
    pub verbose: bool,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        TerminalOptions {
            escape: Some(escape::ESCAPE),
            status_line: true,
            offer_install: true,
            verbose: false,
        }
    }
}

/// The terminal size of stdout, else stdin, else 80x24.
pub fn window_size() -> WindowSize {
    let (cols, rows) = sys::window_size(&std::io::stdout())
        .or_else(|| sys::window_size(&std::io::stdin()))
        .unwrap_or((80, 24));
    WindowSize::new(cols, rows)
}

/// Write a line for the user on stderr (which may be in raw mode: `\r\n`).
fn say(text: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "\r\nqsh: {text}\r\n");
    let _ = stderr.flush();
}

/// A byte count for people.
pub fn human_bytes(n: u64) -> String {
    match n {
        0..=9999 => format!("{n} B"),
        10_000..=9_999_999 => format!("{:.1} kB", n as f64 / 1e3),
        _ => format!("{:.1} MB", n as f64 / 1e6),
    }
}

/// A duration for people: `42s`, `3m05s`, `2h07m`, `3d04h`.
pub fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{:02}s", s / 60, s % 60),
        3600..=86399 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d{:02}h", s / 86400, s % 86400 / 3600),
    }
}

/// The `~s` line: the connection, its round trip time, the bytes, how long this attachment
/// has lasted.
pub fn status_line(destination: &str, status: &Status) -> String {
    let Some(transport) = status.transport else {
        return format!(
            "{destination}: not connected, reconnecting; {} reconnects",
            status.reconnects
        );
    };
    let mut parts = vec![format!("{destination} over {transport}")];
    if let Some(remote) = status.remote {
        let ip = qsh_core::proto::message::canonical_ip(remote.ip());
        parts.push(format!("to {}", std::net::SocketAddr::new(ip, remote.port())));
    }
    if let Some(rtt) = status.rtt {
        parts.push(format!("rtt {} ms", rtt.as_millis()));
    }
    if status.compressed.0 > 0 {
        // What arrived compressed, and its size on the wire
        parts.push(format!(
            "in {} ({} as {} zstd)",
            human_bytes(status.bytes_in),
            human_bytes(status.compressed.0),
            human_bytes(status.compressed.1)
        ));
    } else {
        parts.push(format!("in {}", human_bytes(status.bytes_in)));
    }
    parts.push(format!("out {}", human_bytes(status.bytes_out)));
    if let Some(since) = status.connected_since {
        parts.push(format!("attached {}", human_duration(since.elapsed())));
    }
    if status.reconnects > 0 {
        parts.push(format!(
            "{} reconnect{}",
            status.reconnects,
            if status.reconnects == 1 { "" } else { "s" }
        ));
    }
    if status.skipped > 0 {
        parts.push(format!("{} skipped", human_bytes(status.skipped)));
    }
    if status.snapshots > 0 {
        parts.push(format!(
            "{} screen{} sent instead of a backlog",
            status.snapshots,
            if status.snapshots == 1 { "" } else { "s" }
        ));
    }
    if status.snapshots_refused > 0 {
        // A server whose snapshots fail the client's checks (protocol.md 7.8.4)
        parts.push(format!(
            "{} snapshot{} refused (snapshots off)",
            status.snapshots_refused,
            if status.snapshots_refused == 1 { "" } else { "s" }
        ));
    }
    if status.frames_refused > 0 {
        parts.push(format!(
            "{} zstd frame{} refused",
            status.frames_refused,
            if status.frames_refused == 1 { "" } else { "s" }
        ));
    }
    parts.join(", ")
}

/// The second `~s` line: how each transport fared when this connection was made, and the
/// session.
pub fn attempts_line(status: &Status) -> Option<String> {
    let mut parts = Vec::new();
    if !status.attempts.is_empty() {
        let tried: Vec<String> = status.attempts.iter().map(|(t, o)| format!("{t} {o}")).collect();
        parts.push(format!("transports: {}", tried.join("; ")));
    }
    if let Some(id) = status.session {
        parts.push(format!("session {}", &qsh_core::crypto::hex(&id)[..8]));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// Read stdin and turn it into session input: through the escape filter on a terminal; as
/// is otherwise, with the end of input at end of file.
async fn read_input(
    tx: mpsc::Sender<Input>,
    tty: bool,
    escape: Option<u8>,
    destination: String,
    status: Arc<Mutex<Status>>,
) {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 16384];
    let mut filter = EscapeFilter::with(escape);
    loop {
        let n = match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => {
                if !tty {
                    let _ = tx.send(Input::Eof).await;
                }
                return;
            }
            Ok(n) => n,
        };
        if !tty {
            if tx.send(Input::Data(buf[..n].to_vec())).await.is_err() {
                return;
            }
            continue;
        }
        for action in filter.feed(&buf[..n]) {
            let input = match action {
                Action::Send(bytes) => Input::Data(bytes),
                Action::End => Input::Hangup,
                Action::Detach => Input::Detach,
                Action::Status => {
                    let status = status.lock().unwrap().clone();
                    let mut text = status_line(&destination, &status);
                    if let Some(more) = attempts_line(&status) {
                        text.push_str("\r\nqsh: ");
                        text.push_str(&more);
                    }
                    say(&text);
                    continue;
                }
                Action::Help => {
                    let mut stderr = std::io::stderr().lock();
                    let help = escape::help(escape.unwrap_or(escape::ESCAPE));
                    let _ = write!(stderr, "\r\n{help}");
                    let _ = stderr.flush();
                    continue;
                }
            };
            if tx.send(input).await.is_err() {
                return;
            }
        }
    }
}

/// What the terminal writer gets besides output.
enum Notice {
    /// The connection is lost: show this.
    Lost(String),
    /// It is back.
    Back,
}

/// Write the session's output to stdout, and the outage notice where it does not corrupt the
/// screen ([`crate::screen`]). `repaint` asks the program for a redraw after the notice was
/// drawn over its screen.
async fn write_output(
    mut output: mpsc::Receiver<Vec<u8>>,
    mut notices: mpsc::UnboundedReceiver<Notice>,
    repaint: Option<mpsc::WeakSender<Input>>,
) {
    let mut stdout = tokio::io::stdout();
    let mut alt = AltScreen::default();
    // An overlay is on the bottom line / a line was printed for this outage
    let mut overlay = false;
    let mut line = false;
    let mut notices_open = true;
    loop {
        let bytes = tokio::select! {
            bytes = output.recv() => match bytes {
                Some(b) => {
                    alt.feed(&b);
                    b
                }
                None => break,
            },
            notice = notices.recv(), if notices_open => match notice {
                None => {
                    notices_open = false;
                    continue;
                }
                Some(Notice::Lost(text)) => {
                    let size = window_size();
                    if alt.active() {
                        overlay = true;
                        screen::overlay(&text, size.cols, size.rows)
                    } else if !line {
                        line = true;
                        format!("\r\nqsh: {text}\r\n").into_bytes()
                    } else {
                        continue;
                    }
                }
                Some(Notice::Back) => {
                    line = false;
                    if !std::mem::take(&mut overlay) {
                        continue;
                    }
                    let size = window_size();
                    if let Some(tx) = repaint.as_ref().and_then(|w| w.upgrade()) {
                        tokio::spawn(async move {
                            let smaller = WindowSize::new(size.cols, size.rows.saturating_sub(1).max(1));
                            let _ = tx.send(Input::Resize(smaller)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            let _ = tx.send(Input::Resize(window_size())).await;
                        });
                    }
                    screen::clear_overlay(size.rows)
                }
            },
        };
        if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
            return;
        }
    }
    if overlay {
        let _ = stdout.write_all(&screen::clear_overlay(window_size().rows)).await;
        let _ = stdout.flush().await;
    }
}

/// How one attempt at running a session ended.
struct Ended {
    result: Result<Outcome, ClientError>,
    status: Status,
}

/// Run a session on this terminal and return the exit status for `qsh`. `config.tty`,
/// `config.interactive` and `config.size` are set here from the terminal.
///
/// A new session on a host without qsh-server: on a terminal, in builds with the
/// `self-install` feature, qsh offers once to install it, then connects.
pub async fn run(mut config: ClientConfig, start: Start, options: TerminalOptions) -> i32 {
    restore_on_exit();
    let tty = sys::is_tty(&std::io::stdin());
    config.tty = tty;
    // Snapshots redraw a terminal: only when the output goes to one (m2.md 6.7)
    if !sys::is_tty(&std::io::stdout()) {
        config.catchup = qsh_core::config::Catchup::Off;
    }
    config.interactive = tty || sys::is_tty(&std::io::stderr());
    config.size = window_size();
    let mut offered = false;
    loop {
        let ended = attempt(config.clone(), start.clone(), &options).await;
        if matches!(ended.result, Err(ClientError::NoServer))
            && matches!(start, Start::New)
            && !offered
            && options.offer_install
            && cfg!(feature = "self-install")
            && tty
            && sys::is_tty(&std::io::stderr())
        {
            offered = true;
            if offer_install(&config).await {
                continue;
            }
        }
        return report(&config, ended);
    }
}

/// Ask once whether to install qsh-server on the host, and do it. True when it is installed.
#[cfg(feature = "self-install")]
async fn offer_install(config: &ClientConfig) -> bool {
    let destination = config.ssh.destination.clone();
    let question = format!("qsh-server is not installed on {destination}. Install it to ~/.local/bin there? [Y/n] ");
    let answer = tokio::task::spawn_blocking(move || {
        eprint!("qsh: {question}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await;
    let yes = match answer {
        Ok(Ok(line)) => matches!(line.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes"),
        _ => false,
    };
    if !yes {
        return false;
    }
    let ssh = config.ssh.clone();
    let options = crate::install::Options::from_env(None, config.interactive);
    let installed = tokio::task::spawn_blocking(move || {
        crate::install::install(&ssh, &options, &mut |line| eprintln!("qsh: {line}"))
    })
    .await;
    match installed {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            eprintln!("qsh: {e}");
            false
        }
        Err(e) => {
            eprintln!("qsh: {e}");
            false
        }
    }
}

#[cfg(not(feature = "self-install"))]
async fn offer_install(_config: &ClientConfig) -> bool {
    false
}

/// The command that installs qsh-server on the host, for people to run.
pub fn install_hint(config: &ClientConfig) -> String {
    let options: Vec<String> = config
        .ssh
        .options
        .iter()
        .map(|o| sh_quote(&o.to_string_lossy()))
        .collect();
    let destination = sh_quote(&config.ssh.destination);
    let mut ssh = vec!["ssh".to_string()];
    ssh.extend(options.iter().cloned());
    ssh.push(destination.clone());
    let manual = format!("{} 'curl -fsSL {INSTALL_URL} | sh -s -- --server-only'", ssh.join(" "));
    if cfg!(feature = "self-install") {
        let mut qsh = vec!["qsh".to_string(), "install".to_string()];
        qsh.extend(options);
        qsh.push(destination);
        format!("{}\nor:\n  {manual}", qsh.join(" "))
    } else {
        manual
    }
}

/// Tell the user how the session ended, and the exit status for it.
fn report(config: &ClientConfig, ended: Ended) -> i32 {
    let destination = &config.ssh.destination;
    let short_id = ended
        .status
        .session
        .map(|id| qsh_core::crypto::hex(&id)[..8].to_string());
    match ended.result {
        Ok(Outcome::Exited(status)) => client::exit_code(&status),
        Ok(Outcome::Detached) => {
            let again = match &short_id {
                Some(id) if config.store.is_some() => format!("; back with: qsh attach {destination} {id}"),
                _ => String::new(),
            };
            say(&format!("detached; the session keeps running on {destination}{again}"));
            0
        }
        Ok(Outcome::Abandoned) => {
            say(&format!(
                "{destination} cannot be reached; the session keeps running there"
            ));
            client::EXIT_ERROR
        }
        Err(ClientError::NoServer) => {
            eprintln!(
                "qsh: qsh-server is not installed on {destination}; install it there (no root needed) with:\n  {}",
                install_hint(config)
            );
            client::EXIT_NO_SERVER
        }
        // ssh told the user what went wrong
        Err(ClientError::Ssh(_)) => client::EXIT_ERROR,
        Err(ClientError::TakenOver) => {
            say("the session was taken over by another client (qsh attach takes it back)");
            client::EXIT_ERROR
        }
        Err(e) => {
            eprintln!("qsh: {e}");
            e.exit_code()
        }
    }
}

/// One run of the session: bootstrap or attach, then the terminal until it ends.
async fn attempt(config: ClientConfig, start: Start, options: &TerminalOptions) -> Ended {
    let verbose = options.verbose;
    let escape = options.escape;
    let tty = config.tty;
    let destination = config.ssh.destination.clone();

    let (input_tx, input) = mpsc::channel::<Input>(256);
    let (output, output_rx) = mpsc::channel::<Vec<u8>>(256);
    let (errors, mut errors_rx) = mpsc::channel::<Vec<u8>>(256);
    let (events_tx, mut events) = mpsc::unbounded_channel::<Event>();
    let (notice_tx, notice_rx) = mpsc::unbounded_channel::<Notice>();
    let session = Session::new(config);
    let status = session.status();
    let mut run = tokio::spawn(async move {
        let terminal = Terminal {
            input,
            output,
            // A pipe session's stderr goes to ours, as with ssh
            errors: Some(errors),
            events: Some(events_tx),
        };
        match start {
            Start::New => session.run(terminal).await,
            Start::Saved(saved) => session.attach_saved(*saved, terminal).await,
            Start::Remote { session: id, info } => session.attach_over_ssh(&id, info.as_ref(), terminal).await,
        }
    });
    let repaint = tty.then(|| input_tx.downgrade());
    let writer = tokio::spawn(write_output(output_rx, notice_rx, repaint));
    let error_writer = tokio::spawn(async move {
        let mut stderr = tokio::io::stderr();
        while let Some(bytes) = errors_rx.recv().await {
            if stderr.write_all(&bytes).await.is_err() || stderr.flush().await.is_err() {
                break;
            }
        }
    });

    let mut raw: Option<RawMode> = None;
    let mut started = false;
    // Since when the connection is lost and the last reason; whether the user was told
    let mut outage: Option<(Instant, String)> = None;
    let mut told = false;
    let mut next_notice: Option<tokio::time::Instant> = None;
    let mut input_tx = Some(input_tx);
    let result = loop {
        tokio::select! {
            result = &mut run => break result,
            event = events.recv() => match event {
                Some(Event::Connected(transport)) => {
                    // Input is read only from now on: during the bootstrap, ssh may be asking
                    // for a password on this terminal
                    if !started {
                        started = true;
                        if tty {
                            raw = Some(RawMode::enable());
                        }
                        if let Some(tx) = input_tx.take() {
                            if tty {
                                spawn_resize(tx.clone());
                            }
                            tokio::spawn(read_input(tx, tty, escape, destination.clone(), status.clone()));
                        }
                    } else if verbose {
                        say(&format!("reconnected over {transport}"));
                    }
                    if std::mem::take(&mut told) {
                        let _ = notice_tx.send(Notice::Back);
                    }
                    outage = None;
                    next_notice = None;
                }
                Some(Event::Disconnected(why)) => {
                    if verbose {
                        say(&format!("connection lost: {why}"));
                    }
                    match outage.as_mut() {
                        Some((_, last)) => *last = why,
                        None => {
                            outage = Some((Instant::now(), why));
                            next_notice = Some(tokio::time::Instant::now() + OUTAGE_NOTICE_AFTER);
                        }
                    }
                }
                Some(Event::OutputSkipped(n)) if verbose => say(&format!("{} of output skipped", human_bytes(n))),
                Some(Event::OutputSkipped(_)) => {}
                None => {}
            },
            _ = async { tokio::time::sleep_until(next_notice.expect("guarded")).await }, if next_notice.is_some() => {
                next_notice = None;
                let Some((since, why)) = outage.as_ref() else { continue };
                if !started {
                    // Not attached yet, the terminal is as the user left it: one plain line
                    eprintln!("qsh: cannot reach {destination} yet ({why}); still trying (Ctrl-C to give up)");
                } else if tty && options.status_line {
                    let text = format!(
                        "connection to {destination} lost {} ago; reconnecting{}",
                        human_duration(since.elapsed()),
                        escape.map(|e| {
                            let e = escape::escape_name(e);
                            format!(" ({e}. quits, {e}d detaches)")
                        }).unwrap_or_default()
                    );
                    let _ = notice_tx.send(Notice::Lost(text));
                    told = true;
                    next_notice = Some(tokio::time::Instant::now() + NOTICE_REFRESH);
                }
            }
        }
    };
    drop(notice_tx);
    // The session ended: its output channels closed, let the writers finish
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), error_writer).await;
    // Let the closing connection's last packets (QUIC CONNECTION_CLOSE) leave
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(raw);
    let status = status.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let result = result.unwrap_or_else(|e| Err(ClientError::Io(std::io::Error::other(e))));
    Ended { result, status }
}

/// The terminal's mode comes back however qsh ends: a panic (restored by the hook, before the
/// unwinding; the session's task ends with it and qsh exits with the error) or a signal that
/// ends it (SIGTERM, SIGHUP, SIGQUIT, SIGINT). The process then exits with 128 + the signal, as
/// if it had died of it. A panic that qsh-core contains (its zstd decoder, `fault`) ends
/// nothing: the hook leaves the terminal alone and prints nothing into it (the session logs the
/// fault with `-v`).
fn restore_on_exit() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if qsh_core::fault::hook(info) {
            return;
        }
        sys::restore_terminal();
        previous(info);
    }));
    use tokio::signal::unix::{signal, SignalKind};
    for (kind, number) in [
        (SignalKind::terminate(), 15),
        (SignalKind::hangup(), 1),
        (SignalKind::quit(), 3),
        (SignalKind::interrupt(), 2),
    ] {
        let Ok(mut stream) = signal(kind) else { continue };
        tokio::spawn(async move {
            if stream.recv().await.is_some() {
                sys::restore_terminal();
                std::process::exit(128 + number);
            }
        });
    }
}

fn spawn_resize(tx: mpsc::Sender<Input>) {
    let Ok(mut winch) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()) else {
        return;
    };
    tokio::spawn(async move {
        while winch.recv().await.is_some() {
            if tx.send(Input::Resize(window_size())).await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_core::transport::Transport;

    #[test]
    fn the_status_line_says_what_matters() {
        let mut s = Status::default();
        assert!(status_line("h", &s).contains("not connected"));
        s.transport = Some(Transport::Quic);
        s.rtt = Some(Duration::from_millis(42));
        s.bytes_in = 12_345;
        s.reconnects = 1;
        s.connected_since = Some(Instant::now() - Duration::from_secs(125));
        let line = status_line("h", &s);
        assert!(
            line.contains("h over QUIC")
                && line.contains("rtt 42 ms")
                && line.contains("in 12.3 kB")
                && line.contains("attached 2m05s")
                && line.contains("1 reconnect"),
            "{line}"
        );
        assert!(
            !line.contains("zstd") && !line.contains("instead of a backlog"),
            "{line}"
        );
        s.compressed = (40_000_000, 10_000_000);
        s.snapshots = 2;
        let line = status_line("h", &s);
        assert!(
            line.contains("(40.0 MB as 10.0 MB zstd)") && line.contains("2 screens sent instead of a backlog"),
            "{line}"
        );
        assert!(!line.contains("refused"), "{line}");
        s.snapshots_refused = 1;
        s.frames_refused = 2;
        let line = status_line("h", &s);
        assert!(
            line.contains("1 snapshot refused (snapshots off)") && line.contains("2 zstd frames refused"),
            "{line}"
        );
        assert_eq!(attempts_line(&Status::default()), None);
        s.attempts = vec![
            (Transport::Quic, "failed: timed out".into()),
            (Transport::Tls, "used".into()),
            (Transport::Ssh, "not needed".into()),
        ];
        s.session = Some([0xab; 16]);
        assert_eq!(
            attempts_line(&s).unwrap(),
            "transports: QUIC failed: timed out; TLS used; ssh not needed; session abababab"
        );
    }

    #[test]
    fn durations_for_people() {
        assert_eq!(human_duration(Duration::from_secs(5)), "5s");
        assert_eq!(human_duration(Duration::from_secs(65)), "1m05s");
        assert_eq!(human_duration(Duration::from_secs(7322)), "2h02m");
        assert_eq!(human_duration(Duration::from_secs(90000)), "1d01h");
    }

    #[test]
    fn the_install_hint_keeps_the_ssh_options() {
        let mut config = ClientConfig::new("alice@box");
        config.ssh.options = vec!["-p".into(), "2222".into()];
        let hint = install_hint(&config);
        assert!(
            hint.contains(&format!(
                "ssh -p 2222 alice@box 'curl -fsSL {INSTALL_URL} | sh -s -- --server-only'"
            )),
            "{hint}"
        );
        assert_eq!(
            hint.contains("qsh install -p 2222 alice@box"),
            cfg!(feature = "self-install"),
            "{hint}"
        );
    }
}
