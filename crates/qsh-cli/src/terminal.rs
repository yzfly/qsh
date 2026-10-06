//! A session on this process's terminal: raw mode, window size changes, escapes and the
//! status line; or, when stdin is not a terminal (a script), a pipe session: stdin, stdout and
//! stderr carried byte for byte, the program's input closed at end of file, as with ssh.

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qsh_core::client::{self, ClientConfig, ClientError, Event, Input, Outcome, Session, Status, Terminal};
use qsh_core::proto::WindowSize;
use qsh_core::sys::{self, RawMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::escape::{Action, EscapeFilter, HELP};

/// Tell the user about a lost connection only when it stays lost this long.
const OUTAGE_NOTICE_AFTER: Duration = Duration::from_secs(3);

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

fn human_bytes(n: u64) -> String {
    match n {
        0..=9999 => format!("{n} B"),
        10_000..=9_999_999 => format!("{:.1} kB", n as f64 / 1e3),
        _ => format!("{:.1} MB", n as f64 / 1e6),
    }
}

/// The `~s` line.
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
    parts.push(format!("in {}", human_bytes(status.bytes_in)));
    parts.push(format!("out {}", human_bytes(status.bytes_out)));
    if let Some(since) = status.connected_since {
        parts.push(format!("connected {} s", since.elapsed().as_secs()));
    }
    if status.reconnects > 0 {
        parts.push(format!("{} reconnects", status.reconnects));
    }
    if status.skipped > 0 {
        parts.push(format!("{} skipped", human_bytes(status.skipped)));
    }
    parts.join(", ")
}

/// Read stdin and turn it into session input: through the escape filter on a terminal; as
/// is otherwise, with the end of input at end of file.
async fn read_input(tx: mpsc::Sender<Input>, tty: bool, destination: String, status: Arc<Mutex<Status>>) {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 16384];
    let mut filter = EscapeFilter::new();
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
                    say(&status_line(&destination, &status.lock().unwrap()));
                    continue;
                }
                Action::Help => {
                    let mut stderr = std::io::stderr().lock();
                    let _ = write!(stderr, "\r\n{HELP}");
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

/// Run a session described by `config` on this terminal and return the exit status for
/// `qsh`. `config.tty` and `config.size` are set here from the terminal.
pub async fn run(mut config: ClientConfig, verbose: bool) -> i32 {
    restore_on_exit();
    let tty = sys::is_tty(&std::io::stdin());
    config.tty = tty;
    config.interactive = tty || sys::is_tty(&std::io::stderr());
    config.size = window_size();
    let destination = config.ssh.destination.clone();
    let host = destination.rsplit('@').next().unwrap_or(&destination).to_string();

    let (input_tx, input) = mpsc::channel::<Input>(256);
    let (output, mut output_rx) = mpsc::channel::<Vec<u8>>(256);
    let (errors, mut errors_rx) = mpsc::channel::<Vec<u8>>(256);
    let (events_tx, mut events) = mpsc::unbounded_channel::<Event>();
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
        session.run(terminal).await
    });
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(bytes) = output_rx.recv().await {
            if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });
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
    // Since when the connection is lost, and whether the user was told
    let mut outage: Option<(Instant, bool)> = None;
    let mut input_tx = Some(input_tx);
    let result = loop {
        let notice_at = outage
            .filter(|(_, told)| !told)
            .map(|(t, _)| tokio::time::Instant::from_std(t + OUTAGE_NOTICE_AFTER));
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
                            tokio::spawn(read_input(tx, tty, destination.clone(), status.clone()));
                        }
                    } else if verbose {
                        say(&format!("reconnected over {transport}"));
                    }
                    outage = None;
                }
                Some(Event::Disconnected(why)) => {
                    if verbose {
                        say(&format!("connection lost: {why}"));
                    }
                    if started && outage.is_none() {
                        outage = Some((Instant::now(), false));
                    }
                }
                Some(Event::OutputSkipped(n)) if verbose => say(&format!("{} of output skipped", human_bytes(n))),
                Some(Event::OutputSkipped(_)) => {}
                None => {}
            },
            _ = async { tokio::time::sleep_until(notice_at.expect("guarded")).await }, if notice_at.is_some() => {
                if tty {
                    say(&format!("connection to {host} lost; reconnecting (~. to quit, ~d to detach)"));
                }
                if let Some((_, told)) = outage.as_mut() {
                    *told = true;
                }
            }
        }
    };
    // The session ended: its output channels closed, let the writers finish
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), error_writer).await;
    // Let the closing connection's last packets (QUIC CONNECTION_CLOSE) leave
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(raw);
    match result {
        Ok(Ok(Outcome::Exited(status))) => client::exit_code(&status),
        Ok(Ok(Outcome::Detached)) => {
            say(&format!("detached; the session keeps running on {host}"));
            0
        }
        Ok(Ok(Outcome::Abandoned)) => {
            say(&format!("{host} cannot be reached; the session keeps running there"));
            client::EXIT_ERROR
        }
        Ok(Err(ClientError::NoServer)) => {
            eprintln!("qsh: qsh-server is not installed on {host}; run: qsh install {host}");
            client::EXIT_NO_SERVER
        }
        // ssh told the user what went wrong
        Ok(Err(ClientError::Ssh(_))) => client::EXIT_ERROR,
        Ok(Err(e)) => {
            eprintln!("qsh: {e}");
            e.exit_code()
        }
        Err(e) => {
            eprintln!("qsh: {e}");
            client::EXIT_ERROR
        }
    }
}

/// The terminal's mode comes back however qsh ends: a panic (release builds abort, so no drop
/// runs) or a signal that ends it (SIGTERM, SIGHUP, SIGQUIT, SIGINT). The process then exits
/// with 128 + the signal, as if it had died of it.
fn restore_on_exit() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
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

    #[test]
    fn the_status_line_says_what_matters() {
        let mut s = Status::default();
        assert!(status_line("h", &s).contains("not connected"));
        s.transport = Some(qsh_core::transport::Transport::Quic);
        s.rtt = Some(Duration::from_millis(42));
        s.bytes_in = 12_345;
        let line = status_line("h", &s);
        assert!(
            line.contains("h over QUIC") && line.contains("rtt 42 ms") && line.contains("in 12.3 kB"),
            "{line}"
        );
    }
}
