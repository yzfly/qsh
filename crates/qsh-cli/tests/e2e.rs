//! qsh end to end on one machine: see `common` for the test world.

mod common;

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;

#[test]
fn a_command_round_trip_keeps_output_input_and_exit_code() {
    let mut world = World::new("echo");
    // QUIC only, for the connection count below: on a slow machine TLS, 400 ms later, could win
    world.set("QSH_TRANSPORTS", "quic");
    // No terminal: plain bytes out, the remote exit status back
    let out = world
        .qsh(&["srv", "--", "echo hi; exit 7"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hi\n",
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(7));
    // stdin reaches the program, and its end ends the program's input
    let mut child = world
        .qsh(&["srv", "cat; echo done"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"line one\nline two").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "line one\nline twodone\n");
    assert_eq!(out.status.code(), Some(0));
    // A program killed by a signal: 128 + the signal, like a shell
    let out = world
        .qsh(&["srv", "kill -TERM $$"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(143));
    let stats = world.stats();
    assert_eq!(stats["quic_connections"], 3, "{stats}");
    // Finished sessions are gone from the daemon
    wait_until(
        Duration::from_secs(5),
        || world.status().unwrap()["sessions"].as_array().unwrap().is_empty(),
        "sessions removed",
        true,
    );
}

#[test]
fn a_host_without_qsh_server_exits_42_with_a_hint() {
    let world = World::new("nosrv");
    let out = world
        .qsh(&["user@nosrv", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(42));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("qsh-server is not installed on user@nosrv") && stderr.contains("ssh user@nosrv 'curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh -s -- --server-only'"),
        "{stderr}"
    );
    // Never a question without a terminal
    assert!(!stderr.contains("[Y/n]"), "{stderr}");
    // ssh failing itself is 255
    let mut w = World::new("nossh");
    w.set("PATH", "/usr/bin:/bin");
    w.set("QSH_SSH", "/nonexistent/ssh");
    let out = w.qsh(&["srv", "true"]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(255));
}

#[test]
fn when_udp_is_blocked_tls_wins() {
    let mut world = World::new("tls");
    world.block_udp();
    let run = || {
        let started = Instant::now();
        let out = world
            .qsh(&["srv", "echo over-tls"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "over-tls\n",
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        started.elapsed()
    };
    // The first run starts the daemon, which a slow machine takes a while for; the second is
    // timed: well before QUIC's 8 s timeout, TLS started 400 ms in and won
    run();
    let took = run();
    assert!(took < Duration::from_secs(6), "took {took:?}");
    let stats = world.stats();
    assert_eq!(stats["tls_connections"], 2, "{stats}");
    assert_eq!(stats["quic_connections"], 0, "{stats}");
}

/// The interactive case: a program on a terminal keeps running while the transport is killed;
/// the client reconnects and gets every byte of output it missed, in order.
#[test]
fn an_interactive_session_survives_a_killed_transport() {
    let mut world = World::new("resume");
    // Only the ssh pipe gets through: its process can be killed to break the connection
    world.block_udp();
    world.block_tcp();
    // qsh's log (and its messages, like ~s) in a file, printed if this fails
    let log = world.dir.join("qsh.log");
    let mut tty = Tty::spawn_logged(world.qsh(&["-vv", "srv", TICKER]), log);
    tty.wait_for("tick-5\r", Duration::from_secs(20));
    assert_eq!(world.stats()["pipe_connections"], 1);

    // Escapes: ~s shows the connection
    tty.send(b"\r~s");
    tty.wait_for_log("srv over ssh", Duration::from_secs(10));

    // The ssh pipe: the fake ssh's shells and qsh-server pipe under them
    let pipes = descendants(tty.child.id(), "pipe --version");
    assert!(!pipes.is_empty(), "no ssh pipe");
    let before = ticks(&tty.text()).last().copied().unwrap();
    for pid in &pipes {
        kill(*pid);
    }
    wait_until(
        Duration::from_secs(5),
        || pipes.iter().all(|p| !alive(*p)),
        "the pipe to die",
        true,
    );
    // While the client reconnects (back-off, then the pipe's 3 s head start for QUIC and TLS)
    // the ticker goes on; afterwards everything it printed arrives
    tty.wait_for(&format!("tick-{}\r", before + 120), Duration::from_secs(60));
    let seen = ticks(&tty.text());
    let expected: Vec<u64> = (1..=*seen.last().unwrap()).collect();
    assert_eq!(seen, expected, "ticks lost or repeated across the reconnect");
    let pipes = world.stats()["pipe_connections"].as_u64().unwrap();
    assert!(pipes >= 2, "reconnected over a new pipe: {}", world.stats());

    // Ctrl-C reaches the remote program; its status comes back
    tty.send(b"\x03");
    assert_eq!(tty.exit_code(Duration::from_secs(15)), 130);
}

/// The ticker the tests interrupt with Ctrl-C ends on it in every shell, even when the SIGINT
/// comes right after one of its `sleep`s ended normally: bash then takes the signal as handled
/// by the child and goes on, unless the script traps it (see [`TICKER`]). The shell is stopped
/// in the middle of a `sleep` and only continued once that has ended and Ctrl-C was typed, which
/// is the race made certain.
#[test]
fn the_ticker_ends_on_ctrl_c_in_every_shell() {
    let mut seen = std::collections::HashSet::new();
    let shells = [
        "/bin/sh",
        "/bin/bash",
        "/bin/dash",
        "/bin/zsh",
        "/usr/bin/zsh",
        "/bin/ksh",
    ]
    .into_iter()
    .filter(|s| std::fs::canonicalize(s).is_ok_and(|real| seen.insert(real)));
    for shell in shells {
        let mut command = std::process::Command::new(shell);
        command.args(["-c", TICKER]);
        // Its own session, with the terminal as its controlling terminal: ^C is a SIGINT
        qsh_core::sys::spawn_on_pty(&mut command);
        let mut tty = Tty::spawn(command);
        tty.wait_for("tick-3\r", Duration::from_secs(20));
        let pid = tty.child.id() as i32;
        // In the middle of the `sleep 0.05` after tick-3
        std::thread::sleep(Duration::from_millis(25));
        signal(pid, "-STOP");
        std::thread::sleep(Duration::from_millis(300));
        tty.send(b"\x03");
        std::thread::sleep(Duration::from_millis(100));
        signal(pid, "-CONT");
        // Ended: by its trap (130), or by the signal itself (as qsh would report it: 128 + 2)
        let deadline = Instant::now() + patience(Duration::from_secs(20));
        let status = loop {
            if let Some(status) = tty.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "{shell} went on after ^C: {:?}", tty.text());
            std::thread::sleep(Duration::from_millis(50));
        };
        use std::os::unix::process::ExitStatusExt;
        let code = status.code().or(status.signal().map(|s| 128 + s));
        assert_eq!(code, Some(130), "{shell}: {status:?}");
    }
}

#[test]
fn detach_keeps_the_session_and_hangup_ends_it() {
    let world = World::new("detach");
    let mut tty = Tty::spawn(world.qsh(&["srv", "echo ready; exec cat"]));
    tty.wait_for("ready", Duration::from_secs(20));
    tty.send(b"hello\r");
    tty.wait_for("hello", Duration::from_secs(5));
    tty.send(b"\r~d");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    assert!(tty.text().contains("detached"), "{:?}", tty.text());
    let status = world.status().unwrap();
    let sessions = status["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "{status}");
    assert_eq!(sessions[0]["attached"], 0);
    assert_eq!(sessions[0]["exited"], false);

    // ~. ends the session: the program gets SIGHUP and the session is removed
    let mut tty = Tty::spawn(world.qsh(&["srv", "echo second; exec cat"]));
    tty.wait_for("second", Duration::from_secs(20));
    tty.send(b"\r~.");
    let code = tty.exit_code(Duration::from_secs(10));
    assert_eq!(code, 129, "{:?}", tty.text());
    wait_until(
        Duration::from_secs(5),
        || world.status().unwrap()["sessions"].as_array().unwrap().len() == 1,
        "the hung up session to go",
        true,
    );
}

/// Review M3: without a terminal, `qsh host cmd` is a pipe session: every byte value, long
/// lines and control characters arrive exactly, as with ssh.
#[test]
fn a_pipe_session_is_byte_exact() {
    let world = World::new("bytes");
    let mut data: Vec<u8> = (0..=255u8).cycle().take(256 * 1200).collect();
    // A 1 MiB line, and what a terminal would have turned into signals and line edits
    data.extend(std::iter::repeat_n(b'a', 1 << 20));
    data.extend_from_slice(b"\r\n\x03\x04\x13\x11\x1a\x1c\x7f\n");
    let mut child = world
        .qsh(&["srv", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = data.clone();
    let feeder = std::thread::spawn(move || stdin.write_all(&input).unwrap());
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout.len(), data.len());
    assert!(out.stdout == data, "the bytes differ");
}

/// Pipe sessions keep stderr apart (to qsh's stderr), and deliver the end of input.
#[test]
fn a_pipe_session_keeps_stderr_apart_and_ends_input() {
    let world = World::new("stderr");
    let out = world
        .qsh(&["srv", "--", "echo out; echo err >&2; exit 3"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "out\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
    assert_eq!(out.status.code(), Some(3));
    // printf x | qsh host -- 'cat; echo done >&2'
    let mut child = world
        .qsh(&["srv", "--", "cat; echo done >&2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.stdout, b"x");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "done\n");
    assert_eq!(out.status.code(), Some(0));
}

/// Review L1: stopping the daemon (`qsh-server stop`, or SIGTERM from a service manager) ends
/// each session with its exit status at the client, and the client does not start a new daemon
/// through the ssh pipe afterwards.
#[test]
fn stopping_the_daemon_ends_sessions_cleanly_and_for_good() {
    for how in ["stop", "TERM"] {
        let world = World::new(&format!("stop-{how}"));
        let mut tty = Tty::spawn(world.qsh(&["srv", "echo ready; exec sleep 1000"]));
        tty.wait_for("ready", Duration::from_secs(20));
        let pid = world.status().unwrap()["pid"].as_u64().unwrap() as i32;
        if how == "stop" {
            assert!(world.command(QSH_SERVER, &["stop"]).status().unwrap().success());
        } else {
            signal(pid, "-TERM");
        }
        // The program got SIGHUP, and its status came back
        assert_eq!(tty.exit_code(Duration::from_secs(15)), 129, "{how}: {:?}", tty.text());
        wait_until(Duration::from_secs(5), || !alive(pid), "the daemon to exit", true);
        // Nothing started a new one
        std::thread::sleep(Duration::from_secs(1));
        assert!(world.status().is_none(), "{how}: a daemon was started again");
    }
}

/// Review L2: a qsh ended by a signal puts the terminal back into its normal mode.
#[test]
fn the_terminal_mode_comes_back_when_qsh_is_killed() {
    let world = World::new("termios");
    let mut tty = Tty::spawn(world.qsh(&["srv", "echo ready; exec sleep 1000"]));
    tty.wait_for("ready", Duration::from_secs(20));
    assert!(!tty.cooked(), "raw while connected");
    signal(tty.child.id() as i32, "-TERM");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 143);
    assert!(tty.cooked(), "the terminal was left in raw mode");
}

/// The id prefix `qsh` prints in "back with: qsh attach srv ID".
fn attach_hint(text: &str) -> String {
    let at = text.find("back with: qsh attach srv ").expect("the attach hint") + "back with: qsh attach srv ".len();
    text[at..].chars().take_while(|c| c.is_ascii_hexdigit()).collect()
}

/// A new client attaches FRESH with output from 0 and gets everything the server still buffers.
/// A tty session keeps its output as scrollback, acknowledged or not (up to the replay
/// capacity), so that is the whole history from tick 1, in order, without holes; the previous
/// client ran long enough (tick 12) for its ACKs to reach the server first, which used to trim it.
fn assert_replays_the_whole_history(all: &[u64]) {
    assert_eq!(all.first(), Some(&1), "the scrollback is replayed from the start");
    let expected: Vec<u64> = (1..=*all.last().unwrap()).collect();
    assert_eq!(all, expected, "ticks lost or repeated");
}

/// `~d`, then `qsh attach srv`: everything the program printed while nobody watched arrives
/// (FRESH, output from 0), with no ssh involved.
#[test]
fn attach_after_detach_replays_the_missed_output() {
    let world = World::new("reattach");
    let mut tty = Tty::spawn(world.qsh(&["srv", TICKER]));
    tty.wait_for("tick-12\r", Duration::from_secs(20));
    tty.send(b"\r~d");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    let text = tty.text();
    let seen = ticks(&text).last().copied().unwrap();
    let id = attach_hint(&text);
    assert_eq!(id.len(), 8, "{text:?}");
    // The credentials are saved, in a private file
    let saved = world.saved();
    assert_eq!(saved.len(), 1, "{saved:?}");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&saved[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(world.sessions_dir()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // `qsh ls` without a host: the saved sessions, no network
    let (code, out, _) = world.run(&["ls"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("DESTINATION") && out.contains(&id) && out.contains("saved"),
        "{out}"
    );
    std::thread::sleep(Duration::from_secs(1));
    let bootstraps = world.bootstraps();
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv"]));
    tty.wait_for(&format!("tick-{}\r", seen + 30), Duration::from_secs(20));
    assert_replays_the_whole_history(&ticks(&tty.text()));
    assert_eq!(world.bootstraps(), bootstraps, "no ssh: {}", world.ssh_log());
    // While attached, `qsh ls` says so
    let (_, out, _) = world.run(&["ls"]);
    assert!(out.contains("attached here"), "{out}");
    tty.send(b"\r~s");
    tty.wait_for(&format!("session {id}"), Duration::from_secs(5));
    // The program ends: the saved session is gone with it
    tty.send(b"\x03");
    assert_eq!(tty.exit_code(Duration::from_secs(15)), 130);
    assert!(world.saved().is_empty(), "{:?}", world.saved());
    let (_, out, _) = world.run(&["ls", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["sessions"].as_array().unwrap().len(), 0, "{v}");
}

/// A client killed with SIGKILL leaves its session behind; `qsh attach` takes it back with the
/// saved credentials, at once (the newest attachment wins), without ssh.
#[test]
fn attach_after_the_client_was_killed() {
    let world = World::new("killed");
    let mut tty = Tty::spawn(world.qsh(&["srv", TICKER]));
    tty.wait_for("tick-12\r", Duration::from_secs(20));
    kill(tty.child.id() as i32);
    let _ = tty.exit_code(Duration::from_secs(5));
    let seen = ticks(&tty.text()).last().copied().unwrap();
    let bootstraps = world.bootstraps();
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv"]));
    tty.wait_for(&format!("tick-{}\r", seen + 20), Duration::from_secs(20));
    assert_replays_the_whole_history(&ticks(&tty.text()));
    assert_eq!(world.bootstraps(), bootstraps, "no ssh: {}", world.ssh_log());
    tty.send(b"\x03");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 130);
    assert!(world.saved().is_empty());
}

/// Saved credentials that are no longer valid (an old copy of the state file: the key was
/// rotated since) are refused by the server (AUTH_FAILED); qsh gets new ones over ssh
/// (bootstrap op `attach`) and attaches the same session.
#[test]
fn attach_falls_back_to_ssh_when_the_saved_key_is_stale() {
    let world = World::new("stale");
    let mut tty = Tty::spawn(world.qsh(&["srv", "echo ready; exec cat"]));
    tty.wait_for("ready", Duration::from_secs(20));
    tty.send(b"\r~d");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    let file = world.saved().pop().unwrap();
    let old = std::fs::read(&file).unwrap();
    // Attaching rotates the key and saves the new one
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv"]));
    tty.wait_for("ready", Duration::from_secs(20));
    tty.send(b"\r~d");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    assert_ne!(std::fs::read(&file).unwrap(), old, "the new key was saved");
    // Back to the old key
    std::fs::write(&file, &old).unwrap();
    let bootstraps = world.bootstraps();
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv"]));
    tty.wait_for("ready", Duration::from_secs(20));
    tty.send(b"hello\r");
    tty.wait_for("hello", Duration::from_secs(10));
    let log = world.ssh_log();
    assert_eq!(world.bootstraps(), bootstraps + 1, "one bootstrap: {log}");
    assert!(
        world.stats()["attach_failures"].as_u64().unwrap() >= 1,
        "{}",
        world.stats()
    );
    assert_ne!(std::fs::read(&file).unwrap(), old, "the re-issued key was saved");
    tty.send(b"\r~.");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 129);
}

/// `qsh ls srv` lists the host's sessions, `qsh kill` ends them, one or all.
#[test]
fn ls_and_kill_over_ssh() {
    let world = World::new("lskill");
    let mut ids = Vec::new();
    for word in ["first", "second"] {
        let mut tty = Tty::spawn(world.qsh(&["srv", &format!("echo {word}; exec sleep 1000")]));
        tty.wait_for(word, Duration::from_secs(20));
        tty.send(b"\r~d");
        assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
        ids.push(attach_hint(&tty.text()));
    }
    let (code, out, err) = world.run(&["ls", "srv"]);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(
        lines[0].starts_with("ID ") && lines[0].contains("STATE") && lines[0].contains("COMMAND"),
        "{out}"
    );
    for (line, (id, word)) in lines[1..].iter().zip(ids.iter().zip(["first", "second"])) {
        assert!(line.starts_with(id.as_str()), "oldest first: {out}");
        assert!(
            line.contains("detached") && line.contains("tty") && line.contains(word),
            "{out}"
        );
    }
    let (_, out, _) = world.run(&["ls", "--json", "srv"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let sessions = v["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2, "{v}");
    assert_eq!(sessions[0]["attached"], false);
    assert_eq!(sessions[0]["session"].as_str().unwrap().len(), 32);
    assert!(!out.contains("key"), "never a key: {out}");
    // A prefix, and the saved file goes with the session
    let (code, out, err) = world.run(&["kill", "srv", &ids[0][..6]]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains(&format!("ended session {}", ids[0])), "{out}");
    assert_eq!(world.saved().len(), 1);
    let (_, out, _) = world.run(&["ls", "srv"]);
    assert!(!out.contains(&ids[0]) && out.contains(&ids[1]), "{out}");
    // Unknown
    let (code, _, err) = world.run(&["kill", "srv", "0123456789abcdef0123456789abcdef"]);
    assert_eq!(code, 255);
    assert!(err.contains("no session 01234567 on srv"), "{err}");
    let (code, _, err) = world.run(&["kill", "srv", "nosuchname"]);
    assert_eq!(code, 255);
    assert!(err.contains("no session nosuchname on srv"), "{err}");
    // Everything
    let (code, out, err) = world.run(&["kill", "srv", "--all"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains(&format!("ended session {}", ids[1])), "{out}");
    let (_, out, _) = world.run(&["ls", "srv"]);
    assert_eq!(out.trim(), "no sessions on srv");
    assert!(world.saved().is_empty());
    wait_until(
        Duration::from_secs(5),
        || world.status().unwrap()["sessions"].as_array().unwrap().is_empty(),
        "the sessions to end",
        true,
    );
}

/// Without saved credentials (another machine started them), `qsh attach` asks the host:
/// one detached session is taken, several are a choice, which a script cannot make.
#[test]
fn attach_without_saved_credentials_asks_the_host() {
    let world = World::new("nosaved");
    for word in ["alpha", "beta"] {
        let mut tty = Tty::spawn(world.qsh(&["srv", &format!("echo {word}; exec cat")]));
        tty.wait_for(word, Duration::from_secs(20));
        tty.send(b"\r~d");
        assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    }
    for f in world.saved() {
        std::fs::remove_file(f).unwrap();
    }
    let (code, _, err) = world.run(&["attach", "srv"]);
    assert_eq!(code, 255);
    assert!(
        err.contains("2 detached sessions on srv") && err.contains("alpha") && err.contains("beta"),
        "{err}"
    );
    // On a terminal: a question
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv"]));
    tty.wait_for("Attach which? [1-2]", Duration::from_secs(20));
    tty.send(b"2\r");
    tty.wait_for("beta", Duration::from_secs(20));
    tty.send(b"typed\r");
    tty.wait_for("typed\r\ntyped", Duration::from_secs(10));
    tty.send(b"\r~d");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    // Now saved here: by name or prefix, without ssh
    assert_eq!(world.saved().len(), 1);
    let id = attach_hint(&tty.text());
    let bootstraps = world.bootstraps();
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv", &id]));
    tty.wait_for("typed", Duration::from_secs(20));
    assert_eq!(world.bootstraps(), bootstraps);
    tty.send(b"\r~.");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 129);
    // One detached session left, not saved here: taken without a question
    let mut tty = Tty::spawn(world.qsh(&["attach", "srv"]));
    tty.wait_for("alpha", Duration::from_secs(20));
    tty.send(b"\r~.");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 129);
    let (code, _, err) = world.run(&["attach", "srv"]);
    assert_eq!(code, 255);
    assert!(err.contains("no sessions on srv"), "{err}");
}

/// A host named like a subcommand is reached with `--`.
#[test]
fn a_host_named_ls_is_reached_with_double_dash() {
    let world = World::new("hostls");
    let (code, out, err) = world.run(&["--", "ls", "echo", "host-named-ls"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "host-named-ls\n");
    assert!(
        world.ssh_log().lines().any(|l| l.starts_with("ls ")),
        "{}",
        world.ssh_log()
    );
}

/// Path memory from the command line (m2.md 3.5, S1): after a run on a network where UDP is
/// blocked, the next run starts TLS at once (the transcript's `plan`), and what is remembered
/// is in a private file that names no host.
#[test]
fn the_next_run_starts_with_what_worked_last_time() {
    use std::os::unix::fs::PermissionsExt;
    let mut world = World::new("memory");
    world.block_udp();
    let transcript = world.dir.join("transcript.jsonl");
    world.set("QSH_TRANSCRIPT", transcript.display().to_string());
    for _ in 0..2 {
        let out = world
            .qsh(&["srv", "echo remembered"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "remembered\n",
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let memory = world.dir.join("state/qsh/paths.json");
    if !memory.exists() {
        // A machine without a default route has no network to remember anything for
        eprintln!("no path memory written (no default route?)");
        return;
    }
    assert_eq!(std::fs::metadata(&memory).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!std::fs::read_to_string(&memory).unwrap().contains("127.0.0.1"));
    let plans: Vec<serde_json::Value> = std::fs::read_to_string(&transcript)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v["ev"] == "plan")
        .collect();
    assert_eq!(plans.len(), 2, "{plans:?}");
    let tls_start = |plan: &serde_json::Value| {
        plan["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["transport"] == "TLS")
            .map(|a| a["delay_ms"].as_u64().unwrap())
    };
    assert_eq!(
        (plans[0]["remembered"].as_bool(), tls_start(&plans[0])),
        (Some(false), Some(400))
    );
    assert_eq!(
        (plans[1]["remembered"].as_bool(), tls_start(&plans[1])),
        (Some(true), Some(0))
    );
}
