//! qsh end to end on one machine: see `common` for the test world.

mod common;

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;

#[test]
fn a_command_round_trip_keeps_output_input_and_exit_code() {
    let world = World::new("echo");
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
        stderr.contains("qsh-server is not installed on nosrv; run: qsh install nosrv"),
        "{stderr}"
    );
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
    // Well before QUIC's 8 s timeout: TLS started 400 ms in and won
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "took {:?}",
        started.elapsed()
    );
    let stats = world.stats();
    assert_eq!(stats["tls_connections"], 1, "{stats}");
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
    let mut tty = Tty::spawn(world.qsh(&["srv", TICKER]));
    tty.wait_for("tick-5\r", Duration::from_secs(20));
    assert_eq!(world.stats()["pipe_connections"], 1);

    // Escapes: ~s shows the connection
    tty.send(b"\r~s");
    tty.wait_for("srv over ssh", Duration::from_secs(5));

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
    tty.wait_for(&format!("tick-{}\r", before + 120), Duration::from_secs(40));
    let seen = ticks(&tty.text());
    let expected: Vec<u64> = (1..=*seen.last().unwrap()).collect();
    assert_eq!(seen, expected, "ticks lost or repeated across the reconnect");
    let pipes = world.stats()["pipe_connections"].as_u64().unwrap();
    assert!(pipes >= 2, "reconnected over a new pipe: {}", world.stats());

    // Ctrl-C reaches the remote program; its status comes back
    tty.send(b"\x03");
    assert_eq!(tty.exit_code(Duration::from_secs(15)), 130);
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
