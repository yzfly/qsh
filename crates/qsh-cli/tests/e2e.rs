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
