//! The daemon's upgrade in place (m2.md section 10, protocol.md 10.6) end to end: the real
//! `qsh-server` executes itself again in its own process, keeping its process id, its ports and
//! its sessions, whose programs stay its children. See `common` for the test world.
//!
//! The "new" program is a copy of the same build: `--force` upgrades to a version that is not
//! newer, and `QSH_TEST_VERSION` makes a daemon look older than its requester.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

use common::*;
use serde_json::Value;

/// A copy of qsh-server in the world's `bin`, first in its PATH: the bootstrap and the daemon
/// run it. Mode 0755: a daemon only executes a program its user controls and nobody else can
/// change, and the build's own binary may be group-writable (umask 002). The world lives in
/// /tmp, which every user can write: the daemon is told not to check the directories above
/// the world (test hook; the check itself is a unit test of `handoff`).
fn install_server(world: &mut World) -> PathBuf {
    let path = world.dir.join("bin/qsh-server");
    copy_executable(Path::new(QSH_SERVER), &path);
    fs::set_permissions(&world.dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(world.dir.join("bin"), fs::Permissions::from_mode(0o755)).unwrap();
    let dir = world.dir.display().to_string();
    world.set("QSH_TEST_TRUSTED_DIR", dir);
    path
}

/// Copy a program with cp(1), mode 0755. Not fs::copy: while this process holds the copy open
/// for writing, a thread of another test may fork, and the child keeps that descriptor until
/// it executes; running the copy then fails with ETXTBSY ("Text file busy").
fn copy_executable(from: &Path, to: &Path) {
    let ok = std::process::Command::new("cp")
        .arg(from)
        .arg(to)
        .status()
        .unwrap()
        .success();
    assert!(ok, "cp {} {}", from.display(), to.display());
    fs::set_permissions(to, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Prints `tick-N` every 50 ms until `stop` exists, then exits 3.
fn ticker(stop: &Path) -> String {
    format!(
        "i=0; while [ ! -e {} ]; do i=$((i+1)); echo tick-$i; sleep 0.05; done; exit 3",
        stop.display()
    )
}

fn status(world: &World) -> Value {
    world.status().expect("a daemon")
}

fn last_tick(tty: &Tty) -> u64 {
    ticks(&tty.text()).last().copied().unwrap_or(0)
}

/// The ticker goes on: `more` ticks after the last one seen.
fn ticks_go_on(tty: &Tty, more: u64) {
    let target = last_tick(tty) + more;
    tty.wait_for(&format!("tick-{target}\r"), Duration::from_secs(30));
}

/// Stop the ticker; its exit status comes back; every tick arrived exactly once.
fn ticker_ends(tty: &mut Tty, stop: &Path) {
    fs::write(stop, b"").unwrap();
    assert_eq!(
        tty.exit_code(Duration::from_secs(30)),
        3,
        "the exit status of the program"
    );
    let seen = ticks(&tty.text());
    let expected: Vec<u64> = (1..=*seen.last().unwrap()).collect();
    assert_eq!(seen, expected, "ticks lost or repeated across the upgrade");
}

/// The session programs are still the daemon's children (descendants: the shell that runs
/// the ticker), so the daemon collects their exit statuses.
fn programs_of(pid: u64, needle: &str) -> usize {
    descendants(pid as u32, needle).len()
}

/// Milliseconds from the session's first disconnection to its next connection, from the
/// client's transcript.
fn reconnect_ms(transcript: &Path) -> Option<u64> {
    let text = fs::read_to_string(transcript).ok()?;
    let events: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let lost = events.iter().position(|e| e["ev"] == "disconnected")?;
    let back = events[lost..].iter().find(|e| e["ev"] == "connected")?;
    Some(back["ms"].as_u64()? - events[lost]["ms"].as_u64()?)
}

/// The limit of open files a new session's program gets.
fn open_files_limit(world: &World) -> String {
    let out = world
        .qsh(&["srv", "--", "ulimit -n"])
        .env("QSH_TRANSCRIPT", world.dir.join("transcript-ulimit"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn spawn_pipe_session(world: &World, command: &str, transcript: &Path) -> Child {
    world
        .qsh(&["srv", "--", command])
        .env("QSH_TRANSCRIPT", transcript)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// S7 and m2.md 10.3: `qsh-server upgrade` executes the program in place. The daemon keeps its
/// process id; a tty session goes on with every byte exactly once and its exit status comes
/// back; a pipe session whose program ends after the upgrade reports its exit code; the
/// clients reconnect within about a second of the RESTART.
#[test]
fn an_upgrade_in_place_keeps_the_pid_the_sessions_and_their_exit_codes() {
    let mut world = World::new("upgrade");
    let server = install_server(&mut world);
    let transcript = world.dir.join("transcript");
    world.set("QSH_TRANSCRIPT", transcript.display().to_string());
    let stop = world.dir.join("stop");
    let mut tty = Tty::spawn_logged(world.qsh(&["-vv", "srv", &ticker(&stop)]), world.dir.join("qsh.log"));
    tty.wait_for("tick-5\r", Duration::from_secs(20));
    let pipe = spawn_pipe_session(&world, "sleep 4; echo done; exit 7", &world.dir.join("transcript2"));
    wait_until(
        Duration::from_secs(10),
        || status(&world)["session_count"] == 2,
        "two sessions",
        true,
    );
    let before = status(&world);
    let pid = before["pid"].as_u64().unwrap();
    assert_eq!(before["can_upgrade"], true, "{before}");
    let limit = open_files_limit(&world);
    assert!(programs_of(pid, "tick-") > 0, "the ticker runs under the daemon");

    let out = world
        .command(server.to_str().unwrap(), &["upgrade", "--force"])
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "upgrade failed: {stdout} {stderr}");
    assert!(stdout.contains("upgraded in place"), "{stdout}");

    let after = status(&world);
    assert_eq!(after["pid"].as_u64(), Some(pid), "the same process: {after}");
    assert_eq!(after["restarts"], 1, "{after}");
    assert_eq!(after["upgraded_from"], before["version"], "{after}");
    assert_eq!(after["session_count"], 2, "{after}");
    assert_eq!(
        (&after["udp"], &after["cert_sha256"]),
        (&before["udp"], &before["cert_sha256"])
    );
    assert!(programs_of(pid, "tick-") > 0, "the ticker is still the daemon's");
    // New programs get the limit of open files the daemon was started with, as before
    assert_eq!(open_files_limit(&world), limit);

    ticks_go_on(&tty, 20);
    let gap = reconnect_ms(&transcript).expect("a reconnection in the transcript");
    eprintln!("reconnected {gap} ms after the RESTART");
    assert!(
        u128::from(gap) < patience(Duration::from_millis(1500)).as_millis(),
        "reconnected only after {gap} ms"
    );

    let out = pipe.wait_with_output().unwrap();
    assert_eq!(
        (String::from_utf8_lossy(&out.stdout).as_ref(), out.status.code()),
        ("done\n", Some(7)),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    ticker_ends(&mut tty, &stop);
}

/// m2.md 10.2: a bootstrap from a newer qsh-server upgrades an older daemon before it is
/// served, and the sessions of the older one are still there.
#[test]
fn a_newer_bootstrap_upgrades_an_older_daemon() {
    let mut world = World::new("upnewer");
    let server = install_server(&mut world);
    let old = "0.0.1";
    // The daemon looks old, and so do the commands of the first session
    let out = world
        .command(server.to_str().unwrap(), &["daemon"])
        .env("QSH_TEST_VERSION", old)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let before = status(&world);
    assert_eq!(before["version"], old, "{before}");
    let stop = world.dir.join("stop");
    let mut session = world.qsh(&["-vv", "srv", &ticker(&stop)]);
    session.env("QSH_TEST_VERSION", old);
    let mut tty = Tty::spawn_logged(session, world.dir.join("qsh.log"));
    tty.wait_for("tick-5\r", Duration::from_secs(20));
    assert_eq!(status(&world)["restarts"], 0, "an equal version does not upgrade");

    // Any request of a newer qsh-server: here `qsh ls`
    let (code, stdout, stderr) = world.run(&["ls", "--json", "srv"]);
    assert_eq!(code, 0, "{stdout} {stderr}");
    let listed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(listed["sessions"].as_array().unwrap().len(), 1, "{stdout}");

    let after = status(&world);
    assert_eq!(after["pid"], before["pid"], "{after}");
    assert_eq!(after["version"], env!("CARGO_PKG_VERSION"), "{after}");
    assert_eq!(
        (&after["restarts"], &after["upgraded_from"]),
        (&1.into(), &old.into()),
        "{after}"
    );
    ticks_go_on(&tty, 20);
    ticker_ends(&mut tty, &stop);
}

/// m2.md 10.3 and 10.4: every way an upgrade can fail leaves the daemon as it was, with its
/// sessions: the threads not stopping, the state not written, `execve` failing, and (Linux)
/// the new program unable to resume, which executes the old one again. Then it succeeds.
#[test]
fn failed_upgrades_leave_the_daemon_and_its_sessions_as_they_were() {
    let mut world = World::new("upfault");
    let server = install_server(&mut world);
    let faults: &[&str] = if cfg!(any(target_os = "linux", target_os = "android")) {
        // start: the new image panics right after it started (review M3: before it parses
        // anything, as a later version that renamed an option would fail); commit: the last
        // step before its session threads start fails (review M3: a failure after the
        // state was checked falls back too)
        &["stop", "serialize", "exec", "restore", "start", "commit"]
    } else {
        // macOS cannot execute the old image again: the probe is the protection there
        &["stop", "serialize", "exec"]
    };
    world.set("QSH_TEST_HANDOFF_FAULT", faults.join(","));
    let stop = world.dir.join("stop");
    let mut tty = Tty::spawn_logged(world.qsh(&["-vv", "srv", &ticker(&stop)]), world.dir.join("qsh.log"));
    tty.wait_for("tick-5\r", Duration::from_secs(20));
    let pid = status(&world)["pid"].clone();

    for (i, fault) in faults.iter().enumerate() {
        let out = world
            .command(server.to_str().unwrap(), &["upgrade", "--force"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "fault {fault}: {stderr}");
        assert!(stderr.contains("the upgrade failed"), "fault {fault}: {stderr}");
        let now = status(&world);
        assert_eq!(now["pid"], pid, "fault {fault}: {now}");
        assert_eq!(now["upgrade_failures"], i + 1, "fault {fault}: {now}");
        assert_eq!(now["restarts"], 0, "fault {fault}: {now}");
        assert_eq!(now["session_count"], 1, "fault {fault}: {now}");
        ticks_go_on(&tty, 10);
    }
    let out = world
        .command(server.to_str().unwrap(), &["upgrade", "--force"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let now = status(&world);
    assert_eq!((&now["pid"], &now["restarts"]), (&pid, &1.into()), "{now}");
    ticks_go_on(&tty, 10);
    ticker_ends(&mut tty, &stop);

    // Not newer, without --force: nothing to do, and not an error
    let out = world.command(server.to_str().unwrap(), &["upgrade"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing to do"));
    assert_eq!(status(&world)["restarts"], 1);
}

/// m2.md 10.2: with `upgrade = "auto"` (the default) a daemon whose program was replaced
/// (another file at its path, as a package upgrade leaves it) upgrades by itself once no
/// session is attached, keeping the detached ones.
#[test]
fn a_daemon_upgrades_by_itself_when_its_program_was_replaced() {
    let mut world = World::new("upidle");
    let server = install_server(&mut world);
    let old = "0.0.1";
    let out = world
        .command(server.to_str().unwrap(), &["daemon"])
        .env("QSH_TEST_VERSION", old)
        .env("QSH_TEST_UPGRADE_CHECK_MS", "200")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pid = status(&world)["pid"].clone();
    // A detached session; its client is gone
    let mut session = world.qsh(&["srv", "echo ready; exec sleep 1000"]);
    session.env("QSH_TEST_VERSION", old);
    let mut tty = Tty::spawn(session);
    tty.wait_for("ready", Duration::from_secs(20));
    tty.send(b"\r~d");
    assert_eq!(tty.exit_code(Duration::from_secs(10)), 0);
    // Nothing changed so far: the same file
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(status(&world)["restarts"], 0);
    // A package upgrade: a new file renamed over the old one
    let new = world.dir.join("bin/.qsh-server.new");
    copy_executable(Path::new(QSH_SERVER), &new);
    fs::rename(&new, &server).unwrap();
    wait_until(
        Duration::from_secs(10),
        || status(&world)["restarts"] == 1,
        "the daemon to upgrade by itself",
        true,
    );
    let now = status(&world);
    assert_eq!(
        (&now["pid"], &now["version"]),
        (&pid, &env!("CARGO_PKG_VERSION").into()),
        "{now}"
    );
    assert_eq!(now["session_count"], 1, "the detached session is kept: {now}");
}

/// Review H1: a newer program that cannot take over is tried once, not at every login. Before,
/// every bootstrap, pipe and doctor of the newer qsh-server started the upgrade again, each
/// attempt ended every connection, and the requesters that waited for it got
/// `{"restarting":true}` as their reply. Here every attempt fails: `execve` (the old image goes
/// on), and on Linux the new image too (the old one takes over again from the state, and must
/// remember the program across that).
#[test]
fn a_program_an_upgrade_to_failed_is_not_tried_again() {
    let kinds: &[&str] = if cfg!(any(target_os = "linux", target_os = "android")) {
        &["exec", "restore"]
    } else {
        &["exec"]
    };
    for kind in kinds {
        let mut world = World::new(&format!("uponce-{kind}"));
        let server = install_server(&mut world);
        let old = "0.0.1";
        world.set("QSH_TEST_HANDOFF_FAULT", [*kind; 4].join(","));
        let out = world
            .command(server.to_str().unwrap(), &["daemon"])
            .env("QSH_TEST_VERSION", old)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let pid = status(&world)["pid"].clone();
        let stop = world.dir.join("stop");
        let mut session = world.qsh(&["-vv", "srv", &ticker(&stop)]);
        session.env("QSH_TEST_VERSION", old);
        let mut tty = Tty::spawn_logged(session, world.dir.join("qsh.log"));
        tty.wait_for("tick-5\r", Duration::from_secs(20));

        // Requests of a newer qsh-server: the first one tries, every one is served
        for i in 0..3 {
            let (code, stdout, stderr) = world.run(&["ls", "--json", "srv"]);
            assert_eq!(code, 0, "{kind} {i}: {stdout} {stderr}");
            let listed: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(listed["sessions"].as_array().unwrap().len(), 1, "{kind} {i}: {stdout}");
        }
        // A login, too
        let out = world
            .qsh(&["srv", "--", "echo logged-in"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "{kind}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "logged-in");

        let now = status(&world);
        assert_eq!(now["pid"], pid, "{kind}: {now}");
        assert_eq!(now["version"], old, "{kind}: the old program serves: {now}");
        assert_eq!(now["upgrade_failures"], 1, "{kind}: exactly one attempt: {now}");
        assert_eq!(now["restarts"], 0, "{kind}: {now}");
        ticks_go_on(&tty, 10);

        // Not by itself, but on request with --force
        let out = world.command(server.to_str().unwrap(), &["upgrade"]).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{kind}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--force"),
            "{kind}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(status(&world)["upgrade_failures"], 1, "{kind}");
        ticker_ends(&mut tty, &stop);
    }
}
