//! Smart catch-up and compression end to end (m2.md sections 6 and 7): `qsh` on a terminal and
//! on pipes, the real daemon behind the fake ssh, on a link the daemon throttles
//! (`QSH_TEST_THROTTLE`, a test hook of builds with the `test-hooks` feature).

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;

/// The test link: 300 kB/s.
const THROTTLE: &str = "300000";

/// `config` as the world's qsh_config(5).
fn configure(world: &World, config: &str) {
    let dir = world.dir.join("config/qsh");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config"), config).unwrap();
    fs::set_permissions(dir.join("config"), fs::Permissions::from_mode(0o600)).unwrap();
}

/// Ctrl-C typed during a flood of output on a slow link shows its effect within a fraction of
/// a second: the backlog (megabytes in the daemon) is replaced by the current screen, after a
/// line that says what was skipped.
#[test]
fn ctrl_c_during_a_flood_shows_its_effect_at_once() {
    let mut world = World::new("flood");
    world.set("QSH_TEST_THROTTLE", THROTTLE);
    let transcript = world.dir.join("transcript.jsonl");
    world.set("QSH_TRANSCRIPT", transcript.display().to_string());
    // `yes` compresses a thousandfold: without compression its flood is what the link carries
    configure(&world, "[defaults]\ncompression = \"off\"\n");
    let mut tty = Tty::spawn_logged(
        world.qsh(&[
            "srv",
            "trap 'echo PROMPT-BACK; exec sleep 600' INT; yes catch-up-e2e-line",
        ]),
        world.dir.join("qsh.log"),
    );
    tty.wait_for("catch-up-e2e-line", Duration::from_secs(30));
    // Seconds of flood: snapshots replace the backlog
    std::thread::sleep(Duration::from_secs(3));
    let typed = Instant::now();
    tty.send(b"\x03");
    tty.wait_for("PROMPT-BACK", Duration::from_secs(20));
    let took = typed.elapsed();
    eprintln!("Ctrl-C to PROMPT-BACK on the terminal: {took:?} (link {THROTTLE} B/s, transcript polled every 50 ms)");
    assert!(took < Duration::from_secs(3), "Ctrl-C took {took:?}");
    let text = tty.text();
    assert!(
        text.contains("qsh: skipped"),
        "no skip notice in {:?}",
        &text[text.len().saturating_sub(2000)..]
    );
    let records: Vec<serde_json::Value> = fs::read_to_string(&transcript)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let snapshots = records.iter().filter(|r| r["ev"] == "snapshot").count();
    assert!(snapshots >= 1, "no snapshot in the transcript");
    // Every byte of the stream was delivered, skipped by a gap, or replaced by a snapshot, in
    // order
    let mut expected = None;
    for r in &records {
        let u = |k: &str| r[k].as_u64().unwrap();
        match r["ev"].as_str().unwrap_or("") {
            "output" => {
                if let Some(e) = expected {
                    assert_eq!(u("offset"), e);
                }
                expected = Some(u("offset") + u("len"));
            }
            "gap" => {
                if let Some(e) = expected {
                    assert_eq!(u("from"), e);
                }
                expected = Some(u("to"));
            }
            "snapshot" => {
                assert!(expected.is_none_or(|e| u("offset") >= e));
                expected = Some(u("offset"));
            }
            _ => {}
        }
    }
}

/// The output of `LOG`.
fn build_log(n: u32) -> String {
    (1..=n)
        .map(|i| format!("   Compiling crate-{i} v0.1.0 (/home/user/src/project/crates/crate-{i})\n"))
        .collect()
}

const LOG: &str = "seq 1 20000 | sed 's|.*|   Compiling crate-& v0.1.0 (/home/user/src/project/crates/crate-&)|'";

/// Compression on a slow link: the output is byte for byte the same with and without it, and
/// a build log arrives in a fraction of the time (S5).
#[test]
fn compression_is_byte_exact_and_faster_on_a_slow_link() {
    let mut world = World::new("zstd");
    world.set("QSH_TEST_THROTTLE", THROTTLE);
    let expected = build_log(20_000);
    let mut times = Vec::new();
    let mut onsets = Vec::new();
    for (i, config) in ["", "[defaults]\ncompression = \"off\"\n"].into_iter().enumerate() {
        configure(&world, config);
        // When the first compressed frame arrived and how many there were: what to look at
        // when the time is off
        let transcript = world.dir.join(format!("zstd-{i}.jsonl"));
        world.set("QSH_TRANSCRIPT", transcript.display().to_string());
        let start = Instant::now();
        let out = world.qsh(&["srv", LOG]).stdin(Stdio::null()).output().unwrap();
        let took = start.elapsed();
        assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stdout == expected.as_bytes(), "the output differs with {config:?}");
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&transcript)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let outputs: Vec<&serde_json::Value> = records.iter().filter(|r| r["ev"] == "output").collect();
        let frames = outputs.iter().filter(|r| r.get("zstd").is_some()).count();
        let first = outputs.first().and_then(|r| r["ms"].as_u64());
        let first_frame = outputs
            .iter()
            .find(|r| r.get("zstd").is_some())
            .and_then(|r| r["ms"].as_u64());
        let raw_before: u64 = outputs
            .iter()
            .take_while(|r| r.get("zstd").is_none())
            .filter_map(|r| r["len"].as_u64())
            .sum();
        let onset = format!(
            "{frames} frames; first output at {first:?} ms, first frame at {first_frame:?} ms after {raw_before} raw bytes"
        );
        eprintln!("{} bytes with {config:?}: {took:?}; {onset}", out.stdout.len());
        times.push(took);
        onsets.push(onset);
    }
    // Including the connection and bootstrap, which take the same in both
    assert!(times[0] < times[1] / 2, "{times:?}; {onsets:?}");
}
