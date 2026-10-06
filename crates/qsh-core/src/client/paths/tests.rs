use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::*;
use crate::crypto::Fingerprint;
use crate::proto::bootstrap::ExtraPort;
use crate::transport::ssh::SshCommand;
use crate::transport::Attempt;

const NET: &[u8] = b"\x04\x00\x00\x00\x05wlan0\x04\xc0\xa8\x01\x01\x04\xc0\xa8\x01\x00";
const OTHER_NET: &[u8] = b"\x04\x00\x00\x00\x04eth0\x00\x04\x0a\x00\x00\x00";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qsh-paths-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn target(extra: &[(u16, bool, bool)]) -> Target {
    Target {
        host: "Example.org".into(),
        udp: 60443,
        tcp: 60443,
        fingerprint: Fingerprint([0; 32]),
        ssh: SshCommand::new("box"),
        extra_ports: extra
            .iter()
            .map(|&(port, udp, tcp)| ExtraPort { port, udp, tcp })
            .collect(),
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn attempts(planned: &Planned) -> Vec<(Transport, u16, u64)> {
    planned
        .plan
        .attempts
        .iter()
        .map(|a: &Attempt| (a.transport, a.port, a.delay.as_millis() as u64))
        .collect()
}

const NOW: u64 = 1_790_000_000;
const TODAY: u64 = NOW / DAY;

/// The keys are HMAC-SHA256 under the file's salt, cut to 16 bytes, over the documented
/// labels: pinned, since they are on disk. Host names are compared without case.
#[test]
fn keyed_hashes_are_stable() {
    let salt: [u8; 32] = std::array::from_fn(|i| i as u8);
    assert_eq!(
        crypto::hex(&destination_key(&salt, "example.org")),
        "28a837e7a09ad9aa68a40b194d861080"
    );
    assert_eq!(
        destination_key(&salt, "Example.ORG"),
        destination_key(&salt, "example.org")
    );
    assert_eq!(
        crypto::hex(&network_key(&salt, NET)),
        "4b210179cbed9da46174e8e11f3fae79"
    );
    let other: [u8; 32] = [7; 32];
    assert_ne!(
        destination_key(&other, "example.org"),
        destination_key(&salt, "example.org")
    );
    assert_ne!(network_key(&salt, NET), network_key(&salt, OTHER_NET));
}

#[test]
fn the_file_is_private_names_nothing_and_round_trips() {
    let dir = scratch("roundtrip");
    let path = dir.join("state/paths.json");
    let memory = PathMemory::open(&path);
    assert!(memory.entry("example.org", NET).is_none());
    assert!(
        !path.exists(),
        "nothing is written before there is something to remember"
    );
    let now = now();
    memory.update("Example.org", NET, now, |e| {
        e.succeeded(Transport::Quic, 60443, ms(420), now);
        e.failed(Transport::Tls, FailureKind::Timeout, now);
        e.measured(Some(ms(270)), Some(0.06));
        e.set_keepalive(Duration::from_secs(10));
    });
    assert!(memory.dirty());
    memory.flush().unwrap();
    assert!(!memory.dirty());
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.to_lowercase().contains("example"), "{text}");
    assert!(!text.contains("wlan0"), "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["qsh_paths"], 1);
    assert_eq!(v["salt"].as_str().unwrap().len(), 64);
    let e = &v["entries"][0];
    assert_eq!(e["d"].as_str().unwrap().len(), 32);
    assert_eq!(e["n"].as_str().unwrap().len(), 32);
    assert_eq!(e["day"], now / DAY);
    assert_eq!(e["t"]["quic"]["port"], 60443);
    assert_eq!(e["t"]["quic"]["hs"], 420);
    assert_eq!(e["t"]["tls"]["fail"]["kind"], "timeout");
    assert_eq!(e["t"]["tls"]["fail"]["n"], 1);
    assert_eq!(e["t"]["tls"]["fail"]["retry"], now + 60);
    assert_eq!(e["rtt"], 270);
    assert_eq!(e["ka"], 10.0);

    // Another process (or a later run) finds it under the same host and network
    let again = PathMemory::open(&path);
    let entry = again.entry("EXAMPLE.org", NET).unwrap();
    assert_eq!(entry.transport(Transport::Quic).unwrap().port, Some(60443));
    assert!(entry.blocked(Transport::Tls, now));
    assert_eq!(entry.keepalive(), Some(Duration::from_secs(10)));
    assert!(again.entry("example.org", OTHER_NET).is_none());
    assert!(again.entry("example.net", NET).is_none());
    assert!(again.entry("example.org", b"").is_none());
    fs::remove_dir_all(dir).unwrap();
}

/// Two processes that loaded the file before either wrote: both changes survive, under the
/// salt of whoever wrote first.
#[test]
fn concurrent_writers_merge() {
    let dir = scratch("merge");
    let path = dir.join("paths.json");
    let a = PathMemory::open(&path);
    let b = PathMemory::open(&path);
    let now = now();
    assert!(a.entry("a.example", NET).is_none() && b.entry("b.example", NET).is_none());
    a.update("a.example", NET, now, |e| e.succeeded(Transport::Quic, 1, ms(10), now));
    b.update("b.example", NET, now, |e| e.succeeded(Transport::Tls, 2, ms(10), now));
    a.flush().unwrap();
    b.flush().unwrap();
    let c = PathMemory::open(&path);
    assert!(c.entry("a.example", NET).is_some());
    assert!(c.entry("b.example", NET).is_some());
    // b now knows a's entry too, under the file's salt
    assert!(b.entry("a.example", NET).is_some());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn at_most_256_entries_the_least_recently_used_go_first() {
    let dir = scratch("bound");
    let path = dir.join("paths.json");
    let memory = PathMemory::open(&path);
    let now = now();
    for i in 0..100 {
        memory.update(&format!("old{i}.example"), NET, now - 10 * DAY, |_| {});
    }
    for i in 0..200 {
        memory.update(&format!("new{i}.example"), NET, now, |_| {});
    }
    memory.flush().unwrap();
    let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(v["entries"].as_array().unwrap().len(), MAX_ENTRIES);
    let again = PathMemory::open(&path);
    assert!((0..200).all(|i| again.entry(&format!("new{i}.example"), NET).is_some()));
    let old = (0..100)
        .filter(|i| again.entry(&format!("old{i}.example"), NET).is_some())
        .count();
    assert_eq!(old, MAX_ENTRIES - 200);
    // Without a file, the same bound
    let volatile = PathMemory::in_memory();
    for i in 0..300 {
        volatile.update(&format!("h{i}"), NET, now, |_| {});
    }
    assert_eq!(volatile.inner.lock().unwrap().changed.len(), MAX_ENTRIES);
    volatile.flush().unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn entries_unused_for_30_days_expire() {
    let dir = scratch("expiry");
    let path = dir.join("paths.json");
    let memory = PathMemory::open(&path);
    let now = now();
    memory.update("thirty.example", NET, now - 30 * DAY, |_| {});
    memory.update("older.example", NET, now - 31 * DAY, |_| {});
    assert!(memory.entry("thirty.example", NET).is_some());
    assert!(memory.entry("older.example", NET).is_none());
    memory.flush().unwrap();
    let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    // And the race does not use one
    let entry = Entry {
        day: TODAY - 31,
        ..Entry::default()
    };
    assert!(!plan(Some(&entry), &target(&[]), &RaceConfig::default(), NOW).remembered);
    fs::remove_dir_all(dir).unwrap();
}

/// A file that cannot be used is ignored (path memory never stops a connection) and replaced
/// on the next write; invalid entries are dropped, valid ones kept.
#[test]
fn corrupted_files_and_entries_are_ignored_and_replaced() {
    let dir = scratch("corrupt");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("paths.json");
    let write = |bytes: &[u8], mode: u32| {
        let _ = fs::remove_file(&path);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    };
    let now = now();
    let salt = crypto::hex(&[1; 32]);
    let good = |host: &str| {
        format!(
            r#"{{"d":"{}","n":"{}","day":{},"t":{{"tls":{{"ok":{},"port":443}}}}}}"#,
            crypto::hex(&destination_key(&[1; 32], host)),
            crypto::hex(&network_key(&[1; 32], NET)),
            now / DAY,
            now / DAY
        )
    };
    let bad_loss = good("loss.example").replace(r#""day""#, r#""loss":2.0,"day""#);
    let bad_kind = good("kind.example").replace(
        r#""port":443"#,
        r#""port":443,"fail":{"kind":"refused","n":1,"retry":1}"#,
    );
    let bad_ka = good("ka.example").replace(r#""day""#, r#""ka":0.1,"day""#);
    let file = format!(
        r#"{{"qsh_paths":1,"salt":"{salt}","entries":[{},{{"d":"zz","n":"00","day":1}},{bad_loss},{bad_kind},{bad_ka},"junk",{}]}}"#,
        good("ok.example"),
        good("ok.example").replace("443", "444")
    );
    write(file.as_bytes(), 0o600);
    let memory = PathMemory::open(&path);
    assert_eq!(
        memory
            .entry("ok.example", NET)
            .unwrap()
            .transport(Transport::Tls)
            .unwrap()
            .port,
        Some(443),
        "the first of two entries with the same keys counts"
    );
    for host in ["loss.example", "kind.example", "ka.example"] {
        assert!(memory.entry(host, NET).is_none(), "{host}");
    }
    let unusable: Vec<(Vec<u8>, u32)> = vec![
        (b"not json".to_vec(), 0o600),
        (file.replace(r#""qsh_paths":1"#, r#""qsh_paths":2"#).into_bytes(), 0o600),
        (file.replace(&salt, "short").into_bytes(), 0o600),
        (file.clone().into_bytes(), 0o644),
        (
            format!(
                r#"{{"qsh_paths":1,"salt":"{salt}","entries":[],"pad":"{}"}}"#,
                "x".repeat(1 << 20)
            )
            .into_bytes(),
            0o600,
        ),
    ];
    for (bytes, mode) in unusable {
        write(&bytes, mode);
        let memory = PathMemory::open(&path);
        assert!(memory.entry("ok.example", NET).is_none());
        memory.update("new.example", NET, now, |e| e.succeeded(Transport::Quic, 1, ms(1), now));
        memory.flush().unwrap();
        let again = PathMemory::open(&path);
        assert!(again.entry("new.example", NET).is_some());
        assert!(again.entry("ok.example", NET).is_none());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // A symbolic link is not followed
    let _ = fs::remove_file(&path);
    fs::write(dir.join("elsewhere"), file.as_bytes()).unwrap();
    fs::set_permissions(dir.join("elsewhere"), fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere"), &path).unwrap();
    assert!(PathMemory::open(&path).entry("ok.example", NET).is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failures_back_off_and_success_clears_them() {
    let mut e = Entry::default();
    let waits: Vec<u64> = (0..8)
        .map(|_| {
            e.failed(Transport::Quic, FailureKind::Timeout, NOW);
            e.transport(Transport::Quic).unwrap().fail.as_ref().unwrap().retry - NOW
        })
        .collect();
    assert_eq!(waits, [60, 300, 1800, 7200, 43_200, 86_400, 86_400, 86_400]);
    assert!(e.blocked(Transport::Quic, NOW + 86_399));
    assert!(!e.blocked(Transport::Quic, NOW + 86_400));
    assert_eq!(e.due(NOW + 86_400), [Transport::Quic]);
    assert!(e.due(NOW).is_empty());
    // A probe that fails for a reason that says nothing about the network keeps the kind
    let mut p = Entry::default();
    p.failed(Transport::Tls, FailureKind::Reset, NOW);
    p.probe_failed(Transport::Tls, FailureKind::Refused, NOW);
    let fail = p.transport(Transport::Tls).unwrap().fail.clone().unwrap();
    assert_eq!((fail.kind(), fail.n), (Some(FailureKind::Reset), 2));
    e.succeeded(Transport::Quic, 443, ms(500), NOW);
    let r = e.transport(Transport::Quic).unwrap();
    assert!(r.fail.is_none() && r.ok == Some(TODAY) && r.port == Some(443) && r.hs == Some(500));
    // Handshake times, RTT and loss are moving averages
    e.succeeded(Transport::Quic, 443, ms(1500), NOW);
    assert_eq!(e.transport(Transport::Quic).unwrap().hs, Some(800));
    e.measured(Some(ms(100)), Some(0.0));
    e.measured(Some(ms(200)), Some(1.0));
    assert_eq!((e.rtt, e.loss), (Some(130), Some(0.3)));
    e.failed(Transport::Tls, FailureKind::Hello, NOW);
    e.clear_failures();
    assert!(!e.blocked(Transport::Tls, NOW));
}

#[test]
fn without_memory_the_plan_is_the_configuration_with_extra_ports() {
    let t = target(&[(443, true, true), (61443, true, false)]);
    let planned = plan(None, &t, &RaceConfig::default(), NOW);
    assert!(!planned.remembered && planned.skipped.is_empty());
    assert_eq!(
        attempts(&planned),
        [
            (Transport::Quic, 60443, 0),
            (Transport::Quic, 443, 300),
            (Transport::Tls, 60443, 400),
            (Transport::Quic, 61443, 600),
            (Transport::Tls, 443, 700),
            (Transport::Ssh, 0, 3000),
        ]
    );
    // No more than six direct attempts: the latest go
    let many: Vec<(u16, bool, bool)> = (1..=8).map(|p| (p, true, true)).collect();
    let planned = plan(None, &target(&many), &RaceConfig::default(), NOW);
    let direct = planned
        .plan
        .attempts
        .iter()
        .filter(|a| a.transport != Transport::Ssh)
        .count();
    assert_eq!(direct, crate::transport::MAX_DIRECT_ATTEMPTS);
    assert!(planned.plan.attempts.iter().any(|a| a.transport == Transport::Ssh));
    // A daemon without UDP: no QUIC
    let mut tcp_only = target(&[]);
    tcp_only.udp = 0;
    assert_eq!(
        attempts(&plan(None, &tcp_only, &RaceConfig::default(), NOW)),
        [(Transport::Tls, 60443, 400), (Transport::Ssh, 0, 3000)]
    );
}

fn entry(records: &[(Transport, TransportRecord)]) -> Entry {
    let mut e = Entry {
        day: TODAY,
        ..Entry::default()
    };
    for (t, r) in records {
        *e.transport_mut(*t) = r.clone();
    }
    e
}

fn ok(day: u64, port: Option<u16>, hs: Option<u32>) -> TransportRecord {
    TransportRecord {
        port,
        ok: Some(day),
        hs,
        fail: None,
    }
}

fn blocked(retry: u64) -> TransportRecord {
    TransportRecord {
        fail: Some(Failure {
            kind: "timeout".into(),
            n: 1,
            retry,
        }),
        ..TransportRecord::default()
    }
}

#[test]
fn the_remembered_winner_starts_at_once_and_blocked_transports_wait() {
    let t = target(&[(443, true, true)]);
    let race = RaceConfig::default();
    // UDP blocked here: TLS at once on the port that worked, QUIC left out
    let e = entry(&[
        (Transport::Quic, blocked(NOW + 60)),
        (Transport::Tls, ok(TODAY, Some(443), Some(600))),
    ]);
    let planned = plan(Some(&e), &t, &race, NOW);
    assert!(planned.remembered);
    assert_eq!(planned.skipped, [Transport::Quic]);
    assert_eq!(
        attempts(&planned),
        [
            (Transport::Tls, 443, 0),
            (Transport::Tls, 60443, 300),
            (Transport::Ssh, 0, 3000)
        ]
    );
    // Its retry time passed: back in the race (the background probe may not have run), but
    // the transport that kept working starts first
    let planned = plan(Some(&e), &t, &race, NOW + 60);
    assert!(planned.skipped.is_empty());
    assert_eq!(planned.plan.start_of(Transport::Tls), Some(ms(0)));
    assert_eq!(planned.plan.start_of(Transport::Quic), Some(ms(0)));
    // QUIC worked on 443 with a 420 ms handshake: first, then TLS 1.5 × 420 ms later
    let e = entry(&[
        (Transport::Quic, ok(TODAY, Some(443), Some(420))),
        (Transport::Tls, ok(TODAY - 3, None, Some(700))),
    ]);
    assert_eq!(
        attempts(&plan(Some(&e), &t, &race, NOW)),
        [
            (Transport::Quic, 443, 0),
            (Transport::Quic, 60443, 300),
            (Transport::Tls, 60443, 630),
            (Transport::Tls, 443, 930),
            (Transport::Ssh, 0, 3000),
        ]
    );
    // The stagger stays between 250 ms and 2 s
    for (hs, tls) in [(100, 250), (5000, 2000)] {
        let e = entry(&[(Transport::Quic, ok(TODAY, None, Some(hs)))]);
        assert_eq!(
            plan(Some(&e), &t, &race, NOW).plan.start_of(Transport::Tls),
            Some(ms(tls))
        );
    }
    // Only the ssh pipe got through here: it starts at once
    let e = entry(&[
        (Transport::Quic, blocked(NOW + 300)),
        (Transport::Tls, blocked(NOW + 300)),
        (Transport::Ssh, ok(TODAY, None, Some(1900))),
    ]);
    let planned = plan(Some(&e), &t, &race, NOW);
    assert_eq!(attempts(&planned), [(Transport::Ssh, 0, 0)]);
    assert_eq!(planned.skipped, [Transport::Quic, Transport::Tls]);
    // A remembered port the daemon no longer announces is not tried
    let e = entry(&[(Transport::Quic, ok(TODAY, Some(9999), None))]);
    assert_eq!(
        plan(Some(&e), &t, &race, NOW).plan.attempts[0],
        Attempt {
            transport: Transport::Quic,
            port: 60443,
            delay: ms(0)
        }
    );
}

#[test]
fn ties_and_the_configuration_decide_the_rest() {
    let t = target(&[]);
    let race = RaceConfig::default();
    // Same day: QUIC before TLS before the pipe
    let e = entry(&[
        (Transport::Tls, ok(TODAY, None, None)),
        (Transport::Quic, ok(TODAY, None, None)),
    ]);
    assert_eq!(
        attempts(&plan(Some(&e), &t, &race, NOW))[0],
        (Transport::Quic, 60443, 0)
    );
    // ... unless QUIC is marked as failing (its retry passed): then the one that kept working
    let mut quic = ok(TODAY, None, None);
    quic.fail = blocked(NOW).fail;
    let e = entry(&[(Transport::Tls, ok(TODAY, None, None)), (Transport::Quic, quic)]);
    let planned = plan(Some(&e), &t, &race, NOW);
    assert_eq!(planned.plan.start_of(Transport::Tls), Some(ms(0)));
    // The configuration's transports only: memory never adds one
    let tls_only = RaceConfig {
        quic: None,
        tls: Some(ms(0)),
        ssh: None,
    };
    let e = entry(&[(Transport::Quic, ok(TODAY, None, None))]);
    assert_eq!(
        attempts(&plan(Some(&e), &t, &tls_only, NOW)),
        [(Transport::Tls, 60443, 0)]
    );
    // Everything allowed is blocked: the full plan rather than nothing
    let quic_only = RaceConfig {
        quic: Some(ms(0)),
        tls: None,
        ssh: None,
    };
    let e = entry(&[(Transport::Quic, blocked(NOW + 60))]);
    let planned = plan(Some(&e), &t, &quic_only, NOW);
    assert!(!planned.remembered);
    assert_eq!(attempts(&planned), [(Transport::Quic, 60443, 0)]);
    // An entry without any success changes only what is blocked
    let e = entry(&[(Transport::Tls, blocked(NOW + 60))]);
    assert_eq!(
        attempts(&plan(Some(&e), &t, &race, NOW)),
        [(Transport::Quic, 60443, 0), (Transport::Ssh, 0, 3000)]
    );
}

#[test]
fn keepalive_intervals() {
    assert_eq!(keepalive_for(Keepalive::Auto, None), (KEEPALIVE_START, true));
    let mut e = Entry::default();
    e.set_keepalive(Duration::from_secs(10));
    assert_eq!(
        keepalive_for(Keepalive::Auto, Some(&e)),
        (Duration::from_secs(10), true)
    );
    let fixed = Keepalive::Every(Duration::from_secs(40));
    assert_eq!(keepalive_for(fixed, Some(&e)), (Duration::from_secs(40), false));
    // Halving stops at 5 s, growing at 25 s
    let mut k = KEEPALIVE_START;
    let mut halves = Vec::new();
    for _ in 0..4 {
        k = halve(k);
        halves.push(k.as_millis());
    }
    assert_eq!(halves, [10_000, 5000, 5000, 5000]);
    let mut grows = Vec::new();
    for _ in 0..8 {
        k = grow(k);
        grows.push(k.as_millis());
    }
    assert_eq!(grows, [6250, 7812, 9765, 12_207, 15_258, 19_073, 23_841, 25_000]);
    // Stored with a tenth of a second
    e.set_keepalive(Duration::from_secs_f64(7.8125));
    assert_eq!(e.ka, Some(7.8));
    // A hostile value cannot leave the bounds
    e.ka = Some(1.0);
    assert_eq!(e.keepalive(), Some(KEEPALIVE_MIN));
}

fn rebinding(at: Instant, idle: u64, effective: u64) -> Rebinding {
    Rebinding {
        at,
        idle: Duration::from_secs(idle),
        client_moved: None,
        local_changed: false,
        effective: Duration::from_secs(effective),
    }
}

/// The algorithm of m2.md 4.3 on a scripted sequence of PATH_INFO changes, moves and quiet
/// periods.
#[tokio::test(start_paused = true)]
async fn keepalive_learning_follows_the_script() {
    let s = Duration::from_secs;
    let mut l = Learner::new(KEEPALIVE_START, None);
    let start = Instant::now();
    // Idle for 21 s at K = 20, then a new address: a NAT timed out
    assert_eq!(l.rebinding(&rebinding(start + s(21), 21, 20)), Some(s(10)));
    // Another within a minute of the step: not learned from
    assert_eq!(l.rebinding(&rebinding(start + s(50), 12, 10)), None);
    assert_eq!(l.k(), s(10));
    // While traffic flowed: a NAT doing something else
    assert_eq!(l.rebinding(&rebinding(start + s(100), 3, 10)), None);
    // The client moved itself (rebind, network change) shortly before
    let mut moved = rebinding(start + s(110), 12, 10);
    moved.client_moved = Some(start + s(105));
    assert_eq!(l.rebinding(&moved), None);
    // ... or its local address changed
    let mut local = rebinding(start + s(115), 12, 10);
    local.local_changed = true;
    assert_eq!(l.rebinding(&local), None);
    // A move long enough ago does not count
    let mut long_ago = rebinding(start + s(120), 11, 10);
    long_ago.client_moved = Some(start + s(105));
    assert_eq!(l.rebinding(&long_ago), Some(s(5)));
    // The floor
    assert_eq!(l.rebinding(&rebinding(start + s(200), 6, 5)), None);
    assert_eq!(l.k(), s(5));
    assert_eq!(l.last_step(), Some(start + s(200)));
    // 30 attached minutes without a timeout: a quarter more
    assert_eq!(l.quiet(s(29 * 60)), None);
    assert_eq!(l.quiet(s(60)), Some(ms(6250)));
    assert_eq!(l.quiet(s(30 * 60)), Some(Duration::from_micros(7_812_500)));
    // A timeout restarts the quiet period
    assert_eq!(l.quiet(s(20 * 60)), None);
    assert_eq!(l.rebinding(&rebinding(start + s(400), 9, 7)), Some(s(5)));
    assert_eq!(l.quiet(s(20 * 60)), None);
    // Another network: its own interval, its own quiet time, its own last step
    l.network(s(20), None);
    assert_eq!(l.quiet(s(20 * 60)), None);
    assert_eq!(l.rebinding(&rebinding(start + s(420), 25, 20)), Some(s(10)));
    let mut top = Learner::new(KEEPALIVE_MAX, None);
    assert_eq!(top.quiet(s(30 * 60)), None, "never above 25 s");
}
