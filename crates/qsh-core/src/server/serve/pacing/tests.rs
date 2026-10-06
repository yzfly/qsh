//! The pacing and catch-up logic on simulated time (m2.md 12.1): the delivery rate, the window,
//! the triggers, the compression policy, and the Ctrl-C budget of S3 checked in simulation
//! for round trip times from 20 to 600 ms.

use super::*;
use std::collections::VecDeque;

const MS: Duration = Duration::from_millis(1);

#[test]
fn the_window_follows_rate_and_rtt_within_its_bounds() {
    // 1 MiB/s over 270 ms: 1.25 × 1 MiB × 0.37 s
    let w = window(1048576.0, Duration::from_millis(270), false);
    assert_eq!(w, (1.25 * 1048576.0 * 0.37) as u64);
    assert_eq!(window(1000.0, MS, false), 64 * 1024);
    assert_eq!(window(1000.0, MS, true), 256 * 1024);
    assert_eq!(window(1e12, Duration::from_secs(1), false), 8 << 20);
    assert_eq!(
        window(1048576.0, Duration::from_millis(400), true),
        (2.0 * 1048576.0 * 0.5) as u64
    );
}

#[test]
fn the_rate_is_the_best_second_of_samples_while_output_waits() {
    let t0 = Instant::now();
    let mut rate = Rate::new(INITIAL_RATE_MUX);
    assert_eq!(rate.rate(t0), INITIAL_RATE_MUX);
    // The first ACK only starts the clock; an application-limited interval is no sample
    rate.ack(t0, 0, true);
    rate.ack(t0 + 100 * MS, 10_000, true);
    assert_eq!(rate.rate(t0 + 100 * MS), 100_000.0);
    rate.limited();
    rate.ack(t0 + 200 * MS, 1_000_000, true);
    assert_eq!(rate.rate(t0 + 200 * MS), 100_000.0);
    // A faster second wins; samples older than 10 s are forgotten
    rate.limited();
    rate.ack(t0 + 1500 * MS, 0, true);
    rate.ack(t0 + 1600 * MS, 50_000, true);
    assert_eq!(rate.rate(t0 + 1600 * MS), 500_000.0);
    assert_eq!(rate.sampled(t0 + 1600 * MS), 200 * MS);
    rate.ack(t0 + 12_000 * MS, 1000, true);
    assert!(rate.rate(t0 + 12_000 * MS) < 500_000.0);
}

#[test]
fn backlog_trigger_with_samples_and_hysteresis() {
    let t0 = Instant::now();
    let mut c = Catchup::new(t0, 0, false);
    let rate = 100_000.0;
    // Below max(2 s × T, 256 KiB): nothing
    assert_eq!(c.step(t0, 256 * 1024, 0, rate, Duration::from_secs(5)), Step::Send);
    // Above, but less than 1 s of samples on the mux layer (500 ms on QUIC)
    assert_eq!(c.step(t0, 300_000, 0, rate, 800 * MS), Step::Send);
    assert_eq!(
        Catchup::new(t0, 0, true).step(t0, 300_000, 0, rate, 800 * MS),
        Step::Snapshot
    );
    assert_eq!(c.step(t0, 300_000, 0, rate, Duration::from_secs(1)), Step::Snapshot);
    c.taken(t0, 1_000_000);
    // Not before the snapshot is acknowledged and 1 s has passed
    let t1 = t0 + Duration::from_secs(2);
    assert_eq!(c.step(t1, 300_000, 999_999, rate, Duration::from_secs(3)), Step::Send);
    assert_eq!(
        c.step(t0 + 500 * MS, 300_000, 1_000_000, rate, Duration::from_secs(3)),
        Step::Send
    );
    assert_eq!(
        c.step(t1, 300_000, 1_000_000, rate, Duration::from_secs(3)),
        Step::Snapshot
    );
}

#[test]
fn input_trigger_waits_for_the_program_to_settle() {
    let t0 = Instant::now();
    let mut c = Catchup::new(t0, 0, false);
    // Input with little unsent output: no trigger
    c.input(t0, 64 * 1024, 32 * 1024);
    assert!(!c.interrupted());
    c.input(t0, 2_000_000, 100_000);
    assert!(c.interrupted());
    // Output still flowing: hold, at most 100 ms
    assert_eq!(c.step(t0 + 5 * MS, 0, 0, 1e6, Duration::ZERO), Step::Hold(t0 + 20 * MS));
    c.output(t0 + 15 * MS, 10);
    assert_eq!(
        c.step(t0 + 16 * MS, 0, 0, 1e6, Duration::ZERO),
        Step::Hold(t0 + 35 * MS)
    );
    assert_eq!(c.step(t0 + 35 * MS, 0, 0, 1e6, Duration::ZERO), Step::Snapshot);
    // A program that never pauses: 100 ms
    let mut c = Catchup::new(t0, 0, false);
    c.input(t0, 2_000_000, 100_000);
    for ms in (0..100).step_by(10) {
        c.output(t0 + ms * MS, ms as u64 + 1);
        assert!(matches!(c.step(t0 + ms * MS, 0, 0, 1e6, Duration::ZERO), Step::Hold(_)));
    }
    assert_eq!(c.step(t0 + 100 * MS, 0, 0, 1e6, Duration::ZERO), Step::Snapshot);
    // Even right after a backlog snapshot (no hysteresis for input)
    c.taken(t0, 5);
    c.input(t0 + MS, 2_000_000, 100_000);
    assert_eq!(c.step(t0 + 200 * MS, 0, 0, 1e6, Duration::ZERO), Step::Snapshot);
}

#[test]
fn compression_stops_on_incompressible_output_and_tries_again() {
    let t0 = Instant::now();
    let mut z = Squeeze::new();
    assert!(z.wanted(t0, 1e6, 4096, 0));
    // Fast paths, keystroke echoes: raw
    assert!(!z.wanted(t0, 9.0 * 1048576.0, 4096, 0));
    // A path of 2 MiB/s carries 8 MiB/s of output compressed to a quarter: still slow
    for _ in 0..20 {
        z.record(t0, 65536, 16384, 0);
    }
    assert!(z.wanted(t0, 8.0 * 1048576.0, 4096, 0));
    let mut z = Squeeze::new();
    assert!(!z.wanted(t0, 1e6, 100, 0));
    // A compressed tarball: off after a few frames …
    let mut sent = 0;
    for _ in 0..10 {
        z.record(t0, 65536, 65600, sent);
        sent += 65536;
    }
    assert!(!z.wanted(t0 + MS, 1e6, 65536, sent));
    // … tried again after 2 s or 1 MiB
    assert!(z.wanted(t0 + Duration::from_secs(2), 1e6, 65536, sent));
    assert!(z.wanted(t0 + MS, 1e6, 65536, sent + (1 << 20)));
    // Text again: on
    for _ in 0..3 {
        z.record(t0, 65536, 9000, sent);
    }
    assert!(z.wanted(t0 + MS, 1e6, 65536, sent));
}

#[test]
fn the_minimum_rtt_decays() {
    let t0 = Instant::now();
    let mut m = MinRtt::new();
    assert_eq!(m.get(), None);
    m.sample(t0, 100 * MS);
    m.sample(t0 + MS, 300 * MS);
    assert_eq!(m.get(), Some(100 * MS));
    m.sample(t0 + Duration::from_secs(31), 300 * MS);
    assert_eq!(m.get(), Some(300 * MS));
}

/// One run of the Ctrl-C scenario: an endless flood on a path of `rtt` and `rate` bytes/s; at
/// 3 s the user types Ctrl-C, the program stops at once. The time until the snapshot has
/// reached the client.
fn ctrl_c(rtt: Duration, link: f64, snapshot: u64) -> Duration {
    let t0 = Instant::now();
    let half = rtt / 2;
    let mut now = t0;
    let mut catchup = Catchup::new(now, 0, false);
    let mut rate = Rate::new(INITIAL_RATE_MUX);
    let mut min_rtt = MinRtt::new();
    min_rtt.sample(now, rtt);
    // The bottleneck queue: (bytes left, offset after it, snapshot?)
    let mut queue: VecDeque<(u64, u64, bool)> = VecDeque::new();
    // In propagation to the client: (arrival, offset after it, snapshot?)
    let mut flight: VecDeque<(Instant, u64, bool)> = VecDeque::new();
    // ACKs on the way back: (arrival, received)
    let mut acks: VecDeque<(Instant, u64)> = VecDeque::new();
    let (mut sent, mut last_ack, mut received, mut acked) = (0u64, 0u64, 0u64, 0u64);
    let mut oldest_unacked: Option<Instant> = None;
    let mut snapshot_bytes = 0u64;
    let typed = t0 + Duration::from_secs(3);
    let mut input_arrives = None;
    let mut stopped = false;
    let per_ms = link / 1000.0;
    let mut credit = 0.0;
    loop {
        now += MS;
        // The link serializes, then propagates
        credit += per_ms;
        while let Some(front) = queue.front_mut() {
            let n = (credit as u64).min(front.0);
            if n == 0 {
                break;
            }
            credit -= n as f64;
            front.0 -= n;
            if front.0 == 0 {
                let (_, offset, snap) = queue.pop_front().unwrap();
                flight.push_back((now + half, offset, snap));
            }
        }
        if queue.is_empty() {
            credit = credit.min(per_ms);
        }
        // The client: receives, ACKs every 16 KiB or 50 ms
        while flight.front().is_some_and(|f| f.0 <= now) {
            let (_, offset, snap) = flight.pop_front().unwrap();
            if snap {
                return now - typed;
            }
            received = offset;
            oldest_unacked.get_or_insert(now);
        }
        if received > acked && (received - acked >= 16384 || oldest_unacked.is_some_and(|t| now - t >= 50 * MS)) {
            acks.push_back((now + half, received));
            acked = received;
            oldest_unacked = None;
        }
        if now == typed {
            input_arrives = Some(now + half);
        }
        // The server
        while acks.front().is_some_and(|a| a.0 <= now) {
            let (_, r) = acks.pop_front().unwrap();
            rate.ack(now, r - last_ack, true);
            last_ack = r;
        }
        if input_arrives.is_some_and(|t| t <= now) && !stopped {
            stopped = true;
            let w = window(rate.rate(now), min_rtt.get().unwrap(), false);
            catchup.input(now, u64::MAX / 2 - sent, w);
            assert!(catchup.interrupted());
        }
        if stopped {
            // The program stopped at once: the end no longer grows
            match catchup.step(now, 0, last_ack, rate.rate(now), rate.sampled(now)) {
                Step::Snapshot if snapshot_bytes == 0 => {
                    snapshot_bytes = snapshot;
                    queue.push_back((snapshot, sent, true));
                }
                _ => {}
            }
            continue;
        }
        catchup.output(now, now.duration_since(t0).as_millis() as u64);
        let w = window(rate.rate(now), min_rtt.get().unwrap(), false);
        while sent - last_ack < w {
            let n = 16384.min(w - (sent - last_ack));
            sent += n;
            queue.push_back((n, sent, false));
        }
        assert!(now < t0 + Duration::from_secs(60), "no snapshot");
    }
}

/// S3 in simulation: Ctrl-C during a flood shows its effect within 2 RTT + 100 ms + S / T at
/// round trip times of 100 ms and more, for slow and fast paths (with 20 ms of settling);
/// below 100 ms within 3 RTT + 300 ms + S / T (the p95 bound), since the 100 ms of slack in
/// the window dominate there.
#[test]
fn ctrl_c_budget_in_simulation() {
    let snapshot = 16 * 1024;
    for rate in [250_000.0, 1_000_000.0, 10_000_000.0] {
        for rtt_ms in [20u64, 50, 100, 270, 400, 600] {
            let rtt = Duration::from_millis(rtt_ms);
            let took = ctrl_c(rtt, rate, snapshot);
            let transfer = Duration::from_secs_f64(snapshot as f64 / rate);
            let p50 = 2 * rtt + 100 * MS + transfer;
            let p95 = 3 * rtt + 300 * MS + transfer;
            eprintln!("rate {rate} B/s rtt {rtt_ms} ms: {took:?} (p50 budget {p50:?})");
            if rtt_ms >= 100 {
                assert!(took <= p50, "rate {rate}, rtt {rtt_ms} ms: {took:?} > {p50:?}");
            } else {
                assert!(took <= p95, "rate {rate}, rtt {rtt_ms} ms: {took:?} > {p95:?}");
            }
        }
    }
}
