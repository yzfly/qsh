//! Output pacing, smart catch-up triggers and the compression policy of one attachment (m2.md
//! 6.3, 6.4, 7.2; protocol.md 7.6, 7.8.5, 7.12): pure state machines on an explicit clock, so
//! that the tests run them on simulated time.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The delivery-rate window: `T` is the best per-second average of its last this long.
const RATE_WINDOW: Duration = Duration::from_secs(10);
/// A delivery-rate sample spans at least this long, and at least a quarter of the minimum
/// round trip time: ACKs that arrive together (coalesced by the path or the transport) are
/// one sample, not a rate of gigabytes per second.
const MIN_SAMPLE: Duration = Duration::from_millis(1);
/// A sample counts at most this many times `T` (or the initial estimate): `T` can double
/// per sample, not jump to whatever a burst of ACKs suggests.
const MAX_GROWTH: f64 = 2.0;
/// Before the first sample on the mux transports (TLS, ssh pipe): 1 MiB/s.
pub(super) const INITIAL_RATE_MUX: f64 = 1024.0 * 1024.0;
/// The window: at least this much on a tty session …
const WINDOW_MIN_TTY: u64 = 64 * 1024;
/// … and on a pipe session, and at most this much on either.
const WINDOW_MIN_PIPE: u64 = 256 * 1024;
const WINDOW_MAX: u64 = 8 << 20;
/// Added to the round trip time for the window: the client's ACK delay and some slack.
const WINDOW_SLACK: Duration = Duration::from_millis(100);

/// Backlog trigger: more unacknowledged output than this many seconds of `T` …
pub(super) const CATCHUP_AFTER: Duration = Duration::from_secs(2);
/// … and at least this much (`CATCHUP_MIN`).
pub(super) const CATCHUP_MIN: u64 = 256 * 1024;
/// The backlog trigger needs this much of delivery-rate samples (QUIC: half, it has its
/// congestion window to start from).
const SAMPLED_MUX: Duration = Duration::from_secs(1);
const SAMPLED_QUIC: Duration = Duration::from_millis(500);
/// Input trigger: input during more unsent output than the window, and at least this much.
const INTERRUPT_MIN: u64 = 64 * 1024;
/// After such input: the snapshot once output pauses this long …
const SETTLE: Duration = Duration::from_millis(20);
/// … or after this long anyway.
const SETTLE_MAX: Duration = Duration::from_millis(100);
/// No new backlog snapshot before the last one is acknowledged and this long has passed.
const HYSTERESIS: Duration = Duration::from_secs(1);
/// Snapshots in flight at most: one, and one for input sent while it is in flight.
const MAX_IN_FLIGHT: usize = 2;

/// Compression only below this delivery rate (`COMPRESS_BELOW`, 4 MiB/s).
pub(super) const COMPRESS_BELOW: f64 = 4.0 * 1024.0 * 1024.0;
/// Only chunks of at least this much are compressed (keystroke echoes go out raw).
pub(super) const COMPRESS_MIN: usize = 512;
/// Compression stops while recent frames compress worse than this …
const COMPRESSIBLE: f64 = 0.85;
/// … and a chunk is tried again after this much output or this long.
const RETRY_BYTES: u64 = 1 << 20;
const RETRY_AFTER: Duration = Duration::from_secs(2);

/// The pacing window (m2.md 6.3): `clamp(1.25 × T × (R + 100 ms), 64 KiB, 8 MiB)` on a tty
/// session, `max(2 × T × (R + 100 ms), 256 KiB)` (at most 8 MiB) on a pipe session.
pub(super) fn window(rate: f64, rtt: Duration, pipe: bool) -> u64 {
    let time = (rtt + WINDOW_SLACK).as_secs_f64();
    let (gain, min) = if pipe {
        (2.0, WINDOW_MIN_PIPE)
    } else {
        (1.25, WINDOW_MIN_TTY)
    };
    ((gain * rate * time) as u64).clamp(min, WINDOW_MAX)
}

/// The delivery rate `T` of one output stream, in output offsets per second (m2.md 6.3).
#[derive(Debug)]
pub(super) struct Rate {
    /// Per second of samples: (start, bytes, time).
    buckets: VecDeque<(Instant, u64, Duration)>,
    /// When the current sample started (an accepted ACK), and what was delivered in it since.
    sample: Option<(Instant, u64)>,
    /// Output was not waiting at some point during the current sample: it measures the
    /// program, not the path.
    limited: bool,
    /// `T` before the first sample.
    initial: f64,
}

impl Rate {
    pub(super) fn new(initial: f64) -> Rate {
        Rate {
            buckets: VecDeque::new(),
            sample: None,
            limited: true,
            initial,
        }
    }

    /// Nothing was waiting to be sent (the stream is application-limited).
    pub(super) fn limited(&mut self) {
        self.limited = true;
    }

    /// An ACK newly acknowledged `delivered` output offsets (skipped ones not counted);
    /// `waiting`: output is waiting to be sent right now; `rtt`: the minimum round trip time.
    /// The sample ends here if it spans at least `max(1 ms, rtt / 4)`; otherwise it goes on.
    pub(super) fn ack(&mut self, now: Instant, delivered: u64, waiting: bool, rtt: Duration) {
        let Some((start, before)) = self.sample else {
            self.sample = Some((now, 0));
            self.limited = !waiting;
            return;
        };
        let delivered = before + delivered;
        let time = now.saturating_duration_since(start);
        if time < MIN_SAMPLE.max(rtt / 4) {
            self.sample = Some((start, delivered));
            self.limited |= !waiting;
            return;
        }
        if !self.limited {
            let most = (MAX_GROWTH * self.rate(now).max(self.initial) * time.as_secs_f64()) as u64;
            let delivered = delivered.min(most);
            match self.buckets.back_mut() {
                Some(b) if now.saturating_duration_since(b.0) < Duration::from_secs(1) => {
                    b.1 += delivered;
                    b.2 += time;
                }
                _ => self.buckets.push_back((now, delivered, time)),
            }
        }
        while self
            .buckets
            .front()
            .is_some_and(|b| now.saturating_duration_since(b.0) > RATE_WINDOW)
        {
            self.buckets.pop_front();
        }
        self.sample = Some((now, 0));
        self.limited = !waiting;
    }

    /// `T`: the best per-second average of the last 10 s; the initial estimate before any.
    pub(super) fn rate(&self, now: Instant) -> f64 {
        self.buckets
            .iter()
            .filter(|b| now.saturating_duration_since(b.0) <= RATE_WINDOW && !b.2.is_zero())
            .map(|b| b.1 as f64 / b.2.as_secs_f64())
            .fold(None, |best: Option<f64>, r| Some(best.map_or(r, |b| b.max(r))))
            .unwrap_or(self.initial)
    }

    /// How much sampled time `T` rests on.
    pub(super) fn sampled(&self, now: Instant) -> Duration {
        self.buckets
            .iter()
            .filter(|b| now.saturating_duration_since(b.0) <= RATE_WINDOW)
            .map(|b| b.2)
            .sum()
    }
}

/// What the catch-up logic wants now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    /// Send output as usual.
    Send,
    /// Send no output until then (the program's reaction to input is awaited), or until the
    /// snapshot in flight is acknowledged (None).
    Hold(Option<Instant>),
    /// Take a skip snapshot now.
    Snapshot,
}

/// An attachment's output stream as the triggers see it (protocol.md 7.8.5).
#[derive(Debug, Clone, Copy)]
pub(super) struct Stream {
    /// `U`: output not acknowledged, skipped ranges not counted.
    pub unacked: u64,
    /// `B`: output not sent yet.
    pub unsent: u64,
    pub last_ack: u64,
    /// The output's end.
    pub end: u64,
    /// `T`, and how much sampled time it rests on.
    pub rate: f64,
    pub sampled: Duration,
    /// Snapshots in flight (sent, not acknowledged): the backlog trigger and resyncs wait for
    /// none, the input trigger for at most one.
    pub snapshots: usize,
}

/// The triggers of smart catch-up for one attachment (m2.md 6.4).
#[derive(Debug)]
pub(super) struct Catchup {
    /// The last snapshot: when, and its offset.
    last: Option<(Instant, u64)>,
    /// Input arrived during a backlog, when.
    interrupt: Option<Instant>,
    /// When output last grew, and to where.
    output: (Instant, u64),
    /// A resync snapshot is due once the attachment has sent everything (m2.md 6.5).
    pub(super) resync: bool,
    /// No snapshot could be made of the output up to this offset: the backlog trigger waits
    /// for more output (the attempt would only cost the same again).
    failed: Option<u64>,
    quic: bool,
}

impl Catchup {
    pub(super) fn new(now: Instant, end: u64, quic: bool) -> Catchup {
        Catchup {
            last: None,
            interrupt: None,
            output: (now, end),
            resync: false,
            failed: None,
            quic,
        }
    }

    /// The output's end now.
    pub(super) fn output(&mut self, now: Instant, end: u64) {
        if end != self.output.1 {
            self.output = (now, end);
        }
    }

    /// Input arrived while `backlog` bytes of output were not sent yet, with window `window`.
    pub(super) fn input(&mut self, now: Instant, backlog: u64, window: u64) {
        if self.interrupt.is_none() && backlog > window.max(INTERRUPT_MIN) {
            self.interrupt = Some(now);
            // The pause is measured from here: the program reacts after the input
            self.output.0 = now;
        }
    }

    /// Input is waiting for the program's reaction.
    pub(super) fn interrupted(&self) -> bool {
        self.interrupt.is_some()
    }

    /// What to do with the output stream `s`. At most one snapshot is in flight, and one more
    /// for input: the backlog trigger waits for the acknowledgement of the one in flight, so
    /// that one fresh snapshot follows instead of a stack of them; the input trigger does not
    /// (its snapshot would wait a round trip and the queue ahead of the first, protocol.md
    /// 7.8.5), unless two are in flight already, and then holds the output until one is
    /// acknowledged.
    pub(super) fn step(&self, now: Instant, s: &Stream) -> Step {
        if let Some(since) = self.interrupt {
            let settled = self.output.0 + SETTLE;
            let latest = since + SETTLE_MAX;
            return if now < settled && now < latest {
                Step::Hold(Some(settled.min(latest)))
            } else if s.snapshots >= MAX_IN_FLIGHT {
                Step::Hold(None)
            } else {
                Step::Snapshot
            };
        }
        let enough = if self.quic { SAMPLED_QUIC } else { SAMPLED_MUX };
        let backlog = s.unacked > ((CATCHUP_AFTER.as_secs_f64() * s.rate) as u64).max(CATCHUP_MIN);
        let rested = self
            .last
            .is_none_or(|(at, offset)| s.last_ack >= offset && now.saturating_duration_since(at) >= HYSTERESIS);
        // Something to skip, and something new since a snapshot could not be made
        let new = s.unsent > 0 && self.failed.is_none_or(|f| s.end > f);
        if backlog && s.sampled >= enough && rested && new && s.snapshots == 0 {
            Step::Snapshot
        } else {
            Step::Send
        }
    }

    /// A snapshot at `offset` was sent (or an OUTPUT_GAP to `offset` instead).
    pub(super) fn taken(&mut self, now: Instant, offset: u64) {
        self.last = Some((now, offset));
        self.interrupt = None;
        self.resync = false;
        self.failed = None;
    }

    /// No snapshot could be taken of the output up to `end` (none fits, or the model is gone):
    /// give up on the input trigger rather than hold output, and on the backlog trigger until
    /// more output arrives.
    pub(super) fn failed(&mut self, end: u64) {
        self.interrupt = None;
        self.resync = false;
        self.failed = Some(end);
    }
}

/// The compression policy of one output stream (m2.md 7.2).
#[derive(Debug)]
pub(super) struct Squeeze {
    /// Recent frames' compressed / raw (EWMA, α = 0.25).
    ratio: f64,
    /// Compression is off since (when, output sent by then).
    off: Option<(Instant, u64)>,
}

impl Squeeze {
    pub(super) fn new() -> Squeeze {
        Squeeze { ratio: 0.5, off: None }
    }

    /// Whether to compress a chunk of `ready` bytes now, at delivery rate `rate`, with `sent`
    /// output sent so far. The rate is in output offsets: while compression is on it counts
    /// what the frames carried, so the path's own rate is that times the ratio (otherwise
    /// compression would raise `T` past the limit and turn itself off).
    pub(super) fn wanted(&self, now: Instant, rate: f64, ready: u64, sent: u64) -> bool {
        let path = if self.off.is_none() {
            rate * self.ratio.min(1.0)
        } else {
            rate
        };
        path < COMPRESS_BELOW
            && ready >= COMPRESS_MIN as u64
            && self.off.is_none_or(|(since, at)| {
                now.saturating_duration_since(since) >= RETRY_AFTER || sent.saturating_sub(at) >= RETRY_BYTES
            })
    }

    /// A chunk of `raw` bytes compressed to `frame` bytes.
    pub(super) fn record(&mut self, now: Instant, raw: usize, frame: usize, sent: u64) {
        let sample = frame as f64 / raw.max(1) as f64;
        self.ratio = 0.75 * self.ratio + 0.25 * sample.min(1.5);
        self.off = (self.ratio >= COMPRESSIBLE).then_some((now, sent));
    }
}

/// The smallest round trip time seen recently (a decaying minimum): the window uses it rather
/// than the smoothed RTT, which grows with the queue the window itself builds.
#[derive(Debug)]
pub(super) struct MinRtt {
    value: Option<(Duration, Instant)>,
}

/// A minimum older than this is replaced by the next sample.
const MIN_RTT_FOR: Duration = Duration::from_secs(30);

impl MinRtt {
    pub(super) fn new() -> MinRtt {
        MinRtt { value: None }
    }

    pub(super) fn sample(&mut self, now: Instant, rtt: Duration) {
        match self.value {
            Some((min, at)) if rtt >= min && now.saturating_duration_since(at) < MIN_RTT_FOR => {}
            _ => self.value = Some((rtt, now)),
        }
    }

    pub(super) fn get(&self) -> Option<Duration> {
        self.value.map(|v| v.0)
    }
}

#[cfg(test)]
mod tests;
