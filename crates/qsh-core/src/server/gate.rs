//! Admission of unauthenticated connections (protocol.md section 6.6): how many may be pending
//! at once, per daemon and per source address, and which sources failed to authenticate too
//! often. A connection holds a [`Ticket`] from the moment it is accepted, before any handshake,
//! until it authenticates or closes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::proto::limits::{FAILURE_BURST, FAILURE_REFILL, MAX_PREAUTH_CONNS, MAX_PREAUTH_PER_SOURCE};
use crate::proto::message::canonical_ip;

/// Where a connection comes from, as the limits count it: an IPv4 address, or the /64 prefix of
/// an IPv6 address (one subscriber usually has a whole /64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    V4([u8; 4]),
    V6([u8; 8]),
}

impl Source {
    pub(crate) fn of(ip: IpAddr) -> Source {
        match canonical_ip(ip) {
            IpAddr::V4(v4) => Source::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&v6.octets()[..8]);
                Source::V6(prefix)
            }
        }
    }
}

/// The limits on unauthenticated connections of protocol.md 6.6 whose values may be
/// configured; the defaults are the protocol's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Pending and unauthenticated connections per daemon (`MAX_PREAUTH_CONNS`).
    pub total: usize,
    /// The same per source address (`MAX_PREAUTH_PER_SOURCE`).
    pub per_source: usize,
    /// AUTH_FAILED a source may cause in a burst.
    pub failure_burst: u32,
    /// One more allowed failure per this much time.
    pub failure_refill: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            total: MAX_PREAUTH_CONNS,
            per_source: MAX_PREAUTH_PER_SOURCE,
            failure_burst: FAILURE_BURST,
            failure_refill: FAILURE_REFILL,
        }
    }
}

/// A token bucket of allowed failures.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn refill(&mut self, limits: &Limits, now: Instant) {
        let earned = now.duration_since(self.at).as_secs_f64() / limits.failure_refill.as_secs_f64();
        self.tokens = (self.tokens + earned).min(f64::from(limits.failure_burst));
        self.at = now;
    }
}

/// Source buckets kept at most; full buckets are forgotten first.
const MAX_BUCKETS: usize = 4096;

#[derive(Debug, Default)]
struct State {
    total: usize,
    per_source: HashMap<Source, usize>,
    failures: HashMap<Source, Bucket>,
}

/// The admission state of a daemon.
#[derive(Debug, Default)]
pub(crate) struct Gate {
    limits: Limits,
    state: Mutex<State>,
}

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Too many unauthenticated connections, in all or from this source.
    Busy,
    /// This source failed to authenticate too often lately.
    Blocked,
}

impl Gate {
    pub(crate) fn new(limits: Limits) -> Gate {
        Gate {
            limits,
            state: Mutex::default(),
        }
    }

    /// Admit a new connection from `source` (None for the ssh pipe, which has no network
    /// address and is subject only to the total).
    pub(crate) fn admit(self: &Arc<Self>, source: Option<IpAddr>) -> Result<Ticket, Refusal> {
        let source = source.map(Source::of);
        let mut st = self.state.lock().unwrap();
        if let Some(source) = source {
            if let Some(bucket) = st.failures.get_mut(&source) {
                bucket.refill(&self.limits, Instant::now());
                if bucket.tokens < 1.0 {
                    return Err(Refusal::Blocked);
                }
            }
        }
        if st.total >= self.limits.total {
            return Err(Refusal::Busy);
        }
        if let Some(source) = source {
            let n = st.per_source.entry(source).or_default();
            if *n >= self.limits.per_source {
                return Err(Refusal::Busy);
            }
            *n += 1;
        }
        st.total += 1;
        Ok(Ticket {
            gate: self.clone(),
            source,
        })
    }

    /// True while more than half of the allowed unauthenticated connections are taken: QUIC
    /// then validates addresses with Retry before it admits anyone (section 9.1).
    pub(crate) fn crowded(&self) -> bool {
        self.state.lock().unwrap().total * 2 > self.limits.total
    }

    /// Unauthenticated connections now.
    pub(crate) fn pending(&self) -> usize {
        self.state.lock().unwrap().total
    }

    /// An ATTACH from `source` failed with AUTH_FAILED.
    pub(crate) fn failed(&self, source: IpAddr) {
        let source = Source::of(source);
        let now = Instant::now();
        let limits = self.limits;
        let mut st = self.state.lock().unwrap();
        if !st.failures.contains_key(&source) && st.failures.len() >= MAX_BUCKETS {
            // Forget sources that are back to a full bucket; if that is not enough, everyone
            for bucket in st.failures.values_mut() {
                bucket.refill(&limits, now);
            }
            st.failures.retain(|_, b| b.tokens < f64::from(limits.failure_burst));
            if st.failures.len() >= MAX_BUCKETS {
                st.failures.clear();
            }
        }
        let bucket = st.failures.entry(source).or_insert(Bucket {
            tokens: f64::from(limits.failure_burst),
            at: now,
        });
        bucket.refill(&limits, now);
        bucket.tokens = (bucket.tokens - 1.0).max(0.0);
    }

    fn release(&self, source: Option<Source>) {
        let mut st = self.state.lock().unwrap();
        st.total -= 1;
        if let Some(source) = source {
            if let Some(n) = st.per_source.get_mut(&source) {
                *n -= 1;
                if *n == 0 {
                    st.per_source.remove(&source);
                }
            }
        }
    }
}

/// A place among the unauthenticated connections, given back when dropped: when the connection
/// authenticates or ends.
#[derive(Debug)]
pub(crate) struct Ticket {
    gate: Arc<Gate>,
    source: Option<Source>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.gate.release(self.source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    #[test]
    fn sources_aggregate_ipv6_by_64_and_mapped_ipv4_as_ipv4() {
        assert_eq!(
            Source::of("2001:db8:1:2:aaaa::1".parse().unwrap()),
            Source::of("2001:db8:1:2:bbbb::2".parse().unwrap())
        );
        assert_ne!(
            Source::of("2001:db8:1:2::1".parse().unwrap()),
            Source::of("2001:db8:1:3::1".parse().unwrap())
        );
        assert_eq!(
            Source::of("::ffff:192.0.2.1".parse().unwrap()),
            Source::of("192.0.2.1".parse().unwrap())
        );
    }

    #[test]
    fn per_source_and_total_limits_and_tickets_give_places_back() {
        let gate = Arc::new(Gate::new(Limits {
            total: 10,
            per_source: 3,
            ..Limits::default()
        }));
        let a: Vec<Ticket> = (0..3).map(|_| gate.admit(ip("192.0.2.1")).unwrap()).collect();
        assert_eq!(gate.admit(ip("192.0.2.1")).unwrap_err(), Refusal::Busy);
        // Another /64 of IPv6, and the pipe, are not that source
        let b: Vec<Ticket> = (0..3).map(|_| gate.admit(ip("2001:db8::1")).unwrap()).collect();
        assert_eq!(gate.admit(ip("2001:db8::ffff")).unwrap_err(), Refusal::Busy);
        let c: Vec<Ticket> = (0..4).map(|_| gate.admit(None).unwrap()).collect();
        assert_eq!(gate.pending(), 10);
        assert!(gate.crowded());
        assert_eq!(gate.admit(None).unwrap_err(), Refusal::Busy);
        assert_eq!(gate.admit(ip("198.51.100.1")).unwrap_err(), Refusal::Busy);
        drop(a);
        drop(c);
        assert_eq!(gate.pending(), 3);
        assert!(!gate.crowded());
        assert!(gate.admit(ip("192.0.2.1")).is_ok());
        drop(b);
        assert_eq!(gate.pending(), 0);
        assert!(gate.state.lock().unwrap().per_source.is_empty());
    }

    #[test]
    fn a_source_that_fails_too_often_is_blocked_until_its_bucket_refills() {
        let refill = Duration::from_millis(500);
        let gate = Arc::new(Gate::new(Limits {
            failure_burst: 3,
            failure_refill: refill,
            ..Limits::default()
        }));
        let started = Instant::now();
        for _ in 0..3 {
            assert!(gate.admit(ip("192.0.2.9")).is_ok());
            gate.failed("192.0.2.9".parse().unwrap());
        }
        let refused = gate.admit(ip("192.0.2.9")).map(|_| ());
        // Unless this machine was so slow that a token came back meanwhile
        if started.elapsed() < refill {
            assert_eq!(refused, Err(Refusal::Blocked));
        }
        assert!(gate.admit(ip("192.0.2.10")).is_ok());
        std::thread::sleep(refill + Duration::from_millis(50));
        assert!(gate.admit(ip("192.0.2.9")).is_ok());
    }
}
