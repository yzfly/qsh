//! Path memory (m2.md section 3) and NAT keepalive learning (section 4): what the client
//! learned about reaching a server from a network, and what it does with it.
//!
//! An [`Entry`] is kept per destination (the host QUIC and TLS dial) and network (the default
//! routes, [`crate::netwatch::NetSnapshot::path_key`]): which transports and ports worked,
//! which failed in a way that says something about the network, the handshake times, the
//! path's round-trip time and loss, and the learned keepalive interval. [`plan`] turns an
//! entry into the order and timing of a race's attempts; [`Learner`] adapts the keepalive.
//!
//! # The file
//!
//! [`PathMemory`] keeps the entries in `$XDG_STATE_HOME/qsh/paths.json`
//! ([`crate::Paths::path_memory`]), mode 0600 in the 0700 state directory:
//!
//! ```json
//! {"qsh_paths":1,"salt":"<64 hex>","entries":[
//!  {"d":"9f…(32 hex)","n":"41…(32 hex)","day":20366,
//!   "t":{"quic":{"port":60443,"ok":20366,"hs":420},
//!        "tls":{"port":443,"ok":20360,"hs":610,"fail":{"kind":"timeout","n":2,"retry":1791193600}},
//!        "ssh":{"ok":20101,"hs":1900}},
//!   "rtt":270,"loss":0.06,"ka":10}]}
//! ```
//!
//! `d` and `n` are the first 16 bytes of HMAC-SHA256 keyed with the file's random `salt` over
//! `"qsh-path-dest\0" || host` (lowercased) and `"qsh-path-net\0" || NetKey`: the file names no
//! host and no network, only a guess can be checked against it. Days count from the Unix
//! epoch; the only timestamp is an active `retry`, which goes away once the transport works.
//! At most [`MAX_ENTRIES`] entries (the least recently used goes first), none older than
//! [`EXPIRY_DAYS`]. A file that cannot be used (unknown version, over 1 MiB, invalid JSON, not
//! a private file of this user) is ignored and replaced on the next write; an invalid entry is
//! dropped. Path memory is advisory: it changes the order and timing of attempts, never which
//! transports are allowed, and it can never stop a connection (security.md 4.4).
//!
//! Concurrent `qsh` processes read, merge and write the file under an exclusive lock on
//! `paths.json.lock`; a process writes at most every [`WRITE_INTERVAL`], and when it ends.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::Instant;

use crate::config::Keepalive;
use crate::transport::{FailureKind, Plan, RaceConfig, Target, Transport};
use crate::{crypto, log, paths, sys};

/// The file format version (`qsh_paths`).
pub const FORMAT: u64 = 1;
/// At most this many entries; when full, the least recently used is dropped.
pub const MAX_ENTRIES: usize = 256;
/// An entry unused for this many days is dropped, and not used before that either.
pub const EXPIRY_DAYS: u64 = 30;
/// A larger file is ignored.
pub const MAX_FILE: u64 = 1 << 20;
/// A process writes the file at most this often (and when it ends).
pub const WRITE_INTERVAL: Duration = Duration::from_secs(10);
/// After the n-th consecutive failure of a transport, it is probed again after
/// `RETRY_BACKOFF[n - 1]` seconds (the last value from then on): 1 min, 5 min, 30 min, 2 h,
/// 12 h, 24 h (m2.md 3.6).
pub const RETRY_BACKOFF: [u64; 6] = [60, 300, 1800, 7200, 43_200, 86_400];
/// The keepalive interval of a network nothing is known about (m2.md 4.3).
pub const KEEPALIVE_START: Duration = Duration::from_secs(20);
/// The floor of the learned keepalive interval.
pub const KEEPALIVE_MIN: Duration = Duration::from_secs(5);
/// The ceiling of the learned keepalive interval: two lost keepalives stay within QUIC's
/// 60 s idle timeout.
pub const KEEPALIVE_MAX: Duration = Duration::from_secs(25);
/// Attached time on a network at the current interval without a NAT timeout, after which
/// the interval grows by a quarter.
pub const KEEPALIVE_GROW_AFTER: Duration = Duration::from_secs(30 * 60);
/// At most one learning step per network in this long.
pub const LEARN_INTERVAL: Duration = Duration::from_secs(60);
/// A change of observed address within this long of the client's own move (a rebind, a
/// network change) is the client's doing, not a NAT's.
pub const CLIENT_MOVE_GRACE: Duration = Duration::from_secs(10);
/// The weight of a new sample in the moving averages (handshake time, RTT, loss).
pub const EWMA: f64 = 0.3;
/// A path that loses this share of its packets or more (QUIC's measured loss, [`Entry::loss`])
/// is lossy: a single handshake timeout there blocks nothing ([`Entry::blocked`]).
pub const LOSSY_PATH: f64 = 0.15;

const DAY: u64 = 86_400;
/// How long a write waits for another process's lock before giving up (and trying later).
const LOCK_PATIENCE: Duration = Duration::from_secs(1);

/// Seconds since the Unix epoch, now.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn day_of(now: u64) -> u64 {
    now / DAY
}

/// True when an entry last used on `day` may still be used at `now`.
fn fresh(day: u64, now: u64) -> bool {
    day_of(now).saturating_sub(day) <= EXPIRY_DAYS
}

/// What was learned about one transport (`t.quic`, `t.tls`, `t.ssh`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TransportRecord {
    /// The port that last worked (QUIC, TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The day of the last success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<u64>,
    /// Handshake time in milliseconds (moving average).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hs: Option<u32>,
    /// Present while the transport is considered blocked on this network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail: Option<Failure>,
}

/// A transport considered blocked on a network (m2.md 3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// How it failed: `timeout`, `reset` or `hello`.
    pub kind: String,
    /// Consecutive failures.
    pub n: u32,
    /// When to probe it again, in seconds since the Unix epoch.
    pub retry: u64,
}

impl Failure {
    /// The kind, if it is one path memory records.
    pub fn kind(&self) -> Option<FailureKind> {
        FailureKind::parse(&self.kind).filter(|k| k.recorded())
    }
}

/// The transports of an entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Transports {
    /// QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<TransportRecord>,
    /// TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TransportRecord>,
    /// The ssh pipe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<TransportRecord>,
}

/// What path memory knows about reaching one destination from one network (m2.md 3.3).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// The day of the last use (days since the Unix epoch, UTC).
    pub day: u64,
    /// Per transport.
    #[serde(rename = "t", default)]
    pub transports: Transports,
    /// Smoothed round-trip time in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt: Option<u32>,
    /// QUIC loss ratio, 0 to 1 (moving average).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<f64>,
    /// The learned NAT keepalive interval in seconds; absent: the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ka: Option<f64>,
    /// The transport that won the last race here (`quic`, `tls`, `ssh`), or that the sessions
    /// last moved to: which of two transports that worked the same day worked last, without
    /// storing a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
}

fn ewma(old: Option<f64>, sample: f64) -> f64 {
    match old {
        Some(old) => old * (1.0 - EWMA) + sample * EWMA,
        None => sample,
    }
}

impl Entry {
    /// What is known about `transport`.
    pub fn transport(&self, transport: Transport) -> Option<&TransportRecord> {
        match transport {
            Transport::Quic => self.transports.quic.as_ref(),
            Transport::Tls => self.transports.tls.as_ref(),
            Transport::Ssh => self.transports.ssh.as_ref(),
        }
    }

    fn transport_mut(&mut self, transport: Transport) -> &mut TransportRecord {
        let slot = match transport {
            Transport::Quic => &mut self.transports.quic,
            Transport::Tls => &mut self.transports.tls,
            Transport::Ssh => &mut self.transports.ssh,
        };
        slot.get_or_insert_with(TransportRecord::default)
    }

    /// True while `transport` is considered blocked here: it failed, and is not due to be
    /// probed again before `retry`. On a path that loses [`LOSSY_PATH`] or more of its
    /// packets, a single handshake timeout is not enough: there a handshake runs out of its
    /// 8 s now and then by chance (on the terrible chaos profile, 600 ms and 20 % loss each
    /// way, about one QUIC or TLS attempt in 10 to 20), and leaving the transport out would put
    /// the next sessions on a worse one (m2.md 3.3). The second timeout in a row counts.
    pub fn blocked(&self, transport: Transport, now: u64) -> bool {
        self.transport(transport)
            .and_then(|r| r.fail.as_ref())
            .is_some_and(|f| f.retry > now && !self.by_chance(f))
    }

    /// `f` is a single handshake timeout on a lossy path ([`Entry::blocked`]).
    fn by_chance(&self, f: &Failure) -> bool {
        f.n < 2 && f.kind() == Some(FailureKind::Timeout) && self.loss.is_some_and(|l| l >= LOSSY_PATH)
    }

    /// The transports that failed here and are due to be probed again at `now`.
    pub fn due(&self, now: u64) -> Vec<Transport> {
        TRANSPORTS
            .into_iter()
            .filter(|&t| {
                self.transport(t)
                    .and_then(|r| r.fail.as_ref())
                    .is_some_and(|f| f.retry <= now)
            })
            .collect()
    }

    /// The learned keepalive interval, if any.
    pub fn keepalive(&self) -> Option<Duration> {
        self.ka
            .filter(|k| k.is_finite())
            .map(|k| Duration::from_secs_f64(k).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX))
    }

    /// `transport` reached the server on `port` (0 for the pipe), its handshake taking
    /// `handshake`: it worked today, and is not blocked any more.
    pub fn succeeded(&mut self, transport: Transport, port: u16, handshake: Duration, now: u64) {
        let record = self.transport_mut(transport);
        if transport != Transport::Ssh && port != 0 {
            record.port = Some(port);
        }
        record.ok = Some(day_of(now));
        let ms = handshake.as_secs_f64() * 1000.0;
        record.hs = Some(ewma(record.hs.map(f64::from), ms).round().min(f64::from(u32::MAX)) as u32);
        record.fail = None;
    }

    /// `transport` failed here in a way that says something about the network: it is skipped
    /// until its retry time, which backs off with each consecutive failure
    /// ([`RETRY_BACKOFF`], never more than 24 h ahead).
    pub fn failed(&mut self, transport: Transport, kind: FailureKind, now: u64) {
        let record = self.transport_mut(transport);
        let n = record.fail.as_ref().map_or(0, |f| f.n).saturating_add(1);
        let wait = RETRY_BACKOFF[(n as usize - 1).min(RETRY_BACKOFF.len() - 1)];
        record.fail = Some(Failure {
            kind: kind.as_str().to_string(),
            n,
            retry: now + wait,
        });
    }

    /// A background probe of `transport` failed with `kind` (m2.md 3.6): back off further. A
    /// failure that says nothing about the network keeps the kind already recorded.
    pub fn probe_failed(&mut self, transport: Transport, kind: FailureKind, now: u64) {
        let kind = if kind.recorded() {
            kind
        } else {
            self.transport(transport)
                .and_then(|r| r.fail.as_ref())
                .and_then(Failure::kind)
                .unwrap_or(FailureKind::Timeout)
        };
        self.failed(transport, kind, now);
    }

    /// Forget every failure mark: the memory was wrong (m2.md 3.5, step 4).
    pub fn clear_failures(&mut self) {
        for t in TRANSPORTS {
            if let Some(r) = self.transport_mut_existing(t) {
                r.fail = None;
            }
        }
    }

    fn transport_mut_existing(&mut self, transport: Transport) -> Option<&mut TransportRecord> {
        match transport {
            Transport::Quic => self.transports.quic.as_mut(),
            Transport::Tls => self.transports.tls.as_mut(),
            Transport::Ssh => self.transports.ssh.as_mut(),
        }
    }

    /// The connection measured `rtt` and (QUIC) `loss`.
    pub fn measured(&mut self, rtt: Option<Duration>, loss: Option<f64>) {
        if let Some(rtt) = rtt {
            let ms = rtt.as_secs_f64() * 1000.0;
            self.rtt = Some(ewma(self.rtt.map(f64::from), ms).round().min(f64::from(u32::MAX)) as u32);
        }
        if let Some(loss) = loss.filter(|l| l.is_finite()) {
            let l = ewma(self.loss, loss.clamp(0.0, 1.0));
            self.loss = Some((l * 10_000.0).round() / 10_000.0);
        }
    }

    /// `transport` won a race on `port` (or the sessions moved to it): it worked, and it is
    /// the one to start with next time ([`Entry::last`]).
    pub fn won(&mut self, transport: Transport, port: u16, handshake: Duration, now: u64) {
        self.succeeded(transport, port, handshake, now);
        self.last = Some(name(transport).to_string());
    }

    /// The transport that won the last race here.
    pub fn last(&self) -> Option<Transport> {
        self.last.as_deref().and_then(parse_name)
    }

    /// The transports considered blocked at `now`.
    pub fn blocked_now(&self, now: u64) -> Vec<Transport> {
        TRANSPORTS.into_iter().filter(|&t| self.blocked(t, now)).collect()
    }

    /// Remember the keepalive interval `k`.
    pub fn set_keepalive(&mut self, k: Duration) {
        self.ka = Some((k.as_secs_f64() * 10.0).round() / 10.0);
    }

    /// True when every field is within its range (an entry read from a file).
    fn valid(&self, now: u64) -> bool {
        let records_ok = TRANSPORTS.into_iter().all(|t| {
            self.transport(t).is_none_or(|r| {
                r.fail
                    .as_ref()
                    .is_none_or(|f| f.kind().is_some() && f.n >= 1 && f.retry <= now + RETRY_BACKOFF[5])
                    && r.ok.is_none_or(|d| d <= day_of(now) + 1)
            })
        });
        records_ok
            && self.day <= day_of(now) + 1
            && self.loss.is_none_or(|l| (0.0..=1.0).contains(&l))
            && self.ka.is_none_or(|k| k.is_finite() && (1.0..=3600.0).contains(&k))
            && self.last.as_deref().is_none_or(|l| parse_name(l).is_some())
    }
}

const TRANSPORTS: [Transport; 3] = [Transport::Quic, Transport::Tls, Transport::Ssh];

/// A transport's name in the file.
fn name(t: Transport) -> &'static str {
    match t {
        Transport::Quic => "quic",
        Transport::Tls => "tls",
        Transport::Ssh => "ssh",
    }
}

fn parse_name(name: &str) -> Option<Transport> {
    TRANSPORTS.into_iter().find(|&t| self::name(t) == name)
}

/// The keyed hash that names a destination or a network in the file.
fn keyed(salt: &[u8; 32], label: &[u8], data: &[u8]) -> [u8; 16] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);
    let mut context = ring::hmac::Context::with_key(&key);
    context.update(label);
    context.update(data);
    let tag = context.sign();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag.as_ref()[..16]);
    out
}

/// The destination key `d` of `host` under `salt` (m2.md 3.2).
pub fn destination_key(salt: &[u8; 32], host: &str) -> [u8; 16] {
    keyed(salt, b"qsh-path-dest\0", host.to_lowercase().as_bytes())
}

/// The network key `n` of `network` ([`crate::netwatch::NetSnapshot::path_key`]) under
/// `salt` (m2.md 3.2).
pub fn network_key(salt: &[u8; 32], network: &[u8]) -> [u8; 16] {
    keyed(salt, b"qsh-path-net\0", network)
}

/// An entry as stored: its keys and its content.
#[derive(Debug, Clone)]
struct Stored {
    d: [u8; 16],
    n: [u8; 16],
    entry: Entry,
}

#[derive(Debug, Default)]
struct Inner {
    loaded: bool,
    salt: [u8; 32],
    /// The entries as last read or written.
    stored: Vec<Stored>,
    /// What this process changed since, by destination and network in the clear (in memory
    /// only), so that it can be merged into the file under whatever salt the file has then.
    changed: HashMap<(String, Vec<u8>), Entry>,
    last_write: Option<std::time::Instant>,
}

/// Path memory: the entries, kept in a file ([`PathMemory::open`]) or only in this process
/// ([`PathMemory::in_memory`]). Reads load the file on first use; changes are written by
/// [`PathMemory::flush`].
#[derive(Debug)]
pub struct PathMemory {
    file: Option<PathBuf>,
    inner: Mutex<Inner>,
}

impl PathMemory {
    /// Path memory in the file `path` (read on first use; created on the first write, with
    /// its directory, mode 0700).
    pub fn open(path: impl Into<PathBuf>) -> PathMemory {
        PathMemory {
            file: Some(path.into()),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Path memory in its standard place, [`crate::Paths::path_memory`].
    pub fn standard(paths: &crate::Paths) -> PathMemory {
        PathMemory::open(paths.path_memory())
    }

    /// Path memory that lives only as long as this value: with `path_memory = false`, and
    /// for embedders that keep no files.
    pub fn in_memory() -> PathMemory {
        PathMemory {
            file: None,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The file, if there is one.
    pub fn path(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// The entry for `host` on `network` ([`crate::netwatch::NetSnapshot::path_key`]), if
    /// there is a usable one: what `qsh doctor` shows.
    pub fn entry(&self, host: &str, network: &[u8]) -> Option<Entry> {
        self.entry_at(host, network, now())
    }

    /// [`PathMemory::entry`] at `now` (seconds since the Unix epoch).
    pub fn entry_at(&self, host: &str, network: &[u8], now: u64) -> Option<Entry> {
        if network.is_empty() {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();
        self.load(&mut inner);
        lookup(&inner, host, network).filter(|e| fresh(e.day, now))
    }

    /// Change the entry for `host` on `network` with `change` (creating it), and mark it used
    /// today. Nothing when `network` is empty (offline).
    pub fn update(&self, host: &str, network: &[u8], now: u64, change: impl FnOnce(&mut Entry)) {
        if network.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        self.load(&mut inner);
        let mut entry = lookup(&inner, host, network)
            .filter(|e| fresh(e.day, now))
            .unwrap_or_default();
        change(&mut entry);
        entry.day = day_of(now);
        inner.changed.insert((host.to_lowercase(), network.to_vec()), entry);
        if self.file.is_none() && inner.changed.len() > MAX_ENTRIES {
            let oldest = inner.changed.iter().min_by_key(|(_, e)| e.day).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                inner.changed.remove(&k);
            }
        }
    }

    /// True when there are changes to write.
    pub fn dirty(&self) -> bool {
        self.file.is_some() && !self.inner.lock().unwrap().changed.is_empty()
    }

    /// Write the changes if there are any and the last write is at least [`WRITE_INTERVAL`]
    /// ago. True when it wrote.
    pub fn flush_due(&self) -> io::Result<bool> {
        let due = {
            let inner = self.inner.lock().unwrap();
            !inner.changed.is_empty() && inner.last_write.is_none_or(|t| t.elapsed() >= WRITE_INTERVAL)
        };
        if !due || self.file.is_none() {
            return Ok(false);
        }
        self.flush().map(|()| true)
    }

    /// Write the changes now, merged into what the file holds (another process may have
    /// written it since), under the file's lock. Blocks for the file system and for at most
    /// a second for another process's lock.
    pub fn flush(&self) -> io::Result<()> {
        let Some(path) = &self.file else { return Ok(()) };
        let mut inner = self.inner.lock().unwrap();
        if inner.changed.is_empty() {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            paths::ensure_private_dir(dir)?;
        }
        let _lock = lock(path)?;
        let now = now();
        let (salt, mut stored) = match read_file(path, now) {
            Ok(file) => file,
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    log::debug(format_args!("path memory: replacing {}: {e}", path.display()));
                }
                (crypto::random::<32>(), Vec::new())
            }
        };
        for ((host, network), entry) in &inner.changed {
            let (d, n) = (destination_key(&salt, host), network_key(&salt, network));
            stored.retain(|s| !(s.d == d && s.n == n));
            stored.push(Stored {
                d,
                n,
                entry: entry.clone(),
            });
        }
        prune(&mut stored, now);
        paths::write_private(path, &encode(&salt, &stored))?;
        inner.salt = salt;
        inner.stored = stored;
        inner.changed.clear();
        inner.loaded = true;
        inner.last_write = Some(std::time::Instant::now());
        Ok(())
    }

    fn load(&self, inner: &mut Inner) {
        if inner.loaded {
            return;
        }
        inner.loaded = true;
        inner.salt = crypto::random::<32>();
        let Some(path) = &self.file else { return };
        match read_file(path, now()) {
            Ok((salt, stored)) => {
                inner.salt = salt;
                inner.stored = stored;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => log::debug(format_args!(
                "path memory: ignoring {} (it is replaced on the next write): {e}",
                path.display()
            )),
        }
    }
}

fn lookup(inner: &Inner, host: &str, network: &[u8]) -> Option<Entry> {
    let host = host.to_lowercase();
    if let Some(e) = inner.changed.get(&(host.clone(), network.to_vec())) {
        return Some(e.clone());
    }
    let (d, n) = (destination_key(&inner.salt, &host), network_key(&inner.salt, network));
    inner
        .stored
        .iter()
        .find(|s| s.d == d && s.n == n)
        .map(|s| s.entry.clone())
}

/// Drop expired entries, then the least recently used beyond [`MAX_ENTRIES`].
fn prune(stored: &mut Vec<Stored>, now: u64) {
    stored.retain(|s| fresh(s.entry.day, now));
    if stored.len() > MAX_ENTRIES {
        // Newest first; stable, so the order within a day is kept
        stored.sort_by_key(|s| std::cmp::Reverse(s.entry.day));
        stored.truncate(MAX_ENTRIES);
    }
}

fn encode(salt: &[u8; 32], stored: &[Stored]) -> Vec<u8> {
    let entries: Vec<Value> = stored
        .iter()
        .map(|s| {
            let mut v = serde_json::to_value(&s.entry).unwrap_or(Value::Null);
            if let Value::Object(map) = &mut v {
                map.insert("d".into(), Value::String(crypto::hex(&s.d)));
                map.insert("n".into(), Value::String(crypto::hex(&s.n)));
            }
            v
        })
        .collect();
    let file = serde_json::json!({
        "qsh_paths": FORMAT,
        "salt": crypto::hex(salt),
        "entries": entries,
    });
    let mut bytes = serde_json::to_vec(&file).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

fn invalid(why: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.into())
}

/// The file's salt and its usable entries. An error when the file cannot be used at all.
fn read_file(path: &Path, now: u64) -> io::Result<([u8; 32], Vec<Stored>)> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(invalid("not a regular file"));
    }
    if meta.uid() != sys::euid() {
        return Err(invalid(format!("belongs to another user (uid {})", meta.uid())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "accessible to other users (mode {:o})",
            meta.mode() & 0o7777
        )));
    }
    if meta.len() > MAX_FILE {
        return Err(invalid("larger than 1 MiB"));
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(invalid("larger than 1 MiB"));
    }
    parse(&bytes, now)
}

/// Parse the file's content: its salt and its usable entries (invalid and expired ones are
/// dropped).
fn parse(bytes: &[u8], now: u64) -> io::Result<([u8; 32], Vec<Stored>)> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| invalid(format!("not JSON: {e}")))?;
    if v.get("qsh_paths").and_then(Value::as_u64) != Some(FORMAT) {
        return Err(invalid("unknown format version"));
    }
    let salt = v
        .get("salt")
        .and_then(Value::as_str)
        .and_then(crypto::unhex::<32>)
        .ok_or_else(|| invalid("no valid salt"))?;
    let entries = v
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("no entries"))?;
    let mut stored = Vec::new();
    let mut dropped = 0;
    for e in entries {
        match parse_entry(e, now) {
            Some(s) if fresh(s.entry.day, now) && !stored.iter().any(|o: &Stored| o.d == s.d && o.n == s.n) => {
                stored.push(s)
            }
            Some(_) => {}
            None => dropped += 1,
        }
    }
    if dropped > 0 {
        log::debug(format_args!("path memory: {dropped} invalid entries dropped"));
    }
    prune(&mut stored, now);
    Ok((salt, stored))
}

fn parse_entry(v: &Value, now: u64) -> Option<Stored> {
    let d = crypto::unhex::<16>(v.get("d")?.as_str()?)?;
    let n = crypto::unhex::<16>(v.get("n")?.as_str()?)?;
    let entry: Entry = serde_json::from_value(v.clone()).ok()?;
    entry.valid(now).then_some(Stored { d, n, entry })
}

/// Hold the exclusive lock on `paths.json.lock` beside `path`.
fn lock(path: &Path) -> io::Result<fs::File> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.with_file_name(format!("{name}.lock")))?;
    let deadline = std::time::Instant::now() + LOCK_PATIENCE;
    loop {
        if sys::try_lock(&file)? {
            return Ok(file);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "path memory is locked"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A race's plan from path memory, and what it left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    /// The attempts.
    pub plan: Plan,
    /// Transports allowed by the configuration but left out because they are blocked here;
    /// they are probed in the background (m2.md 3.6).
    pub skipped: Vec<Transport>,
    /// True when an entry shaped the plan.
    pub remembered: bool,
}

/// The plan of a race to `target` on a network whose entry is `entry` (m2.md 3.5): without
/// an entry, or with one older than 30 days, the configuration's plan (QUIC at once, TLS
/// after 400 ms, the pipe after 3 s, each transport's ports 300 ms apart). With one:
///
/// 1. the winner (the transport with the most recent success; among those, one not marked
///    as failing, then the one that won the last race here, then QUIC before TLS before the
///    pipe) starts at once, on its remembered port, first among the attempts at 0 ms;
/// 2. transports blocked here (a failure whose retry time is ahead) are left out, unless that
///    would leave nothing;
/// 3. when QUIC starts before TLS and has a handshake time, TLS starts
///    `clamp(1.5 × hs, 250 ms, 2 s)` after QUIC instead of the configured stagger.
///
/// Path memory never adds a transport the configuration does not allow.
pub fn plan(entry: Option<&Entry>, target: &Target, race: &RaceConfig, now: u64) -> Planned {
    let default = || Planned {
        plan: Plan::new(target, race),
        skipped: Vec::new(),
        remembered: false,
    };
    let Some(entry) = entry.filter(|e| fresh(e.day, now)) else {
        return default();
    };
    let allowed: Vec<Transport> = TRANSPORTS
        .into_iter()
        .filter(|&t| race.start(t).is_some() && !target.candidates(t, None).is_empty())
        .collect();
    let (skipped, in_race): (Vec<Transport>, Vec<Transport>) = allowed.iter().partition(|&&t| entry.blocked(t, now));
    if in_race.is_empty() {
        return default();
    }
    // `ok` is a day: among transports that worked the same day, the last race's winner
    let last = entry.last();
    let winner = in_race
        .iter()
        .filter_map(|&t| {
            let r = entry.transport(t)?;
            Some((t, r.ok?, r.fail.is_none()))
        })
        .max_by_key(|&(t, ok, clean)| (clean, ok, Some(t) == last, std::cmp::Reverse(t)))
        .map(|(t, _, _)| t);
    // The winner first: it is preferred among the attempts that start at once
    let order = winner
        .into_iter()
        .chain(in_race.iter().copied().filter(|&t| Some(t) != winner));
    let mut starts: Vec<(Transport, Duration)> = order
        .map(|t| {
            let start = if Some(t) == winner {
                Duration::ZERO
            } else {
                race.start(t).unwrap_or_default()
            };
            (t, start)
        })
        .collect();
    let start_of = |starts: &[(Transport, Duration)], t| starts.iter().find(|(x, _)| *x == t).map(|(_, d)| *d);
    if let (Some(quic), Some(tls), Some(hs)) = (
        start_of(&starts, Transport::Quic),
        start_of(&starts, Transport::Tls),
        entry.transport(Transport::Quic).and_then(|r| r.hs),
    ) {
        if winner != Some(Transport::Tls) && tls > quic {
            let stagger =
                Duration::from_millis(u64::from(hs) * 3 / 2).clamp(Duration::from_millis(250), Duration::from_secs(2));
            for (t, d) in &mut starts {
                if *t == Transport::Tls {
                    *d = quic + stagger;
                }
            }
        }
    }
    let plan = Plan::build(
        target,
        starts
            .into_iter()
            .map(|(t, d)| (t, Some(d), entry.transport(t).and_then(|r| r.port))),
    );
    Planned {
        plan,
        skipped,
        remembered: true,
    }
}

/// The keepalive interval for a connection on a network whose entry is `entry`, and whether
/// it is learned (`keepalive = "auto"`) rather than configured.
pub fn keepalive_for(config: Keepalive, entry: Option<&Entry>) -> (Duration, bool) {
    match config {
        Keepalive::Every(k) => (k, false),
        Keepalive::Auto => (entry.and_then(Entry::keepalive).unwrap_or(KEEPALIVE_START), true),
    }
}

/// A NAT timeout was detected: the interval halves, down to [`KEEPALIVE_MIN`].
pub fn halve(k: Duration) -> Duration {
    (k / 2).max(KEEPALIVE_MIN)
}

/// Quiet for [`KEEPALIVE_GROW_AFTER`]: the interval grows by a quarter, up to
/// [`KEEPALIVE_MAX`].
pub fn grow(k: Duration) -> Duration {
    k.mul_f64(1.25).min(KEEPALIVE_MAX)
}

/// A PATH_INFO reported a new address for a QUIC connection (m2.md 4.2).
#[derive(Debug, Clone, Copy)]
pub struct Rebinding {
    /// When it arrived.
    pub at: Instant,
    /// How long the client had sent nothing but keepalives when the change happened.
    pub idle: Duration,
    /// When the client last moved itself (rebound its socket, saw the network change).
    pub client_moved: Option<Instant>,
    /// The local address of the endpoint changed since the previous PATH_INFO.
    pub local_changed: bool,
    /// The keepalive interval in effect on the connection.
    pub effective: Duration,
}

/// NAT keepalive learning on one network (m2.md 4.3): the interval `K`, halved when a NAT
/// timeout is detected and grown after quiet periods.
#[derive(Debug, Clone)]
pub struct Learner {
    k: Duration,
    quiet: Duration,
    last_step: Option<Instant>,
}

impl Learner {
    /// Learning from `k`, the network's current interval; `last_step`: the last learning step
    /// on this network, if recent.
    pub fn new(k: Duration, last_step: Option<Instant>) -> Learner {
        Learner {
            k,
            quiet: Duration::ZERO,
            last_step,
        }
    }

    /// The current interval.
    pub fn k(&self) -> Duration {
        self.k
    }

    /// The last learning step.
    pub fn last_step(&self) -> Option<Instant> {
        self.last_step
    }

    /// An observed address changed: when that means a NAT forgot an idle mapping (the
    /// client did not move, it was idle for at least the interval in effect, and there was
    /// no other step in the last minute), halve the interval. Returns the new interval when it
    /// changed.
    pub fn rebinding(&mut self, r: &Rebinding) -> Option<Duration> {
        if r.local_changed {
            return None;
        }
        let recently = |t: Instant, within: Duration| r.at.checked_duration_since(t).is_none_or(|d| d < within);
        if r.client_moved.is_some_and(|m| recently(m, CLIENT_MOVE_GRACE)) {
            return None;
        }
        if r.idle < r.effective {
            return None;
        }
        if self.last_step.is_some_and(|s| recently(s, LEARN_INTERVAL)) {
            return None;
        }
        self.last_step = Some(r.at);
        self.quiet = Duration::ZERO;
        let k = halve(self.k);
        (k != self.k).then(|| {
            self.k = k;
            k
        })
    }

    /// `elapsed` more of attached time on this network during which the interval was in
    /// effect: after [`KEEPALIVE_GROW_AFTER`] of it without a step, grow. Returns the new
    /// interval when it changed.
    pub fn quiet(&mut self, elapsed: Duration) -> Option<Duration> {
        self.quiet += elapsed;
        if self.quiet < KEEPALIVE_GROW_AFTER {
            return None;
        }
        self.quiet = Duration::ZERO;
        let k = grow(self.k);
        (k != self.k).then(|| {
            self.k = k;
            k
        })
    }

    /// The connection moved to another network, whose interval is `k`.
    pub fn network(&mut self, k: Duration, last_step: Option<Instant>) {
        self.k = k;
        self.quiet = Duration::ZERO;
        self.last_step = last_step;
    }
}

#[cfg(test)]
mod tests;
