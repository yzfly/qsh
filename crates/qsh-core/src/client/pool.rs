//! Connections to daemons, one per daemon and shared by the sessions to it, the transport
//! race that establishes them (protocol.md section 12.1), and the network watcher that moves
//! them when the network changes (sections 12.3 and 12.4).
//!
//! Path intelligence (m2.md sections 3 to 5) lives here:
//!
//! - every race runs a [`Plan`] built from path memory ([`paths::plan`]): the transport and
//!   port that worked on this network start at once, transports blocked here are left out,
//!   extra ports follow the primary one 300 ms apart; a race that fails without the left-out
//!   transports is followed at once by the full race, and the failure marks are cleared;
//! - the outcome of every attempt is recorded, including the attempts still running when the
//!   race was decided (a blocked QUIC port shows as a timeout 8 s later); failures only when
//!   another transport reached the server from the same network (no poisoning);
//! - while a connection is up, a monitor task learns the NAT keepalive interval from PATH_INFO
//!   (m2.md 4.2, 4.3), records the path's round-trip time and loss, writes path memory, and
//!   probes transports that were blocked once their retry time comes; a probe that finds a
//!   better transport moves the sessions to it (a transport upgrade, m2.md 3.6).
//!
//! # Transcript events (`QSH_TRANSCRIPT`, unstable)
//!
//! Besides `attempt` (one per finished attempt: `won`, `ok` for a late success or a probe, or
//! the failure kind), the pool records `plan` (`attempts`: `transport`, `port` and `delay_ms`
//! of each; `remembered`; `skipped`; `keepalive_ms`), `keepalive` (`k_ms`, `why`:
//! `nat-timeout` or `quiet`), `probe` (`transport`, `outcome`) and `upgrade` (`from`, `to`).

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::conn::{Conn, PathChange};
use super::paths::{self, Learner, PathMemory, Planned, Rebinding};
use super::transcript::{self, Record};
use super::ClientConfig;
use crate::config::Keepalive;
use crate::crypto;
use crate::log;
use crate::netwatch::{NetSnapshot, NetWatch};
use crate::proto::limits::ATTACH_TIMEOUT;
use crate::proto::ErrorCode;
use crate::transport::quic::{self, QuicClient};
use crate::transport::{
    Attempt, Connector, Direct, FailureKind, Plan, Race, RaceConfig, RaceError, RaceEvent, Target, Transport,
};

/// After a network change, a connection that answers nothing for this long is dead.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// A failure is recorded only when another transport reached the server from the same network
/// in the same race or within this long (m2.md 3.3, no poisoning).
const NO_POISON_WINDOW: Duration = Duration::from_secs(60);
/// At most one transport upgrade per server in this long (m2.md 3.6).
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);
/// How often a connection's monitor looks at it.
const MONITOR_TICK: Duration = Duration::from_secs(1);
/// How often the path's round-trip time and loss go into path memory (and when the
/// connection ends): rarely, since each is a write of the file.
const MEASURE_EVERY: Duration = Duration::from_secs(300);
/// A retired connection is closed once its sessions moved, or after this long.
const RETIRE_PATIENCE: Duration = Duration::from_secs(30);

/// Which daemon a connection goes to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServerKey {
    destination: String,
    host: String,
    udp: u16,
    tcp: u16,
    fingerprint: [u8; 32],
}

#[derive(Debug, Default)]
struct Slot {
    current: Option<Arc<Conn>>,
    failed_at: Option<std::time::Instant>,
    last_error: Option<String>,
    pin_mismatch: bool,
    no_server: bool,
    /// The last transport upgrade.
    upgraded_at: Option<Instant>,
}

/// The network as the pool last saw it.
#[derive(Debug, Default)]
struct NetState {
    /// Counts network changes: an outcome seen across one says nothing about either network.
    generation: u64,
    /// The last network change: the client moved itself.
    moved_at: Option<Instant>,
}

/// A failure of a race in which nothing worked, kept in case another transport works soon.
#[derive(Debug)]
struct Pending {
    host: String,
    network: Vec<u8>,
    transport: Transport,
    kind: FailureKind,
    at: Instant,
}

/// What a race, and the monitor of the connection it makes, need to know.
#[derive(Clone)]
struct Ctx {
    target: Target,
    race: RaceConfig,
    keepalive_config: Keepalive,
    memory: Arc<PathMemory>,
    /// The destination as path memory keys it (lowercase).
    host: String,
    /// The network ([`NetSnapshot::path_key`]); empty when offline.
    network: Vec<u8>,
    generation: u64,
    /// The keepalive interval for this network now.
    keepalive: Duration,
}

impl Ctx {
    fn learning(&self) -> bool {
        self.keepalive_config == Keepalive::Auto
    }

    fn entry(&self) -> Option<paths::Entry> {
        self.memory.entry(&self.host, &self.network)
    }

    /// Change the entry. What the next connection on this network depends on (the transports
    /// blocked here, the last winner, the keepalive interval) is written at once, in the
    /// background: a client may be killed a second after a reconnect, and the next one must
    /// start with what this one learned. The rest waits for the next write (every 10 s).
    fn update(&self, change: impl FnOnce(&mut paths::Entry)) {
        let now = paths::now();
        let mut decisive = false;
        self.memory.update(&self.host, &self.network, now, |e| {
            let before = (e.blocked_now(now), e.last.clone(), e.ka);
            change(e);
            decisive = (e.blocked_now(now), e.last.clone(), e.ka) != before;
        });
        if decisive {
            flush_now(&self.memory);
        }
    }
}

/// Write path memory now, in the background when there is a runtime.
fn flush_now(memory: &Arc<PathMemory>) {
    let flush = {
        let memory = memory.clone();
        move || {
            if let Err(e) = memory.flush() {
                log::debug(format_args!("path memory not written: {e}"));
            }
        }
    };
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(flush);
    } else {
        flush();
    }
}

/// Connections to servers, one per daemon, shared by the sessions to it (a hub carries all
/// its terminals to a server on one connection). One connection attempt per server at a time.
///
/// Inside a tokio runtime a pool watches the network ([`NetWatch`]): when it changes, the QUIC
/// endpoint moves to the new network, every connection is probed, and sessions waiting to
/// reconnect try at once ([`Pool::network_changed`]).
///
/// A pool remembers what worked per destination and network in a [`PathMemory`]
/// ([`Pool::with_memory`]), which it writes when it is dropped.
pub struct Pool {
    me: Weak<Pool>,
    quic: Arc<QuicClient>,
    connector: Arc<dyn Connector>,
    /// Path memory in its file; None: the embedder keeps none.
    memory: Option<Arc<PathMemory>>,
    /// What this process learned, for sessions with `path_memory = false` and pools without
    /// a file.
    volatile: Arc<PathMemory>,
    net_key: Box<dyn Fn() -> Vec<u8> + Send + Sync>,
    net: Mutex<NetState>,
    pending: Mutex<Vec<Pending>>,
    /// The last keepalive learning step per destination and network (m2.md 4.2, condition 4).
    learned: Mutex<HashMap<(String, Vec<u8>), Instant>>,
    slots: Mutex<HashMap<ServerKey, Arc<tokio::sync::Mutex<Slot>>>>,
    /// Sessions waiting out a back-off wait on this.
    pub(crate) network: Arc<tokio::sync::Notify>,
    watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("quic", &self.quic)
            .field("memory", &self.memory.as_ref().and_then(|m| m.path()))
            .finish_non_exhaustive()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(watcher) = self.watcher.lock().unwrap().take() {
            watcher.abort();
        }
        if let Some(memory) = &self.memory {
            if let Err(e) = memory.flush() {
                log::debug(format_args!("path memory not written: {e}"));
            }
        }
    }
}

impl Pool {
    /// A pool with its own QUIC endpoint and path memory in its standard place
    /// ([`crate::Paths::path_memory`] of [`crate::Paths::from_env`]).
    pub fn new() -> Arc<Pool> {
        Pool::with_quic(Arc::new(QuicClient::new()))
    }

    /// A pool using `quic`'s endpoint, with path memory in its standard place. Within a tokio
    /// runtime it watches the network.
    pub fn with_quic(quic: Arc<QuicClient>) -> Arc<Pool> {
        let memory = PathMemory::standard(&crate::Paths::from_env());
        Pool::with_memory(quic, Some(memory))
    }

    /// A pool using `quic`'s endpoint and `memory` (None: what it learns lives only as long
    /// as the pool). Within a tokio runtime it watches the network.
    pub fn with_memory(quic: Arc<QuicClient>, memory: Option<PathMemory>) -> Arc<Pool> {
        let connector = Arc::new(Direct(quic.clone()));
        let pool = Pool::build(quic, connector, memory, Box::new(|| NetSnapshot::take().path_key()));
        if tokio::runtime::Handle::try_current().is_ok() {
            match NetWatch::spawn() {
                Ok(net) => {
                    log::debug(format_args!("watching the network ({})", net.mechanism()));
                    let task = tokio::spawn(watch_network(Arc::downgrade(&pool), net));
                    *pool.watcher.lock().unwrap() = Some(task);
                }
                Err(e) => log::debug(format_args!("not watching the network: {e}")),
            }
        }
        pool
    }

    fn build(
        quic: Arc<QuicClient>,
        connector: Arc<dyn Connector>,
        memory: Option<PathMemory>,
        net_key: Box<dyn Fn() -> Vec<u8> + Send + Sync>,
    ) -> Arc<Pool> {
        Arc::new_cyclic(|me| Pool {
            me: me.clone(),
            quic,
            connector,
            memory: memory.map(Arc::new),
            volatile: Arc::new(PathMemory::in_memory()),
            net_key,
            net: Mutex::new(NetState::default()),
            pending: Mutex::new(Vec::new()),
            learned: Mutex::new(HashMap::new()),
            slots: Mutex::new(HashMap::new()),
            network: Arc::new(tokio::sync::Notify::new()),
            watcher: Mutex::new(None),
        })
    }

    /// The pool's path memory, if it keeps one in a file (for `qsh doctor`).
    pub fn path_memory(&self) -> Option<&Arc<PathMemory>> {
        self.memory.as_ref()
    }

    /// The network changed (the pool's own watcher calls this; an embedder that hears of
    /// changes first, such as an Android app, may too): move the QUIC endpoint to a socket on
    /// the new network, which migrates every QUIC connection; PING every connection and drop
    /// those that answer nothing within 2 s, so their sessions race the transports again; and
    /// wake the sessions waiting to reconnect, regardless of their back-off (protocol.md 12.2).
    pub fn network_changed(&self) {
        {
            let mut net = self.net.lock().unwrap();
            net.generation += 1;
            net.moved_at = Some(Instant::now());
        }
        match self.quic.rebind() {
            Ok(true) => log::debug(format_args!("QUIC moved to {:?}", self.quic.local_addr())),
            Ok(false) => {}
            Err(e) => log::info(format_args!("cannot move QUIC to the new network: {e}")),
        }
        for conn in self.live() {
            conn.probe(PROBE_TIMEOUT);
        }
        self.network.notify_waiters();
    }

    fn generation(&self) -> u64 {
        self.net.lock().unwrap().generation
    }

    /// When the client last moved itself: a network change, or a rebind of the endpoint.
    fn moved_at(&self) -> Option<Instant> {
        let changed = self.net.lock().unwrap().moved_at;
        changed.max(self.quic.rebound_at())
    }

    fn live(&self) -> Vec<Arc<Conn>> {
        let slots: Vec<_> = self.slots.lock().unwrap().values().cloned().collect();
        slots
            .into_iter()
            .filter_map(|slot| slot.try_lock().ok().and_then(|s| s.current.clone()))
            .filter(|c| c.usable())
            .collect()
    }

    /// The QUIC endpoint, e.g. to rebind it when the network changed.
    pub fn quic(&self) -> &Arc<QuicClient> {
        &self.quic
    }

    /// A usable connection to `target`: the current one, or a new one from a race planned
    /// with `config` (its `race`, `keepalive` and `path_memory`).
    pub async fn get(&self, target: &Target, config: &ClientConfig) -> Result<Arc<Conn>, RaceError> {
        let key = ServerKey {
            destination: target.ssh.destination.clone(),
            host: target.host.clone(),
            udp: target.udp,
            tcp: target.tcp,
            fingerprint: target.fingerprint.0,
        };
        let slot_ref = self.slots.lock().unwrap().entry(key).or_default().clone();
        let asked = std::time::Instant::now();
        let mut slot = slot_ref.lock().await;
        if let Some(c) = slot.current.as_ref().filter(|c| c.usable()) {
            return Ok(c.clone());
        }
        // Another session just tried and failed while this one waited: share its result
        if slot.failed_at.is_some_and(|t| t >= asked) {
            let mut e = RaceError::default();
            let message = if slot.pin_mismatch {
                crypto::PIN_MISMATCH.to_string()
            } else {
                slot.last_error.clone().unwrap_or_default()
            };
            e.errors.push((Transport::Quic, io::Error::other(message)));
            if slot.no_server {
                e.errors
                    .push((Transport::Ssh, io::Error::new(io::ErrorKind::NotFound, "no qsh-server")));
            }
            return Err(e);
        }
        match self.establish(target, config).await {
            Ok((c, ctx)) => {
                slot.current = Some(c.clone());
                slot.failed_at = None;
                self.watch(&slot_ref, &c, ctx);
                Ok(c)
            }
            Err(e) => {
                slot.current = None;
                slot.failed_at = Some(std::time::Instant::now());
                slot.last_error = Some(e.to_string());
                slot.pin_mismatch = e.pin_mismatch();
                slot.no_server = e.no_server();
                Err(e)
            }
        }
    }

    /// Close every connection (they reconnect as needed).
    pub fn reset(&self) {
        let slots: Vec<_> = self.slots.lock().unwrap().values().cloned().collect();
        for slot in slots {
            if let Ok(slot) = slot.try_lock() {
                if let Some(c) = &slot.current {
                    c.close(ErrorCode::NO_ERROR, "reset");
                }
            }
        }
    }

    /// The live connections: destination, transport and round-trip time.
    pub fn connections(&self) -> Vec<(String, Transport, Option<Duration>)> {
        let slots: Vec<_> = self
            .slots
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        slots
            .into_iter()
            .filter_map(|(k, slot)| {
                let current = slot
                    .try_lock()
                    .ok()
                    .and_then(|s| s.current.clone())
                    .filter(|c| c.usable())?;
                Some((k.destination, current.transport(), current.rtt()))
            })
            .collect()
    }

    fn memory_for(&self, config: &ClientConfig) -> Arc<PathMemory> {
        match &self.memory {
            Some(m) if config.path_memory => m.clone(),
            _ => self.volatile.clone(),
        }
    }

    /// Race with the plan path memory gives (m2.md 3.5); when a race that left transports
    /// out fails, race again at once with every transport and forget the failure marks.
    async fn establish(&self, target: &Target, config: &ClientConfig) -> Result<(Arc<Conn>, Ctx), RaceError> {
        let memory = self.memory_for(config);
        let network = (self.net_key)();
        let host = target.host.to_lowercase();
        let now = paths::now();
        let entry = memory.entry_at(&host, &network, now);
        let planned = paths::plan(entry.as_ref(), target, &config.race, now);
        let (keepalive, _) = paths::keepalive_for(config.keepalive, entry.as_ref());
        let ctx = Ctx {
            target: target.clone(),
            race: config.race.clone(),
            keepalive_config: config.keepalive,
            memory,
            host,
            network,
            generation: self.generation(),
            keepalive,
        };
        match self.race(&planned, &ctx).await {
            Ok(c) => Ok((c, ctx)),
            Err(first) if !planned.skipped.is_empty() => {
                log::info(format_args!(
                    "nothing worked without {}; trying every transport",
                    names(&planned.skipped)
                ));
                ctx.update(paths::Entry::clear_failures);
                let full = Planned {
                    plan: Plan::new(target, &config.race),
                    skipped: Vec::new(),
                    remembered: false,
                };
                match self.race(&full, &ctx).await {
                    Ok(c) => Ok((c, ctx)),
                    Err(mut e) => {
                        let mut errors = first.errors;
                        errors.append(&mut e.errors);
                        Err(RaceError { errors })
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Run one race and keep the first connection whose hello succeeds within 5 s
    /// (protocol.md 12.1); record what each attempt showed.
    async fn race(&self, planned: &Planned, ctx: &Ctx) -> Result<Arc<Conn>, RaceError> {
        let mut plan = planned.plan.clone();
        plan.quic = quic::Options::with_keepalive(ctx.keepalive);
        record_plan(&plan, planned, ctx.keepalive);
        let mut race = Race::with_connector(&ctx.target, &plan, self.connector.clone());
        let mut failures: Vec<(Transport, FailureKind)> = Vec::new();
        while let Some(event) = race.next_event().await {
            let won = match event {
                RaceEvent::Failed { attempt, error } => {
                    let kind = FailureKind::of(&error);
                    log::debug(format_args!(
                        "{} port {} failed ({kind}): {error}",
                        attempt.transport, attempt.port
                    ));
                    record_attempt(attempt, kind.as_str());
                    failures.push((attempt.transport, kind));
                    continue;
                }
                RaceEvent::Connected(won) => *won,
            };
            let (attempt, handshake) = (won.attempt, won.handshake);
            match tokio::time::timeout(ATTACH_TIMEOUT, Conn::hello(won.connection)).await {
                Ok(Ok(conn)) => {
                    log::debug(format_args!(
                        "connected over {} port {} in {} ms",
                        attempt.transport,
                        attempt.port,
                        handshake.as_millis()
                    ));
                    record_attempt(attempt, "won");
                    // Attempts that started no later than the winner and are still waiting
                    // for an answer: on this network they lost to a slower handshake. That
                    // is a timeout here, recorded now rather than when their own timeout
                    // fires (8 s, by which time a client may be gone); an answer that comes
                    // later still clears it (`conclude`).
                    let unanswered: Vec<Transport> = race
                        .running()
                        .into_iter()
                        .filter(|a| {
                            a.transport != attempt.transport
                                && a.transport != Transport::Ssh
                                && a.delay <= attempt.delay
                        })
                        .map(|a| a.transport)
                        .collect();
                    failures.extend(unanswered.iter().map(|&t| (t, FailureKind::Timeout)));
                    self.won(ctx, attempt, handshake, &failures);
                    let quic_keepalive = (conn.transport() == Transport::Quic).then_some(plan.quic.keep_alive);
                    conn.set_keepalive(quic_keepalive, ctx.keepalive);
                    *conn.attempts.lock().unwrap() = attempts(ctx, planned, attempt.transport, race.errors());
                    self.conclude(race, ctx, attempt.transport, unanswered);
                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    // A connection ended or reset during the hello: a middlebox, as far as
                    // the network is concerned; anything else (the server refused) is not
                    let kind = match FailureKind::of(&e) {
                        FailureKind::Reset => FailureKind::Reset,
                        _ => FailureKind::Other,
                    };
                    record_attempt(attempt, kind.as_str());
                    failures.push((attempt.transport, kind));
                    race.failed(attempt.transport, e);
                }
                Err(_) => {
                    record_attempt(attempt, FailureKind::Hello.as_str());
                    failures.push((attempt.transport, FailureKind::Hello));
                    race.failed(
                        attempt.transport,
                        io::Error::new(io::ErrorKind::TimedOut, "no SERVER_HELLO"),
                    );
                }
            }
        }
        // Nothing worked: what failed is only a fact about the network if something else
        // works from it soon
        let at = Instant::now();
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|p| at.duration_since(p.at) < NO_POISON_WINDOW);
        for (transport, kind) in dedup(&failures) {
            pending.push(Pending {
                host: ctx.host.clone(),
                network: ctx.network.clone(),
                transport,
                kind,
                at,
            });
        }
        Err(race.take_errors())
    }

    /// `attempt` won: record it, and the failures of other transports in this race and in
    /// races that failed in the last minute from the same network.
    fn won(&self, ctx: &Ctx, attempt: Attempt, handshake: Duration, failures: &[(Transport, FailureKind)]) {
        if self.generation() != ctx.generation {
            // The network changed during the race: the outcome says nothing about either
            return;
        }
        let now = Instant::now();
        let mut all: Vec<(Transport, FailureKind)> = {
            let mut pending = self.pending.lock().unwrap();
            let (mine, others): (Vec<Pending>, Vec<Pending>) = pending
                .drain(..)
                .partition(|p| p.host == ctx.host && p.network == ctx.network);
            *pending = others;
            mine.into_iter()
                .filter(|p| now.duration_since(p.at) < NO_POISON_WINDOW)
                .map(|p| (p.transport, p.kind))
                .collect()
        };
        all.extend_from_slice(failures);
        let failed: Vec<(Transport, FailureKind)> = dedup(&all)
            .into_iter()
            .filter(|(t, _)| *t != attempt.transport)
            .collect();
        let unix = paths::now();
        ctx.update(|e| {
            for (t, kind) in failed {
                e.failed(t, kind, unix);
            }
            e.won(attempt.transport, attempt.port, handshake, unix);
        });
    }

    /// The race is decided: let the attempts still running finish, and record what they
    /// show (a late success, or a failure, now that another transport worked). `marked`:
    /// transports already recorded as failed by this race.
    fn conclude(&self, race: Race, ctx: &Ctx, winner: Transport, marked: Vec<Transport>) {
        let pool = self.me.clone();
        let ctx = ctx.clone();
        let mut worked = vec![winner];
        let mut failed: Vec<Transport> = marked;
        race.conclude(move |attempt, outcome| {
            record_attempt(
                attempt,
                match &outcome {
                    Ok(_) => "ok",
                    Err(kind) => kind.as_str(),
                },
            );
            let Some(pool) = pool.upgrade() else { return };
            if pool.generation() != ctx.generation {
                return;
            }
            let t = attempt.transport;
            let unix = paths::now();
            match outcome {
                Ok(handshake) if !worked.contains(&t) => {
                    worked.push(t);
                    ctx.update(|e| e.succeeded(t, attempt.port, handshake, unix));
                }
                Err(kind) if kind.recorded() && !worked.contains(&t) && !failed.contains(&t) => {
                    failed.push(t);
                    ctx.update(|e| e.failed(t, kind, unix));
                }
                _ => {}
            }
        });
    }

    /// Start the monitor of `conn`, the current connection of `slot`.
    fn watch(&self, slot: &Arc<tokio::sync::Mutex<Slot>>, conn: &Arc<Conn>, ctx: Ctx) {
        let (tx, rx) = mpsc::unbounded_channel();
        conn.watch_path(tx);
        let last_step = self.last_step(&ctx);
        let monitor = Monitor {
            pool: self.me.clone(),
            slot: Arc::downgrade(slot),
            conn: Arc::downgrade(conn),
            learner: Learner::new(ctx.keepalive, last_step),
            last_local: self.quic.local_addr(),
            probing: Arc::new(AtomicBool::new(false)),
            ctx,
        };
        tokio::spawn(monitor.run(rx));
    }

    fn last_step(&self, ctx: &Ctx) -> Option<Instant> {
        self.learned
            .lock()
            .unwrap()
            .get(&(ctx.host.clone(), ctx.network.clone()))
            .copied()
    }

    fn set_last_step(&self, ctx: &Ctx, at: Instant) {
        self.learned
            .lock()
            .unwrap()
            .insert((ctx.host.clone(), ctx.network.clone()), at);
    }

    /// A background probe found `new`, a better transport than `old`: make it the slot's
    /// connection and move the sessions over (m2.md 3.6). Gives `new` back when it is not
    /// used: `old` is no longer current or carries no session, or an upgrade happened within
    /// the last minute.
    fn upgrade(
        &self,
        slot: &Weak<tokio::sync::Mutex<Slot>>,
        old: &Weak<Conn>,
        new: Arc<Conn>,
        ctx: &Ctx,
    ) -> Result<(), Arc<Conn>> {
        let (Some(slot_ref), Some(old)) = (slot.upgrade(), old.upgrade()) else {
            return Err(new);
        };
        if rank(new.transport()) <= rank(old.transport()) {
            return Err(new);
        }
        let Ok(mut s) = slot_ref.try_lock() else {
            return Err(new);
        };
        let current = s.current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &old));
        // Held here and by the slot: anything more is a session attached on it
        let attached = Arc::strong_count(&old) > 2;
        let recently = s.upgraded_at.is_some_and(|t| t.elapsed() < UPGRADE_INTERVAL);
        if !current || !old.usable() || !attached || recently {
            return Err(new);
        }
        s.current = Some(new.clone());
        s.upgraded_at = Some(Instant::now());
        drop(s);
        log::info(format_args!(
            "{} works again; moving the sessions from {}",
            new.transport(),
            old.transport()
        ));
        record_event(
            "upgrade",
            json!({"from": old.transport().to_string(), "to": new.transport().to_string()}),
        );
        self.watch(&slot_ref, &new, ctx.clone());
        // The sessions move once their input is acknowledged; then the old one goes
        old.retire();
        tokio::spawn(async move {
            let deadline = Instant::now() + RETIRE_PATIENCE;
            while Arc::strong_count(&old) > 1 && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            goodbye(&old, "moved").await;
        });
        Ok(())
    }
}

/// Close a connection on purpose: GOAWAY (NO_ERROR), then close (protocol.md 5.7).
async fn goodbye(conn: &Conn, why: &str) {
    conn.goaway(ErrorCode::NO_ERROR);
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.close(ErrorCode::NO_ERROR, why);
}

/// QUIC over TLS over the ssh pipe: only QUIC survives address changes, and the pipe has
/// head-of-line blocking through ssh.
fn rank(t: Transport) -> u8 {
    match t {
        Transport::Quic => 2,
        Transport::Tls => 1,
        Transport::Ssh => 0,
    }
}

/// Each transport once, with the first kind recorded for it; only kinds path memory records.
fn dedup(failures: &[(Transport, FailureKind)]) -> Vec<(Transport, FailureKind)> {
    let mut out: Vec<(Transport, FailureKind)> = Vec::new();
    for &(t, kind) in failures {
        if kind.recorded() && !out.iter().any(|(x, _)| *x == t) {
            out.push((t, kind));
        }
    }
    out
}

fn names(transports: &[Transport]) -> String {
    transports
        .iter()
        .map(Transport::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn record_attempt(attempt: Attempt, outcome: &str) {
    transcript::record(Record::Attempt {
        transport: attempt.transport,
        port: attempt.port,
        outcome,
    });
}

fn record_event(ev: &str, fields: Value) {
    if transcript::get().is_none() {
        return;
    }
    if let Value::Object(fields) = fields {
        transcript::record(Record::Other { ev, fields: &fields });
    }
}

fn record_plan(plan: &Plan, planned: &Planned, keepalive: Duration) {
    if transcript::get().is_none() {
        return;
    }
    let attempts: Vec<Value> = plan
        .attempts
        .iter()
        .map(|a| json!({"transport": a.transport.to_string(), "port": a.port, "delay_ms": a.delay.as_millis() as u64}))
        .collect();
    let skipped: Vec<String> = planned.skipped.iter().map(Transport::to_string).collect();
    record_event(
        "plan",
        json!({
            "attempts": attempts,
            "remembered": planned.remembered,
            "skipped": skipped,
            "keepalive_ms": keepalive.as_millis() as u64,
        }),
    );
}

/// Follow the network for `pool` until it is dropped.
async fn watch_network(pool: Weak<Pool>, mut net: NetWatch) {
    loop {
        let change = net.changed().await;
        let Some(pool) = pool.upgrade() else { return };
        log::info(format_args!("the network changed: {}", change.snapshot));
        if !change.snapshot.is_online() {
            // No route anywhere: nothing to try until the next change
            continue;
        }
        pool.network_changed();
    }
}

/// How each transport fared in a race that `winner` won, for the status line.
fn attempts(ctx: &Ctx, planned: &Planned, winner: Transport, errors: &RaceError) -> Vec<(Transport, String)> {
    [Transport::Quic, Transport::Tls, Transport::Ssh]
        .into_iter()
        .map(|transport| {
            let outcome = if transport == winner {
                "used".to_string()
            } else if ctx.race.start(transport).is_none() {
                "off".to_string()
            } else if ctx.target.candidates(transport, None).is_empty() {
                "no port".to_string()
            } else if planned.skipped.contains(&transport) {
                "skipped: blocked on this network".to_string()
            } else if let Some((_, e)) = errors.errors.iter().rev().find(|(t, _)| *t == transport) {
                format!("failed: {e}")
            } else {
                "not needed".to_string()
            };
            (transport, outcome)
        })
        .collect()
}

/// Watches one connection while it lives: keepalive learning, measurements, writing path
/// memory, background probes of blocked transports and transport upgrades.
struct Monitor {
    pool: Weak<Pool>,
    slot: Weak<tokio::sync::Mutex<Slot>>,
    conn: Weak<Conn>,
    ctx: Ctx,
    learner: Learner,
    /// The endpoint's local address at the previous PATH_INFO.
    last_local: Option<SocketAddr>,
    probing: Arc<AtomicBool>,
}

impl Monitor {
    async fn run(mut self, mut changes: mpsc::UnboundedReceiver<PathChange>) {
        let mut tick = tokio::time::interval(MONITOR_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_tick = Instant::now();
        // The first measurement once the RTT estimate settled a little
        let mut measured = Instant::now();
        let mut first = true;
        loop {
            tokio::select! {
                change = changes.recv() => match change {
                    Some(change) => self.path_changed(change),
                    None => break,
                },
                _ = tick.tick() => {
                    let now = Instant::now();
                    let elapsed = now.duration_since(last_tick);
                    last_tick = now;
                    let since = now.duration_since(measured);
                    let measure = since >= MEASURE_EVERY || first && since >= Duration::from_secs(5);
                    if measure {
                        measured = now;
                        first = false;
                    }
                    if !self.tick(elapsed, measure) {
                        break;
                    }
                }
            }
        }
        if let Some(conn) = self.conn.upgrade() {
            self.measure(&conn);
        }
        self.flush();
    }

    /// False when the connection is gone.
    fn tick(&mut self, elapsed: Duration, measure: bool) -> bool {
        let (Some(pool), Some(conn)) = (self.pool.upgrade(), self.conn.upgrade()) else {
            return false;
        };
        if conn.connection.is_closed() {
            return false;
        }
        let generation = pool.generation();
        if generation != self.ctx.generation {
            // Another network: its own entry, its own keepalive interval
            self.ctx.generation = generation;
            self.ctx.network = (pool.net_key)();
            let (k, _) = paths::keepalive_for(self.ctx.keepalive_config, self.ctx.entry().as_ref());
            self.ctx.keepalive = k;
            self.learner.network(k, pool.last_step(&self.ctx));
            conn.set_network_keepalive(k);
            self.last_local = pool.quic.local_addr();
        }
        if self.ctx.learning() && conn.transport() == Transport::Quic {
            let held_by_slot = self.slot.upgrade().is_none_or(|slot| {
                slot.try_lock()
                    .map(|s| s.current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)))
                    .unwrap_or(true)
            });
            // References: this one, the slot's, and one per session attached on it
            let attached = Arc::strong_count(&conn) > 1 + usize::from(held_by_slot);
            // Growth is only learned while the network's interval is the one in effect
            let exercised = conn.keepalive() == Some(self.learner.k());
            if attached && exercised {
                if let Some(k) = self.learner.quiet(elapsed) {
                    self.set_keepalive(&conn, k, "quiet");
                }
            }
        }
        if measure {
            self.measure(&conn);
        }
        self.flush();
        if conn.usable() && !self.probing.load(Ordering::SeqCst) {
            self.probe(&pool, &conn);
        }
        true
    }

    fn measure(&self, conn: &Conn) {
        let (rtt, loss) = (conn.rtt(), conn.loss());
        if rtt.is_some() || loss.is_some() {
            self.ctx.update(|e| e.measured(rtt, loss));
        }
    }

    /// Write path memory in the background (it may wait for the disk), at most every 10 s.
    fn flush(&self) {
        if !self.ctx.memory.dirty() {
            return;
        }
        let memory = self.ctx.memory.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = memory.flush_due() {
                log::debug(format_args!("path memory not written: {e}"));
            }
        });
    }

    /// The server reported a new address: learn when it means a NAT timed out (m2.md 4.2).
    fn path_changed(&mut self, change: PathChange) {
        let (Some(pool), Some(conn)) = (self.pool.upgrade(), self.conn.upgrade()) else {
            return;
        };
        let local = pool.quic.local_addr();
        let local_changed = local != self.last_local;
        self.last_local = local;
        if !self.ctx.learning() || conn.transport() != Transport::Quic {
            return;
        }
        let Some(effective) = conn.keepalive() else { return };
        let rebinding = Rebinding {
            at: change.at,
            idle: change.idle,
            client_moved: pool.moved_at(),
            local_changed,
            effective,
        };
        let before = self.learner.last_step();
        let stepped = self.learner.rebinding(&rebinding);
        if let Some(at) = self.learner.last_step().filter(|&at| Some(at) != before) {
            pool.set_last_step(&self.ctx, at);
        }
        if let Some(k) = stepped {
            log::info(format_args!(
                "a NAT forgot this connection after {} s without traffic ({} -> {}); keepalive every {:.1} s",
                change.idle.as_secs(),
                change.from,
                change.to,
                k.as_secs_f64()
            ));
            self.set_keepalive(&conn, k, "nat-timeout");
        }
    }

    /// The network's interval is `k` now: in effect at once, saved at once.
    fn set_keepalive(&mut self, conn: &Conn, k: Duration, why: &str) {
        self.ctx.keepalive = k;
        conn.set_network_keepalive(k);
        // Written at once (Ctx::update)
        self.ctx.update(|e| e.set_keepalive(k));
        record_event("keepalive", json!({"k_ms": k.as_millis() as u64, "why": why}));
    }

    /// Probe one transport that failed here and whose retry time came (m2.md 3.6).
    fn probe(&self, pool: &Arc<Pool>, conn: &Arc<Conn>) {
        let Some(entry) = self.ctx.entry() else { return };
        let due = entry.due(paths::now()).into_iter().find(|&t| {
            t != conn.transport() && self.ctx.race.start(t).is_some() && !self.ctx.target.candidates(t, None).is_empty()
        });
        let Some(transport) = due else { return };
        self.probing.store(true, Ordering::SeqCst);
        let remembered = entry.transport(transport).and_then(|r| r.port);
        let probe = Probe {
            pool: self.pool.clone(),
            slot: self.slot.clone(),
            old: self.conn.clone(),
            ctx: self.ctx.clone(),
            connector: pool.connector.clone(),
            probing: self.probing.clone(),
        };
        tokio::spawn(probe.run(transport, remembered));
    }
}

/// One background probe of a transport: handshake and hello, then GOAWAY, or a transport
/// upgrade when it is better than the connection in use (m2.md 3.6).
struct Probe {
    pool: Weak<Pool>,
    slot: Weak<tokio::sync::Mutex<Slot>>,
    old: Weak<Conn>,
    ctx: Ctx,
    connector: Arc<dyn Connector>,
    probing: Arc<AtomicBool>,
}

impl Probe {
    async fn run(self, transport: Transport, remembered: Option<u16>) {
        log::debug(format_args!("probing {transport} in the background"));
        let mut plan = Plan::build(&self.ctx.target, [(transport, Some(Duration::ZERO), remembered)]);
        plan.quic = quic::Options::with_keepalive(self.ctx.keepalive);
        let mut race = Race::with_connector(&self.ctx.target, &plan, self.connector.clone());
        let mut outcome: Result<(Arc<Conn>, Attempt, Duration), FailureKind> = Err(FailureKind::Other);
        while let Some(event) = race.next_event().await {
            match event {
                RaceEvent::Failed { attempt, error } => {
                    let kind = FailureKind::of(&error);
                    record_attempt(attempt, kind.as_str());
                    if matches!(outcome, Err(k) if !k.recorded()) {
                        outcome = Err(kind);
                    }
                }
                RaceEvent::Connected(won) => {
                    match tokio::time::timeout(ATTACH_TIMEOUT, Conn::hello(won.connection)).await {
                        Ok(Ok(conn)) => {
                            record_attempt(won.attempt, "ok");
                            outcome = Ok((conn, won.attempt, won.handshake));
                            break;
                        }
                        Ok(Err(e)) => {
                            record_attempt(won.attempt, FailureKind::Other.as_str());
                            log::debug(format_args!("probe of {transport}: {e}"));
                        }
                        Err(_) => {
                            record_attempt(won.attempt, FailureKind::Hello.as_str());
                            outcome = Err(FailureKind::Hello);
                        }
                    }
                }
            }
        }
        drop(race);
        self.finish(transport, outcome).await;
        self.probing.store(false, Ordering::SeqCst);
    }

    async fn finish(&self, transport: Transport, outcome: Result<(Arc<Conn>, Attempt, Duration), FailureKind>) {
        let Some(pool) = self.pool.upgrade() else { return };
        if pool.generation() != self.ctx.generation {
            // The network changed meanwhile: the outcome says nothing
            if let Ok((conn, _, _)) = outcome {
                goodbye(&conn, "").await;
            }
            return;
        }
        let unix = paths::now();
        match outcome {
            Ok((conn, attempt, handshake)) => {
                record_event("probe", json!({"transport": transport.to_string(), "outcome": "ok"}));
                log::debug(format_args!("{transport} works here again"));
                let quic_keepalive = (conn.transport() == Transport::Quic).then_some(self.ctx.keepalive);
                conn.set_keepalive(quic_keepalive, self.ctx.keepalive);
                match pool.upgrade(&self.slot, &self.old, conn, &self.ctx) {
                    // The sessions use it now: the one to start with next time
                    Ok(()) => self.ctx.update(|e| e.won(transport, attempt.port, handshake, unix)),
                    Err(conn) => {
                        self.ctx
                            .update(|e| e.succeeded(transport, attempt.port, handshake, unix));
                        goodbye(&conn, "probe").await;
                    }
                }
            }
            Err(kind) => {
                record_event(
                    "probe",
                    json!({"transport": transport.to_string(), "outcome": kind.as_str()}),
                );
                log::debug(format_args!("{transport} still fails here ({kind})"));
                self.ctx.update(|e| e.probe_failed(transport, kind, unix));
            }
        }
    }
}

#[cfg(test)]
mod tests;
