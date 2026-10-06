//! Connections to daemons, one per daemon and shared by the sessions to it, the transport
//! race that establishes them (protocol.md section 12.1), and the network watcher that moves
//! them when the network changes (sections 12.3 and 12.4).
//!
//! Work package WP-1 (m2.md sections 3 to 5) turns the race into a plan built from path
//! memory, records the outcome of every attempt, and adds background probes and transport
//! upgrades here.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::conn::Conn;
use crate::crypto;
use crate::log;
use crate::netwatch::NetWatch;
use crate::proto::limits::ATTACH_TIMEOUT;
use crate::proto::ErrorCode;
use crate::transport::quic::QuicClient;
use crate::transport::{Race, RaceConfig, RaceError, Target, Transport};

/// After a network change, a connection that answers nothing for this long is dead.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
    failed_at: Option<Instant>,
    last_error: Option<String>,
    pin_mismatch: bool,
    no_server: bool,
}

/// Connections to servers, one per daemon, shared by the sessions to it (a hub carries all
/// its terminals to a server on one connection). One connection attempt per server at a time.
///
/// Inside a tokio runtime a pool watches the network ([`NetWatch`]): when it changes, the QUIC
/// endpoint moves to the new network, every connection is probed, and sessions waiting to
/// reconnect try at once ([`Pool::network_changed`]).
pub struct Pool {
    quic: Arc<QuicClient>,
    slots: Mutex<HashMap<ServerKey, Arc<tokio::sync::Mutex<Slot>>>>,
    /// Sessions waiting out a back-off wait on this.
    pub(crate) network: Arc<tokio::sync::Notify>,
    watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool").field("quic", &self.quic).finish_non_exhaustive()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(watcher) = self.watcher.lock().unwrap().take() {
            watcher.abort();
        }
    }
}

impl Pool {
    /// A pool with its own QUIC endpoint.
    pub fn new() -> Arc<Pool> {
        Pool::with_quic(Arc::new(QuicClient::new()))
    }

    /// A pool using `quic`'s endpoint. Within a tokio runtime it watches the network.
    pub fn with_quic(quic: Arc<QuicClient>) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            quic,
            slots: Mutex::new(HashMap::new()),
            network: Arc::new(tokio::sync::Notify::new()),
            watcher: Mutex::new(None),
        });
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

    /// The network changed (the pool's own watcher calls this; an embedder that hears of
    /// changes first, such as an Android app, may too): move the QUIC endpoint to a socket on
    /// the new network, which migrates every QUIC connection; PING every connection and drop
    /// those that answer nothing within 2 s, so their sessions race the transports again; and
    /// wake the sessions waiting to reconnect, regardless of their back-off (protocol.md 12.2).
    pub fn network_changed(&self) {
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

    /// A usable connection to `target`: the current one, or a new one from a race.
    pub async fn get(&self, target: &Target, race: &RaceConfig) -> Result<Arc<Conn>, RaceError> {
        let key = ServerKey {
            destination: target.ssh.destination.clone(),
            host: target.host.clone(),
            udp: target.udp,
            tcp: target.tcp,
            fingerprint: target.fingerprint.0,
        };
        let slot = self.slots.lock().unwrap().entry(key).or_default().clone();
        let asked = Instant::now();
        let mut slot = slot.lock().await;
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
        match establish(target, &self.quic, race).await {
            Ok(c) => {
                slot.current = Some(c.clone());
                slot.failed_at = None;
                Ok(c)
            }
            Err(e) => {
                slot.current = None;
                slot.failed_at = Some(Instant::now());
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
}

/// Follow the network for `pool` until it is dropped.
async fn watch_network(pool: std::sync::Weak<Pool>, mut net: NetWatch) {
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

/// Race the transports and keep the first connection whose hello succeeds within 5 s
/// (section 12.1); the others are dropped.
async fn establish(target: &Target, quic: &Arc<QuicClient>, config: &RaceConfig) -> Result<Arc<Conn>, RaceError> {
    let mut race = Race::start(target, quic, config);
    while let Some(connection) = race.next().await {
        let transport = connection.transport();
        match tokio::time::timeout(ATTACH_TIMEOUT, Conn::hello(connection)).await {
            Ok(Ok(conn)) => {
                log::debug(format_args!("connected over {transport}"));
                *conn.attempts.lock().unwrap() = attempts(target, config, transport, race.errors());
                return Ok(conn);
            }
            Ok(Err(e)) => race.failed(transport, e),
            Err(_) => race.failed(transport, io::Error::new(io::ErrorKind::TimedOut, "no SERVER_HELLO")),
        }
    }
    Err(race.take_errors())
}

/// How each transport fared in a race that `winner` won, for the status line.
fn attempts(target: &Target, config: &RaceConfig, winner: Transport, errors: &RaceError) -> Vec<(Transport, String)> {
    [
        (Transport::Quic, config.quic, target.udp != 0),
        (Transport::Tls, config.tls, target.tcp != 0),
        (Transport::Ssh, config.ssh, true),
    ]
    .into_iter()
    .map(|(transport, delay, port)| {
        let outcome = if transport == winner {
            "used".to_string()
        } else if delay.is_none() {
            "off".to_string()
        } else if !port {
            "no port".to_string()
        } else if let Some((_, e)) = errors.errors.iter().rev().find(|(t, _)| *t == transport) {
            format!("failed: {e}")
        } else {
            "not needed".to_string()
        };
        (transport, outcome)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::message::{MAX_CONTROL, MAX_HELLO};
    use crate::proto::{self, read_message, write_message, Message};
    use crate::transport::Connection;
    use tokio::io::BufReader;

    /// The far end of a pipe connection that does the hello and then answers PINGs, or not.
    async fn fake_server(conn: Connection, answer: bool) {
        let (_, mut send, recv) = conn.accept().await.unwrap();
        let mut recv = BufReader::new(recv);
        let _hello = read_message(&mut recv, MAX_HELLO).await.unwrap();
        let hello = Message::ServerHello {
            version: u64::from(proto::VERSION),
            nonce: [0; 32],
            capabilities: Vec::new(),
            implementation: "test".into(),
        };
        write_message(&mut send, &hello).await.unwrap();
        while let Ok(Some(m)) = read_message(&mut recv, MAX_CONTROL).await {
            if let (Message::Ping { data }, true) = (m, answer) {
                write_message(&mut send, &Message::Pong { data }).await.unwrap();
            }
        }
    }

    /// After a network change every connection is probed: one that answers is kept, one that
    /// answers nothing is closed (its sessions then race the transports again), and sessions
    /// waiting out a back-off are woken.
    ///
    /// On paused time: the probe's 300 ms pass only once everything else waits, so the PONG
    /// over the in-memory pipe is always handled first, however slow the machine.
    #[tokio::test(start_paused = true)]
    async fn a_network_change_probes_connections_and_wakes_waiting_sessions() {
        for answer in [true, false] {
            let (a, b) = tokio::io::duplex(1 << 16);
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);
            let client = Connection::pipe(crate::mux::Role::Client, ar, aw, None, None);
            let server = Connection::pipe(crate::mux::Role::Server, br, bw, None, None);
            let far = tokio::spawn(fake_server(server, answer));
            let conn = Conn::hello(client).await.unwrap();
            conn.probe(Duration::from_millis(300));
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert_eq!(conn.connection.is_closed(), !answer, "answer: {answer}");
            far.abort();
        }
        let pool = Pool::new();
        let network = pool.network.clone();
        let waiting = tokio::spawn(async move { network.notified().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        pool.network_changed();
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("woken")
            .unwrap();
    }
}
