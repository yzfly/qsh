//! Network change events (docs/DESIGN.md section 7, "Network change").
//!
//! [`NetWatch`] tells a client when the network it is on changed: the default route moved to
//! another interface or gateway, or the addresses of that interface changed (Wi-Fi to
//! cellular, a new Wi-Fi network, a VPN coming up, waking from sleep somewhere else). Each
//! state of the network has a [`NetFingerprint`], stable across runs; path memory (m2.md 3.2)
//! keys networks by the coarser [`NetSnapshot::path_key`].
//!
//! Where the news comes from:
//!
//! - Linux and Android: an rtnetlink socket (links, addresses, routes), read through tokio.
//! - macOS: a routing socket (`PF_ROUTE`).
//! - Elsewhere, or when the socket cannot be opened (sandboxes, Android apps targeting API 30
//!   and later): the state is compared every 5 seconds.
//!
//! Kernel messages only say that something may have changed. After a burst of them settles
//! (250 ms without another, at most 1 s), the state is read again ([`NetSnapshot::take`]) and
//! a change is reported only when its fingerprint differs: a DHCP renewal or a Wi-Fi scan does
//! not wake anybody.
//!
//! # Use in a client
//!
//! ```no_run
//! # async fn example(pool: std::sync::Arc<qsh_core::client::Pool>) -> std::io::Result<()> {
//! use qsh_core::netwatch::NetWatch;
//!
//! let mut net = NetWatch::spawn()?;
//! loop {
//!     let change = net.changed().await;
//!     if !change.snapshot.is_online() {
//!         // No route anywhere: nothing to try until the next change
//!         continue;
//!     }
//!     // Move the QUIC endpoint to a socket on the new network; every QUIC connection
//!     // migrates with it (the server validates the new path)
//!     pool.quic().rebind()?;
//!     // Then probe each connection at once (PING) instead of waiting for the dead path
//!     // timers: no answer within about 2 s means the path is gone, so race the transports
//!     // again (TLS and ssh pipe connections usually die with the old address). Path
//!     // memory keys what worked by `change.snapshot.path_key()`, a coarser view.
//! }
//! # }
//! ```
//!
//! # Verifying by hand
//!
//! There is no way to change the network in a test without root, so the parts are tested
//! apart (message parsers on captured bytes, the debouncer with a fake source). To see the
//! whole thing work on Linux: run a client with `-v` and, as root, `ip addr add
//! 192.0.2.10/24 dev eth0` then `ip route replace default via …`, or switch Wi-Fi networks
//! on a laptop; on macOS switch Wi-Fi networks or toggle a VPN.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;

use crate::sys;

#[cfg(test)]
mod tests;

/// How long the kernel must stay quiet after a message before the state is read again.
pub const DEBOUNCE: Duration = Duration::from_millis(250);
/// The longest a burst of messages may delay reading the state.
pub const DEBOUNCE_MAX: Duration = Duration::from_secs(1);
/// How often the state is compared when there are no kernel messages to wait for.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Documentation addresses (RFC 5737, RFC 3849) whose route a UDP socket is connected along to
/// learn the source address of the default route. Connecting a UDP socket sends nothing.
const PROBE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// The way into one address family's default route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefaultRoute {
    /// The interface the route leaves through (`wlan0`, `en0`, `wg0`); empty when no
    /// interface has the source address.
    pub interface: String,
    /// The local address packets on that route come from.
    pub source: IpAddr,
    /// The next hop, when known (Linux; None on point-to-point links and on macOS).
    pub gateway: Option<IpAddr>,
}

/// The state of the network that matters to connections: the default routes and the
/// addresses of their interfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct NetSnapshot {
    /// The IPv4 default route; None: no IPv4 connectivity.
    pub ipv4: Option<DefaultRoute>,
    /// The IPv6 default route; None: no IPv6 connectivity.
    pub ipv6: Option<DefaultRoute>,
    /// The addresses of the default routes' interfaces, sorted: IPv4 addresses, and the /64
    /// prefixes of IPv6 addresses (privacy addresses rotate within the prefix; link-local
    /// addresses are left out).
    pub addresses: Vec<IpAddr>,
}

impl NetSnapshot {
    /// Read the current state from the system. Takes a few system calls and, on Linux, two
    /// small files of `/proc`; never blocks on the network.
    pub fn take() -> NetSnapshot {
        let interfaces = sys::interface_addresses().unwrap_or_default();
        let ipv4 = source_address(false).map(|source| default_route(source, &interfaces));
        let ipv6 = source_address(true).map(|source| default_route(source, &interfaces));
        let addresses = route_addresses(&interfaces, [&ipv4, &ipv6]);
        NetSnapshot { ipv4, ipv6, addresses }
    }

    /// True when there is a default route of either family.
    pub fn is_online(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }

    /// The fingerprint of this state: equal states have equal fingerprints, on every run and
    /// every version of qsh that keeps the same format (`v1`).
    pub fn fingerprint(&self) -> NetFingerprint {
        let mut bytes = b"qsh-net-v1".to_vec();
        for (tag, route) in [(4u8, &self.ipv4), (6u8, &self.ipv6)] {
            bytes.push(tag);
            let Some(route) = route else {
                bytes.push(0);
                continue;
            };
            bytes.push(1);
            push_field(&mut bytes, route.interface.as_bytes());
            // IPv6: only the /64 of the source, which privacy addresses keep
            push_address(&mut bytes, &stable_address(route.source));
            match &route.gateway {
                Some(gateway) => push_address(&mut bytes, gateway),
                None => bytes.push(0),
            }
        }
        for address in &self.addresses {
            push_address(&mut bytes, address);
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let mut out = [0; 16];
        out.copy_from_slice(&digest.as_ref()[..16]);
        NetFingerprint(out)
    }

    /// The network as path memory keys it (m2.md 3.2, `NetKey`): a coarser view than
    /// [`NetSnapshot::fingerprint`], so that a new DHCP lease on the same Wi-Fi is still the
    /// same network. For each address family with a default route, IPv4 then IPv6: the family
    /// tag (4 or 6), the interface name, the gateway (a zero byte when there is none) and the
    /// route's source address cut to its /24 (IPv4) or /64 (IPv6), encoded as in the
    /// fingerprint. The interfaces' address list is not part of it. Empty when offline.
    ///
    /// These bytes are never stored: path memory keeps only a keyed hash of them.
    pub fn path_key(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (tag, route) in [(4u8, &self.ipv4), (6u8, &self.ipv6)] {
            let Some(route) = route else { continue };
            bytes.push(tag);
            push_field(&mut bytes, route.interface.as_bytes());
            match &route.gateway {
                Some(gateway) => push_address(&mut bytes, gateway),
                None => bytes.push(0),
            }
            push_address(&mut bytes, &network_prefix(route.source));
        }
        bytes
    }
}

/// The source address as path memory keys a network: IPv4 cut to its /24, IPv6 to its /64.
fn network_prefix(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(a) => {
            let mut octets = a.octets();
            octets[3] = 0;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(_) => stable_address(address),
    }
}

impl fmt::Display for NetSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.is_online() {
            return f.write_str("offline");
        }
        let mut first = true;
        for route in [&self.ipv4, &self.ipv6].into_iter().flatten() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{} from {}", route.interface, route.source)?;
            if let Some(gateway) = &route.gateway {
                write!(f, " via {gateway}")?;
            }
        }
        Ok(())
    }
}

fn push_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
    bytes.extend_from_slice(field);
}

fn push_address(bytes: &mut Vec<u8>, address: &IpAddr) {
    match address {
        IpAddr::V4(a) => {
            bytes.push(4);
            bytes.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            bytes.push(6);
            bytes.extend_from_slice(&a.octets());
        }
    }
}

/// An identifier of a network state ([`NetSnapshot::fingerprint`]): 128 bits of a SHA-256 of
/// the default routes' interfaces, source addresses and gateways and the interfaces'
/// addresses. Shown as 32 hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetFingerprint(pub [u8; 16]);

impl fmt::Display for NetFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// How a [`NetWatch`] learns about changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// rtnetlink messages (Linux, Android).
    Netlink,
    /// Routing socket messages (macOS).
    RouteSocket,
    /// Comparing the state every [`Options::poll_interval`].
    Polling,
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mechanism::Netlink => "netlink",
            Mechanism::RouteSocket => "route socket",
            Mechanism::Polling => "polling",
        })
    }
}

/// A change of network, from [`NetWatch::changed`].
#[derive(Debug, Clone)]
pub struct NetChange {
    /// The fingerprint this watcher saw last.
    pub previous: NetFingerprint,
    /// The fingerprint now.
    pub fingerprint: NetFingerprint,
    /// The state now.
    pub snapshot: Arc<NetSnapshot>,
}

/// Settings of a [`NetWatch`]; the defaults suit clients.
#[derive(Debug, Clone)]
pub struct Options {
    /// Listen to the kernel's messages when the system has them; false: always poll.
    pub kernel_events: bool,
    /// See [`DEBOUNCE`].
    pub debounce: Duration,
    /// See [`DEBOUNCE_MAX`].
    pub debounce_max: Duration,
    /// See [`POLL_INTERVAL`].
    pub poll_interval: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            kernel_events: true,
            debounce: DEBOUNCE,
            debounce_max: DEBOUNCE_MAX,
            poll_interval: POLL_INTERVAL,
        }
    }
}

#[derive(Debug)]
struct State {
    snapshot: Arc<NetSnapshot>,
    fingerprint: NetFingerprint,
    mechanism: Mechanism,
}

/// Watches the network and reports changes ([`NetWatch::changed`]).
///
/// Clones share one watcher, and each clone sees every change (changes that come faster than
/// a clone looks are merged into one). The watcher's task ends when the last clone is
/// dropped.
#[derive(Debug, Clone)]
pub struct NetWatch {
    state: watch::Receiver<State>,
    check: Arc<Notify>,
    seen: NetFingerprint,
}

impl NetWatch {
    /// Start watching with the default [`Options`]. Must be called within a tokio runtime
    /// (with the IO and time drivers enabled); fails only outside one. Never fails because of
    /// the system: without kernel messages it polls.
    pub fn spawn() -> io::Result<NetWatch> {
        NetWatch::spawn_with(Options::default())
    }

    /// Start watching with `options`.
    pub fn spawn_with(options: Options) -> io::Result<NetWatch> {
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let source: Arc<dyn Fn() -> NetSnapshot + Send + Sync> = Arc::new(NetSnapshot::take);
        // Inside the runtime: AsyncFd needs its reactor
        let _entered = runtime.enter();
        let events = if options.kernel_events {
            match kernel_events() {
                Ok(e) => Some(e),
                Err(e) => {
                    crate::log::debug(format_args!("network changes: no kernel messages ({e}); polling"));
                    None
                }
            }
        } else {
            None
        };
        Ok(NetWatch::start(&runtime, events, source, options))
    }

    /// The watcher on a given source of kernel messages and of snapshots (also the tests').
    fn start(
        runtime: &tokio::runtime::Handle,
        events: Option<(mpsc::Receiver<()>, Mechanism)>,
        source: Arc<dyn Fn() -> NetSnapshot + Send + Sync>,
        options: Options,
    ) -> NetWatch {
        let snapshot = source();
        let fingerprint = snapshot.fingerprint();
        let (kicks, mechanism) = match events {
            Some((rx, mechanism)) => (Some(rx), mechanism),
            None => (None, Mechanism::Polling),
        };
        let (tx, rx) = watch::channel(State {
            snapshot: Arc::new(snapshot),
            fingerprint,
            mechanism,
        });
        let check = Arc::new(Notify::new());
        runtime.spawn(watch_loop(kicks, check.clone(), source, tx, options));
        NetWatch {
            state: rx,
            check,
            seen: fingerprint,
        }
    }

    /// Wait for the next change of network. Never returns if the watcher stopped (it only
    /// stops when every clone is dropped), so it is safe in a `select!` loop.
    pub async fn changed(&mut self) -> NetChange {
        loop {
            if self.state.changed().await.is_err() {
                return std::future::pending().await;
            }
            let state = self.state.borrow_and_update();
            if state.fingerprint != self.seen {
                let change = NetChange {
                    previous: self.seen,
                    fingerprint: state.fingerprint,
                    snapshot: state.snapshot.clone(),
                };
                self.seen = state.fingerprint;
                return change;
            }
        }
    }

    /// Look at the network now, without waiting for the kernel or the next poll: for
    /// embedders that hear of changes first (Android's connectivity callbacks), and after the
    /// machine woke up.
    pub fn check_now(&self) {
        self.check.notify_one();
    }

    /// The network as last seen.
    pub fn snapshot(&self) -> Arc<NetSnapshot> {
        self.state.borrow().snapshot.clone()
    }

    /// The fingerprint of the network as last seen.
    pub fn fingerprint(&self) -> NetFingerprint {
        self.state.borrow().fingerprint
    }

    /// How changes are learned of (for `~s` and doctor output).
    pub fn mechanism(&self) -> Mechanism {
        self.state.borrow().mechanism
    }
}

/// Wait for a reason to look (a kernel message, a request, the poll interval), let a burst of
/// messages settle, take a snapshot and publish it if it differs from the last one. Ends when
/// every receiver is gone.
async fn watch_loop(
    mut kicks: Option<mpsc::Receiver<()>>,
    check: Arc<Notify>,
    source: Arc<dyn Fn() -> NetSnapshot + Send + Sync>,
    tx: watch::Sender<State>,
    options: Options,
) {
    loop {
        let wake = match kicks.as_mut() {
            Some(rx) => tokio::select! {
                kick = rx.recv() => if kick.is_some() { Wake::Kernel } else { Wake::ReaderEnded },
                () = check.notified() => Wake::Other,
                () = tx.closed() => return,
            },
            None => tokio::select! {
                () = tokio::time::sleep(options.poll_interval) => Wake::Other,
                () = check.notified() => Wake::Other,
                () = tx.closed() => return,
            },
        };
        match wake {
            // Look once more anyway: something may have changed while nobody listened
            Wake::ReaderEnded => fall_back_to_polling(&mut kicks, &tx),
            Wake::Kernel => {
                if let Some(rx) = kicks.as_mut() {
                    if !settle(rx, &options).await {
                        fall_back_to_polling(&mut kicks, &tx);
                    }
                }
            }
            Wake::Other => {}
        }
        let snapshot = source();
        let fingerprint = snapshot.fingerprint();
        tx.send_if_modified(|state| {
            if state.fingerprint == fingerprint {
                return false;
            }
            crate::log::debug(format_args!("network changed: {snapshot} ({fingerprint})"));
            state.snapshot = Arc::new(snapshot);
            state.fingerprint = fingerprint;
            true
        });
    }
}

/// What made [`watch_loop`] look.
enum Wake {
    /// A batch of kernel messages.
    Kernel,
    /// The reader of kernel messages ended.
    ReaderEnded,
    /// A request ([`NetWatch::check_now`]) or the poll timer.
    Other,
}

/// Wait until no message came for `debounce`, or `debounce_max` passed. False when the
/// messages ended (the reader stopped).
async fn settle(rx: &mut mpsc::Receiver<()>, options: &Options) -> bool {
    let deadline = Instant::now() + options.debounce_max;
    loop {
        let quiet_until = (Instant::now() + options.debounce).min(deadline);
        tokio::select! {
            kick = rx.recv() => {
                if kick.is_none() {
                    return false;
                }
                if Instant::now() >= deadline {
                    return true;
                }
            }
            () = tokio::time::sleep_until(quiet_until) => return true,
        }
    }
}

fn fall_back_to_polling(kicks: &mut Option<mpsc::Receiver<()>>, tx: &watch::Sender<State>) {
    crate::log::debug(format_args!("network changes: kernel messages stopped; polling"));
    *kicks = None;
    tx.send_modify(|state| state.mechanism = Mechanism::Polling);
}

/// Open the kernel's notifications and start their reader: a channel that carries one `()`
/// per batch of relevant messages (coalesced), and ends when the reader fails.
fn kernel_events() -> io::Result<(mpsc::Receiver<()>, Mechanism)> {
    let (relevant, mechanism): (fn(&[u8]) -> bool, Mechanism) = if cfg!(target_os = "macos") {
        (route_message_relevant, Mechanism::RouteSocket)
    } else {
        (netlink_relevant, Mechanism::Netlink)
    };
    let fd = AsyncFd::new(File::from(sys::route_socket()?))?;
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(read_events(fd, tx, relevant));
    Ok((rx, mechanism))
}

async fn read_events(fd: AsyncFd<File>, tx: mpsc::Sender<()>, relevant: fn(&[u8]) -> bool) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut guard = tokio::select! {
            ready = fd.readable() => match ready {
                Ok(g) => g,
                Err(e) => {
                    crate::log::debug(format_args!("network changes: {e}"));
                    return;
                }
            },
            () = tx.closed() => return,
        };
        let kick = match guard.try_io(|f| f.get_ref().read(&mut buf)) {
            Err(_would_block) => continue,
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => relevant(&buf[..n]),
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            // The socket's buffer overflowed and messages were lost: anything may have changed
            Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => true,
            Ok(Err(e)) => {
                crate::log::debug(format_args!("network changes: {e}"));
                return;
            }
        };
        if kick {
            // Full: a look is already due; this message is covered by it
            let _ = tx.try_send(());
        }
    }
}

// rtnetlink, linux/netlink.h and linux/rtnetlink.h (kernel ABI, native byte order)
const NLMSG_HDRLEN: usize = 16;
const NLMSG_OVERRUN: u16 = 4;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
/// Length of struct ifinfomsg, the body of link messages.
const IFINFOMSG_LEN: usize = 16;
/// Length of struct rtmsg, the body of route messages.
const RTMSG_LEN: usize = 12;
const RT_TABLE_LOCAL: u8 = 255;
const IFLA_WIRELESS: u16 = 11;

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// True when a datagram of rtnetlink messages may have changed the default route or the
/// local addresses: any address message, a link message other than a wireless extension
/// event (Wi-Fi drivers send those during every scan), a route message for a default route
/// outside the local table, and anything malformed or truncated (better look once more).
pub fn netlink_relevant(datagram: &[u8]) -> bool {
    let mut rest = datagram;
    while !rest.is_empty() {
        let (Some(len), Some(kind)) = (u32_at(rest, 0), u16_at(rest, 4)) else {
            return true;
        };
        let len = len as usize;
        if len < NLMSG_HDRLEN || len > rest.len() {
            return true;
        }
        let body = &rest[NLMSG_HDRLEN..len];
        let relevant = match kind {
            RTM_NEWADDR | RTM_DELADDR | RTM_DELLINK | NLMSG_OVERRUN => true,
            RTM_NEWLINK => !link_is_wireless_event(body),
            RTM_NEWROUTE | RTM_DELROUTE => route_is_default(body),
            _ => false,
        };
        if relevant {
            return true;
        }
        // Messages are aligned to 4 bytes
        let next = (len + 3) & !3;
        rest = rest.get(next..).unwrap_or_default();
    }
    false
}

/// A link message that carries a wireless extension event (IFLA_WIRELESS) and nothing about
/// the link's state.
fn link_is_wireless_event(body: &[u8]) -> bool {
    let Some(mut attributes) = body.get(IFINFOMSG_LEN..) else {
        return false;
    };
    // struct rtattr: u16 length (header included), u16 type; 4-byte aligned
    while let (Some(len), Some(kind)) = (u16_at(attributes, 0), u16_at(attributes, 2)) {
        let len = len as usize;
        if len < 4 || len > attributes.len() {
            return false;
        }
        if kind & 0x3fff == IFLA_WIRELESS {
            return true;
        }
        let next = (len + 3) & !3;
        attributes = attributes.get(next..).unwrap_or_default();
    }
    false
}

/// A route message for a default route (destination length 0) outside the local table.
fn route_is_default(body: &[u8]) -> bool {
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
    if body.len() < RTMSG_LEN {
        return true;
    }
    body[1] == 0 && body[4] != RT_TABLE_LOCAL
}

// Routing socket messages of macOS, net/route.h (struct rt_msghdr and friends)
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_CHANGE: u8 = 0x3;
const RTM_NEWADDR_BSD: u8 = 0xc;
const RTM_DELADDR_BSD: u8 = 0xd;
const RTM_IFINFO: u8 = 0xe;
const RTF_HOST: u32 = 0x4;

/// True when routing socket messages (macOS layout) may have changed the default route or
/// the local addresses: address and interface messages, and route messages for a network
/// route (not the host routes that ARP and neighbor discovery add and remove all the time);
/// anything malformed counts too.
pub fn route_message_relevant(datagram: &[u8]) -> bool {
    let mut rest = datagram;
    while !rest.is_empty() {
        // u16 rtm_msglen, u8 rtm_version, u8 rtm_type, u16 rtm_index, padding, int rtm_flags
        let Some(len) = u16_at(rest, 0) else {
            return true;
        };
        let len = len as usize;
        if len < 4 || len > rest.len() {
            return true;
        }
        let relevant = match rest[3] {
            RTM_NEWADDR_BSD | RTM_DELADDR_BSD | RTM_IFINFO => true,
            RTM_ADD | RTM_DELETE | RTM_CHANGE => match u32_at(&rest[..len], 8) {
                Some(flags) => flags & RTF_HOST == 0,
                None => true,
            },
            _ => false,
        };
        if relevant {
            return true;
        }
        rest = &rest[len..];
    }
    false
}

/// The source address of the default route of one family: the local address of a UDP socket
/// connected towards a documentation address (nothing is sent). None without such a route.
fn source_address(v6: bool) -> Option<IpAddr> {
    let (local, remote): (SocketAddr, SocketAddr) = if v6 {
        ((Ipv6Addr::UNSPECIFIED, 0).into(), (PROBE_V6, 9).into())
    } else {
        ((Ipv4Addr::UNSPECIFIED, 0).into(), (PROBE_V4, 9).into())
    };
    let socket = UdpSocket::bind(local).ok()?;
    socket.connect(remote).ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_unspecified()).then_some(address)
}

fn default_route(source: IpAddr, interfaces: &[sys::InterfaceAddress]) -> DefaultRoute {
    let interface = interfaces
        .iter()
        .find(|a| a.address == source)
        .map(|a| a.interface.clone())
        .unwrap_or_default();
    let gateway = gateway(&interface, source.is_ipv6());
    DefaultRoute {
        interface,
        source,
        gateway,
    }
}

/// The gateway of the default route through `interface` (Linux: from /proc).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn gateway(interface: &str, v6: bool) -> Option<IpAddr> {
    if interface.is_empty() {
        return None;
    }
    let path = if v6 { "/proc/net/ipv6_route" } else { "/proc/net/route" };
    let text = std::fs::read_to_string(path).ok()?;
    let routes = if v6 {
        parse_ipv6_route(&text)
    } else {
        parse_ipv4_route(&text)
    };
    routes
        .into_iter()
        .filter(|r| r.interface == interface)
        .min_by_key(|r| r.metric)
        .and_then(|r| r.gateway)
}

/// macOS and others: not looked up (it would take parsing a routing table dump); the
/// interface and its addresses identify the network.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn gateway(_interface: &str, _v6: bool) -> Option<IpAddr> {
    None
}

/// A default route from /proc.
#[cfg(any(target_os = "linux", target_os = "android", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcRoute {
    interface: String,
    gateway: Option<IpAddr>,
    metric: u32,
}

// Route flags of linux/route.h and linux/ipv6_route.h
#[cfg(any(target_os = "linux", target_os = "android", test))]
const RTF_UP: u32 = 0x1;
#[cfg(any(target_os = "linux", target_os = "android", test))]
const RTF_REJECT: u32 = 0x200;

/// The usable default routes in /proc/net/route: `Iface Destination Gateway Flags RefCnt Use
/// Metric Mask …`, addresses as the hex of the network-order 32-bit value read in host order.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_ipv4_route(text: &str) -> Vec<ProcRoute> {
    let hex = |s: &str| u32::from_str_radix(s, 16).ok();
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (destination, gateway, flags, metric, mask) = (
                hex(f.get(1)?)?,
                hex(f.get(2)?)?,
                hex(f.get(3)?)?,
                f.get(6)?.parse().ok()?,
                hex(f.get(7)?)?,
            );
            if destination != 0 || mask != 0 || flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
                return None;
            }
            let gateway = Ipv4Addr::from(gateway.to_ne_bytes());
            Some(ProcRoute {
                interface: f[0].to_string(),
                gateway: (!gateway.is_unspecified()).then_some(gateway.into()),
                metric,
            })
        })
        .collect()
}

/// The usable default routes in /proc/net/ipv6_route: `dst dst_len src src_len next_hop
/// metric refcnt use flags iface`, addresses as 32 hex digits, numbers in hex.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_ipv6_route(text: &str) -> Vec<ProcRoute> {
    let address = |s: &str| -> Option<Ipv6Addr> {
        if s.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for (i, o) in octets.iter_mut().enumerate() {
            *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Ipv6Addr::from(octets))
    };
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let destination = address(f[0])?;
            let destination_len = u8::from_str_radix(f[1], 16).ok()?;
            let next_hop = address(f[4])?;
            let metric = u32::from_str_radix(f[5], 16).ok()?;
            let flags = u32::from_str_radix(f[8], 16).ok()?;
            if !destination.is_unspecified()
                || destination_len != 0
                || flags & RTF_UP == 0
                || flags & RTF_REJECT != 0
                || f[9] == "lo"
            {
                return None;
            }
            Some(ProcRoute {
                interface: f[9].to_string(),
                gateway: (!next_hop.is_unspecified()).then_some(next_hop.into()),
                metric,
            })
        })
        .collect()
}

/// The address as it identifies a network: IPv4 as is, IPv6 cut to its /64.
fn stable_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(a) => {
            let mut octets = a.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

fn is_ipv6_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// The addresses of the routes' interfaces, as in [`NetSnapshot::addresses`].
fn route_addresses(interfaces: &[sys::InterfaceAddress], routes: [&Option<DefaultRoute>; 2]) -> Vec<IpAddr> {
    let names: Vec<&str> = routes
        .into_iter()
        .flatten()
        .map(|r| r.interface.as_str())
        .filter(|n| !n.is_empty())
        .collect();
    let mut addresses: Vec<IpAddr> = interfaces
        .iter()
        .filter(|a| names.contains(&a.interface.as_str()) && !a.loopback)
        .filter(|a| match a.address {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => !is_ipv6_link_local(&v6) && !v6.is_multicast(),
        })
        .map(|a| stable_address(a.address))
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}
