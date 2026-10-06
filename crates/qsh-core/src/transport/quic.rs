//! QUIC, the preferred transport: survives address changes (connection migration) and carries
//! every channel on a native stream.
//!
//! A client process has one endpoint, that is one UDP socket, for all its connections; moving
//! to a new network rebinds it ([`QuicClient::rebind`]) and every connection migrates.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::crypto::{self, Fingerprint, Identity};
use crate::sys;

/// A QUIC handshake gives up after this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

/// The client's QUIC keep-alive interval when nothing was learned about the network
/// (`KEEPALIVE_START`, m2.md 4.3; protocol.md 9.1).
pub const KEEPALIVE_DEFAULT: Duration = Duration::from_secs(20);

/// The QUIC idle timeout both ends advertise (protocol.md 9.1).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Settings of one client connection that QUIC fixes when the connection is created (quinn
/// cannot change them later, m2.md 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Send a QUIC PING after this long without sending anything: holds NAT mappings open.
    pub keep_alive: Duration,
    /// The client's `max_idle_timeout`; QUIC uses the smaller of both ends' values.
    pub idle_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            keep_alive: KEEPALIVE_DEFAULT,
            idle_timeout: IDLE_TIMEOUT,
        }
    }
}

impl Options {
    /// The options for a keep-alive interval `k`: an interval above 25 s raises the idle
    /// timeout to three times `k`, so that two lost keep-alives do not end the connection
    /// (m2.md 4.3; the server's 60 s still bound it unless it allows more).
    pub fn with_keepalive(k: Duration) -> Options {
        Options {
            keep_alive: k,
            idle_timeout: if k > Duration::from_secs(25) {
                k * 3
            } else {
                IDLE_TIMEOUT
            },
        }
    }
}

/// The client side: one endpoint, created on first use.
#[derive(Debug, Default)]
pub struct QuicClient {
    endpoint: Mutex<Option<(quinn::Endpoint, bool)>>,
    /// When the endpoint last moved to a new socket ([`QuicClient::rebind`]).
    rebound: Mutex<Option<tokio::time::Instant>>,
}

impl QuicClient {
    /// A client without an endpoint yet.
    pub fn new() -> QuicClient {
        QuicClient::default()
    }

    /// The endpoint and whether its socket is dual stack (reaches IPv6 too).
    fn endpoint(&self) -> io::Result<(quinn::Endpoint, bool)> {
        let mut endpoint = self.endpoint.lock().unwrap();
        if let Some(e) = endpoint.as_ref() {
            return Ok(e.clone());
        }
        let socket = sys::udp_any(0)?;
        let ipv6 = socket.local_addr()?.is_ipv6();
        let runtime = quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime"))?;
        let e = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
        *endpoint = Some((e.clone(), ipv6));
        Ok((e, ipv6))
    }

    /// Connect to the daemon at `host`:`port` whose certificate has `fingerprint`, with the
    /// default [`Options`].
    pub async fn connect(&self, host: &str, port: u16, fingerprint: Fingerprint) -> io::Result<quinn::Connection> {
        self.connect_with(host, port, fingerprint, &Options::default()).await
    }

    /// [`QuicClient::connect`] with `options` for this connection.
    pub async fn connect_with(
        &self,
        host: &str,
        port: u16,
        fingerprint: Fingerprint,
        options: &Options,
    ) -> io::Result<quinn::Connection> {
        let (endpoint, ipv6) = self.endpoint()?;
        let (mut config, pin) = crypto::pinned_quic_client(fingerprint)?;
        let mut transport = crypto::transport();
        // qsh/1 has no server-initiated channels
        transport.max_concurrent_bidi_streams(0u32.into());
        transport.keep_alive_interval(Some(options.keep_alive));
        let idle = quinn::IdleTimeout::try_from(options.idle_timeout).unwrap_or(quinn::VarInt::MAX.into());
        transport.max_idle_timeout(Some(idle));
        config.transport_config(Arc::new(transport));
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
            // A dual stack socket reaches both families; an IPv4 one only IPv4
            let address = addresses
                .iter()
                .find(|a| ipv6 || a.is_ipv4())
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no usable address for {host}")))?;
            endpoint
                .connect_with(config, address, crypto::SERVER_NAME)
                .map_err(io::Error::other)?
                .await
                .map_err(|e| pin.error(io::Error::other(e)))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))??;
        if let Err(e) = check_alpn(&connection) {
            connection.close(quinn::VarInt::from_u32(0), b"");
            return Err(e);
        }
        Ok(connection)
    }

    /// The network changed: move the endpoint, and with it every connection, to a new UDP
    /// socket on the new network. False when there is no endpoint yet.
    pub fn rebind(&self) -> io::Result<bool> {
        let mut endpoint = self.endpoint.lock().unwrap();
        let Some((e, ipv6)) = endpoint.as_mut() else {
            return Ok(false);
        };
        let socket = sys::udp_any(0)?;
        *ipv6 = socket.local_addr()?.is_ipv6();
        e.rebind(socket)?;
        *self.rebound.lock().unwrap() = Some(tokio::time::Instant::now());
        Ok(true)
    }

    /// When the endpoint last moved to a new socket, if it did: a change of address the
    /// server reports after that is the client's own doing, not a NAT's (m2.md 4.2).
    pub fn rebound_at(&self) -> Option<tokio::time::Instant> {
        *self.rebound.lock().unwrap()
    }

    /// The local address of the endpoint, if there is one.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.endpoint
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|(e, _)| e.local_addr().ok())
    }
}

/// Check that a QUIC connection negotiated ALPN `qsh/1` (protocol.md 9.1), on either side.
pub fn check_alpn(connection: &quinn::Connection) -> io::Result<()> {
    let protocol = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol);
    crypto::check_alpn(protocol.as_deref())
}

/// The daemon's QUIC endpoint on an already bound UDP socket (see `sys::udp_any`).
pub fn server_endpoint(socket: std::net::UdpSocket, identity: &Identity) -> io::Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime"))?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(crypto::quic_server(identity)?),
        socket,
        runtime,
    )
}
