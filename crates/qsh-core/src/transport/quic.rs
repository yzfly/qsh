//! QUIC, the preferred transport: survives address changes (connection migration) and carries
//! every channel on a native stream.
//!
//! A client process has one endpoint, that is one UDP socket, for all its connections; moving
//! to a new network rebinds it ([`QuicClient::rebind`]) and every connection migrates.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use crate::crypto::{self, Fingerprint, Identity};
use crate::sys;

/// A QUIC handshake gives up after this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

/// The client side: one endpoint, created on first use.
#[derive(Debug, Default)]
pub struct QuicClient {
    endpoint: Mutex<Option<(quinn::Endpoint, bool)>>,
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

    /// Connect to the daemon at `host`:`port` whose certificate has `fingerprint`.
    pub async fn connect(&self, host: &str, port: u16, fingerprint: Fingerprint) -> io::Result<quinn::Connection> {
        let (endpoint, ipv6) = self.endpoint()?;
        let config = crypto::quic_client(fingerprint)?;
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
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
                .map_err(io::Error::other)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
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
        Ok(true)
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
