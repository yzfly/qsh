//! TLS 1.3 over TCP: for networks that block or throttle UDP. Channels are multiplexed over
//! the one byte stream by [`crate::mux`].

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

use crate::crypto::{self, Fingerprint, Identity};

/// A TLS handshake (including the TCP connect) gives up after this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

/// Connect to the daemon at `host`:`port` whose certificate has `fingerprint`.
pub async fn connect(host: &str, port: u16, fingerprint: Fingerprint) -> io::Result<client::TlsStream<TcpStream>> {
    let connector = TlsConnector::from(Arc::new(crypto::client_tls(fingerprint)?));
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        connector.connect(crypto::server_name(), tcp).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
}

/// The daemon's side of TLS.
#[derive(Clone)]
pub struct Acceptor(TlsAcceptor);

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Acceptor")
    }
}

impl Acceptor {
    /// An acceptor presenting `identity`.
    pub fn new(identity: &Identity) -> io::Result<Acceptor> {
        Ok(Acceptor(TlsAcceptor::from(Arc::new(crypto::server_tls(identity)?))))
    }

    /// The handshake of an accepted TCP connection. Anyone can connect, so it has to finish
    /// within [`HANDSHAKE_TIMEOUT`].
    pub async fn accept(&self, tcp: TcpStream) -> io::Result<server::TlsStream<TcpStream>> {
        let _ = tcp.set_nodelay(true);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.0.accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
    }
}
