//! TLS 1.3 over TCP: for networks that block or throttle UDP. Channels are multiplexed over
//! the one byte stream by [`crate::mux`].

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::{client, server, LazyConfigAcceptor, TlsConnector};

use crate::crypto::{self, Fingerprint, Identity, ALPN};

/// A TLS handshake (including the TCP connect) gives up after this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

/// A fatal TLS alert `no_application_protocol` (120) in a plaintext record, as a server sends it
/// before its ServerHello (RFC 8446 sections 5.1 and 6).
const NO_APPLICATION_PROTOCOL_ALERT: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 120];

/// Connect to the daemon at `host`:`port` whose certificate has `fingerprint`. The handshake
/// must negotiate ALPN `qsh/1` (protocol.md 9.1); a certificate that does not match the pin is
/// reported as a pin mismatch ([`crypto::PIN_MISMATCH`]).
pub async fn connect(host: &str, port: u16, fingerprint: Fingerprint) -> io::Result<client::TlsStream<TcpStream>> {
    let (config, pin) = crypto::pinned_client_tls(fingerprint)?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        connector
            .connect(crypto::server_name(), tcp)
            .await
            .map_err(|e| pin.error(e))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    crypto::check_alpn(stream.get_ref().1.alpn_protocol())?;
    Ok(stream)
}

/// The daemon's side of TLS.
#[derive(Clone)]
pub struct Acceptor(Arc<rustls::ServerConfig>);

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Acceptor")
    }
}

impl Acceptor {
    /// An acceptor presenting `identity`.
    pub fn new(identity: &Identity) -> io::Result<Acceptor> {
        Ok(Acceptor(Arc::new(crypto::server_tls(identity)?)))
    }

    /// The handshake of an accepted TCP connection. Anyone can connect, so it has to finish
    /// within [`HANDSHAKE_TIMEOUT`].
    pub async fn accept(&self, tcp: TcpStream) -> io::Result<server::TlsStream<TcpStream>> {
        let _ = tcp.set_nodelay(true);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
    }

    /// The handshake on any byte stream. A client that does not offer ALPN `qsh/1` is refused
    /// with the alert no_application_protocol (protocol.md 9.1): rustls refuses one that offers
    /// only other protocols, but would accept one that offers none.
    pub async fn handshake<IO>(&self, io: IO) -> io::Result<server::TlsStream<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await?;
        let offers_qsh = start
            .client_hello()
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ALPN));
        if !offers_qsh {
            let mut io = start.io;
            let _ = io.write_all(&NO_APPLICATION_PROTOCOL_ALERT).await;
            let _ = io.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the client did not offer ALPN qsh/1",
            ));
        }
        let stream = start.into_stream(self.0.clone()).await?;
        crypto::check_alpn(stream.get_ref().1.alpn_protocol())?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review: a TLS client offering no ALPN must be refused with no_application_protocol, not
    /// served (rustls alone accepts it).
    #[tokio::test]
    async fn clients_without_alpn_qsh1_are_refused() {
        let identity = Identity::generate().unwrap();
        let acceptor = Acceptor::new(&identity).unwrap();
        for (alpn, ok) in [
            (vec![], false),
            (vec![b"h2".to_vec()], false),
            (vec![ALPN.to_vec()], true),
        ] {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let acceptor = acceptor.clone();
            let server = tokio::spawn(async move { acceptor.handshake(server).await.map(|_| ()) });
            let mut config = crypto::client_tls(identity.fingerprint()).unwrap();
            config.alpn_protocols = alpn.clone();
            let client = TlsConnector::from(Arc::new(config))
                .connect(crypto::server_name(), client)
                .await;
            assert_eq!(server.await.unwrap().is_ok(), ok, "{alpn:?}");
            match client {
                Ok(stream) => {
                    assert!(ok, "{alpn:?}");
                    crypto::check_alpn(stream.get_ref().1.alpn_protocol()).unwrap();
                }
                Err(e) => {
                    assert!(!ok);
                    let alert = e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()).cloned();
                    assert_eq!(
                        alert,
                        Some(rustls::Error::AlertReceived(
                            rustls::AlertDescription::NoApplicationProtocol
                        )),
                        "{alpn:?}: {e}"
                    );
                }
            }
        }
    }
}
