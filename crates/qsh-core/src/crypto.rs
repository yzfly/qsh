//! Identity, pinning, session proofs and the TLS / QUIC configurations.
//!
//! Trust is anchored in SSH (docs/DESIGN.md section 2): the daemon has a self-signed
//! certificate, and a client accepts exactly the certificate whose SHA-256 fingerprint it got
//! from the bootstrap, which ran over the user's own ssh. No certificate authority is involved.
//!
//! Sessions are authenticated with proofs bound to the connection (protocol.md section 6):
//! HMAC-SHA256 under the session key over a TLS exporter value of this very connection (or a
//! hash of the server's nonce on the ssh pipe), so a proof seen on one connection is worthless
//! on another.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::paths;

/// The ALPN protocol identifier of qsh/1, on QUIC and on TLS over TCP.
pub const ALPN: &[u8] = crate::proto::ALPN;

/// The name in the daemon's certificate. Clients check the fingerprint, not the name, and send
/// no SNI.
pub const SERVER_NAME: &str = "qsh";

/// Part of the error a client gets when the server's certificate does not match the pin.
pub const PIN_MISMATCH: &str = "certificate does not match the pin from the bootstrap";

/// Length of a session key, in bytes.
pub const KEY_LEN: usize = 32;

/// A SHA-256 certificate fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// The fingerprint of a DER certificate.
    pub fn of(cert: &[u8]) -> Fingerprint {
        Fingerprint(sha256(cert))
    }

    /// Lower-case hex, as in the bootstrap reply.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parse 64 hex digits.
    pub fn from_hex(text: &str) -> Option<Fingerprint> {
        unhex::<32>(text).map(Fingerprint)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

/// A secret session key. Its `Debug` output does not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(pub [u8; KEY_LEN]);

impl SessionKey {
    /// A new random key.
    pub fn generate() -> SessionKey {
        SessionKey(random())
    }

    /// The proof of knowing this key on a connection (section 6.3): HMAC-SHA256(key, CB), where
    /// CB is the connection's channel binding value (section 6.2).
    pub fn proof(&self, binding: &[u8]) -> [u8; 32] {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &self.0), binding);
        tag.as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
    }

    /// The server's proof in ATTACHED (section 6.3): HMAC-SHA256(key, "qsh/1 attached" || CB).
    pub fn server_proof(&self, binding: &[u8]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &self.0));
        ctx.update(crate::proto::SERVER_PROOF_LABEL);
        ctx.update(binding);
        ctx.sign().as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
    }

    /// Check a server proof in constant time.
    pub fn verify_server(&self, binding: &[u8], proof: &[u8]) -> bool {
        constant_time_eq(&self.server_proof(binding), proof)
    }

    /// Check a proof in constant time.
    pub fn verify(&self, binding: &[u8], proof: &[u8]) -> bool {
        hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &self.0), binding, proof).is_ok()
    }

    /// Lower-case hex, as in the bootstrap reply.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parse 64 hex digits.
    pub fn from_hex(text: &str) -> Option<SessionKey> {
        unhex::<KEY_LEN>(text).map(SessionKey)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// The channel binding value of the ssh pipe (section 6.2):
/// SHA-256("qsh/1 pipe attach" || nonce || session id).
pub fn pipe_binding(nonce: &[u8; 32], session: &[u8; 16]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(crate::proto::PIPE_BINDING_LABEL);
    ctx.update(nonce);
    ctx.update(session);
    ctx.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// `N` random bytes from the operating system.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system random number generator failed");
    bytes
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Exactly `N` bytes from `2 * N` hex digits.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

/// Compare two byte strings without revealing through timing where they differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The daemon's certificate and private key.
#[derive(Debug)]
pub struct Identity {
    /// The self-signed certificate, DER.
    pub cert: CertificateDer<'static>,
    /// Its PKCS#8 private key.
    pub key: PrivatePkcs8KeyDer<'static>,
}

impl Identity {
    /// A new self-signed ECDSA P-256 identity.
    pub fn generate() -> io::Result<Identity> {
        let generated = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).map_err(io::Error::other)?;
        Ok(Identity {
            cert: generated.cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()),
        })
    }

    /// The identity kept in `dir` (`cert.der`, `key.der`, mode 0600), created on first use.
    ///
    /// It is kept across daemon restarts so that a client coming back to a restarted daemon
    /// gets a clean "unknown session" answer (and bootstraps again) instead of a certificate
    /// that no longer matches its pin.
    pub fn load_or_create(dir: &Path) -> io::Result<Identity> {
        paths::ensure_private_dir(dir)?;
        let cert_path = dir.join("cert.der");
        let key_path = dir.join("key.der");
        if let (Ok(cert), Ok(key)) = (fs::read(&cert_path), fs::read(&key_path)) {
            return Ok(Identity {
                cert: CertificateDer::from(cert),
                key: PrivatePkcs8KeyDer::from(key),
            });
        }
        let identity = Identity::generate()?;
        paths::write_private(&key_path, identity.key.secret_pkcs8_der())?;
        paths::write_private(&cert_path, identity.cert.as_ref())?;
        Ok(identity)
    }

    /// The certificate's fingerprint, which the bootstrap hands to clients.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(self.cert.as_ref())
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }
}

/// The rustls crypto provider qsh uses: ring.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The daemon's TLS configuration: TLS 1.3 only, ALPN `qsh/1`, no client certificates.
pub fn server_tls(identity: &Identity) -> io::Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.clone()], identity.private_key())
        .map_err(io::Error::other)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    // Resumed TLS sessions are of no use (a session proof follows anyway) and 0-RTT data could
    // be replayed
    config.send_tls13_tickets = 0;
    Ok(config)
}

/// The client's TLS configuration: TLS 1.3 only, ALPN `qsh/1`, accepting exactly the
/// certificate with `fingerprint`.
pub fn client_tls(fingerprint: Fingerprint) -> io::Result<rustls::ClientConfig> {
    let provider = provider();
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert { fingerprint, provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    // Section 9: no SNI, no resumption, no early data; every handshake checks the pin
    config.enable_sni = false;
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

/// The name passed to TLS connects. It is not sent (no SNI) and not checked (pinning).
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("a valid DNS name")
}

/// QUIC transport parameters shared by both ends (protocol.md 9.1).
fn transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // Keepalives hold NAT mappings open (carrier UDP mappings last 30 s or more), and are rare
    // enough to let a phone's cellular radio go idle. The session layer finds dead paths.
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    // Long enough to ride out a network switch; the client reconnects after that
    transport.max_idle_timeout(Some(
        Duration::from_secs(60)
            .try_into()
            .expect("60 s is a valid idle timeout"),
    ));
    // BBR keeps throughput up on lossy long distance links where loss based control collapses
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Datagrams are not used: no max_datagram_frame_size
    transport.datagram_receive_buffer_size(None);
    transport.max_concurrent_uni_streams(0u32.into());
    transport.stream_receive_window((1u32 << 20).into());
    transport
}

/// Bidirectional streams a client may have open on one connection (protocol.md 4.5).
pub const MAX_STREAMS: u32 = 128;

/// The daemon's connection receive window before a connection is authenticated (9.1).
pub const PREAUTH_RECEIVE_WINDOW: u32 = 64 * 1024;

/// The daemon's QUIC configuration.
pub fn quic_server(identity: &Identity) -> io::Result<quinn::ServerConfig> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(identity)?).map_err(io::Error::other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = transport();
    transport.max_concurrent_bidi_streams(MAX_STREAMS.into());
    // Small until the connection is authenticated; raised by the attach
    transport.receive_window(PREAUTH_RECEIVE_WINDOW.into());
    config.transport_config(Arc::new(transport));
    // Clients change address when they move between networks
    config.migration(true);
    Ok(config)
}

/// The client's QUIC configuration, pinned to `fingerprint`.
pub fn quic_client(fingerprint: Fingerprint) -> io::Result<quinn::ClientConfig> {
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(fingerprint)?).map_err(io::Error::other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = transport();
    // qsh/1 has no server-initiated channels
    transport.max_concurrent_bidi_streams(0u32.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Accept exactly the certificate with the pinned fingerprint, and still verify the handshake
/// signatures made with its key.
#[derive(Debug)]
struct PinnedCert {
    fingerprint: Fingerprint,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if constant_time_eq(&sha256(end_entity.as_ref()), &self.fingerprint.0) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!("the server {PIN_MISMATCH}")))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Never negotiated (TLS 1.3 only); verified properly all the same
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_rejects_bad_input() {
        let bytes: [u8; 4] = [0, 0x7f, 0x80, 0xff];
        assert_eq!(hex(&bytes), "007f80ff");
        assert_eq!(unhex::<4>("007f80ff"), Some(bytes));
        assert_eq!(unhex::<4>("007f80f"), None);
        assert_eq!(unhex::<4>("007f80fg"), None);
        // A multi-byte character must not make slicing panic
        assert_eq!(unhex::<2>("é00"), None);
    }

    #[test]
    fn proofs_bind_to_the_connection() {
        let key = SessionKey::generate();
        let proof = key.proof(b"exporter of connection A");
        assert!(key.verify(b"exporter of connection A", &proof));
        assert!(!key.verify(b"exporter of connection B", &proof));
        assert!(!SessionKey::generate().verify(b"exporter of connection A", &proof));
    }

    /// protocol.md A.4
    #[test]
    fn proof_test_vectors() {
        let key = SessionKey::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let cb = unhex::<32>("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf").unwrap();
        assert_eq!(
            hex(&key.proof(&cb)),
            "0c95bd8bdd96004ec3f84f7bcc9526ee33491925dae778d32b6b81a42c38fe93"
        );
        assert_eq!(
            hex(&key.server_proof(&cb)),
            "8ff9d481ebe0f5683b3e82707d8172e8bf8392b92d556fb9272ceecf814a2606"
        );
        assert!(key.verify_server(&cb, &key.server_proof(&cb)));
        let session = unhex::<16>("00112233445566778899aabbccddeeff").unwrap();
        let cb = pipe_binding(&[0x5a; 32], &session);
        assert_eq!(
            hex(&cb),
            "4818fc1f170f8040596b57e87868f65744f69bb3e37a93f9028eed89130a3801"
        );
        assert_eq!(
            hex(&key.proof(&cb)),
            "d011e9b69acaa41b9f815cab5a6e073d6caba66b8e9b1bc79d1d65a92f0d9694"
        );
    }

    #[test]
    fn identity_persists() {
        let dir = std::env::temp_dir().join(format!("qsh-crypto-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        fs::remove_dir_all(dir).unwrap();
    }

    /// A TLS handshake succeeds against the pinned certificate and fails against another.
    #[tokio::test]
    async fn pinning_accepts_only_the_pinned_certificate() {
        let identity = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        for (pin, ok) in [(identity.fingerprint(), true), (other.fingerprint(), false)] {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(&identity).unwrap()));
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(pin).unwrap()));
            let server = tokio::spawn(async move { acceptor.accept(server).await.map(|_| ()) });
            let client = connector.connect(server_name(), client).await;
            assert_eq!(client.is_ok(), ok);
            if ok {
                let stream = client.unwrap();
                assert_eq!(stream.get_ref().1.alpn_protocol(), Some(ALPN));
                server.await.unwrap().unwrap();
            }
        }
    }
}
