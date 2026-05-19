//! Build rustls configs for server and client. The client uses a custom
//! verifier that pins by SHA-256 of the leaf cert — TOFU semantics.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn install_crypto_provider() {
    // Idempotent: first caller wins. Subsequent calls return an error we
    // ignore. The provider gives us the cipher suites and KX groups rustls
    // needs at construction time.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn server_acceptor(cert_pem: &str, key_pem: &str) -> anyhow::Result<TlsAcceptor> {
    install_crypto_provider();

    let mut cert_cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_cursor).collect::<Result<_, _>>()?;

    let mut key_cursor = std::io::Cursor::new(key_pem.as_bytes());
    let mut keys: Vec<PrivatePkcs8KeyDer<'static>> =
        rustls_pemfile::pkcs8_private_keys(&mut key_cursor).collect::<Result<_, _>>()?;
    let key = keys
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 private key found in PEM"))?;

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

#[derive(Debug)]
struct PinnedVerifier {
    fingerprint: [u8; 32],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let mut h = Sha256::new();
        h.update(end_entity.as_ref());
        let actual: [u8; 32] = h.finalize().into();
        if actual == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(format!(
                "cert pinning failed: got {} expected {}",
                hex::encode(actual),
                hex::encode(self.fingerprint)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub fn client_connect(expected_fingerprint: [u8; 32]) -> TlsConnector {
    install_crypto_provider();
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            fingerprint: expected_fingerprint,
        }))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{fingerprint_sha256, generate_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn end_to_end_localhost_tls() {
        let pair = generate_self_signed("test.local").unwrap();
        let fp = fingerprint_sha256(&pair.cert_pem).unwrap();
        let acceptor = server_acceptor(&pair.cert_pem, &pair.key_pem).unwrap();
        let connector = client_connect(fp);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"world").await.unwrap();
            buf
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("test.local").unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        assert_eq!(&server.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn wrong_fingerprint_rejected() {
        let pair = generate_self_signed("test.local").unwrap();
        let acceptor = server_acceptor(&pair.cert_pem, &pair.key_pem).unwrap();
        let wrong_fp = [0u8; 32];
        let connector = client_connect(wrong_fp);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("test.local").unwrap();
        assert!(connector.connect(server_name, stream).await.is_err());
    }
}
