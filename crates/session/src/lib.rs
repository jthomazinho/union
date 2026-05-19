//! Per-client session: TLS handshake → PSK challenge → message loop.

use std::sync::Arc;

use union_tls::psk::{hmac_psk, verify_psk};
use protocol::{read_message, write_message, Message, ProtoError, PROTOCOL_VERSION};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("protocol: {0}")]
    Protocol(#[from] ProtoError),
    #[error("auth failed")]
    AuthFailed,
    #[error("version mismatch (got {got}, expected {expected})")]
    VersionMismatch { got: u16, expected: u16 },
    #[error("unexpected message")]
    UnexpectedMessage,
}

/// Run the auth handshake from the server side.
///
/// Returns the negotiated hostname on success.
pub async fn server_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    psk: &[u8; 32],
) -> Result<String, HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hello = read_message(reader).await?;
    let Message::Hello {
        protocol_version,
        hostname,
    } = hello
    else {
        return Err(HandshakeError::UnexpectedMessage);
    };
    if protocol_version != PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            got: protocol_version,
            expected: PROTOCOL_VERSION,
        });
    }

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    write_message(writer, &Message::AuthChallenge { nonce }).await?;

    let resp = read_message(reader).await?;
    let Message::AuthResponse { mac } = resp else {
        return Err(HandshakeError::UnexpectedMessage);
    };
    if !verify_psk(psk, &nonce, &mac) {
        warn!(client = %hostname, "PSK mismatch");
        return Err(HandshakeError::AuthFailed);
    }
    write_message(writer, &Message::AuthOk).await?;
    info!(client = %hostname, "authenticated");
    Ok(hostname)
}

/// Run the auth handshake from the client side.
pub async fn client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    psk: &[u8; 32],
    hostname: &str,
) -> Result<(), HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_message(
        writer,
        &Message::Hello {
            protocol_version: PROTOCOL_VERSION,
            hostname: hostname.to_string(),
        },
    )
    .await?;
    let chal = read_message(reader).await?;
    let Message::AuthChallenge { nonce } = chal else {
        return Err(HandshakeError::UnexpectedMessage);
    };
    let mac = hmac_psk(psk, &nonce);
    write_message(writer, &Message::AuthResponse { mac }).await?;
    let ok = read_message(reader).await?;
    if !matches!(ok, Message::AuthOk) {
        return Err(HandshakeError::AuthFailed);
    }
    debug!("client handshake ok");
    Ok(())
}

/// Spawn a writer task that drains `rx` and writes frames to `writer`.
/// Designed for `Arc<Mutex<W>>` so multiple senders can share one connection.
pub fn spawn_writer<W>(
    writer: Arc<Mutex<W>>,
    mut rx: mpsc::UnboundedReceiver<Message>,
) -> tokio::task::JoinHandle<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut w = writer.lock().await;
            if let Err(e) = write_message(&mut *w, &msg).await {
                warn!("write failed, closing: {e}");
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use union_tls::cert::{fingerprint_sha256, generate_self_signed};
    use union_tls::psk::derive_psk_from_passphrase;
    use rustls::pki_types::ServerName;
    use tokio::io::split;
    use tokio::net::{TcpListener, TcpStream};

    /// Spin up a real TLS server + TLS client over a localhost socket, run
    /// the full PSK handshake from both sides, then exchange one message.
    #[tokio::test]
    async fn full_handshake_over_tls() {
        let pair = generate_self_signed("test.local").unwrap();
        let fp = fingerprint_sha256(&pair.cert_pem).unwrap();
        let psk = derive_psk_from_passphrase("hunter2");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor =
            union_tls::server_acceptor(&pair.cert_pem, &pair.key_pem).unwrap();

        let psk_srv = psk;
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(sock).await.unwrap();
            let (mut r, mut w) = split(tls);
            let host = server_handshake(&mut r, &mut w, &psk_srv).await.unwrap();
            assert_eq!(host, "client-A");
            // Send an EnterScreen as a smoke message.
            write_message(
                &mut w,
                &Message::EnterScreen { x: 50, y: 100 },
            )
            .await
            .unwrap();
        });

        let connector = union_tls::client_connect(fp);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sni = ServerName::try_from("test.local").unwrap();
        let tls = connector.connect(sni, tcp).await.unwrap();
        let (mut r, mut w) = split(tls);
        client_handshake(&mut r, &mut w, &psk, "client-A").await.unwrap();

        let msg = read_message(&mut r).await.unwrap();
        assert!(matches!(msg, Message::EnterScreen { x: 50, y: 100 }));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_psk_rejected_over_tls() {
        let pair = generate_self_signed("test.local").unwrap();
        let fp = fingerprint_sha256(&pair.cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor =
            union_tls::server_acceptor(&pair.cert_pem, &pair.key_pem).unwrap();
        let psk_srv = derive_psk_from_passphrase("correct");

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(sock).await.unwrap();
            let (mut r, mut w) = split(tls);
            server_handshake(&mut r, &mut w, &psk_srv).await
        });

        let connector = union_tls::client_connect(fp);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sni = ServerName::try_from("test.local").unwrap();
        let tls = connector.connect(sni, tcp).await.unwrap();
        let (mut r, mut w) = split(tls);
        let psk_cli = derive_psk_from_passphrase("wrong");
        let _ = client_handshake(&mut r, &mut w, &psk_cli, "client-A").await;

        let res = server.await.unwrap();
        assert!(matches!(res, Err(HandshakeError::AuthFailed)));
    }

    #[tokio::test]
    async fn version_mismatch_rejected() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(64 * 1024);
        let psk = derive_psk_from_passphrase("x");

        // Client side: send wrong version.
        let writer = tokio::spawn(async move {
            write_message(
                &mut a,
                &Message::Hello {
                    protocol_version: 99,
                    hostname: "x".into(),
                },
            )
            .await
            .unwrap();
        });
        let (mut br, mut bw) = split(&mut b);
        let res = server_handshake(&mut br, &mut bw, &psk).await;
        writer.await.unwrap();
        assert!(matches!(res, Err(HandshakeError::VersionMismatch { .. })));
    }
}
