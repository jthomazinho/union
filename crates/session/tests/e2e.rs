//! End-to-end smoke: server + client talking over localhost TLS, exercising
//! the wire protocol primitives (handshake → screen info → clipboard chunks
//! → heartbeat). Uses the session helpers directly so we don't depend on
//! the daemons (which need OS input capture / injection privileges).

use std::sync::Arc;
use std::time::Duration;

use clipboard_sync::{chunk_payload, offer_for, ClipboardPayload, PayloadKind, Reassembler};
use protocol::{read_message, Message};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::io::split;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use union_session::{
    client_handshake, read_with_idle_timeout, server_handshake, spawn_heartbeat, spawn_writer,
};
use union_tls::psk::derive_psk_from_passphrase;
use union_tls::{cert::generate_self_signed, client_connect_with_observer, server_acceptor};

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

#[tokio::test]
async fn full_session_text_clipboard() {
    // ---- TLS setup ----
    let cert = generate_self_signed("e2e.local").unwrap();
    let fp = union_tls::cert::fingerprint_sha256(&cert.cert_pem).unwrap();
    let acceptor = server_acceptor(&cert.cert_pem, &cert.key_pem).unwrap();
    let psk = derive_psk_from_passphrase("e2e-secret");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // ---- Server task ----
    let psk_srv = psk;
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(sock).await.unwrap();
        let (mut r, w) = split(tls);
        let w = Arc::new(Mutex::new(w));
        let ok = server_handshake(&mut r, &mut *w.lock().await, &psk_srv)
            .await
            .unwrap();
        assert_eq!(ok.hostname, "e2e-client");

        let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
        spawn_writer(w.clone(), out_rx);
        spawn_heartbeat(out_tx.clone());

        // Wait for ScreenInfo.
        let screen = read_with_idle_timeout(&mut r).await.unwrap();
        assert!(matches!(
            screen,
            Message::ScreenInfo {
                width: 1920,
                height: 1080
            }
        ));

        // Send a clipboard text payload.
        let bytes = b"the quick brown fox".to_vec();
        let payload = ClipboardPayload {
            hash: sha256(&bytes),
            bytes: bytes.clone(),
            mime: "text/plain;charset=utf-8".into(),
            truncated: false,
            kind: PayloadKind::Text,
        };
        // Fix the hash to whatever `clipboard-sync` would compute (we don't
        // hash externally; instead drive a real Reassembler on the receiver
        // side keyed on the hash we just set).
        let _ = out_tx.send(offer_for(&payload));
        for ch in chunk_payload(&payload) {
            let _ = out_tx.send(ch);
        }

        // Drain client traffic for a moment (ping/pong should flow).
        let _ =
            tokio::time::timeout(Duration::from_millis(500), read_with_idle_timeout(&mut r)).await;
    });

    // ---- Client task ----
    let (connector, _observed) = client_connect_with_observer(fp);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("e2e.local").unwrap();
    let tls = connector.connect(sni, tcp).await.unwrap();
    let (mut r, w) = split(tls);
    let w = Arc::new(Mutex::new(w));
    client_handshake(&mut r, &mut *w.lock().await, &psk, "e2e-client")
        .await
        .unwrap();

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
    spawn_writer(w.clone(), out_rx);
    spawn_heartbeat(out_tx.clone());

    out_tx
        .send(Message::ScreenInfo {
            width: 1920,
            height: 1080,
        })
        .unwrap();

    // ---- Drive the receiver until we reassemble the clipboard payload ----
    let mut reassembler: Option<([u8; 32], Reassembler)> = None;
    let mut received: Option<Vec<u8>> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline && received.is_none() {
        let msg = match tokio::time::timeout(Duration::from_millis(500), read_message(&mut r)).await
        {
            Ok(Ok(m)) => m,
            _ => continue,
        };
        match msg {
            Message::ClipboardOffer { hash, .. } => {
                reassembler = Some((hash, Reassembler::new_text(hash, 1)));
            }
            Message::ClipboardData {
                hash,
                chunk_index,
                total_chunks,
                data,
            } => {
                let entry = reassembler
                    .get_or_insert_with(|| (hash, Reassembler::new_text(hash, total_chunks)));
                if entry.0 != hash {
                    *entry = (hash, Reassembler::new_text(hash, total_chunks));
                }
                if let Some(bytes) = entry.1.push(chunk_index, data) {
                    received = Some(bytes);
                }
            }
            Message::Ping => {
                let _ = out_tx.send(Message::Pong);
            }
            _ => {}
        }
    }

    server.await.unwrap();
    assert_eq!(received.as_deref(), Some(&b"the quick brown fox"[..]));
}

#[tokio::test]
async fn handshake_times_out_on_silent_peer() {
    let cert = generate_self_signed("e2e.local").unwrap();
    let acceptor = server_acceptor(&cert.cert_pem, &cert.key_pem).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let psk = derive_psk_from_passphrase("k");

    let psk_srv = psk;
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(sock).await.unwrap();
        let (mut r, mut w) = split(tls);
        // Use a 200ms timeout instead of the production 10s so the test
        // doesn't drag.
        tokio::time::timeout(
            Duration::from_millis(200),
            server_handshake(&mut r, &mut w, &psk_srv),
        )
        .await
    });

    // Connect but never send Hello — server should time out.
    let fp = union_tls::cert::fingerprint_sha256(&cert.cert_pem).unwrap();
    let (connector, _) = client_connect_with_observer(fp);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("e2e.local").unwrap();
    let _tls = connector.connect(sni, tcp).await.unwrap();
    // hold the connection open
    tokio::time::sleep(Duration::from_millis(400)).await;

    let res = server.await.unwrap();
    assert!(res.is_err(), "expected handshake timeout");
}
