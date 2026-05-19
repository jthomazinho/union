mod cert_store;
mod config;
mod state;

use union_session as session;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use union_tls::psk::derive_psk_from_passphrase;
use clap::Parser;
use clipboard_sync::{chunk_payload, spawn_watcher, ClipboardPayload};
use config::ServerConfig;
use input_capture::{start_capture, CaptureEvent};
use protocol::{Message, MouseButton};
use state::{Focus, ServerState};
use tokio::io::split;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "union-server", version)]
struct Cli {
    /// Path to server.toml config.
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg: ServerConfig = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;

    let hostname = hostname_default();
    let (cert_pair, fp) = cert_store::load_or_generate(&cfg.cert_dir, &hostname)?;
    println!(
        "==> share this fingerprint with each client: {}",
        hex::encode(fp)
    );

    let acceptor = union_tls::server_acceptor(&cert_pair.cert_pem, &cert_pair.key_pem)?;
    let psk = Arc::new(derive_psk_from_passphrase(&cfg.psk));
    let state = ServerState::new();

    // Clipboard watcher → broadcast to all clients.
    let (cb_tx, mut cb_rx) = mpsc::unbounded_channel::<ClipboardPayload>();
    spawn_watcher(cfg.clipboard_limit_bytes, cb_tx);
    {
        let state = state.clone();
        tokio::spawn(async move {
            while let Some(payload) = cb_rx.recv().await {
                let offer = Message::ClipboardOffer {
                    hash: payload.hash,
                    size: payload.bytes.len() as u32,
                    truncated: payload.truncated,
                    mime: payload.mime.clone(),
                };
                let chunks = chunk_payload(&payload);
                let st = state.0.lock().await;
                for c in st.clients.values() {
                    let _ = c.outbox.send(offer.clone());
                    for ch in &chunks {
                        let _ = c.outbox.send(ch.clone());
                    }
                }
            }
        });
    }

    // Input capture → routing loop.
    let mut capture_handle = match start_capture() {
        Ok(h) => h,
        Err(e) => {
            error!("input capture init failed: {e} — server will still relay clipboard");
            // Fall back to relay-only mode: park forever.
            return relay_only_mode(state, acceptor, psk, cfg).await;
        }
    };
    let state_cap = state.clone();
    let cfg_cap = cfg.clone();
    tokio::spawn(async move {
        routing_loop(state_cap, &mut capture_handle, cfg_cap).await;
    });

    // Accept loop.
    let bind_addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("listening on {bind_addr}");
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let psk = psk.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, peer, acceptor, psk, state).await {
                warn!(peer = %peer, "client session ended: {e}");
            }
        });
    }
}

async fn relay_only_mode(
    state: ServerState,
    acceptor: tokio_rustls::TlsAcceptor,
    psk: Arc<[u8; 32]>,
    cfg: ServerConfig,
) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("listening on {bind_addr} (relay-only, no input capture)");
    loop {
        let (sock, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let psk = psk.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, peer, acceptor, psk, state).await {
                warn!(peer = %peer, "client session ended: {e}");
            }
        });
    }
}

async fn handle_client(
    sock: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    psk: Arc<[u8; 32]>,
    state: ServerState,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(sock).await?;
    let (mut reader, writer) = split(tls);
    let writer = Arc::new(Mutex::new(writer));

    let hostname = session::server_handshake(&mut reader, &mut *writer.lock().await, &psk).await?;

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
    session::spawn_writer(writer.clone(), out_rx);

    let id = state.alloc_id().await;
    state
        .add_client(state::ConnectedClient {
            id,
            hostname: hostname.clone(),
            screen: None,
            outbox: out_tx.clone(),
        })
        .await;
    info!(peer = %peer, client = %hostname, id, "client connected");

    let read_state = state.clone();
    let read_id = id;
    let mut reassembler: Option<(
        [u8; 32],
        clipboard_sync::Reassembler,
    )> = None;
    let result: anyhow::Result<()> = async {
        loop {
            let msg = protocol::read_message(&mut reader).await?;
            match msg {
                Message::ScreenInfo { width, height } => {
                    let mut st = read_state.0.lock().await;
                    if let Some(c) = st.clients.get_mut(&read_id) {
                        c.screen = Some((width, height));
                    }
                }
                Message::ClipboardOffer { hash, mime, size, truncated } => {
                    tracing::debug!(?hash, size, truncated, %mime, "got clipboard offer from client");
                    // Server-side: rebroadcast to other clients (excluding source).
                    let st = read_state.0.lock().await;
                    let offer = Message::ClipboardOffer { hash, size, truncated, mime: mime.clone() };
                    for (cid, c) in st.clients.iter() {
                        if *cid != read_id {
                            let _ = c.outbox.send(offer.clone());
                        }
                    }
                }
                Message::ClipboardData { hash, chunk_index, total_chunks, data } => {
                    let entry = reassembler.get_or_insert_with(|| {
                        (hash, clipboard_sync::Reassembler::new(hash, total_chunks))
                    });
                    if entry.0 != hash {
                        // New payload; restart.
                        *entry = (hash, clipboard_sync::Reassembler::new(hash, total_chunks));
                    }
                    if let Some(bytes) = entry.1.push(chunk_index, data.clone()) {
                        // Apply to local clipboard.
                        if let Err(e) = clipboard_sync::write_text(&bytes) {
                            warn!("clipboard write: {e}");
                        }
                        // Forward to other clients.
                        let forward = Message::ClipboardData { hash, chunk_index, total_chunks, data };
                        let st = read_state.0.lock().await;
                        for (cid, c) in st.clients.iter() {
                            if *cid != read_id {
                                let _ = c.outbox.send(forward.clone());
                            }
                        }
                        reassembler = None;
                    } else {
                        // Forward chunk as it arrives so other clients can stream.
                        let forward = Message::ClipboardData { hash, chunk_index, total_chunks, data };
                        let st = read_state.0.lock().await;
                        for (cid, c) in st.clients.iter() {
                            if *cid != read_id {
                                let _ = c.outbox.send(forward.clone());
                            }
                        }
                    }
                }
                Message::Ping => {
                    let _ = out_tx.send(Message::Pong);
                }
                _ => {
                    tracing::trace!("ignoring message from client: {msg:?}");
                }
            }
        }
    }
    .await;

    state.remove_client(id).await;
    info!(client = %hostname, "disconnected");
    result
}

async fn routing_loop(
    state: ServerState,
    capture: &mut input_capture::CaptureHandle,
    cfg: ServerConfig,
) {
    let hk = cfg.hotkey.clone();
    while let Some(ev) = capture.events.recv().await {
        // Intercept hotkey before forwarding anything.
        if let CaptureEvent::Key { key, pressed, modifiers } = ev {
            if pressed
                && (!hk.require_ctrl || modifiers.ctrl)
                && (!hk.require_alt || modifiers.alt)
                && (!hk.require_meta || modifiers.meta)
            {
                if key.0 == hk.cycle_forward_key {
                    cycle(&state, 1).await;
                    continue;
                }
                if key.0 == hk.cycle_backward_key {
                    cycle(&state, -1).await;
                    continue;
                }
            }
        }

        let st = state.0.lock().await;
        let Focus::Remote { client_id } = st.focus else { continue };
        let Some(c) = st.clients.get(&client_id) else { continue };
        let msg = match ev {
            CaptureEvent::MouseMove { dx, dy } => Message::MouseMove { dx, dy },
            CaptureEvent::MouseButton { button, pressed } => Message::MouseButton { button, pressed },
            CaptureEvent::MouseWheel { dx, dy } => Message::MouseWheel { dx, dy },
            CaptureEvent::Key { key, pressed, modifiers } => Message::KeyEvent { key, pressed, modifiers },
        };
        let _ = c.outbox.send(msg);
    }
}

async fn cycle(state: &ServerState, dir: i32) {
    let mut st = state.0.lock().await;
    if st.order.is_empty() {
        return;
    }
    let new_focus = match st.focus {
        Focus::Local => {
            if dir > 0 {
                Focus::Remote { client_id: st.order[0] }
            } else {
                Focus::Remote { client_id: *st.order.last().unwrap() }
            }
        }
        Focus::Remote { client_id } => {
            let idx = st.order.iter().position(|&c| c == client_id);
            match idx {
                None => Focus::Local,
                Some(i) => {
                    let n = st.order.len() as i32;
                    let next = i as i32 + dir;
                    if next < 0 || next >= n {
                        // Out of bounds → back to local.
                        Focus::Local
                    } else {
                        Focus::Remote { client_id: st.order[next as usize] }
                    }
                }
            }
        }
    };

    // Notify clients of focus changes.
    if let Focus::Remote { client_id: prev } = st.focus {
        if let Some(c) = st.clients.get(&prev) {
            let _ = c.outbox.send(Message::LeaveScreen);
        }
    }
    if let Focus::Remote { client_id: next } = new_focus {
        if let Some(c) = st.clients.get(&next) {
            // Place cursor at midpoint of the remote screen if known.
            let (x, y) = c
                .screen
                .map(|(w, h)| (w as i32 / 2, h as i32 / 2))
                .unwrap_or((100, 100));
            let _ = c.outbox.send(Message::EnterScreen { x, y });
        }
    }
    info!("focus → {:?}", new_focus);
    st.focus = new_focus;
    // Touch unused variable to satisfy compiler.
    let _ = MouseButton::Left;
}

fn hostname_default() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "union-server".to_string())
    })
}
