mod config;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use union_session as session;
use union_tls::psk::derive_psk_from_passphrase;
use clap::Parser;
use clipboard_sync::{chunk_payload, spawn_watcher, ClipboardPayload, Reassembler};
use config::ClientConfig;
use input_inject::{spawn_injector_thread, InjectCmd};
use protocol::{read_message, Message};
use rustls::pki_types::ServerName;
use tokio::io::split;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "union-client", version)]
struct Cli {
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
    let cfg: ClientConfig = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;
    let fp = parse_fingerprint(&cfg.server_fingerprint_hex)?;
    let psk = derive_psk_from_passphrase(&cfg.psk);

    let connector = union_tls::client_connect(fp);
    let addr = format!("{}:{}", cfg.server_addr, cfg.port);
    info!("connecting to {addr}");
    let tcp = TcpStream::connect(&addr).await?;
    let sni = ServerName::try_from(cfg.sni.clone())
        .map_err(|_| anyhow!("invalid SNI: {}", cfg.sni))?;
    let tls = connector.connect(sni, tcp).await?;

    let (mut reader, writer) = split(tls);
    let writer = Arc::new(Mutex::new(writer));

    session::client_handshake(
        &mut reader,
        &mut *writer.lock().await,
        &psk,
        &cfg.hostname,
    )
    .await?;
    info!("authenticated");

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
    session::spawn_writer(writer.clone(), out_rx);

    // Send local screen info.
    let (sw, sh) = local_screen_size();
    let _ = out_tx.send(Message::ScreenInfo { width: sw, height: sh });
    info!("local screen: {sw}x{sh}");

    // Spawn the input injector thread.
    let inject_tx = spawn_injector_thread();

    // Spawn clipboard watcher → server.
    let (cb_tx, mut cb_rx) = mpsc::unbounded_channel::<ClipboardPayload>();
    spawn_watcher(cfg.clipboard_limit_bytes, cb_tx);
    let out_tx_cb = out_tx.clone();
    tokio::spawn(async move {
        while let Some(payload) = cb_rx.recv().await {
            let offer = Message::ClipboardOffer {
                hash: payload.hash,
                size: payload.bytes.len() as u32,
                truncated: payload.truncated,
                mime: payload.mime.clone(),
            };
            if out_tx_cb.send(offer).is_err() {
                break;
            }
            for ch in chunk_payload(&payload) {
                if out_tx_cb.send(ch).is_err() {
                    break;
                }
            }
        }
    });

    let mut reassembler: Option<([u8; 32], Reassembler)> = None;

    loop {
        let msg = match read_message(&mut reader).await {
            Ok(m) => m,
            Err(e) => {
                warn!("read failed: {e}");
                break;
            }
        };
        match msg {
            Message::EnterScreen { x, y } => {
                info!("→ entering screen at ({x},{y})");
                let _ = inject_tx.send(InjectCmd::MoveAbs(x, y));
            }
            Message::LeaveScreen => {
                info!("← leaving screen");
            }
            Message::MouseMove { dx, dy } => {
                let _ = inject_tx.send(InjectCmd::MoveRel(dx, dy));
            }
            Message::MouseButton { button, pressed } => {
                let _ = inject_tx.send(InjectCmd::Button(button, pressed));
            }
            Message::MouseWheel { dx, dy } => {
                let _ = inject_tx.send(InjectCmd::Wheel(dx, dy));
            }
            Message::KeyEvent { key, pressed, modifiers } => {
                let _ = inject_tx.send(InjectCmd::Key { key, pressed, modifiers });
            }
            Message::ClipboardOffer { hash, size: _, truncated: _, mime: _ } => {
                // We can't know total chunks until first data arrives; start
                // empty and let push() resize via the total field there.
                reassembler = Some((hash, Reassembler::new(hash, 1)));
            }
            Message::ClipboardData {
                hash,
                chunk_index,
                total_chunks,
                data,
            } => {
                let entry = reassembler.get_or_insert_with(|| {
                    (hash, Reassembler::new(hash, total_chunks))
                });
                if entry.0 != hash {
                    *entry = (hash, Reassembler::new(hash, total_chunks));
                }
                if let Some(bytes) = entry.1.push(chunk_index, data) {
                    if let Err(e) = clipboard_sync::write_text(&bytes) {
                        warn!("clipboard write: {e}");
                    }
                    reassembler = None;
                }
            }
            Message::Ping => {
                let _ = out_tx.send(Message::Pong);
            }
            other => {
                tracing::trace!("ignoring {other:?}");
            }
        }
    }
    Ok(())
}

fn parse_fingerprint(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim().replace(':', ""))
        .map_err(|e| anyhow!("server_fingerprint_hex must be hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "expected 32-byte SHA-256 fingerprint, got {} bytes",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn local_screen_size() -> (u32, u32) {
    rdev::display_size()
        .map(|(w, h)| (w as u32, h as u32))
        .unwrap_or((1920, 1080))
}
