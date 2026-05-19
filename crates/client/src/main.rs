mod config;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::Parser;
use clipboard_sync::{
    chunk_payload, offer_for, spawn_watcher, ClipboardPayload, PayloadKind, Reassembler,
};
use config::ClientConfig;
use input_capture::{start_capture, CaptureControl, CaptureEvent, HotkeyMatch};
use input_inject::{spawn_injector_thread, InjectCmd};
use protocol::{Edge, Message};
use rustls::pki_types::ServerName;
use tokio::io::split;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use union_session as session;
use union_tls::psk::derive_psk_from_passphrase;

const AUTOSTART_LABEL: &str = "dev.union.client";

#[derive(Parser)]
#[command(name = "union-client", version)]
struct Cli {
    #[arg(short, long)]
    config: PathBuf,
    /// Register this binary + config as a per-user auto-start service.
    #[arg(long)]
    install_autostart: bool,
    /// Remove the auto-start entry installed by `--install-autostart`.
    #[arg(long)]
    uninstall_autostart: bool,
    /// Try the full TCP+TLS+PSK handshake against the configured server
    /// and exit (0 on success, 2 on fingerprint mismatch, 1 on any other
    /// failure). Used by the GUI's "Test connection" button.
    #[arg(long)]
    test_connection: bool,
}

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const EDGE_BAND: i32 = 2;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    if cli.uninstall_autostart {
        union_autostart::uninstall(AUTOSTART_LABEL)?;
        println!("removed auto-start entry {AUTOSTART_LABEL}");
        return Ok(());
    }
    if cli.install_autostart {
        let bin = std::env::current_exe()?;
        let cfg_abs = cli.config.canonicalize().with_context(|| {
            format!(
                "config file {} must exist before --install-autostart",
                cli.config.display()
            )
        })?;
        union_autostart::install(
            AUTOSTART_LABEL,
            &bin,
            &["--config", cfg_abs.to_str().unwrap()],
        )?;
        println!("installed auto-start entry {AUTOSTART_LABEL}");
        return Ok(());
    }

    let mut cfg: ClientConfig = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;
    if cfg.discover {
        let found = discover_server(Duration::from_secs(5)).await?;
        info!(
            "discovered server: {}:{} (fp={})",
            found.addr, found.port, found.fingerprint_hex
        );
        cfg.server_addr = found.addr;
        cfg.port = found.port;
        cfg.server_fingerprint_hex = found.fingerprint_hex;
    }
    let fp = parse_fingerprint(&cfg.server_fingerprint_hex)?;
    let psk = derive_psk_from_passphrase(&cfg.psk);

    if cli.test_connection {
        let code = test_connection(&cfg, &psk, fp).await;
        std::process::exit(code);
    }

    // The injector thread + capture thread outlive reconnects: they own
    // OS-level handles and can't be torn down cleanly from `rdev::grab`.
    let inject_tx = spawn_injector_thread();
    let capture = start_capture(HotkeyMatch::disabled())
        .map_err(|e| anyhow!("input capture init failed: {e}"))?;
    let bounds =
        input_capture::virtual_bounds().unwrap_or_else(input_capture::VirtualBounds::fallback);
    info!(
        "virtual desktop: {}x{} (origin {},{})",
        bounds.width(),
        bounds.height(),
        bounds.min_x,
        bounds.min_y
    );

    let (connector, observed) = union_tls::client_connect_with_observer(fp);

    // Shared state between the capture forwarder and the session reader:
    //  - focused: are we currently being controlled by the server?
    //  - exit_edge: which edge of our screen sends focus back?
    //  - return_tx: how to ask the server to give focus back.
    let session_state = Arc::new(SessionState::new());
    spawn_edge_watcher(
        capture.events,
        capture.control.clone(),
        session_state.clone(),
        bounds,
    );

    let mut backoff = BACKOFF_MIN;
    loop {
        match run_session(&cfg, &psk, &connector, &inject_tx, &session_state).await {
            Ok(()) => {
                info!("session ended cleanly; reconnecting");
                backoff = BACKOFF_MIN;
            }
            Err(e) => {
                if let Some(actual) = observed.get() {
                    if actual != fp {
                        report_fingerprint_mismatch(&cli.config, fp, actual)?;
                        std::process::exit(2);
                    }
                }
                warn!("session failed: {e}; retrying in {:?}", backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Persist the fingerprint the server is actually presenting and tell the
/// user how to act on it. Exiting (instead of retrying) is deliberate:
/// silently reconnecting against a mismatched cert would mask a real MITM.
fn report_fingerprint_mismatch(
    config_path: &Path,
    expected: [u8; 32],
    actual: [u8; 32],
) -> anyhow::Result<()> {
    let pending_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("pending_fingerprint.txt");
    let body = format!(
        "# Server presented a fingerprint that does NOT match the pinned one.\n\
         # Either the server's cert was rotated (re-install, new cert_dir) or\n\
         # someone is impersonating it. If you trust the new value, replace\n\
         # `server_fingerprint_hex` in {} and restart the client.\n\
         expected = \"{}\"\n\
         actual   = \"{}\"\n",
        config_path.display(),
        hex::encode(expected),
        hex::encode(actual)
    );
    std::fs::write(&pending_path, &body).ok();
    eprintln!("{body}");
    eprintln!("(wrote details to {})", pending_path.display());
    Ok(())
}

/// Shared state set by the session reader and read by the capture forwarder.
struct SessionState {
    inner: tokio::sync::Mutex<SessionStateInner>,
}

struct SessionStateInner {
    focused: bool,
    exit_edge: Option<Edge>,
    /// Sender that pushes a `RequestFocusReturn` into the current session's
    /// outbox. Replaced on every reconnect; `None` when no session is up.
    request_return: Option<mpsc::UnboundedSender<Message>>,
    /// Re-arm flag so we don't spam RequestFocusReturn while the cursor is
    /// pinned against the edge.
    armed: bool,
}

impl SessionState {
    fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(SessionStateInner {
                focused: false,
                exit_edge: None,
                request_return: None,
                armed: true,
            }),
        }
    }
}

fn spawn_edge_watcher(
    mut events: mpsc::UnboundedReceiver<CaptureEvent>,
    _control: CaptureControl,
    state: Arc<SessionState>,
    bounds: input_capture::VirtualBounds,
) {
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            let CaptureEvent::MouseMove { x, y, .. } = ev else {
                continue;
            };
            let mut s = state.inner.lock().await;
            if !s.focused {
                s.armed = true;
                continue;
            }
            let Some(edge) = s.exit_edge else { continue };
            let on_edge = match edge {
                Edge::Left => x <= bounds.min_x + EDGE_BAND,
                Edge::Right => x >= bounds.max_x - 1 - EDGE_BAND,
                Edge::Top => y <= bounds.min_y + EDGE_BAND,
                Edge::Bottom => y >= bounds.max_y - 1 - EDGE_BAND,
            };
            let in_safe_zone = match edge {
                Edge::Left => x > bounds.min_x + EDGE_BAND * 4,
                Edge::Right => x < bounds.max_x - 1 - EDGE_BAND * 4,
                Edge::Top => y > bounds.min_y + EDGE_BAND * 4,
                Edge::Bottom => y < bounds.max_y - 1 - EDGE_BAND * 4,
            };
            if on_edge && s.armed {
                if let Some(tx) = &s.request_return {
                    if tx.send(Message::RequestFocusReturn).is_ok() {
                        s.armed = false;
                        info!("cursor on exit edge {:?} → requesting focus return", edge);
                    }
                }
            } else if !s.armed && in_safe_zone {
                s.armed = true;
            }
        }
    });
}

async fn run_session(
    cfg: &ClientConfig,
    psk: &[u8; 32],
    connector: &TlsConnector,
    inject_tx: &std::sync::mpsc::Sender<InjectCmd>,
    session_state: &Arc<SessionState>,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", cfg.server_addr, cfg.port);
    info!("connecting to {addr}");
    let tcp = TcpStream::connect(&addr).await?;
    let sni =
        ServerName::try_from(cfg.sni.clone()).map_err(|_| anyhow!("invalid SNI: {}", cfg.sni))?;
    let tls = connector.connect(sni, tcp).await?;

    let (mut reader, writer) = split(tls);
    let writer = Arc::new(Mutex::new(writer));

    session::client_handshake(&mut reader, &mut *writer.lock().await, psk, &cfg.hostname).await?;
    info!("authenticated");

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
    session::spawn_writer(writer.clone(), out_rx);
    let heartbeat = session::spawn_heartbeat(out_tx.clone());

    {
        let mut s = session_state.inner.lock().await;
        s.focused = false;
        s.exit_edge = None;
        s.armed = true;
        s.request_return = Some(out_tx.clone());
    }

    let (sw, sh) = input_capture::primary_display_size().unwrap_or((1920, 1080));
    let _ = out_tx.send(Message::ScreenInfo {
        width: sw,
        height: sh,
    });

    let (cb_tx, mut cb_rx) = mpsc::unbounded_channel::<ClipboardPayload>();
    let cb_handle = spawn_watcher(cfg.clipboard_limit_bytes, cb_tx);
    let out_tx_cb = out_tx.clone();
    let cb_forward = tokio::spawn(async move {
        while let Some(payload) = cb_rx.recv().await {
            if out_tx_cb.send(offer_for(&payload)).is_err() {
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
    let result: anyhow::Result<()> = async {
        loop {
            let msg = session::read_with_idle_timeout(&mut reader).await?;
            match msg {
                Message::EnterScreen { x, y } => {
                    info!("→ entering screen at ({x},{y})");
                    let _ = inject_tx.send(InjectCmd::MoveAbs(x, y));
                    if cfg.notify_on_focus {
                        notify_focus_change("Union: foco recebido");
                    }
                    if cfg.overlay_on_focus {
                        spawn_overlay("foco recebido".into());
                    }
                    let mut s = session_state.inner.lock().await;
                    s.focused = true;
                    s.armed = true;
                }
                Message::LeaveScreen => {
                    info!("← leaving screen");
                    let _ = inject_tx.send(InjectCmd::ReleaseAllModifiers);
                    if cfg.notify_on_focus {
                        notify_focus_change("Union: foco liberado");
                    }
                    let mut s = session_state.inner.lock().await;
                    s.focused = false;
                    s.exit_edge = None;
                    s.armed = true;
                }
                Message::SetExitEdge { edge } => {
                    info!("exit edge set to {:?}", edge);
                    let mut s = session_state.inner.lock().await;
                    s.exit_edge = Some(edge);
                    s.armed = true;
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
                Message::KeyEvent {
                    key,
                    pressed,
                    modifiers,
                } => {
                    let _ = inject_tx.send(InjectCmd::Key {
                        key,
                        pressed,
                        modifiers,
                    });
                }
                Message::ClipboardOffer {
                    hash,
                    size: _,
                    truncated: _,
                    mime: _,
                } => {
                    reassembler = Some((hash, Reassembler::new_text(hash, 1)));
                }
                Message::ClipboardImageOffer {
                    hash,
                    width,
                    height,
                    total_chunks,
                } => {
                    reassembler = Some((
                        hash,
                        Reassembler::new_image(hash, total_chunks, width, height),
                    ));
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
                        let result = match entry.1.kind.clone() {
                            PayloadKind::Text => clipboard_sync::write_text(&bytes),
                            PayloadKind::Image { width, height } => {
                                clipboard_sync::write_image(bytes, width, height)
                            }
                        };
                        if let Err(e) = result {
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
    }
    .await;

    cb_forward.abort();
    cb_handle.abort();
    heartbeat.abort();
    // Defensive: always drop modifiers when a session ends — a crash mid-
    // keystroke would otherwise leave the local OS with Shift/Ctrl latched.
    let _ = inject_tx.send(InjectCmd::ReleaseAllModifiers);
    {
        let mut s = session_state.inner.lock().await;
        s.focused = false;
        s.exit_edge = None;
        s.request_return = None;
    }
    result
}

struct Discovered {
    addr: String,
    port: u16,
    fingerprint_hex: String,
}

async fn discover_server(timeout: Duration) -> anyhow::Result<Discovered> {
    let daemon = mdns_sd::ServiceDaemon::new()?;
    let receiver = daemon.browse(protocol::MDNS_SERVICE_TYPE)?;
    let deadline = tokio::time::Instant::now() + timeout;
    let result = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break Err(anyhow!("mDNS discovery timed out after {:?}", timeout));
        }
        let event = match tokio::time::timeout(remaining, async {
            tokio::task::block_in_place(|| receiver.recv())
        })
        .await
        {
            Ok(Ok(ev)) => ev,
            Ok(Err(e)) => break Err(anyhow!("mDNS channel closed: {e}")),
            Err(_) => break Err(anyhow!("mDNS discovery timed out after {:?}", timeout)),
        };
        if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
            let Some(addr) = info.get_addresses().iter().next().map(|a| a.to_string()) else {
                continue;
            };
            let port = info.get_port();
            let props = info.get_properties();
            let Some(fp) = props.get_property_val_str("fp").map(|s| s.to_string()) else {
                tracing::warn!("mDNS service missing `fp` TXT record; skipping");
                continue;
            };
            break Ok(Discovered {
                addr,
                port,
                fingerprint_hex: fp,
            });
        }
    };
    let _ = daemon.shutdown();
    result
}

/// Fire-and-forget OS notification so the user sees the focus change even
/// when the client window isn't visible.
fn notify_focus_change(body: &str) {
    let body = body.to_string();
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .summary("Union")
            .body(&body)
            .timeout(notify_rust::Timeout::Milliseconds(1500))
            .show();
    });
}

/// Spawn the `union-overlay` sidecar binary, if present, for a stronger
/// visual cue than the OS notification.
fn spawn_overlay(text: String) {
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(overlay_binary_name())));
    let Some(bin) = bin else {
        return;
    };
    if !bin.exists() {
        return;
    }
    std::thread::spawn(move || {
        let _ = std::process::Command::new(&bin)
            .arg("--text")
            .arg(&text)
            .spawn();
    });
}

fn overlay_binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "union-overlay.exe"
    } else {
        "union-overlay"
    }
}

/// Connect, run the full TLS + auth handshake, then drop the connection.
/// Used by `--test-connection` so a GUI / smoke test can validate config
/// without spinning up captures/clipboard.
async fn test_connection(cfg: &ClientConfig, psk: &[u8; 32], fp: [u8; 32]) -> i32 {
    let (connector, observed) = union_tls::client_connect_with_observer(fp);
    let addr = format!("{}:{}", cfg.server_addr, cfg.port);
    let attempt = async {
        let tcp = TcpStream::connect(&addr).await?;
        let sni = ServerName::try_from(cfg.sni.clone())
            .map_err(|_| anyhow!("invalid SNI: {}", cfg.sni))?;
        let tls = connector.connect(sni, tcp).await?;
        let (mut reader, writer) = split(tls);
        let writer = Arc::new(Mutex::new(writer));
        session::client_handshake(&mut reader, &mut *writer.lock().await, psk, &cfg.hostname)
            .await?;
        anyhow::Ok(())
    };
    match tokio::time::timeout(Duration::from_secs(5), attempt).await {
        Ok(Ok(())) => {
            println!("OK: handshake succeeded against {addr}");
            0
        }
        Ok(Err(e)) => {
            if let Some(actual) = observed.get() {
                if actual != fp {
                    eprintln!(
                        "FINGERPRINT MISMATCH: expected {} got {}",
                        hex::encode(fp),
                        hex::encode(actual)
                    );
                    return 2;
                }
            }
            eprintln!("FAILED: {e}");
            1
        }
        Err(_) => {
            eprintln!("TIMEOUT after 5s connecting to {addr}");
            1
        }
    }
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
