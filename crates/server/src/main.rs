mod auth_throttle;
mod cert_store;
mod config;
mod ipc;
mod metrics;
mod reload;
mod state;
mod status;

use union_session as session;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use auth_throttle::AuthThrottle;
use clap::Parser;
use clipboard_sync::{chunk_payload, offer_for, spawn_watcher, ClipboardPayload};
use config::ServerConfig;
use input_capture::{start_capture, CaptureControl, CaptureEvent, HotkeyMatch};
use protocol::{Edge, Message};
use state::{Focus, ServerState};
use tokio::io::split;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};
use union_tls::psk::derive_psk_from_passphrase;

const AUTOSTART_LABEL: &str = "dev.union.server";

#[derive(Parser)]
#[command(name = "union-server", version)]
struct Cli {
    /// Path to server.toml config.
    #[arg(short, long)]
    config: PathBuf,
    /// Register this binary + config as a per-user auto-start service
    /// (systemd user unit on Linux, LaunchAgent on macOS, HKCU Run on
    /// Windows), then exit without running the daemon.
    #[arg(long)]
    install_autostart: bool,
    /// Remove the auto-start entry installed by `--install-autostart`.
    #[arg(long)]
    uninstall_autostart: bool,
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
    let cfg: ServerConfig = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;

    let hostname = hostname_default();
    let (cert_pair, fp) = cert_store::load_or_generate(&cfg.cert_dir, &hostname)?;
    let fp_hex = hex::encode(fp);
    println!("==> share this fingerprint with each client: {fp_hex}");

    // mDNS advertisement: clients with `discover = true` find us by service
    // type and pick up the pinning fingerprint from the TXT record, so the
    // manual copy step from the log line above becomes optional.
    let _mdns = match register_mdns(&hostname, cfg.port, &fp_hex) {
        Ok(d) => Some(d),
        Err(e) => {
            warn!("mDNS advertise failed: {e} (clients with `discover = true` won't find us)");
            None
        }
    };

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
                let bytes = payload.bytes.len() as u64;
                match payload.kind {
                    clipboard_sync::PayloadKind::Text => {
                        metrics::inc(&metrics::CLIPBOARD_TEXT_BYTES, bytes);
                    }
                    clipboard_sync::PayloadKind::Image { .. } => {
                        metrics::inc(&metrics::CLIPBOARD_IMAGE_BYTES, bytes);
                    }
                }
                let offer = offer_for(&payload);
                let chunks = chunk_payload(&payload);
                let st = state.0.lock().await;
                for c in st.clients.values() {
                    c.send_compat(offer.clone());
                    for ch in &chunks {
                        c.send_compat(ch.clone());
                    }
                }
            }
        });
    }

    let hotkey_match = HotkeyMatch {
        cycle_forward_key: cfg.hotkey.cycle_forward_key,
        cycle_backward_key: cfg.hotkey.cycle_backward_key,
        require_ctrl: cfg.hotkey.require_ctrl,
        require_alt: cfg.hotkey.require_alt,
        require_meta: cfg.hotkey.require_meta,
    };

    // Input capture → routing loop.
    let mut capture_handle = match start_capture(hotkey_match) {
        Ok(h) => h,
        Err(e) => {
            error!("input capture init failed: {e} — server will still relay clipboard");
            return relay_only_mode(state, acceptor, psk, cfg).await;
        }
    };
    let capture_control = capture_handle.control.clone();
    let bounds =
        input_capture::virtual_bounds().unwrap_or_else(input_capture::VirtualBounds::fallback);
    info!(
        "virtual desktop: {}x{} (origin {},{})",
        bounds.width(),
        bounds.height(),
        bounds.min_x,
        bounds.min_y
    );

    let layout = Arc::new(tokio::sync::RwLock::new(cfg.layout.clone()));
    let throttle = AuthThrottle::new();
    let _reload_task = reload::spawn(
        cli.config.clone(),
        state.clone(),
        layout.clone(),
        cfg.clone(),
    );
    NOTIFY_FOCUS.store(cfg.notify_on_focus, std::sync::atomic::Ordering::Release);
    OVERLAY_FOCUS.store(cfg.overlay_on_focus, std::sync::atomic::Ordering::Release);

    if cfg.release_focus_on_lock {
        let (lock_tx, mut lock_rx) =
            tokio::sync::mpsc::unbounded_channel::<union_lock_watch::LockState>();
        if let Err(e) = union_lock_watch::spawn(move |s| {
            let _ = lock_tx.send(s);
        }) {
            warn!("lock-watch failed to start: {e}");
        }
        let state_lock = state.clone();
        let control_lock = capture_control.clone();
        tokio::spawn(async move {
            while let Some(s) = lock_rx.recv().await {
                if matches!(s, union_lock_watch::LockState::Locked) {
                    info!("screen locked — forcing focus back to local");
                    return_to_local(&state_lock, &control_lock).await;
                }
            }
        });
    }
    let state_cap = state.clone();
    let cfg_cap = cfg.clone();
    let control_for_loop = capture_control.clone();
    tokio::spawn(async move {
        routing_loop(
            state_cap,
            &mut capture_handle,
            cfg_cap,
            control_for_loop,
            bounds,
        )
        .await;
    });

    // Accept loop.
    let bind_addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("listening on {bind_addr}");
    let ipc_token = ipc::random_token();
    let ipc_handle = ipc::spawn(state.clone(), ipc_token).await.ok();
    let _status_writer = status::spawn_writer(
        state.clone(),
        fp_hex.clone(),
        bind_addr.clone(),
        bounds,
        ipc_handle.as_ref().map(|h| h.addr.clone()),
        ipc_token,
    );
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
        let control = capture_control.clone();
        let layout = layout.clone();
        let throttle = throttle.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_client(sock, peer, acceptor, psk, state, control, layout, throttle).await
            {
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
    let dummy_control = CaptureControl::dummy();
    let layout = Arc::new(tokio::sync::RwLock::new(cfg.layout.clone()));
    let throttle = AuthThrottle::new();
    let bind_addr = format!("{}:{}", cfg.bind, cfg.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("listening on {bind_addr} (relay-only, no input capture)");
    loop {
        let (sock, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let psk = psk.clone();
        let state = state.clone();
        let control = dummy_control.clone();
        let layout = layout.clone();
        let throttle = throttle.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_client(sock, peer, acceptor, psk, state, control, layout, throttle).await
            {
                warn!(peer = %peer, "client session ended: {e}");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_client(
    sock: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    psk: Arc<[u8; 32]>,
    state: ServerState,
    control: CaptureControl,
    layout: Arc<tokio::sync::RwLock<reload::LayoutMap>>,
    throttle: AuthThrottle,
) -> anyhow::Result<()> {
    if let Some(remaining) = throttle.blocked(peer.ip()).await {
        warn!(peer = %peer, ?remaining, "auth throttled; dropping connection");
        return Err(anyhow::anyhow!("peer rate-limited"));
    }

    let tls = match tokio::time::timeout(protocol::HANDSHAKE_TIMEOUT, acceptor.accept(sock)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            throttle.record_failure(peer.ip()).await;
            return Err(e.into());
        }
        Err(_) => {
            throttle.record_failure(peer.ip()).await;
            return Err(anyhow::anyhow!("TLS handshake timeout"));
        }
    };
    let (mut reader, writer) = split(tls);
    let writer = Arc::new(Mutex::new(writer));

    let handshake = match tokio::time::timeout(protocol::HANDSHAKE_TIMEOUT, async {
        session::server_handshake(&mut reader, &mut *writer.lock().await, &psk).await
    })
    .await
    {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            throttle.record_failure(peer.ip()).await;
            return Err(e.into());
        }
        Err(_) => {
            throttle.record_failure(peer.ip()).await;
            return Err(anyhow::anyhow!("auth handshake timeout"));
        }
    };
    let hostname = handshake.hostname;
    let proto_version = handshake.peer_version;
    throttle.record_success(peer.ip()).await;
    metrics::inc(&metrics::SESSIONS_OPENED, 1);

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
    session::spawn_writer(writer.clone(), out_rx);
    let heartbeat = session::spawn_heartbeat(out_tx.clone());

    let position = layout
        .read()
        .await
        .get(&hostname)
        .map(|l| l.position)
        .unwrap_or(config::Position::Right);

    let id = state.alloc_id().await;
    state
        .add_client(state::ConnectedClient {
            id,
            hostname: hostname.clone(),
            screen: None,
            outbox: out_tx.clone(),
            position,
            proto_version,
        })
        .await;
    info!(peer = %peer, client = %hostname, id, ?position, proto_version, "client connected");

    let read_state = state.clone();
    let read_id = id;
    let mut reassembler: Option<([u8; 32], clipboard_sync::Reassembler)> = None;
    let result: anyhow::Result<()> = async {
        loop {
            let msg = session::read_with_idle_timeout(&mut reader).await?;
            match msg {
                Message::ScreenInfo { width, height } => {
                    let mut st = read_state.0.lock().await;
                    if let Some(c) = st.clients.get_mut(&read_id) {
                        c.screen = Some((width, height));
                    }
                }
                Message::ClipboardOffer {
                    hash,
                    mime,
                    size,
                    truncated,
                } => {
                    tracing::debug!(?hash, size, truncated, %mime, "got text offer from client");
                    reassembler = Some((hash, clipboard_sync::Reassembler::new_text(hash, 1)));
                    let st = read_state.0.lock().await;
                    let offer = Message::ClipboardOffer {
                        hash,
                        size,
                        truncated,
                        mime: mime.clone(),
                    };
                    for (cid, c) in st.clients.iter() {
                        if *cid != read_id {
                            c.send_compat(offer.clone());
                        }
                    }
                }
                Message::ClipboardImageOffer {
                    hash,
                    width,
                    height,
                    total_chunks,
                } => {
                    tracing::debug!(?hash, width, height, "got image offer from client");
                    reassembler = Some((
                        hash,
                        clipboard_sync::Reassembler::new_image(hash, total_chunks, width, height),
                    ));
                    let st = read_state.0.lock().await;
                    let offer = Message::ClipboardImageOffer {
                        hash,
                        width,
                        height,
                        total_chunks,
                    };
                    for (cid, c) in st.clients.iter() {
                        if *cid != read_id {
                            c.send_compat(offer.clone());
                        }
                    }
                }
                Message::ClipboardData {
                    hash,
                    chunk_index,
                    total_chunks,
                    data,
                } => {
                    let entry = reassembler.get_or_insert_with(|| {
                        (
                            hash,
                            clipboard_sync::Reassembler::new_text(hash, total_chunks),
                        )
                    });
                    if entry.0 != hash {
                        *entry = (
                            hash,
                            clipboard_sync::Reassembler::new_text(hash, total_chunks),
                        );
                    }
                    let forward = Message::ClipboardData {
                        hash,
                        chunk_index,
                        total_chunks,
                        data: data.clone(),
                    };
                    {
                        let st = read_state.0.lock().await;
                        for (cid, c) in st.clients.iter() {
                            if *cid != read_id {
                                c.send_compat(forward.clone());
                            }
                        }
                    }
                    if let Some(bytes) = entry.1.push(chunk_index, data) {
                        let kind = entry.1.kind.clone();
                        let write_result = match kind {
                            clipboard_sync::PayloadKind::Text => clipboard_sync::write_text(&bytes),
                            clipboard_sync::PayloadKind::Image { width, height } => {
                                clipboard_sync::write_image(bytes, width, height)
                            }
                        };
                        if let Err(e) = write_result {
                            warn!("clipboard write: {e}");
                        }
                        reassembler = None;
                    }
                }
                Message::Ping => {
                    let _ = out_tx.send(Message::Pong);
                }
                Message::RequestFocusReturn => {
                    info!(client = %hostname, "client requested focus return");
                    return_to_local(&read_state, &control).await;
                }
                _ => {
                    tracing::trace!("ignoring message from client: {msg:?}");
                }
            }
        }
    }
    .await;

    heartbeat.abort();
    state.remove_client(id).await;
    info!(client = %hostname, "disconnected");
    result
}

/// Pixels from the screen edge that count as "edge crossed". rdev coords
/// may be slightly inside the physical edge on hi-DPI macOS, so we use a
/// small band rather than == 0 / == width-1.
const EDGE_BAND: i32 = 2;

/// Toggled at startup from `cfg.notify_on_focus`. Read on every focus
/// change so we don't have to thread the flag through 4+ helpers.
static NOTIFY_FOCUS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Same idea for the transparent banner overlay (`cfg.overlay_on_focus`).
static OVERLAY_FOCUS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

async fn routing_loop(
    state: ServerState,
    capture: &mut input_capture::CaptureHandle,
    cfg: ServerConfig,
    control: CaptureControl,
    bounds: input_capture::VirtualBounds,
) {
    let hk = cfg.hotkey.clone();
    // Suppress repeated edge crossings while the cursor is still pinned
    // against an edge. Re-arm when it moves into the "safe zone".
    let mut edge_armed = true;

    while let Some(ev) = capture.events.recv().await {
        // Hotkey: always handled even when focus=Local. The capture layer
        // already swallowed the keypress at the OS level.
        if let CaptureEvent::Key {
            key,
            pressed,
            modifiers,
        } = ev
        {
            if pressed
                && (!hk.require_ctrl || modifiers.ctrl)
                && (!hk.require_alt || modifiers.alt)
                && (!hk.require_meta || modifiers.meta)
            {
                if key.0 == hk.cycle_forward_key {
                    hotkey_cycle(&state, &control, 1).await;
                    edge_armed = true;
                    continue;
                }
                if key.0 == hk.cycle_backward_key {
                    hotkey_cycle(&state, &control, -1).await;
                    edge_armed = true;
                    continue;
                }
            }
        }

        let focus = {
            let st = state.0.lock().await;
            st.focus
        };

        match focus {
            Focus::Local => {
                if let CaptureEvent::MouseMove { x, y, .. } = ev {
                    let crossed = detect_edge(x, y, bounds);
                    let in_safe = x > bounds.min_x + EDGE_BAND
                        && x < bounds.max_x - 1 - EDGE_BAND
                        && y > bounds.min_y + EDGE_BAND
                        && y < bounds.max_y - 1 - EDGE_BAND;
                    if let Some(edge) = crossed {
                        if edge_armed && cross_edge(&state, &control, edge).await {
                            edge_armed = false;
                            continue;
                        }
                    } else if in_safe {
                        edge_armed = true;
                    }
                }
                // Other events while local are not forwarded.
            }
            Focus::Remote { client_id, .. } => {
                let st = state.0.lock().await;
                let Some(c) = st.clients.get(&client_id) else {
                    continue;
                };
                let msg = match ev {
                    CaptureEvent::MouseMove { dx, dy, .. } => Message::MouseMove { dx, dy },
                    CaptureEvent::MouseButton { button, pressed } => {
                        Message::MouseButton { button, pressed }
                    }
                    CaptureEvent::MouseWheel { dx, dy } => Message::MouseWheel { dx, dy },
                    CaptureEvent::Key {
                        key,
                        pressed,
                        modifiers,
                    } => Message::KeyEvent {
                        key,
                        pressed,
                        modifiers,
                    },
                };
                c.send_compat(msg);
            }
        }
    }
}

fn detect_edge(x: i32, y: i32, bounds: input_capture::VirtualBounds) -> Option<Edge> {
    if x <= bounds.min_x + EDGE_BAND {
        Some(Edge::Left)
    } else if x >= bounds.max_x - 1 - EDGE_BAND {
        Some(Edge::Right)
    } else if y <= bounds.min_y + EDGE_BAND {
        Some(Edge::Top)
    } else if y >= bounds.max_y - 1 - EDGE_BAND {
        Some(Edge::Bottom)
    } else {
        None
    }
}

/// Edge-crossing: cursor on the server crossed `server_edge`; activate the
/// client that lives on the matching side, if any. Returns `true` if focus
/// actually changed.
async fn cross_edge(state: &ServerState, control: &CaptureControl, server_edge: Edge) -> bool {
    let target_position = state::position_for_server_edge(server_edge);
    let mut st = state.0.lock().await;
    let target_id = st
        .order
        .iter()
        .copied()
        .find(|id| st.clients.get(id).map(|c| c.position) == Some(target_position));
    let Some(client_id) = target_id else {
        return false;
    };
    let entry_edge = state::entry_edge_for_position(target_position);
    apply_focus_change(
        &mut st,
        control,
        Focus::Remote {
            client_id,
            entry_edge,
        },
    );
    true
}

/// Pop focus straight back to Local. Used when a client reports its cursor
/// reached the exit edge.
async fn return_to_local(state: &ServerState, control: &CaptureControl) {
    let mut st = state.0.lock().await;
    apply_focus_change(&mut st, control, Focus::Local);
}

/// Hotkey cycle: ignore 2D layout, just walk `order` linearly. Forward
/// arrows pick the next client (or Local after the last); backward arrows
/// mirror. Used by the `Ctrl+Alt+→` shortcut.
async fn hotkey_cycle(state: &ServerState, control: &CaptureControl, dir: i32) {
    let mut st = state.0.lock().await;
    if st.order.is_empty() {
        return;
    }
    // Default entry edge for hotkey-driven focus: pretend the cursor came
    // through the side opposite to the direction of travel.
    let assumed_entry = if dir > 0 { Edge::Left } else { Edge::Right };
    let new_focus = match st.focus {
        Focus::Local => {
            let id = if dir > 0 {
                st.order[0]
            } else {
                *st.order.last().unwrap()
            };
            Focus::Remote {
                client_id: id,
                entry_edge: assumed_entry,
            }
        }
        Focus::Remote { client_id, .. } => {
            let idx = st.order.iter().position(|&c| c == client_id);
            match idx {
                None => Focus::Local,
                Some(i) => {
                    let n = st.order.len() as i32;
                    let next = i as i32 + dir;
                    if next < 0 || next >= n {
                        Focus::Local
                    } else {
                        Focus::Remote {
                            client_id: st.order[next as usize],
                            entry_edge: assumed_entry,
                        }
                    }
                }
            }
        }
    };
    apply_focus_change(&mut st, control, new_focus);
}

/// Common tail of `cross_edge` and `hotkey_cycle`: tell the previous client
/// to release focus, tell the new one to receive it (with its exit edge),
/// flip capture mode, log.
fn apply_focus_change(
    st: &mut state::ServerStateInner,
    control: &CaptureControl,
    new_focus: Focus,
) {
    if let Focus::Remote {
        client_id: prev, ..
    } = st.focus
    {
        if let Some(c) = st.clients.get(&prev) {
            c.send_compat(Message::LeaveScreen);
        }
    }
    if let Focus::Remote {
        client_id: next,
        entry_edge,
    } = new_focus
    {
        if let Some(c) = st.clients.get(&next) {
            let (x, y) = c
                .screen
                .map(|(w, h)| place_cursor_inside_edge(w as i32, h as i32, entry_edge))
                .unwrap_or((100, 100));
            c.send_compat(Message::SetExitEdge { edge: entry_edge });
            c.send_compat(Message::EnterScreen { x, y });
        }
    }
    let new_label = match new_focus {
        Focus::Local => "local".to_string(),
        Focus::Remote { client_id, .. } => st
            .clients
            .get(&client_id)
            .map(|c| c.hostname.clone())
            .unwrap_or_else(|| format!("client #{client_id}")),
    };
    if NOTIFY_FOCUS.load(std::sync::atomic::Ordering::Acquire) {
        let label = new_label.clone();
        std::thread::spawn(move || {
            let _ = notify_rust::Notification::new()
                .summary("Union")
                .body(&format!("focus → {label}"))
                .timeout(notify_rust::Timeout::Milliseconds(1500))
                .show();
        });
    }
    if OVERLAY_FOCUS.load(std::sync::atomic::Ordering::Acquire) {
        spawn_overlay(format!("→ {new_label}"));
    }
    info!("focus → {:?}", new_focus);
    st.focus = new_focus;
    metrics::inc(&metrics::FOCUS_SWITCHES, 1);
    control.set_capturing(matches!(new_focus, Focus::Remote { .. }));
}

/// Place the cursor a few pixels inside `edge` so the first cursor movement
/// doesn't immediately re-trigger the exit edge.
fn place_cursor_inside_edge(w: i32, h: i32, edge: Edge) -> (i32, i32) {
    const INSET: i32 = 8;
    let cx = w / 2;
    let cy = h / 2;
    match edge {
        Edge::Left => (INSET, cy),
        Edge::Right => (w - INSET - 1, cy),
        Edge::Top => (cx, INSET),
        Edge::Bottom => (cx, h - INSET - 1),
    }
}

/// Drop guard that keeps the mDNS service registered for the daemon's lifetime.
struct MdnsHandle {
    daemon: mdns_sd::ServiceDaemon,
    fullname: String,
}

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

fn register_mdns(hostname: &str, port: u16, fp_hex: &str) -> anyhow::Result<MdnsHandle> {
    let daemon = mdns_sd::ServiceDaemon::new()?;
    let instance = sanitize_instance_name(hostname);
    let host_record = format!("{instance}.local.");
    let mut props = std::collections::HashMap::new();
    props.insert("fp".to_string(), fp_hex.to_string());
    props.insert("v".to_string(), protocol::PROTOCOL_VERSION.to_string());
    let info = mdns_sd::ServiceInfo::new(
        protocol::MDNS_SERVICE_TYPE,
        &instance,
        &host_record,
        "",
        port,
        Some(props),
    )?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.register(info)?;
    info!("mDNS: advertising {fullname} on port {port}");
    Ok(MdnsHandle { daemon, fullname })
}

fn sanitize_instance_name(host: &str) -> String {
    // mDNS instance names: stick to ASCII alnum / `-` for portability.
    let cleaned: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "union-server".into()
    } else {
        trimmed.to_string()
    }
}

/// Fire-and-forget spawn of the `union-overlay` binary sitting next to us.
/// Silently ignores any failure — the OS notification is still the canonical
/// path, the overlay is sugar on top.
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
