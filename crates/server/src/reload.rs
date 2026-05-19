//! Hot-reload of `server.toml`. Polls the file's mtime once a second; on
//! change, parses the new config and updates the live state. Fields that
//! can't be changed without restarting (bind, port, psk, cert_dir, hotkey)
//! are reported in a warning and otherwise left alone.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

use crate::config::{ClientLayout, Position, ServerConfig};
use crate::state::ServerState;
use crate::NOTIFY_FOCUS;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub type LayoutMap = std::collections::HashMap<String, ClientLayout>;

pub fn spawn(
    path: PathBuf,
    state: ServerState,
    layout: Arc<RwLock<LayoutMap>>,
    initial: ServerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_mtime = mtime(&path);
        let mut last_cfg = initial;
        let mut ticker = interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let m = mtime(&path);
            if m == last_mtime {
                continue;
            }
            last_mtime = m;
            let new_cfg = match crate::config::load(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("config reload: parse failed, keeping previous: {e}");
                    continue;
                }
            };
            apply_diff(&last_cfg, &new_cfg, &state, &layout).await;
            last_cfg = new_cfg;
        }
    })
}

fn mtime(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

async fn apply_diff(
    old: &ServerConfig,
    new: &ServerConfig,
    state: &ServerState,
    layout: &Arc<RwLock<LayoutMap>>,
) {
    if old.notify_on_focus != new.notify_on_focus {
        NOTIFY_FOCUS.store(new.notify_on_focus, Ordering::Release);
        tracing::info!("config reload: notify_on_focus = {}", new.notify_on_focus);
    }

    // Restart-required fields: warn and keep old behaviour.
    if old.port != new.port
        || old.bind != new.bind
        || old.psk != new.psk
        || old.cert_dir != new.cert_dir
    {
        tracing::warn!("config reload: bind/port/psk/cert_dir change ignored (requires restart)");
    }
    if old.hotkey.cycle_forward_key != new.hotkey.cycle_forward_key
        || old.hotkey.cycle_backward_key != new.hotkey.cycle_backward_key
        || old.hotkey.require_ctrl != new.hotkey.require_ctrl
        || old.hotkey.require_alt != new.hotkey.require_alt
        || old.hotkey.require_meta != new.hotkey.require_meta
    {
        tracing::warn!("config reload: hotkey change ignored (requires restart)");
    }

    if !layout_equal(&old.layout, &new.layout) {
        {
            let mut w = layout.write().await;
            *w = new.layout.clone();
        }
        apply_layout_to_connected(state, &new.layout).await;
        tracing::info!(
            "config reload: layout updated ({} entries)",
            new.layout.len()
        );
    }
}

fn layout_equal(a: &LayoutMap, b: &LayoutMap) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .all(|(k, v)| b.get(k).map(|e| e.position == v.position).unwrap_or(false))
}

async fn apply_layout_to_connected(state: &ServerState, layout: &LayoutMap) {
    let mut st = state.0.lock().await;
    let updates: Vec<(crate::state::ClientId, Position)> = st
        .clients
        .iter()
        .filter_map(|(id, c)| {
            let new_pos = layout
                .get(&c.hostname)
                .map(|l| l.position)
                .unwrap_or(Position::Right);
            (new_pos != c.position).then_some((*id, new_pos))
        })
        .collect();
    for (id, pos) in updates {
        if let Some(c) = st.clients.get_mut(&id) {
            tracing::info!(client = %c.hostname, ?pos, "config reload: position updated");
            c.position = pos;
        }
    }
}
