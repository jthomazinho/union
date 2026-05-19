//! Periodic snapshot of server runtime state, dumped to a JSON file the
//! GUI tails. Atomic write (tmp + rename) so readers never see a half-
//! written buffer.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::time::{interval, Duration};

use crate::config::Position;
use crate::metrics;
use crate::state::{Focus, ServerState};

const WRITE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Serialize)]
struct StatusSnapshot {
    pid: u32,
    timestamp_unix: u64,
    fingerprint_hex: String,
    listening_on: String,
    virtual_desktop: (i32, i32, i32, i32),
    focus: FocusSnapshot,
    clients: Vec<ClientSnapshot>,
    metrics: metrics::Snapshot,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
enum FocusSnapshot {
    Local,
    Remote(String),
}

#[derive(Serialize)]
struct ClientSnapshot {
    hostname: String,
    position: String,
    screen: Option<(u32, u32)>,
}

pub fn status_path() -> PathBuf {
    config_dir().join("runtime").join("status.json")
}

fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("UNION_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(target_os = "windows") {
        if let Some(a) = std::env::var_os("APPDATA") {
            return PathBuf::from(a).join("Union");
        }
    }
    if cfg!(target_os = "macos") {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("Union");
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("union")
}

pub fn spawn_writer(
    state: ServerState,
    fingerprint_hex: String,
    listening_on: String,
    bounds: input_capture::VirtualBounds,
) -> tokio::task::JoinHandle<()> {
    let path = status_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let pid = std::process::id();
    let state = Arc::new(state);
    tokio::spawn(async move {
        let mut ticker = interval(WRITE_INTERVAL);
        loop {
            ticker.tick().await;
            let snap = build_snapshot(&state, &fingerprint_hex, &listening_on, bounds, pid).await;
            if let Err(e) = write_atomic(&path, &snap) {
                tracing::debug!("status write failed: {e}");
            }
        }
    })
}

async fn build_snapshot(
    state: &ServerState,
    fingerprint_hex: &str,
    listening_on: &str,
    bounds: input_capture::VirtualBounds,
    pid: u32,
) -> StatusSnapshot {
    let st = state.0.lock().await;
    let clients: Vec<ClientSnapshot> = st
        .order
        .iter()
        .filter_map(|id| st.clients.get(id))
        .map(|c| ClientSnapshot {
            hostname: c.hostname.clone(),
            position: position_str(c.position).to_string(),
            screen: c.screen,
        })
        .collect();
    let focus = match st.focus {
        Focus::Local => FocusSnapshot::Local,
        Focus::Remote { client_id, .. } => st
            .clients
            .get(&client_id)
            .map(|c| FocusSnapshot::Remote(c.hostname.clone()))
            .unwrap_or(FocusSnapshot::Local),
    };
    StatusSnapshot {
        pid,
        timestamp_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        fingerprint_hex: fingerprint_hex.to_string(),
        listening_on: listening_on.to_string(),
        virtual_desktop: (bounds.min_x, bounds.min_y, bounds.max_x, bounds.max_y),
        focus,
        clients,
        metrics: metrics::snapshot(),
    }
}

fn position_str(p: Position) -> &'static str {
    match p {
        Position::Left => "left",
        Position::Right => "right",
        Position::Above => "above",
        Position::Below => "below",
    }
}

fn write_atomic(path: &std::path::Path, snap: &StatusSnapshot) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(snap).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}
