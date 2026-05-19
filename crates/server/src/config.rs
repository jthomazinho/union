use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where a client sits relative to the server's screen. Edge-crossing of the
/// server's right edge goes to a `Right` client; left edge → `Left`; top
/// → `Above`; bottom → `Below`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Position {
    Left,
    Right,
    Above,
    Below,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientLayout {
    pub position: Position,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// TCP port to listen on.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Bind address (default 0.0.0.0 = all interfaces).
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Pre-shared passphrase. Client must use the same.
    pub psk: String,
    /// Where to store the auto-generated TLS cert + key (PEM). Created if
    /// missing on first run.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    /// Max clipboard payload in bytes; larger payloads are truncated with a
    /// notification.
    #[serde(default = "default_clipboard_limit")]
    pub clipboard_limit_bytes: usize,
    /// Hotkey to cycle focus through clients linearly (in connect order).
    #[serde(default)]
    pub hotkey: HotkeyConfig,
    /// Show an OS notification whenever focus moves to/from a client.
    #[serde(default = "default_true")]
    pub notify_on_focus: bool,
    /// Pop a transparent always-on-top banner ("UNION → hostname") on each
    /// focus change. Off by default — turn on for stronger visual feedback
    /// when the OS notification isn't enough.
    #[serde(default)]
    pub overlay_on_focus: bool,
    /// When the local screen locks, force focus back to the server. Prevents
    /// typing the lock-screen password into a remote machine by mistake.
    #[serde(default = "default_true")]
    pub release_focus_on_lock: bool,
    /// Optional 2D layout keyed by client hostname. Clients without an entry
    /// default to `right`.
    ///
    /// ```toml
    /// [layout.macbook]
    /// position = "right"
    /// [layout.workpc]
    /// position = "above"
    /// ```
    #[serde(default)]
    pub layout: HashMap<String, ClientLayout>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HotkeyConfig {
    /// HID Usage ID of the cycle-forward key. 0x4F = RightArrow.
    pub cycle_forward_key: u16,
    /// HID Usage ID of the cycle-backward key. 0x50 = LeftArrow.
    pub cycle_backward_key: u16,
    /// Required modifiers (must all be held).
    pub require_ctrl: bool,
    pub require_alt: bool,
    pub require_meta: bool,
}

impl Default for HotkeyConfig {
    fn default() -> Self {
        Self {
            cycle_forward_key: 0x4F,
            cycle_backward_key: 0x50,
            require_ctrl: true,
            require_alt: true,
            require_meta: false,
        }
    }
}

fn default_port() -> u16 {
    protocol::DEFAULT_PORT
}
fn default_bind() -> String {
    "0.0.0.0".into()
}
fn default_cert_dir() -> PathBuf {
    dirs_home().join(".config").join("union").join("certs")
}
fn default_clipboard_limit() -> usize {
    clipboard_sync::DEFAULT_LIMIT_BYTES
}
fn default_true() -> bool {
    true
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn load(path: &std::path::Path) -> anyhow::Result<ServerConfig> {
    let s = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&s)?)
}
