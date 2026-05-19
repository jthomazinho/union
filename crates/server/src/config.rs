use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    /// Hotkey to cycle focus forward through clients (Ctrl+Alt+Right by
    /// default — for MVP, edge-crossing detection is future work).
    #[serde(default)]
    pub hotkey: HotkeyConfig,
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
    dirs_home()
        .join(".config")
        .join("union")
        .join("certs")
}
fn default_clipboard_limit() -> usize {
    clipboard_sync::DEFAULT_LIMIT_BYTES
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
