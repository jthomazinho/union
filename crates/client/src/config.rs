use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    /// Server address (hostname or IP). Ignored if `discover = true`.
    #[serde(default)]
    pub server_addr: String,
    /// Server port. Ignored if `discover = true`.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Logical name shown in the server's client list.
    pub hostname: String,
    /// Pre-shared passphrase. Must match the server's.
    pub psk: String,
    /// Hex-encoded SHA-256 of the server's leaf cert. Optional when
    /// `discover = true` — the fingerprint is picked up from the mDNS TXT
    /// record. Required otherwise.
    #[serde(default)]
    pub server_fingerprint_hex: String,
    /// Max size of clipboard payloads we ourselves originate (server-side
    /// limit is independent).
    #[serde(default = "default_clipboard_limit")]
    pub clipboard_limit_bytes: usize,
    /// SNI value sent in the TLS ClientHello. Cert is pinned so this can be
    /// anything; defaults to "union-server".
    #[serde(default = "default_sni")]
    pub sni: String,
    /// If true, ignore `server_addr` / `server_fingerprint_hex` and find the
    /// server via mDNS (service type `_union._tcp.local.`).
    #[serde(default)]
    pub discover: bool,
    /// Show an OS notification whenever focus arrives at or leaves this client.
    #[serde(default = "default_true")]
    pub notify_on_focus: bool,
    /// Pop a transparent always-on-top banner on each focus arrival.
    #[serde(default)]
    pub overlay_on_focus: bool,
    /// When this machine's screen locks, ask the server to take focus back.
    /// Useful so password entry doesn't end up on a different host.
    #[serde(default = "default_true")]
    pub release_focus_on_lock: bool,
}

fn default_true() -> bool {
    true
}

fn default_port() -> u16 {
    protocol::DEFAULT_PORT
}
fn default_clipboard_limit() -> usize {
    clipboard_sync::DEFAULT_LIMIT_BYTES
}
fn default_sni() -> String {
    "union-server".into()
}

pub fn load(path: &std::path::Path) -> anyhow::Result<ClientConfig> {
    let s = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&s)?)
}
