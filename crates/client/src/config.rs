use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    /// Server address (hostname or IP).
    pub server_addr: String,
    /// Server port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Logical name shown in the server's client list.
    pub hostname: String,
    /// Pre-shared passphrase. Must match the server's.
    pub psk: String,
    /// Hex-encoded SHA-256 of the server's leaf cert. Obtain on first run by
    /// reading the server's startup log line; pin in config thereafter.
    pub server_fingerprint_hex: String,
    /// Max size of clipboard payloads we ourselves originate (server-side
    /// limit is independent).
    #[serde(default = "default_clipboard_limit")]
    pub clipboard_limit_bytes: usize,
    /// SNI value sent in the TLS ClientHello. Cert is pinned so this can be
    /// anything; defaults to "union-server".
    #[serde(default = "default_sni")]
    pub sni: String,
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
