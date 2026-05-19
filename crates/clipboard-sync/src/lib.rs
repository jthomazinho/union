//! Clipboard watcher + writer with a size limit (truncate + notify).

use std::time::Duration;

use protocol::CLIPBOARD_CHUNK_BYTES;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub const DEFAULT_LIMIT_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone)]
pub struct ClipboardPayload {
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
    pub mime: String,
    pub truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error("arboard: {0}")]
    Arboard(String),
}

/// Find a UTF-8 boundary at or below `limit`. Safe to use for `text/plain`.
fn truncate_utf8(s: &str, limit: usize) -> &str {
    if s.len() <= limit {
        return s;
    }
    let mut end = limit;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

/// Spawn a blocking watcher task. The task owns an `arboard::Clipboard`
/// (which cannot cross threads on some OSes), polls every 200ms, and emits
/// new `ClipboardPayload`s on `tx`. Returns the join handle.
pub fn spawn_watcher(
    limit_bytes: usize,
    tx: mpsc::UnboundedSender<ClipboardPayload>,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut clipboard = match arboard::Clipboard::new() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("clipboard init failed: {e}");
                return;
            }
        };
        let mut last_hash: Option<[u8; 32]> = None;
        loop {
            std::thread::sleep(POLL_INTERVAL);
            let text = match clipboard.get_text() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let raw = text.as_bytes();
            let raw_hash = sha256(raw);
            if last_hash == Some(raw_hash) {
                continue;
            }
            let (bytes, truncated) = if raw.len() > limit_bytes {
                let trimmed = truncate_utf8(&text, limit_bytes);
                if let Err(e) = notify_rust::Notification::new()
                    .summary("Clipboard truncado")
                    .body(&format!(
                        "Conteúdo de {} KB excedeu limite de {} KB; enviando truncado.",
                        raw.len() / 1024,
                        limit_bytes / 1024
                    ))
                    .show()
                {
                    tracing::debug!("notify failed: {e}");
                }
                (trimmed.as_bytes().to_vec(), true)
            } else {
                (raw.to_vec(), false)
            };
            let hash = sha256(&bytes);
            last_hash = Some(raw_hash);
            let payload = ClipboardPayload {
                hash,
                bytes,
                mime: "text/plain;charset=utf-8".into(),
                truncated,
            };
            if tx.send(payload).is_err() {
                return;
            }
        }
    })
}

/// Set the local clipboard from an assembled payload.
pub fn write_text(bytes: &[u8]) -> Result<(), ClipboardError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|e| ClipboardError::Arboard(format!("non-utf8 text: {e}")))?
        .to_string();
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(s))
        .map_err(|e| ClipboardError::Arboard(e.to_string()))
}

/// Split a payload into chunks for transmission.
pub fn chunk_payload(p: &ClipboardPayload) -> Vec<protocol::Message> {
    let total = p.bytes.len().div_ceil(CLIPBOARD_CHUNK_BYTES).max(1) as u16;
    p.bytes
        .chunks(CLIPBOARD_CHUNK_BYTES)
        .enumerate()
        .map(|(i, c)| protocol::Message::ClipboardData {
            hash: p.hash,
            chunk_index: i as u16,
            total_chunks: total,
            data: c.to_vec(),
        })
        .collect()
}

/// Reassemble chunks, validating final hash.
pub struct Reassembler {
    expected_hash: [u8; 32],
    chunks: Vec<Option<Vec<u8>>>,
}

impl Reassembler {
    pub fn new(expected_hash: [u8; 32], total: u16) -> Self {
        Self {
            expected_hash,
            chunks: vec![None; total as usize],
        }
    }
    pub fn push(&mut self, index: u16, data: Vec<u8>) -> Option<Vec<u8>> {
        if (index as usize) >= self.chunks.len() {
            return None;
        }
        self.chunks[index as usize] = Some(data);
        if self.chunks.iter().all(|c| c.is_some()) {
            let mut out = Vec::new();
            for c in self.chunks.iter().flatten() {
                out.extend_from_slice(c);
            }
            if sha256(&out) == self.expected_hash {
                return Some(out);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_respects_boundary() {
        // "é" is 2 bytes; limit=3 should yield "aé" (3 bytes).
        let s = "aéééé";
        assert_eq!(truncate_utf8(s, 3), "aé");
        assert_eq!(truncate_utf8(s, 4), "aé"); // 4 still <=, drops next "é"
        assert_eq!(truncate_utf8(s, 100), s);
    }

    #[test]
    fn chunking_and_reassembly() {
        let payload = ClipboardPayload {
            hash: sha256(b"hello world hello world"),
            bytes: b"hello world hello world".to_vec(),
            mime: "text/plain;charset=utf-8".into(),
            truncated: false,
        };
        let msgs = chunk_payload(&payload);
        assert!(!msgs.is_empty());
        let mut r = Reassembler::new(payload.hash, msgs.len() as u16);
        let mut result = None;
        for m in msgs {
            if let protocol::Message::ClipboardData {
                chunk_index, data, ..
            } = m
            {
                result = r.push(chunk_index, data);
            }
        }
        assert_eq!(result.as_deref(), Some(&payload.bytes[..]));
    }
}
