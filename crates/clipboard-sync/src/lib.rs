//! Clipboard watcher + writer with a size limit (truncate text, drop images
//! that exceed the cap).

use std::time::Duration;

use protocol::CLIPBOARD_CHUNK_BYTES;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub const DEFAULT_LIMIT_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// What kind of clipboard payload this is. Determines how the receiver
/// applies it locally.
#[derive(Debug, Clone)]
pub enum PayloadKind {
    Text,
    /// Raw RGBA8 bytes of size `width * height * 4`.
    Image {
        width: u32,
        height: u32,
    },
}

#[derive(Debug, Clone)]
pub struct ClipboardPayload {
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
    pub mime: String,
    pub truncated: bool,
    pub kind: PayloadKind,
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

fn image_hash(png_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"img-png:");
    h.update(png_bytes);
    h.finalize().into()
}

/// Encode an RGBA8 buffer as PNG bytes. Width/height must match `rgba.len() / 4`.
fn encode_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, ClipboardError> {
    let img = image::RgbaImage::from_raw(width, height, rgba.to_vec())
        .ok_or_else(|| ClipboardError::Arboard("rgba length mismatch".into()))?;
    let mut out = Vec::with_capacity(rgba.len() / 4);
    let encoder = image::codecs::png::PngEncoder::new_with_quality(
        &mut out,
        image::codecs::png::CompressionType::Default,
        image::codecs::png::FilterType::Adaptive,
    );
    image::ImageEncoder::write_image(
        encoder,
        img.as_raw(),
        width,
        height,
        image::ExtendedColorType::Rgba8,
    )
    .map_err(|e| ClipboardError::Arboard(format!("png encode: {e}")))?;
    Ok(out)
}

/// Decode a PNG byte stream into RGBA8.
fn decode_png(png_bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), ClipboardError> {
    let img = image::load_from_memory_with_format(png_bytes, image::ImageFormat::Png)
        .map_err(|e| ClipboardError::Arboard(format!("png decode: {e}")))?
        .into_rgba8();
    let (w, h) = img.dimensions();
    Ok((w, h, img.into_raw()))
}

/// Spawn a blocking watcher task. Owns an `arboard::Clipboard` (which can't
/// always cross threads) and polls every 200ms, emitting both text and image
/// changes.
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

            // Prefer image if present (some platforms report empty text when
            // the clipboard is image-only).
            if let Ok(img) = clipboard.get_image() {
                let raw = img.bytes.as_ref();
                let w = img.width as u32;
                let h = img.height as u32;
                let png = match encode_png(raw, w, h) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("png encode failed: {e}");
                        continue;
                    }
                };
                let hash = image_hash(&png);
                if last_hash == Some(hash) {
                    // not a new image; fall through to text check
                } else if png.len() > protocol::MAX_IMAGE_BYTES {
                    if let Err(e) = notify_rust::Notification::new()
                        .summary("Imagem do clipboard ignorada")
                        .body(&format!(
                            "PNG comprimido tem {} KB e excede o limite de {} KB.",
                            png.len() / 1024,
                            protocol::MAX_IMAGE_BYTES / 1024
                        ))
                        .show()
                    {
                        tracing::debug!("notify failed: {e}");
                    }
                    last_hash = Some(hash);
                    continue;
                } else {
                    let payload = ClipboardPayload {
                        hash,
                        bytes: png,
                        mime: "image/png".into(),
                        truncated: false,
                        kind: PayloadKind::Image {
                            width: w,
                            height: h,
                        },
                    };
                    last_hash = Some(hash);
                    if tx.send(payload).is_err() {
                        return;
                    }
                    continue;
                }
            }

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
                kind: PayloadKind::Text,
            };
            if tx.send(payload).is_err() {
                return;
            }
        }
    })
}

/// Set the local clipboard from an assembled text payload.
pub fn write_text(bytes: &[u8]) -> Result<(), ClipboardError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|e| ClipboardError::Arboard(format!("non-utf8 text: {e}")))?
        .to_string();
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(s))
        .map_err(|e| ClipboardError::Arboard(e.to_string()))
}

/// Set the local clipboard from an assembled image payload (PNG bytes).
///
/// `hint_width`/`hint_height` come from the Offer message and are informational;
/// the authoritative dimensions are decoded from the PNG header.
pub fn write_image(
    png_bytes: Vec<u8>,
    _hint_width: u32,
    _hint_height: u32,
) -> Result<(), ClipboardError> {
    let (w, h, rgba) = decode_png(&png_bytes)?;
    let img = arboard::ImageData {
        width: w as usize,
        height: h as usize,
        bytes: std::borrow::Cow::Owned(rgba),
    };
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_image(img))
        .map_err(|e| ClipboardError::Arboard(e.to_string()))
}

/// Split a payload into chunks for transmission. The receiver pairs them
/// with the preceding `ClipboardOffer` or `ClipboardImageOffer` by hash.
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

/// Build the appropriate Offer message for this payload.
pub fn offer_for(p: &ClipboardPayload) -> protocol::Message {
    match p.kind {
        PayloadKind::Text => protocol::Message::ClipboardOffer {
            hash: p.hash,
            size: p.bytes.len() as u32,
            truncated: p.truncated,
            mime: p.mime.clone(),
        },
        PayloadKind::Image { width, height } => {
            let total = p.bytes.len().div_ceil(CLIPBOARD_CHUNK_BYTES).max(1) as u16;
            protocol::Message::ClipboardImageOffer {
                hash: p.hash,
                width,
                height,
                total_chunks: total,
            }
        }
    }
}

/// Reassemble chunks, validating final hash. Caller knows the kind from the
/// preceding Offer message.
pub struct Reassembler {
    expected_hash: [u8; 32],
    chunks: Vec<Option<Vec<u8>>>,
    pub kind: PayloadKind,
}

impl Reassembler {
    pub fn new_text(expected_hash: [u8; 32], total: u16) -> Self {
        Self {
            expected_hash,
            chunks: vec![None; total as usize],
            kind: PayloadKind::Text,
        }
    }
    pub fn new_image(expected_hash: [u8; 32], total: u16, width: u32, height: u32) -> Self {
        Self {
            expected_hash,
            chunks: vec![None; total as usize],
            kind: PayloadKind::Image { width, height },
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
            let valid = match self.kind {
                PayloadKind::Text => sha256(&out) == self.expected_hash,
                PayloadKind::Image { .. } => image_hash(&out) == self.expected_hash,
            };
            if valid {
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
        let s = "aéééé";
        assert_eq!(truncate_utf8(s, 3), "aé");
        assert_eq!(truncate_utf8(s, 4), "aé");
        assert_eq!(truncate_utf8(s, 100), s);
    }

    #[test]
    fn chunking_and_reassembly() {
        let payload = ClipboardPayload {
            hash: sha256(b"hello world hello world"),
            bytes: b"hello world hello world".to_vec(),
            mime: "text/plain;charset=utf-8".into(),
            truncated: false,
            kind: PayloadKind::Text,
        };
        let msgs = chunk_payload(&payload);
        assert!(!msgs.is_empty());
        let mut r = Reassembler::new_text(payload.hash, msgs.len() as u16);
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

    #[test]
    fn image_png_round_trip() {
        let w = 4u32;
        let h = 3u32;
        let raw: Vec<u8> = (0..(w * h * 4) as u8).collect();
        let png = encode_png(&raw, w, h).unwrap();
        let (dw, dh, decoded) = decode_png(&png).unwrap();
        assert_eq!((dw, dh), (w, h));
        assert_eq!(decoded, raw);
    }

    #[test]
    fn image_chunking_and_reassembly() {
        let w = 4u32;
        let h = 3u32;
        let raw: Vec<u8> = (0..(w * h * 4) as u8).collect();
        let png = encode_png(&raw, w, h).unwrap();
        let payload = ClipboardPayload {
            hash: image_hash(&png),
            bytes: png.clone(),
            mime: "image/png".into(),
            truncated: false,
            kind: PayloadKind::Image {
                width: w,
                height: h,
            },
        };
        let msgs = chunk_payload(&payload);
        let mut r = Reassembler::new_image(payload.hash, msgs.len() as u16, w, h);
        let mut result = None;
        for m in msgs {
            if let protocol::Message::ClipboardData {
                chunk_index, data, ..
            } = m
            {
                result = r.push(chunk_index, data);
            }
        }
        assert_eq!(result.as_deref(), Some(&png[..]));
    }
}
