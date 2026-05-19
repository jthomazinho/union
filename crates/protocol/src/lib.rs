//! Wire protocol for Union.
//!
//! Frame format: `u32 BE length` followed by bincode-serialized [`Message`].
//! Max frame size is enforced at read time to bound memory.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_PORT: u16 = 24800;
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const CLIPBOARD_CHUNK_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub meta: bool,
}

/// Hardware-independent key code. We use HID Usage IDs from page 0x07
/// (Keyboard/Keypad) for portability across OSes. Each backend translates
/// this to its native keycode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCode(pub u16);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Handshake step 1 — client → server.
    Hello {
        protocol_version: u16,
        hostname: String,
    },
    /// Server → client, random 32 bytes for PSK proof.
    AuthChallenge { nonce: [u8; 32] },
    /// Client → server, HMAC-SHA256(psk, nonce).
    AuthResponse { mac: [u8; 32] },
    /// Server → client after successful auth.
    AuthOk,
    /// Either side → after auth: announce screen dimensions.
    ScreenInfo { width: u32, height: u32 },

    /// Server → client: cursor just entered this client's screen at (x, y).
    EnterScreen { x: i32, y: i32 },
    /// Server → client: cursor left this client's screen.
    LeaveScreen,

    /// Relative mouse motion (delta-x, delta-y). Used during remote control.
    MouseMove { dx: i32, dy: i32 },
    MouseButton { button: MouseButton, pressed: bool },
    MouseWheel { dx: i16, dy: i16 },

    KeyEvent {
        key: KeyCode,
        pressed: bool,
        modifiers: Modifiers,
    },

    /// Announce that source has a new clipboard payload available.
    ClipboardOffer {
        hash: [u8; 32],
        size: u32,
        truncated: bool,
        mime: String,
    },
    /// Receiver requests the data (after dedup check).
    ClipboardRequest { hash: [u8; 32] },
    /// Data chunk, 0-indexed. Receiver assembles in order, validates hash.
    ClipboardData {
        hash: [u8; 32],
        chunk_index: u16,
        total_chunks: u16,
        data: Vec<u8>,
    },

    /// Keepalive; either side may send.
    Ping,
    Pong,
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(#[from] bincode::Error),
    #[error("frame too large: {0} > {max}", max = MAX_FRAME_BYTES)]
    FrameTooLarge(usize),
    #[error("peer closed before frame complete")]
    PeerClosed,
}

/// Write a single message as a length-prefixed bincode frame.
pub async fn write_message<W>(w: &mut W, msg: &Message) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
{
    let payload = bincode::serialize(msg)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge(payload.len()));
    }
    let len = (payload.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&payload).await?;
    Ok(())
}

/// Read one length-prefixed bincode frame. Bounded by [`MAX_FRAME_BYTES`].
pub async fn read_message<R>(r: &mut R) -> Result<Message, ProtoError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtoError::PeerClosed
        } else {
            ProtoError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(bincode::deserialize(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn roundtrip(msg: Message) -> Message {
        let (mut a, mut b) = duplex(64 * 1024);
        let m_clone = msg.clone();
        let writer = tokio::spawn(async move {
            write_message(&mut a, &m_clone).await.unwrap();
        });
        let received = read_message(&mut b).await.unwrap();
        writer.await.unwrap();
        received
    }

    #[tokio::test]
    async fn hello_roundtrip() {
        let m = Message::Hello {
            protocol_version: PROTOCOL_VERSION,
            hostname: "macbook.local".into(),
        };
        assert_eq!(roundtrip(m.clone()).await, m);
    }

    #[tokio::test]
    async fn mouse_move_roundtrip() {
        let m = Message::MouseMove { dx: -7, dy: 12 };
        assert_eq!(roundtrip(m.clone()).await, m);
    }

    #[tokio::test]
    async fn key_event_roundtrip() {
        let m = Message::KeyEvent {
            key: KeyCode(0x04),
            pressed: true,
            modifiers: Modifiers {
                shift: true,
                ctrl: false,
                alt: false,
                meta: false,
            },
        };
        assert_eq!(roundtrip(m.clone()).await, m);
    }

    #[tokio::test]
    async fn clipboard_offer_roundtrip() {
        let m = Message::ClipboardOffer {
            hash: [1u8; 32],
            size: 42,
            truncated: false,
            mime: "text/plain;charset=utf-8".into(),
        };
        assert_eq!(roundtrip(m.clone()).await, m);
    }

    #[tokio::test]
    async fn rejects_oversize_frame() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let err = read_message(&mut reader).await.unwrap_err();
        assert!(matches!(err, ProtoError::FrameTooLarge(_)));
    }
}
