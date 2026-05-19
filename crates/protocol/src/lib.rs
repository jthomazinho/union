//! Wire protocol for Union.
//!
//! Frame format: `u32 BE length` followed by bincode-serialized [`Message`].
//! Max frame size is enforced at read time to bound memory.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 2;
/// Oldest peer protocol version this build still accepts. Clients <
/// MIN_PROTOCOL_VERSION are rejected with a `VersionMismatch`. Newer ones
/// downgrade gracefully — the server simply withholds variants that didn't
/// exist when their version shipped.
pub const MIN_PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_PORT: u16 = 24800;
/// mDNS service type used by [`union-server`] to advertise itself.
pub const MDNS_SERVICE_TYPE: &str = "_union._tcp.local.";
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const CLIPBOARD_CHUNK_BYTES: usize = 32 * 1024;
/// Hard ceiling on image clipboard payloads (RGBA8); above this we drop and notify.
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

// Heartbeat: each side emits a Ping at this cadence, expects any frame
// (Pong, MouseMove, etc.) within READ_IDLE_TIMEOUT, else assumes the peer
// is gone and tears down the session.
pub const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
pub const READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Upper bound on how long the server waits for the initial Hello before
/// dropping a TLS peer.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Which physical edge of a screen a cursor crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}

impl Edge {
    pub const fn opposite(self) -> Edge {
        match self {
            Edge::Left => Edge::Right,
            Edge::Right => Edge::Left,
            Edge::Top => Edge::Bottom,
            Edge::Bottom => Edge::Top,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Handshake step 1 — client → server.
    Hello {
        protocol_version: u16,
        hostname: String,
    },
    /// Server → client, random 32 bytes for PSK proof.
    AuthChallenge {
        nonce: [u8; 32],
    },
    /// Client → server, HMAC-SHA256(psk, nonce).
    AuthResponse {
        mac: [u8; 32],
    },
    /// Server → client after successful auth.
    AuthOk,
    /// Either side → after auth: announce screen dimensions.
    ScreenInfo {
        width: u32,
        height: u32,
    },

    /// Server → client: cursor just entered this client's screen at (x, y).
    EnterScreen {
        x: i32,
        y: i32,
    },
    /// Server → client: cursor left this client's screen.
    LeaveScreen,

    /// Relative mouse motion (delta-x, delta-y). Used during remote control.
    MouseMove {
        dx: i32,
        dy: i32,
    },
    MouseButton {
        button: MouseButton,
        pressed: bool,
    },
    MouseWheel {
        dx: i16,
        dy: i16,
    },

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
    ClipboardRequest {
        hash: [u8; 32],
    },
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

    // ---- v2 additions ----
    /// Server → client: image clipboard ahead. Data arrives as `ClipboardData`
    /// frames keyed by `hash`; payload is raw RGBA8 of size `width*height*4`.
    ClipboardImageOffer {
        hash: [u8; 32],
        width: u32,
        height: u32,
        total_chunks: u16,
    },
    /// Server → client, on focus enter: which edge of the client's screen
    /// the cursor should "exit through" to return focus to the server.
    SetExitEdge {
        edge: Edge,
    },
    /// Client → server: cursor reached the configured exit edge; please pop
    /// focus back to the server (or to the next client in the chain).
    RequestFocusReturn,
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

    /// Property-style fuzz: feed `read_message` a few thousand random byte
    /// buffers and assert it never panics — just returns Err. Catches
    /// out-of-bounds reads, integer overflows, and bincode bugs in our
    /// derive surface area.
    #[tokio::test]
    async fn read_message_never_panics_on_garbage() {
        use rand::{Rng, SeedableRng};
        // Seed deterministically so failures are reproducible. Change the
        // seed to rotate the input corpus.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..2000 {
            let len = rng.gen_range(0..=1024);
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf[..]);
            let (mut w, mut r) = duplex(64 * 1024);
            w.write_all(&buf).await.unwrap();
            drop(w); // signal EOF
                     // We only care that this does not panic — the result can be
                     // anything (Ok for a lucky valid bincode, Err for the usual case).
            let _ = read_message(&mut r).await;
        }
    }

    /// Specific shapes the fuzz might miss but bite in practice: a valid
    /// length prefix followed by truncated payload.
    #[tokio::test]
    async fn truncated_payload_errors_cleanly() {
        let (mut w, mut r) = duplex(64 * 1024);
        // claim 100 bytes, send 10
        w.write_all(&100u32.to_be_bytes()).await.unwrap();
        w.write_all(&[0u8; 10]).await.unwrap();
        drop(w);
        let err = read_message(&mut r).await.unwrap_err();
        assert!(matches!(err, ProtoError::Io(_) | ProtoError::PeerClosed));
    }
}
