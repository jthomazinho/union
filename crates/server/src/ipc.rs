//! Local-only IPC for `union-send` to push files into the running daemon.
//!
//! Loopback-bound TCP socket (no TLS — same host) gated by a per-startup
//! random token written to the status.json. Once authenticated, the helper
//! streams a file as length-prefixed bincode frames; the daemon re-emits
//! it as `FileTransferOffer` + `FileTransferChunk` + `FileTransferDone`
//! to whatever client currently has focus.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::state::{Focus, ServerState};
use protocol::{Message, FILE_CHUNK_BYTES, MAX_FILE_BYTES};

/// 32 random bytes the daemon hands to local helpers via the status file.
pub type IpcToken = [u8; 32];

const MAX_IPC_FRAME: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub enum IpcRequest {
    /// First frame from the helper.
    Hello { token: IpcToken },
    /// Metadata of a file about to be streamed.
    File {
        name: String,
        size: u64,
        sha256: [u8; 32],
    },
    /// Raw chunk of the current file. Repeated until `size` bytes have been
    /// delivered.
    Chunk(Vec<u8>),
}

#[derive(Serialize, Deserialize)]
pub enum IpcResponse {
    Ok,
    /// Sent once the receiver acknowledged the transfer (or we gave up).
    Done {
        client_count: u32,
    },
    Err(String),
}

pub struct Ipc {
    pub addr: String,
}

pub fn random_token() -> IpcToken {
    use rand::RngCore;
    let mut t = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut t);
    t
}

/// Bind, spawn the accept loop, return the address that was actually bound
/// so it can be written to `status.json` for `union-send` to find.
pub async fn spawn(state: ServerState, token: IpcToken) -> anyhow::Result<Ipc> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    info!("IPC listening on {addr}");
    tokio::spawn(async move {
        let next_id = Arc::new(AtomicU32::new(1));
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("ipc accept failed: {e}");
                    continue;
                }
            };
            if !peer.ip().is_loopback() {
                warn!("ipc rejected non-loopback peer {peer}");
                continue;
            }
            let state = state.clone();
            let next_id = next_id.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_helper(sock, state, token, next_id).await {
                    tracing::debug!("ipc session ended: {e}");
                }
            });
        }
    });
    Ok(Ipc { addr })
}

async fn handle_helper(
    mut sock: TcpStream,
    state: ServerState,
    expected_token: IpcToken,
    next_id: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    // Hello first — drop the connection if the wrong token shows up.
    let hello: IpcRequest =
        tokio::time::timeout(Duration::from_secs(5), read_frame(&mut sock)).await??;
    let IpcRequest::Hello { token } = hello else {
        anyhow::bail!("expected Hello, got something else");
    };
    if token != expected_token {
        write_frame(&mut sock, &IpcResponse::Err("invalid token".into())).await?;
        anyhow::bail!("ipc auth failed");
    }
    write_frame(&mut sock, &IpcResponse::Ok).await?;

    // File metadata.
    let meta: IpcRequest =
        tokio::time::timeout(Duration::from_secs(5), read_frame(&mut sock)).await??;
    let IpcRequest::File { name, size, sha256 } = meta else {
        anyhow::bail!("expected File metadata");
    };
    if size > MAX_FILE_BYTES {
        write_frame(
            &mut sock,
            &IpcResponse::Err(format!("file too large ({size} > {MAX_FILE_BYTES})")),
        )
        .await?;
        return Ok(());
    }
    write_frame(&mut sock, &IpcResponse::Ok).await?;

    // Pick the target client now: whoever has focus, falling back to the
    // first connected client.
    let target = pick_target_client(&state).await;
    let Some(target) = target else {
        write_frame(&mut sock, &IpcResponse::Err("no client connected".into())).await?;
        return Ok(());
    };

    // Allocate a transfer id and announce.
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    let total_chunks: u32 = size.div_ceil(FILE_CHUNK_BYTES as u64).max(1) as u32;
    {
        let st = state.0.lock().await;
        let Some(c) = st.clients.get(&target) else {
            write_frame(
                &mut sock,
                &IpcResponse::Err("target client disappeared".into()),
            )
            .await?;
            return Ok(());
        };
        c.send_compat(Message::FileTransferOffer {
            id,
            name: name.clone(),
            size,
            total_chunks,
        });
    }

    // Pipe chunks from the helper to the client.
    let mut got: u64 = 0;
    let mut chunk_index: u32 = 0;
    let mut hasher = Sha256::new();
    while got < size {
        let req: IpcRequest =
            tokio::time::timeout(Duration::from_secs(30), read_frame(&mut sock)).await??;
        let IpcRequest::Chunk(buf) = req else {
            anyhow::bail!("expected Chunk while streaming");
        };
        if buf.is_empty() {
            break;
        }
        got += buf.len() as u64;
        hasher.update(&buf);
        let st = state.0.lock().await;
        if let Some(c) = st.clients.get(&target) {
            c.send_compat(Message::FileTransferChunk {
                id,
                chunk_index,
                data: buf,
            });
        }
        chunk_index += 1;
    }

    let actual: [u8; 32] = hasher.finalize().into();
    if actual != sha256 {
        warn!("ipc file '{name}' sha mismatch: dropping");
        write_frame(
            &mut sock,
            &IpcResponse::Err("payload hash mismatch on the way in".into()),
        )
        .await?;
        let st = state.0.lock().await;
        if let Some(c) = st.clients.get(&target) {
            c.send_compat(Message::FileTransferReject {
                id,
                reason: "ipc-side hash mismatch".into(),
            });
        }
        return Ok(());
    }

    {
        let st = state.0.lock().await;
        if let Some(c) = st.clients.get(&target) {
            c.send_compat(Message::FileTransferDone { id, sha256 });
        }
    }
    let count = state.0.lock().await.clients.len() as u32;
    write_frame(
        &mut sock,
        &IpcResponse::Done {
            client_count: count,
        },
    )
    .await?;
    info!("ipc file '{name}' ({size} B) delivered to client #{target}");
    Ok(())
}

async fn pick_target_client(state: &ServerState) -> Option<crate::state::ClientId> {
    let st = state.0.lock().await;
    match st.focus {
        Focus::Remote { client_id, .. } => Some(client_id),
        Focus::Local => st.order.first().copied(),
    }
}

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = bincode::serialize(msg).map_err(std::io::Error::other)?;
    if body.len() > MAX_IPC_FRAME {
        return Err(std::io::Error::other("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_IPC_FRAME {
        return Err(std::io::Error::other("frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    bincode::deserialize(&body).map_err(std::io::Error::other)
}
