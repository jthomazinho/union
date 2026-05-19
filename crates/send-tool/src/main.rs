//! `union-send` — push a local file to whichever Union client currently
//! holds focus.
//!
//! Reads the running daemon's `status.json` to find its IPC endpoint and
//! the per-startup auth token, hashes the file, then streams it as
//! length-prefixed bincode frames over the loopback socket. The daemon
//! re-emits each chunk as a `FileTransferChunk` to the focused client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::Parser;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CHUNK: usize = 32 * 1024;
const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "union-send",
    version,
    about = "Send a file to the focused Union client"
)]
struct Cli {
    /// One or more files to send, in order.
    files: Vec<PathBuf>,
    /// Optional override of the daemon's config dir (defaults to
    /// `$UNION_CONFIG_DIR` or the platform default).
    #[arg(long)]
    config_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Status {
    ipc_addr: Option<String>,
    ipc_token: String,
}

// Wire structs — mirror `server/src/ipc.rs::IpcRequest`/`IpcResponse`.
#[derive(Serialize)]
enum IpcRequest {
    Hello {
        token: [u8; 32],
    },
    File {
        name: String,
        size: u64,
        sha256: [u8; 32],
    },
    Chunk(Vec<u8>),
}

#[derive(Deserialize)]
enum IpcResponse {
    Ok,
    Done { client_count: u32 },
    Err(String),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.files.is_empty() {
        eprintln!("usage: union-send <file>...");
        std::process::exit(2);
    }
    let status = load_status(cli.config_dir.as_deref())?;
    let addr = status
        .ipc_addr
        .ok_or_else(|| anyhow!("daemon has no IPC listener (start union-server first)"))?;
    let token = parse_token(&status.ipc_token)?;
    for file in &cli.files {
        match send_one(&addr, token, file).await {
            Ok(count) => {
                println!(
                    "{}: delivered to focused client ({count} client(s) connected)",
                    file.display()
                );
            }
            Err(e) => {
                eprintln!("{}: FAILED — {e}", file.display());
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

async fn send_one(addr: &str, token: [u8; 32], path: &Path) -> anyhow::Result<u32> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let size = bytes.len() as u64;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid filename"))?
        .to_string();
    let mut h = Sha256::new();
    h.update(&bytes);
    let sha: [u8; 32] = h.finalize().into();

    let mut sock = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .context("connect ipc timeout")??;
    write_frame(&mut sock, &IpcRequest::Hello { token }).await?;
    expect_ok(read_frame::<_, IpcResponse>(&mut sock).await?)?;

    write_frame(
        &mut sock,
        &IpcRequest::File {
            name,
            size,
            sha256: sha,
        },
    )
    .await?;
    expect_ok(read_frame::<_, IpcResponse>(&mut sock).await?)?;

    for chunk in bytes.chunks(CHUNK) {
        write_frame(&mut sock, &IpcRequest::Chunk(chunk.to_vec())).await?;
    }

    match read_frame::<_, IpcResponse>(&mut sock).await? {
        IpcResponse::Done { client_count } => Ok(client_count),
        IpcResponse::Err(e) => Err(anyhow!("server rejected: {e}")),
        IpcResponse::Ok => Err(anyhow!("unexpected Ok at end of transfer")),
    }
}

fn expect_ok(r: IpcResponse) -> anyhow::Result<()> {
    match r {
        IpcResponse::Ok => Ok(()),
        IpcResponse::Err(e) => Err(anyhow!("server: {e}")),
        IpcResponse::Done { .. } => Err(anyhow!("server: unexpected Done")),
    }
}

fn load_status(override_dir: Option<&Path>) -> anyhow::Result<Status> {
    let path = override_dir
        .map(|d| d.join("runtime").join("status.json"))
        .unwrap_or_else(|| config_dir().join("runtime").join("status.json"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} — is the daemon running?", path.display()))?;
    let s: Status =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(s)
}

fn parse_token(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("ipc_token must be hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("ipc_token must be 32 bytes (64 hex chars)"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Ok(a)
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

async fn write_frame<W, T>(w: &mut W, msg: &T) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let body = bincode::serialize(msg)?;
    if body.len() > MAX_FRAME {
        return Err(anyhow!("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

async fn read_frame<R, T>(r: &mut R) -> anyhow::Result<T>
where
    R: AsyncReadExt + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(anyhow!("frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(bincode::deserialize(&body)?)
}
