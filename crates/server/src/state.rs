//! Shared server state — clients map and current focus.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Position;
use protocol::{Edge, Message};
use tokio::sync::{mpsc, Mutex};

pub type ClientId = u64;

#[derive(Debug)]
pub struct ConnectedClient {
    pub id: ClientId,
    pub hostname: String,
    pub screen: Option<(u32, u32)>,
    /// Send a message to this client.
    pub outbox: mpsc::UnboundedSender<Message>,
    /// Where this client sits relative to the server's screen. Defaults to
    /// `Right` when the config doesn't list the hostname.
    pub position: Position,
    /// Highest protocol version this client supports. Server uses this to
    /// withhold variants that didn't exist in older revisions.
    pub proto_version: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum Focus {
    Local,
    /// `entry_edge` is the edge of the *client's* screen through which the
    /// cursor entered. To return focus to the server, the cursor must exit
    /// through the same edge.
    Remote {
        client_id: ClientId,
        entry_edge: Edge,
    },
}

pub struct ServerStateInner {
    pub clients: HashMap<ClientId, ConnectedClient>,
    /// Ordered list of client IDs, in connection order. The cycle hotkey
    /// walks this list.
    pub order: Vec<ClientId>,
    pub focus: Focus,
    next_id: ClientId,
}

#[derive(Clone)]
pub struct ServerState(pub Arc<Mutex<ServerStateInner>>);

impl ServerState {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(ServerStateInner {
            clients: HashMap::new(),
            order: Vec::new(),
            focus: Focus::Local,
            next_id: 1,
        })))
    }

    pub async fn add_client(&self, c: ConnectedClient) -> ClientId {
        let mut st = self.0.lock().await;
        let id = c.id;
        st.order.push(id);
        st.clients.insert(id, c);
        id
    }

    pub async fn remove_client(&self, id: ClientId) {
        let mut st = self.0.lock().await;
        st.clients.remove(&id);
        st.order.retain(|&x| x != id);
        if let Focus::Remote { client_id, .. } = st.focus {
            if client_id == id {
                st.focus = Focus::Local;
            }
        }
    }

    pub async fn alloc_id(&self) -> ClientId {
        let mut st = self.0.lock().await;
        let id = st.next_id;
        st.next_id += 1;
        id
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Variants introduced in protocol v2. Sending them to v1 peers would decode
/// as an unknown bincode tag and kill the session — silently drop instead.
fn is_v2_only(msg: &Message) -> bool {
    matches!(
        msg,
        Message::ClipboardImageOffer { .. }
            | Message::SetExitEdge { .. }
            | Message::RequestFocusReturn
    )
}

/// Variants introduced in protocol v3 (file transfer).
fn is_v3_only(msg: &Message) -> bool {
    matches!(
        msg,
        Message::FileTransferOffer { .. }
            | Message::FileTransferChunk { .. }
            | Message::FileTransferDone { .. }
            | Message::FileTransferReject { .. }
    )
}

impl ConnectedClient {
    /// Send a frame to this client, dropping variants the peer is too old
    /// to decode.
    pub fn send_compat(&self, msg: Message) {
        if self.proto_version < 2 && is_v2_only(&msg) {
            tracing::trace!(
                client = %self.hostname,
                "dropping v2-only frame for v{} peer",
                self.proto_version,
            );
            return;
        }
        if self.proto_version < 3 && is_v3_only(&msg) {
            tracing::trace!(
                client = %self.hostname,
                "dropping v3-only frame for v{} peer",
                self.proto_version,
            );
            return;
        }
        let _ = self.outbox.send(msg);
    }
}

/// Which `Position` corresponds to a cursor exiting through the given edge
/// of the server's screen.
pub const fn position_for_server_edge(edge: Edge) -> Position {
    match edge {
        Edge::Left => Position::Left,
        Edge::Right => Position::Right,
        Edge::Top => Position::Above,
        Edge::Bottom => Position::Below,
    }
}

/// Which edge of a client's screen the cursor enters through, given that
/// client's `Position` relative to the server.
pub const fn entry_edge_for_position(p: Position) -> Edge {
    match p {
        // Client to the right → cursor entering through its LEFT side.
        Position::Right => Edge::Left,
        Position::Left => Edge::Right,
        Position::Above => Edge::Bottom,
        Position::Below => Edge::Top,
    }
}
