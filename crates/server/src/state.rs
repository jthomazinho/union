//! Shared server state — clients map and current focus.

use std::collections::HashMap;
use std::sync::Arc;

use protocol::Message;
use tokio::sync::{mpsc, Mutex};

pub type ClientId = u64;

#[derive(Debug)]
pub struct ConnectedClient {
    pub id: ClientId,
    #[allow(dead_code)] // surfaced via logs / future GUI; keep
    pub hostname: String,
    pub screen: Option<(u32, u32)>,
    /// Send a message to this client.
    pub outbox: mpsc::UnboundedSender<Message>,
}

#[derive(Debug, Clone, Copy)]
pub enum Focus {
    Local,
    Remote { client_id: ClientId },
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
        if let Focus::Remote { client_id } = st.focus {
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
