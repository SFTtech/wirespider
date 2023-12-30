use serde::{Deserialize, Serialize};

use super::{NodeState, PeerId};

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionState {
    NoConnection,
    DirectConnection,
    IndirectConnection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConnection {
    peer: PeerId,
    state: ConnectionState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    state: NodeState,
    connections: Vec<PeerConnection>,
}
