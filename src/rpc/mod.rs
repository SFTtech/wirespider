use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::PublicKey;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tarpc::context;

use tokio::sync::RwLock;

pub mod raft_state;
use raft_state::RaftState;

pub mod log;
use log::LogEntry;

//pub mod signed;
//use signed::Signed;
use tracing_unwrap::ResultExt;
use uuid::Uuid;

use self::raft_state::RaftRole;

type PeerId = ed25519_dalek::PublicKey;
type WireguardKey = x25519_dalek::PublicKey;



#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

const WIRESPIDER_VERSION : Version = Version {major: 0, minor: 4, patch: 0};

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    state: NodeState,
    connections: Vec<PeerConnection>,
}

#[derive(Debug, Serialize, Deserialize)]
enum NatType {
    NoNat,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeState {
    node: PeerId,
    wireguard_key: PublicKey,
    public_endpoint: String,
    nat_type: NatType,
    external_ips: Vec<SocketAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionState {
    NoConnection,
    DirectConnection,
    IndirectConnection,
}

/// Permissions of a node
#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum Permission {
    /// Node can participate in mesh and discover peers. A node that should only connect to a gateway node does not have this permission.
    Mesh,
    /// Node can be elected as a raft leader. Should be online 24/7.
    Server,
    /// Can send commands to the raft leader that modify the network
    Admin,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterNodeState {
    node: PeerId,
    permissions: HashSet<Permission>,
    overlay_ips: Vec<IpNet>,
    attached_networks: Vec<IpNet>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterNetwork {
    net: IpNet,
    net_type: ClusterNetworkType,
    /// parent defines on top of which network is this network built.
    /// if it is none, then it is the outermost layer and it is using the internet
    parent: Option<Uuid>
}

///
#[derive(Debug, Serialize, Deserialize)]
pub enum ClusterNetworkType {
    Wireguard,
    VXLAN { vni: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClusterStateUpdate {
    Add(ClusterNodeState),
    Change(ClusterNodeState),
    Remove(PeerId),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClusterStateEntry {
    Initial {
        nodes: Vec<ClusterNodeState>,
        networks: Vec<ClusterNetwork>,
    },
    Update(ClusterStateUpdate),
}


#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConnection {
    peer: PeerId,
    state: ConnectionState,
}

#[tarpc::service]
pub trait NodeService {
    async fn get_version() -> Version;
    async fn append_entries(
        term: u64,
        leader_id: PeerId,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    ) -> (u64, bool);
    async fn request_vote(
        term: u64,
        candidate_id: PeerId,
        last_log_index: u64,
        last_log_term: u64,
    ) -> (u64, bool);
    async fn install_snapshot(
        term: u64,
        leader_id: PeerId,
        last_included_index: u64,
        last_included_term: u64,
        data: Vec<u8>,
        last: bool,
    ) -> u64;
}


struct Service {
    raft_state: Arc<RwLock<RaftState>>,
}

#[tarpc::server]
impl NodeService for Service {
    async fn get_version(self, _: context::Context) -> Version {
        return WIRESPIDER_VERSION;
    }

    async fn append_entries(
        self, _: context::Context,
        term: u64,
        leader_id: PeerId,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    ) -> (u64, bool) {
        let mut state = self.raft_state.write().await;
        let current_term = state.persistent.current_term;
        if current_term > term {
            return (current_term, false);
        }
        state.election_timeout.reset();
        if state.persistent.current_term < term {
            state.persistent.current_term = term;
            state.commit_persistent().await.unwrap_or_log();
        }
        if ! state.persistent.log_contains(prev_log_index, prev_log_term) {
            return (term, false);
        }
        state.persistent.log_append(entries);
        state.persistent.commit_until(leader_commit).await;
        state.role = RaftRole::Follower(leader_id);
        (term, true)
    }

    async fn request_vote(
        self, _: context::Context,
        term: u64,
        candidate_id: PeerId,
        last_log_index: u64,
        last_log_term: u64,
    ) -> (u64, bool) {
        let mut state = self.raft_state.write().await;
        let (current_term, current_vote, current_log_index, current_log_term) = {
            (state.persistent.current_term, state.persistent.current_vote, state.persistent.get_log_index(), state.persistent.get_log_term())
        };
        if term < current_term || current_vote.is_some() || current_log_index > last_log_index || current_log_term > last_log_term {
            return (current_term, false);
        }
        // preconditions fulfilled, vote for candidate
        if term == current_term {
            state.persistent.current_vote.get_or_insert(candidate_id);
        } else if term > current_term {
            // in this case we increase 
        }

        state.persistent.current_term = term;
        state.commit_persistent().await.unwrap_or_log();
        (state.persistent.current_term, true)
    }

    async fn install_snapshot(
        self, _: context::Context,
        _term: u64,
        _leader_id: PeerId,
        _last_included_index: u64,
        _last_included_term: u64,
        _data: Vec<u8>,
        _last: bool,
    ) -> u64 {
        unimplemented!()
    }
}


#[test]
fn test_node_service() {

}