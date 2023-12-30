use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use ed25519_dalek::VerifyingKey;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub mod raft_state;

pub mod log;

pub mod connection;

pub mod service;

pub mod signed;
//use signed::Signed;

use uuid::Uuid;

type PeerId = ed25519_dalek::VerifyingKey;

use super::WIRESPIDER_VERSION;

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
    wireguard_key: VerifyingKey,
    public_endpoint: String,
    nat_type: NatType,
    external_ips: Vec<SocketAddr>,
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
    overlay_ips: Vec<(IpAddr, Uuid)>,
    attached_networks: Vec<Uuid>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterNetwork {
    net: IpNet,
    net_type: ClusterNetworkType,
    /// parent defines on top of which network is this network built.
    /// if it is none, then it is the outermost layer and it is using the internet
    parent: Option<Uuid>,
}

/// Technology of the overlay network and if needed additional info.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClusterNetworkType {
    Wireguard,
    VXLAN { vni: u32 },
}

/// Messages to update a ClusterState. Stored in the Raft log
#[derive(Debug, Serialize, Deserialize)]
pub enum ClusterStateUpdate {
    /// Used when nothing was updated. This is used as a first entry in the log
    Empty,
    AddNode(ClusterNodeState),
    ChangeNode(ClusterNodeState),
    RemoveNode(PeerId),
    AddNetwork(Uuid, ClusterNetwork),
    ChangeNetwork(Uuid, ClusterNetwork),
    RemoveNetwork(Uuid),
}

/**
Full state of the cluster. Used for snapshots. Updated by [`ClusterStateUpdate`]
*/
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ClusterState {
    // TODO use Hashmap, as soon as Pubkey implements Hash: https://github.com/dalek-cryptography/ed25519-dalek/issues/183
    #[serde(default)]
    nodes: Vec<ClusterNodeState>,
    #[serde(default)]
    networks: HashMap<Uuid, ClusterNetwork>,
}
