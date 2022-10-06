use std::collections::HashSet;
use std::net::{SocketAddr};

use ipnet::IpNet;
use rand::rngs::StdRng;
use rand::{CryptoRng, rngs::OsRng};
use tarpc::context::Context;
use serde::{Serialize, Deserialize};
use tarpc::serde_transport as transport;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio::net::{UnixListener, UnixStream};
use ed25519_dalek::{PublicKey, Signature, Verifier, Signer};
use tarpc::{
    client, context,
    server::{self, incoming::Incoming},
};

pub mod signed;
use signed::Signed;

type PeerId = ed25519_dalek::PublicKey;
type WireguardKey = x25519_dalek::PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    state: State,
    connections: Vec<PeerConnection>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

#[derive(Debug, Serialize, Deserialize)]
enum NatType {
    NoNat,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    node: PeerId,
    timestamp: u64,
    wireguard_key: PublicKey,
    public_endpoint: String,
    nat_type: NatType,
    external_ips: Vec<SocketAddr>,
    last_seen_log_entry: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionState {
    NoConnection,
    DirectConnection,
    IndirectConnection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterState {
    log: Vec<Signed<ClusterStateEntry>>,
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum Permission {
    Mesh,
    Monitor,
    Route,
    Sign,
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
pub enum ClusterNetwork {
    Wireguard(IpNet),
    VXLAN{net: IpNet, vni: u32},
}


#[derive(Debug, Serialize, Deserialize)]
pub enum ClusterStateUpdate {
    Add(ClusterNodeState),
    Change(ClusterNodeState),
    Remove(PeerId)
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
    async fn get_peer_info() -> Signed<PeerInfo>;
    async fn get_version() -> Version;
    async fn update_state(state: Signed<State>, targets: Vec<PeerId>);
    async fn get_cluster_state(last_known: u64) -> ClusterState;
}

#[derive(Clone)]
struct Service;

#[tarpc::server]
impl NodeService for Service {
    async fn get_peer_info(self, _: context::Context) -> Signed<PeerInfo> {
        todo!();
    }
    async fn get_version(self, _: context::Context) -> Version {
        todo!();
    }
    async fn update_state(self, _: context::Context, _state: Signed<State>, _targets: Vec<PeerId>) {
        todo!();
    }

    async fn get_cluster_state(self, _: context::Context, _last_known: u64) -> ClusterState {
        todo!();
    }
}



