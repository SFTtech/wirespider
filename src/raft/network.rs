//! RaftNetwork implementation over tonic.
//!
//! Each RPC is serialized to JSON, signed with the local node's raft key and
//! sent as a [`SignedRaftPayload`] envelope to the target node's gRPC service.
//! The address of a target node comes from openraft's membership config
//! (`BasicNode.addr`, a `host:port` string).

use openraft::error::NetworkError;
use openraft::error::RPCError;
use openraft::error::RaftError;
use openraft::error::Unreachable;
use openraft::network::RPCOption;
use openraft::network::RaftNetwork;
use openraft::network::RaftNetworkFactory;
use openraft::raft::AppendEntriesRequest;
use openraft::raft::AppendEntriesResponse;
use openraft::raft::InstallSnapshotRequest;
use openraft::raft::InstallSnapshotResponse;
use openraft::raft::VoteRequest;
use openraft::raft::VoteResponse;
use openraft::RaftTypeConfig;
use tonic::transport::Channel;

use super::envelope;
use super::TypeConfig;
use crate::protocol::raft_client::RaftClient;
use crate::protocol::SignedRaftAppendRequest;
use crate::protocol::SignedRaftAppendResponse;
use crate::protocol::SignedRaftPayload;
use crate::protocol::SignedRaftSnapshotChunk;
use crate::protocol::SignedRaftSnapshotResponse;
use crate::protocol::SignedRaftVoteRequest;
use crate::protocol::SignedRaftVoteResponse;

pub type RpcResult<T> = Result<
    T,
    RPCError<
        <TypeConfig as RaftTypeConfig>::NodeId,
        openraft::BasicNode,
        RaftError<<TypeConfig as RaftTypeConfig>::NodeId>,
    >,
>;

/// Creates per-target network clients. One instance lives inside the `Raft` node.
#[derive(Clone)]
pub struct TonicNetworkFactory {
    /// Signing key of the local node, used to sign outgoing RPCs.
    signing_key: ed25519_dalek::SigningKey,
}

impl TonicNetworkFactory {
    pub fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { signing_key }
    }
}

impl RaftNetworkFactory<TypeConfig> for TonicNetworkFactory {
    type Network = TonicNetworkClient;

    async fn new_client(
        &mut self,
        _target: <TypeConfig as RaftTypeConfig>::NodeId,
        node: &openraft::BasicNode,
    ) -> Self::Network {
        TonicNetworkClient {
            signing_key: self.signing_key.clone(),
            addr: node.addr.clone(),
            client: None,
        }
    }
}

/// Network client for one target node.
pub struct TonicNetworkClient {
    signing_key: ed25519_dalek::SigningKey,
    addr: String,
    client: Option<RaftClient<Channel>>,
}

impl TonicNetworkClient {
    fn sign<T: serde::Serialize>(
        &self,
        payload: &T,
        payload_type: &str,
    ) -> Result<
        SignedRaftPayload,
        RPCError<
            <TypeConfig as RaftTypeConfig>::NodeId,
            openraft::BasicNode,
            RaftError<<TypeConfig as RaftTypeConfig>::NodeId>,
        >,
    > {
        envelope::sign_payload(payload, payload_type, &self.signing_key)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))
    }

    async fn client(
        &mut self,
    ) -> Result<
        &mut RaftClient<Channel>,
        RPCError<
            <TypeConfig as RaftTypeConfig>::NodeId,
            openraft::BasicNode,
            RaftError<<TypeConfig as RaftTypeConfig>::NodeId>,
        >,
    > {
        if self.client.is_none() {
            let channel = Channel::from_shared(format!("http://{}", self.addr))
                .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?
                .connect()
                .await
                .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
            self.client = Some(RaftClient::new(channel));
        }
        Ok(self.client.as_mut().expect("client was just set"))
    }
}

/// The snapshot install RPC reports a dedicated error type.
pub type SnapshotRpcResult<T> = Result<
    T,
    RPCError<
        <TypeConfig as RaftTypeConfig>::NodeId,
        openraft::BasicNode,
        RaftError<<TypeConfig as RaftTypeConfig>::NodeId, openraft::error::InstallSnapshotError>,
    >,
>;

fn status_err(status: tonic::Status) -> Unreachable {
    Unreachable::new(&status)
}

/// Convert a network error to the snapshot RPC error type.
fn snapshot_err(
    e: impl std::error::Error + 'static,
) -> RPCError<
    <TypeConfig as RaftTypeConfig>::NodeId,
    openraft::BasicNode,
    RaftError<<TypeConfig as RaftTypeConfig>::NodeId, openraft::error::InstallSnapshotError>,
> {
    RPCError::Unreachable(Unreachable::new(&e))
}

impl RaftNetwork<TypeConfig> for TonicNetworkClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> RpcResult<AppendEntriesResponse<<TypeConfig as RaftTypeConfig>::NodeId>> {
        let payload = self.sign(&rpc, envelope::TYPE_APPEND_REQUEST)?;
        let client = self.client().await?;
        let response: tonic::Response<SignedRaftAppendResponse> = client
            .append(tonic::Request::new(SignedRaftAppendRequest {
                payload: Some(payload),
            }))
            .await
            .map_err(status_err)?;
        let (response, _signer): (
            AppendEntriesResponse<<TypeConfig as RaftTypeConfig>::NodeId>,
            _,
        ) = envelope::verify_and_decode(
            response.into_inner().payload.as_ref(),
            envelope::TYPE_APPEND_RESPONSE,
        )
        .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        Ok(response)
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> SnapshotRpcResult<InstallSnapshotResponse<<TypeConfig as RaftTypeConfig>::NodeId>> {
        // Send the snapshot in chunks: the first chunk carries the signed
        // header (vote, meta, offset, done), following chunks carry raw data.
        let header = self
            .sign(
                &envelope::SnapshotHeader {
                    vote: rpc.vote,
                    meta: rpc.meta.clone(),
                    offset: rpc.offset,
                    done: rpc.done,
                },
                envelope::TYPE_SNAPSHOT_REQUEST,
            )
            .map_err(snapshot_err)?;
        let client = self.client().await.map_err(snapshot_err)?;
        let (tx, rx) = tokio::sync::mpsc::channel::<SignedRaftSnapshotChunk>(4);

        let chunks = vec![
            SignedRaftSnapshotChunk {
                header: Some(header),
                data: Vec::new(),
                done: false,
            },
            SignedRaftSnapshotChunk {
                header: None,
                data: rpc.data.clone(),
                done: rpc.done,
            },
        ];
        for chunk in chunks {
            tx.send(chunk).await.map_err(|e| {
                RPCError::Network(NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                )))
            })?;
        }
        drop(tx);

        let response: tonic::Response<SignedRaftSnapshotResponse> = client
            .snapshot(tonic::Request::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
            .await
            .map_err(snapshot_err)?;
        let (response, _signer): (
            InstallSnapshotResponse<<TypeConfig as RaftTypeConfig>::NodeId>,
            _,
        ) = envelope::verify_and_decode(
            response.into_inner().payload.as_ref(),
            envelope::TYPE_SNAPSHOT_RESPONSE,
        )
        .map_err(snapshot_err)?;
        Ok(response)
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<<TypeConfig as RaftTypeConfig>::NodeId>,
        _option: RPCOption,
    ) -> RpcResult<VoteResponse<<TypeConfig as RaftTypeConfig>::NodeId>> {
        let payload = self.sign(&rpc, envelope::TYPE_VOTE_REQUEST)?;
        let client = self.client().await?;
        let response: tonic::Response<SignedRaftVoteResponse> = client
            .vote(tonic::Request::new(SignedRaftVoteRequest {
                payload: Some(payload),
            }))
            .await
            .map_err(status_err)?;
        let (response, _signer): (VoteResponse<<TypeConfig as RaftTypeConfig>::NodeId>, _) =
            envelope::verify_and_decode(
                response.into_inner().payload.as_ref(),
                envelope::TYPE_VOTE_RESPONSE,
            )
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        Ok(response)
    }
}
