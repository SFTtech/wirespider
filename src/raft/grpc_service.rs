//! gRPC service receiving raft RPCs from other nodes.
//!
//! Every incoming RPC is signature-verified against the enrolled node keys
//! before it reaches the local openraft node. Unknown signers are rejected
//! with `PermissionDenied`.

use openraft::BasicNode;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

use super::envelope;
use super::raft_handle::RaftHandle;
use super::NodeId;
use super::TypeConfig;
use crate::protocol::raft_server::Raft;
use crate::protocol::SignedRaftAppendRequest;
use crate::protocol::SignedRaftAppendResponse;
use crate::protocol::SignedRaftPayload;
use crate::protocol::SignedRaftSnapshotChunk;
use crate::protocol::SignedRaftSnapshotResponse;
use crate::protocol::SignedRaftVoteRequest;
use crate::protocol::SignedRaftVoteResponse;

/// gRPC service handling incoming raft RPCs.
pub struct RaftService {
    raft: RaftHandle,
    /// Public keys of all enrolled cluster nodes (voters and learners).
    members: tokio::sync::RwLock<std::collections::HashSet<[u8; 32]>>,
}

impl RaftService {
    pub fn new(raft: RaftHandle) -> Self {
        Self {
            raft,
            members: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Register a node pubkey whose signed RPCs will be accepted.
    pub async fn add_member(&self, key: [u8; 32]) {
        self.members.write().await.insert(key);
    }

    /// Load member keys from the current raft membership config, merging with
    /// the existing set (never removing bootstrap keys).
    pub async fn sync_members_from_membership(
        &self,
        membership: &openraft::Membership<NodeId, BasicNode>,
    ) {
        let mut members = self.members.write().await;
        for (id, _node) in membership.nodes() {
            members.insert(*id.as_bytes());
        }
    }

    /// Refresh the enrolled keys from the live membership config.
    ///
    /// Called before verifying a signature: membership changes (join,
    /// promote) must be picked up without a restart. The check is only a
    /// pre-filter; the signature itself is always verified.
    async fn refresh_members(&self) {
        let membership = self.raft.membership().await;
        self.sync_members_from_membership(&membership).await;
    }

    async fn check_signer(&self, payload: Option<&SignedRaftPayload>) -> Result<(), Status> {
        let payload = payload.ok_or_else(|| Status::invalid_argument("missing payload"))?;
        let signer: [u8; 32] = payload
            .signer
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid signer key"))?;
        if !self.members.read().await.contains(&signer) {
            // membership may have changed since the last sync
            self.refresh_members().await;
            if !self.members.read().await.contains(&signer) {
                return Err(Status::permission_denied("unknown raft node"));
            }
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl Raft for RaftService {
    async fn vote(
        &self,
        request: tonic::Request<SignedRaftVoteRequest>,
    ) -> Result<Response<SignedRaftVoteResponse>, Status> {
        let request = request.into_inner();
        self.check_signer(request.payload.as_ref()).await?;
        let (rpc, _signer): (openraft::raft::VoteRequest<NodeId>, _) =
            envelope::verify_and_decode(request.payload.as_ref(), envelope::TYPE_VOTE_REQUEST)
                .map_err(|e| Status::permission_denied(e.to_string()))?;

        let response = self
            .raft
            .raft
            .vote(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let payload = envelope::sign_payload(
            &response,
            envelope::TYPE_VOTE_RESPONSE,
            &self.raft.signing_key,
        )
        .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SignedRaftVoteResponse {
            payload: Some(payload),
        }))
    }

    async fn append(
        &self,
        request: tonic::Request<SignedRaftAppendRequest>,
    ) -> Result<Response<SignedRaftAppendResponse>, Status> {
        let request = request.into_inner();
        self.check_signer(request.payload.as_ref()).await?;
        let (rpc, _signer): (openraft::raft::AppendEntriesRequest<TypeConfig>, _) =
            envelope::verify_and_decode(request.payload.as_ref(), envelope::TYPE_APPEND_REQUEST)
                .map_err(|e| Status::permission_denied(e.to_string()))?;

        let response = self
            .raft
            .raft
            .append_entries(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let payload = envelope::sign_payload(
            &response,
            envelope::TYPE_APPEND_RESPONSE,
            &self.raft.signing_key,
        )
        .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SignedRaftAppendResponse {
            payload: Some(payload),
        }))
    }

    async fn snapshot(
        &self,
        request: tonic::Request<Streaming<SignedRaftSnapshotChunk>>,
    ) -> Result<Response<SignedRaftSnapshotResponse>, Status> {
        let mut stream = request.into_inner();
        // First chunk carries the signed InstallSnapshotRequest header (vote,
        // meta, offset, done); data chunks follow raw. Tampering with the
        // data fails at install time when the snapshot is deserialized.
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("empty snapshot stream"))?;
        let header = first.header.clone();
        self.check_signer(header.as_ref()).await?;
        let (snapshot_header, _signer): (envelope::SnapshotHeader, _) =
            envelope::verify_and_decode(header.as_ref(), envelope::TYPE_SNAPSHOT_REQUEST)
                .map_err(|e| Status::permission_denied(e.to_string()))?;

        let mut data = first.data;
        let mut done = first.done;
        while !done {
            let chunk = stream
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("snapshot stream ended early"))?;
            data.extend_from_slice(&chunk.data);
            done = chunk.done;
        }

        let request = openraft::raft::InstallSnapshotRequest::<TypeConfig> {
            vote: snapshot_header.vote,
            meta: snapshot_header.meta,
            offset: snapshot_header.offset,
            data,
            done: snapshot_header.done,
        };
        let response = self
            .raft
            .raft
            .install_snapshot(request)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let payload = envelope::sign_payload(
            &response,
            envelope::TYPE_SNAPSHOT_RESPONSE,
            &self.raft.signing_key,
        )
        .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SignedRaftSnapshotResponse {
            payload: Some(payload),
        }))
    }
}
