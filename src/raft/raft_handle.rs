//! Shared handle to the running openraft node plus the node's raft identity.

use openraft::error::CheckIsLeaderError;
use openraft::error::ClientWriteError;
use openraft::error::Fatal;
use openraft::error::RaftError;
use openraft::BasicNode;
use openraft::Vote;
use std::sync::Arc;

use super::entry::AppliedEvent;
use super::entry::Mutation;
use super::entry::MutationResponse;
use super::network::TonicNetworkFactory;
use super::NodeId;
use super::TypeConfig;

pub type RaftNode = openraft::Raft<TypeConfig>;

/// Handle shared by all services: the openraft node and the node's raft key.
#[derive(Clone)]
pub struct RaftHandle {
    pub raft: RaftNode,
    pub signing_key: ed25519_dalek::SigningKey,
    /// Pool for local lookups (ownership checks etc.) that do not belong in
    /// the state machine.
    pool: sqlx::SqlitePool,
}

impl RaftHandle {
    /// Start a raft node backed by SQLite storage and state machine.
    pub async fn new(
        id: NodeId,
        config: Arc<openraft::Config>,
        log_store: super::store::RaftLogStore,
        state_machine: super::state_machine::RaftStateMachine,
        signing_key: ed25519_dalek::SigningKey,
        pool: sqlx::SqlitePool,
    ) -> Result<Self, Fatal<NodeId>> {
        let network = TonicNetworkFactory::new(signing_key.clone());
        let raft = openraft::Raft::new(id, config, network, log_store, state_machine).await?;
        Ok(Self {
            raft,
            signing_key,
            pool,
        })
    }

    /// The local database pool, for ownership lookups outside the state
    /// machine.
    pub fn pool(&self) -> &sqlx::SqlitePool {
        &self.pool
    }

    /// Submit a mutation through consensus. Returns `ForwardToLeader` as an
    /// error so callers can redirect clients to the current leader.
    pub async fn write(
        &self,
        mutation: Mutation,
    ) -> Result<MutationResponse, RaftError<NodeId, ClientWriteError<NodeId, BasicNode>>> {
        let response = self.raft.client_write(mutation).await?;
        Ok(response.data)
    }

    /// Ensure this node is the leader and its state is up to date, for
    /// linearizable reads.
    pub async fn ensure_linearizable(
        &self,
    ) -> Result<
        Option<openraft::LogId<NodeId>>,
        RaftError<NodeId, CheckIsLeaderError<NodeId, BasicNode>>,
    > {
        self.raft.ensure_linearizable().await
    }

    /// Metrics containing the current leader, for redirecting clients.
    pub async fn leader(&self) -> Option<(NodeId, Option<BasicNode>)> {
        let metrics = self.raft.metrics().borrow().clone();
        let leader_id = metrics.current_leader?;
        let node = metrics
            .membership_config
            .membership()
            .get_node(&leader_id)
            .cloned();
        Some((leader_id, node))
    }

    /// The local vote, used as a hint when building InstallSnapshotRequests.
    pub async fn current_vote_hint(&self) -> Vote<NodeId> {
        self.raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .unwrap_or_default()
    }

    /// Current membership, for signature verification against enrolled keys.
    pub async fn membership(&self) -> openraft::Membership<NodeId, BasicNode> {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .clone()
    }
}

/// Receives events applied by the state machine.
pub type EventReceiver = tokio::sync::mpsc::UnboundedReceiver<AppliedEvent>;
