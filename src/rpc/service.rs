use std::sync::Arc;

use tarpc::context;
use tokio::sync::{RwLock, Mutex};
use tracing_unwrap::ResultExt;

use crate::{rpc::ClusterState, Version};

use super::{PeerId, raft_state::{RaftState, Term, RaftRole}, WIRESPIDER_VERSION, log::{LogEntry, LogIndex}};


#[tarpc::service]
pub trait NodeService {
    async fn get_version() -> Version;
    /**
    This is the append entries RPC from the Raft paper
    From the paper:
    Arguments:
        term - leader’s term
        leaderId - so follower can redirect clients
        prevLogIndex - index of log entry immediately preceding new ones
        prevLogTerm - term of prevLogIndex entry
        entries[] - log entries to store (empty for heartbeat; may send more than one for efficiency)
        leaderCommit - leader’s commitIndex
    Results:
        term - currentTerm, for leader to update itself
        success - true if follower contained entry matching prevLogIndex and prevLogTerm
    Receiver implementation:
        1. Reply false if term < currentTerm (§5.1)
        2. Reply false if log doesn’t contain an entry at prevLogIndex
        whose term matches prevLogTerm (§5.3)
        3. If an existing entry conflicts with a new one (same index
        but different terms), delete the existing entry and all that
        follow it (§5.3)
        4. Append any new entries not already in the log
        5. If leaderCommit > commitIndex, set commitIndex =
        min(leaderCommit, index of last new entry)
    */
    async fn append_entries(
        term: Term,
        leader_id: PeerId,
        prev_log_index: LogIndex,
        prev_log_term: Term,
        entries: Vec<LogEntry>,
        leader_commit: LogIndex,
    ) -> (Term, bool);
    async fn request_vote(
        term: Term,
        candidate_id: PeerId,
        last_log_index: LogIndex,
        last_log_term: Term,
    ) -> (Term, bool);
    /// This is the Raft InstallSnapshot RPC
    async fn install_snapshot(
        term: Term,
        leader_id: PeerId,
        last_included_index: LogIndex,
        last_included_term: Term,
        data: Vec<u8>,
        last: bool,
    ) -> Term;
}

/// State when getting chunks of a snapshot
#[derive(Debug,Clone)]
struct SnapshotState {
    data: Vec<u8>,
    leader: PeerId,
    last_log_index: LogIndex,
    last_log_term: Term,
}


/// This comparison
impl PartialEq<SnapshotState> for SnapshotState {
    fn eq(&self, other: &SnapshotState) -> bool {
        other.last_log_index == self.last_log_index && 
        other.last_log_term == self.last_log_term && 
        other.leader == self.leader
    }
}

struct Service {
    raft_state: Arc<RwLock<RaftState>>,
    snapshot: Arc<Mutex<Option<SnapshotState>>>,
}

#[tarpc::server]
impl NodeService for Service {
    async fn get_version(self, _: context::Context) -> Version {
        return WIRESPIDER_VERSION;
    }

    async fn append_entries(
        self, _: context::Context,
        term: Term,
        leader_id: PeerId,
        prev_log_index: LogIndex,
        prev_log_term: Term,
        entries: Vec<LogEntry>,
        leader_commit: LogIndex,
    ) -> (Term, bool) {
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
        term: Term,
        candidate_id: PeerId,
        last_log_index: LogIndex,
        last_log_term: Term,
    ) -> (Term, bool) {
        let mut state = self.raft_state.write().await;
        state.persistent.update_term(term);
        let current_term = state.persistent.current_term;
        let current_vote = state.persistent.current_vote;
        let current_log_index = state.persistent.get_log_index();
        let current_log_term = state.persistent.get_log_term();
        if term < current_term || current_vote.is_some() || current_log_index > last_log_index || current_log_term > last_log_term {
            return (current_term, false);
        }
        // preconditions fulfilled, vote for candidate
        state.persistent.current_vote = Some(candidate_id);

        state.commit_persistent().await.unwrap_or_log();
        (state.persistent.current_term, true)
    }

    async fn install_snapshot(
        self, _: context::Context,
        term: Term,
        leader: PeerId,
        last_log_index: LogIndex,
        last_log_term: Term,
        data: Vec<u8>,
        last: bool,
    ) -> Term {
        assert!(leader != self.raft_state.read().await.persistent.keypair.public);
        let new_snapshot_state = SnapshotState {
            data: Vec::new(),
            leader,
            last_log_index,
            last_log_term
        };
        let mut snapshot_state_guard = self.snapshot.lock().await;
        let snapshot_state = snapshot_state_guard.get_or_insert_with(|| new_snapshot_state.clone());
        
        // check if leader, last_log_index, last_log_term are the same, otherwise reset snapshot state.
        // Indicates we are still handling the same update
        if *snapshot_state != new_snapshot_state {
            *snapshot_state = new_snapshot_state;
        }
        snapshot_state.data.extend_from_slice(&data);
        if last {
            let mut state = self.raft_state.write().await;

            let received_state : ClusterState = serde_json::from_slice(&snapshot_state.data).expect_or_log("Could not deserialize snapshot");
            
            state.persistent.update_term(term);
            state.set_from_raft_snapshot(received_state, last_log_index, last_log_term, leader);
        }
        term
    }
}
