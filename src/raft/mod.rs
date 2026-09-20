//! Raft consensus based on openraft.
//!
//! The cluster state (peers, routes, networks, addresses) is replicated with
//! openraft; the state machine applies [`Mutation`]s to the live SQLite schema.
//! Every node applies every entry, derives client events from `apply()`, and
//! serves reads from its applied state.

pub mod entry;
pub mod envelope;
pub mod event_hub;
pub mod grpc_service;
pub mod keys;
pub mod network;
pub mod node;
pub mod raft_handle;
pub mod startup;
pub mod state_machine;
pub mod state_reader;
pub mod store;

use std::io::Cursor;

use openraft::BasicNode;
use openraft::Entry;

pub use entry::AppliedChange;
pub use entry::AppliedEvent;
pub use entry::Mutation;
pub use entry::MutationResponse;
pub use node::NodeId;
pub use state_machine::RaftStateMachine;
pub use store::RaftLogStore;
pub use store::StoreError;

openraft::declare_raft_types!(
    /// The type configuration of wirespider's raft cluster.
    pub TypeConfig:
        D = Mutation,
        R = MutationResponse,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

/// Run the database migrations on a fresh pool. Used by tests and by tests of
/// dependent crates; production startup runs them in `server_manage`.
pub async fn run_migrations(pool: &sqlx::SqlitePool) {
    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();
    MIGRATOR.run(pool).await.expect("database migration failed");
}
