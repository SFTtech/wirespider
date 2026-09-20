use openraft::testing::Suite;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePool;
use std::str::FromStr;

use wirespider::raft::state_machine::RaftStateMachine;
use wirespider::raft::store::RaftLogStore;
use wirespider::raft::TypeConfig;

/// Builds a raft store backed by a fresh in-memory SQLite database.
struct SqliteStoreBuilder;

impl openraft::testing::StoreBuilder<TypeConfig, RaftLogStore, RaftStateMachine, ()>
    for SqliteStoreBuilder
{
    async fn build(
        &self,
    ) -> Result<((), RaftLogStore, RaftStateMachine), wirespider::raft::StoreError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("valid sqlite url")
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Full);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        wirespider::raft::run_migrations(&pool).await;
        Ok((
            (),
            RaftLogStore::new(pool.clone()),
            RaftStateMachine::new(pool, None),
        ))
    }
}

#[test]
pub fn test_storage_suite() {
    Suite::<TypeConfig, RaftLogStore, RaftStateMachine, _, ()>::test_all(SqliteStoreBuilder)
        .expect("storage test suite");
}
