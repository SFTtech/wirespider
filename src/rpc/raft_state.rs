use std::{collections::HashMap, pin::Pin};
use std::time::{Duration, Instant};

use ed25519_dalek::Keypair;
use rand::Rng;
use rand::rngs::OsRng;
use sqlx::{prelude::*, query, SqlitePool};
use serde_json::{from_str, to_string};
use futures::Future;
use tokio::time::{Sleep, sleep};
use tracing_unwrap::ResultExt;
use super::ClusterState;
use super::{PeerId, log::LogEntry};
use serde::{Serialize, Deserialize};
use thiserror::Error;

use super::log::{Log, LogError, LogIndex};

#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Term(u64);

impl Into<u64> for Term {
    fn into(self) -> u64 {
        self.0
    }
}

impl From<u64> for Term {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl TryFrom<i64> for Term {
    type Error = <u64 as TryFrom<i64>>::Error;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(Term(value.try_into()?))
    }
}

impl TryInto<i64> for Term {
    type Error = <u64 as TryInto<i64>>::Error;
    fn try_into(self) -> Result<i64, Self::Error> {
        Ok(self.0.try_into()?)
    }
}

#[derive(Clone)]
pub struct LeaderState {
    pub follower_next_index: HashMap<PeerId, u64>,
    pub follower_match_index: HashMap<PeerId, u64>,
}

pub struct RaftVolatileState {
    
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RaftPersistentState {
    pub current_term: Term,
    pub current_vote: Option<PeerId>,
    #[serde(default)]
    pub last_applied: Term,
    #[serde(skip)]
    log: Log,
    state: ClusterState,
    pub keypair: Keypair,
}

#[derive(Clone)]
pub enum RaftRole {
    /// this is the follower role without a known leader
    Initialized, 
    Follower(PeerId),
    Candidate(HashMap<PeerId, bool>),
    Leader(LeaderState),
}

/// State of the Raft consensus
pub struct RaftState {
    pool: SqlitePool,
    pub role: RaftRole,
    pub persistent: RaftPersistentState,
    pub election_timeout: ElectionTimeout,
}

#[derive(Error, Debug)]
pub enum RaftStateError {
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error("Could not deserialize state")]
    DeserializeError(#[from] serde_json::Error),
    #[error(transparent)]
    LogError(#[from] LogError),
}

impl RaftState {
    pub async fn new(pool: SqlitePool) -> Result<RaftState, RaftStateError> {
        let persistent = RaftPersistentState::from_db(&pool).await?;
        let key_bytes : Vec<u8> = query("SELECT value FROM keyvalue WHERE key='last_leader'").fetch_one(&pool).await?.try_get("value")?;
        let role = if key_bytes.is_empty() {
            RaftRole::Initialized
        } else {
            let last_known_leader = PeerId::from_bytes(&key_bytes).expect_or_log("Invalid leaderid in DB");
            RaftRole::Follower(last_known_leader)
        };

        Ok(RaftState {
            pool,
            role,
            persistent,
            election_timeout: ElectionTimeout::new(),
        })
    }

    /// write current state to database
    pub async fn commit_persistent(&self) -> Result<(), RaftStateError> {
        self.persistent.store(&self.pool).await?;
        Ok(())
    }

    pub fn set_from_raft_snapshot(&mut self, received : ClusterState, last_log_index: LogIndex, last_log_term : Term, leader: PeerId) {
        self.persistent.state = received;
        self.persistent.log.reset_to(last_log_term, last_log_index);
        self.role = RaftRole::Follower(leader);
    }

}

impl RaftPersistentState {
    pub fn new() -> RaftPersistentState {
        let mut rng = OsRng{};
        let keypair = Keypair::generate(&mut rng);
        RaftPersistentState {
            keypair,
            log: Log::default(),
            current_term: Term(0),
            current_vote: None,
            last_applied: Term(0),
            state: ClusterState::default()
        }
    }

    pub async fn from_db(pool: &SqlitePool) -> Result<RaftPersistentState, RaftStateError> {
        let data = query("SELECT value FROM keyvalue WHERE key='raft'").fetch_one(pool).await?;
        let data_str : &str = data.try_get("value")?;
        let store = if data_str.len() == 0 {
            let store = RaftPersistentState::new();
            store.store(pool).await?;
            store
        } else {
            let mut store: RaftPersistentState = from_str(data_str)?;
            store.log = Log::from_db(pool).await?;
            store
        };
        Ok(store)
    }

    pub async fn store(&self, pool: &SqlitePool) -> Result<(), RaftStateError> {
        query("UPDATE keyvalue SET value=? WHERE key='raft'").bind(to_string(self)?).execute(pool).await?;
        self.log.store(pool).await?;
        Ok(())
    }

    pub fn get_log_index(&self) -> LogIndex {
        self.log.get_index()
    }

    /// this is the last entry that was commited to the state
    pub fn get_log_commited(&self) -> LogIndex {
        self.log.commit_index()
    }

    /// this 
    pub fn get_log_term(&self) -> Term {
        self.log.last_log_term()
    }

    pub fn log_contains(&self, index: LogIndex, term: Term) -> bool {
        self.log.contains(index, term)
    }

    pub fn log_append(&mut self, _entries: Vec<LogEntry>) {
        todo!()
    }

    pub async fn commit_until(&mut self, _leader_commit_index: LogIndex) {
        todo!()
    }

    /**
    update the term to the given term
    if the given term is lower or equal to the current term, nothing happens.
    if the given term is higher the stored term is updated and the current vote is discarded
    */
    pub fn update_term(&mut self, new_term: Term) {
        if self.current_term < new_term {
            self.current_term = new_term;
            self.current_vote = None;
        }
    }

}

#[derive(Debug)]
pub struct ElectionTimeout {
    minimum_timeout_ms: u64,
    maximum_timeout_ms: u64,
    timer: Pin<Box<Sleep>>,
}

impl Future for ElectionTimeout {
    type Output = ();

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        self.timer.as_mut().poll(cx)
    }
}

impl ElectionTimeout {
    pub fn reset(&mut self) {
        let timeout = Duration::from_millis(rand::thread_rng().gen_range(self.minimum_timeout_ms..self.maximum_timeout_ms));
        self.timer.as_mut().reset(Instant::now().checked_add(timeout).ok_or("invalid timeout").unwrap_or_log().into());
    }

    fn new() -> ElectionTimeout {
        //TODO: make this configurable
        let minimum = 1000;
        let maximum = 10000;
        let duration = Duration::from_millis(rand::thread_rng().gen_range(minimum..maximum));
        ElectionTimeout { minimum_timeout_ms: minimum, maximum_timeout_ms: maximum, timer: Box::pin(sleep(duration)) }
    }
}

#[cfg(test)]
mod tests {
    use sqlx::migrate::Migrator;
    use sqlx::sqlite::SqlitePool;

    use super::RaftState;

    static MIGRATOR: Migrator = sqlx::migrate!();

    async fn get_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_commit_raft_state_persistant() {
        let pool = get_pool().await;
        let state = RaftState::new(pool).await.unwrap();
        state.commit_persistent().await.unwrap();
    }

}