use std::{collections::HashSet, pin::Pin};
use std::time::{Duration, Instant};

use rand::Rng;
use sqlx::{prelude::*, query, SqlitePool};
use serde_json::{from_str, to_string};
use futures::Future;
use tokio::time::{Sleep, sleep};
use tracing_unwrap::ResultExt;
use super::{PeerId, log::LogEntry};
use serde::{Serialize, Deserialize};
use thiserror::Error;

use super::log::{Log, LogError};


#[derive(Clone)]
pub struct LeaderState {
    pub follower_next_index: HashSet<PeerId, u64>,
    pub follower_match_index: HashSet<PeerId, u64>,
}

pub struct RaftVolatileState {
    
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RaftPersistentState {
    pub current_term: u64,
    pub current_vote: Option<PeerId>,
    pub last_applied: u64,
    #[serde(skip)]
    log: Log,
}

#[derive(Clone)]
pub enum RaftRole {
    Follower(PeerId),
    Candidate(HashSet<PeerId, bool>),
    Leader(LeaderState),
}

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
    async fn new(pool: SqlitePool) -> Result<RaftState, RaftStateError> {
        let persistent = RaftPersistentState::from_db(&pool).await?;
        let key_bytes : Vec<u8> = query("SELECT FROM settings WHERE name='last_leader'").fetch_one(&pool).await?.try_get("value")?;
        let last_known_leader = PeerId::from_bytes(&key_bytes).expect_or_log("Invalid leaderid in DB");
        let last_commited = persistent.get_log_commited();
        Ok(RaftState {
            pool,
            role: RaftRole::Follower(last_known_leader),
            persistent: persistent,
            election_timeout: ElectionTimeout::new(),
        })
    }

    pub async fn commit_persistent(&self) -> Result<(), RaftStateError> {
        self.persistent.store(&self.pool).await?;
        Ok(())
    }


}

impl RaftPersistentState {
    async fn from_db(pool: &SqlitePool) -> Result<RaftPersistentState, RaftStateError> {
        let data = query("SELECT FROM settings WHERE name='raft'").fetch_one(pool).await?;
        let mut store: RaftPersistentState = from_str(data.try_get("value")?)?;
        store.log = Log::from_db(pool).await?;
        return Ok(store);
    }

    async fn store(&self, pool: &SqlitePool) -> Result<(), RaftStateError> {
        query("UPDATE settings WHERE name='raft' SET value=?").bind(to_string(self)?).execute(pool).await?;
        self.log.store(pool).await?;
        Ok(())
    }

    pub fn get_log_index(&self) -> u64 {
        self.log.get_index()
    }

    pub fn get_log_commited(&self) -> u64 {
        self.log.commit_index()
    }

    pub fn get_log_term(&self) -> u64 {
        self.log.last_log_term()
    }

    pub fn log_contains(&self, index: u64, term: u64) -> bool {
        self.log.contains(index, term)
    }

    pub fn log_append(&mut self, entries: Vec<LogEntry>) {
        
    }

    pub async fn commit_until(&mut self, leader_commit_index: u64) {
        todo!()
    }


}

fn default_sleep() -> Pin<Box<Sleep>> {
    Box::pin(sleep(Duration::from_secs(3600)))
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