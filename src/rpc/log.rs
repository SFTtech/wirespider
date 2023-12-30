use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteArguments;
use sqlx::{sqlite::SqliteRow, SqlitePool};
use tracing_unwrap::ResultExt;

use super::raft_state::Term;
use super::ClusterStateUpdate;
use getset::{CopyGetters, Setters};
use serde_json::{from_str, to_string};
use sqlx::query;
use sqlx::{prelude::*, Arguments};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogIndex(u64);

impl Into<u64> for LogIndex {
    fn into(self) -> u64 {
        self.0
    }
}

impl From<u64> for LogIndex {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl TryFrom<i64> for LogIndex {
    type Error = <u64 as TryFrom<i64>>::Error;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(LogIndex(value.try_into()?))
    }
}

impl TryInto<i64> for LogIndex {
    type Error = <u64 as TryInto<i64>>::Error;
    fn try_into(self) -> Result<i64, Self::Error> {
        Ok(self.0.try_into()?)
    }
}

#[derive(Debug, Default, CopyGetters, Setters)]
pub struct Log {
    #[getset(get_copy = "pub(crate)", set = "pub(crate)")]
    commit_index: LogIndex,
    #[getset(get_copy = "pub(crate)")]
    last_applied: LogIndex,
    #[getset(skip)]
    entries: BTreeMap<LogIndex, LogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    term: Term,
    data: ClusterStateUpdate,
}

#[derive(Error, Debug)]
pub enum LogError {
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error("Could not deserialize state")]
    DeserializeError(#[from] serde_json::Error),
}

impl Log {
    /// load log from database
    pub async fn from_db(pool: &SqlitePool) -> Result<Log, LogError> {
        let last_applied: u64 = query("SELECT value FROM keyvalue WHERE key='last_applied'")
            .fetch_one(pool)
            .await?
            .get::<i64, &str>("value")
            .try_into()
            .expect_or_log("Could not convert to u64, probably invalid data in DB");
        let last_applied = last_applied.into();
        let entries = BTreeMap::new();
        Ok(Log {
            last_applied,
            commit_index: last_applied,
            entries,
        })
    }
    /// store current log state to database, overwriting the log there
    pub async fn store(&self, pool: &SqlitePool) -> Result<(), LogError> {
        let mut transaction = pool.begin().await?;
        query("DELETE FROM log").execute(&mut *transaction).await?;
        let insert = pool
            .prepare(r#"INSERT INTO log ("index", "term", "value") VALUES (?, ?, ?)"#)
            .await?;
        for entry in &self.entries {
            let mut args = SqliteArguments::default();
            args.add(TryInto::<i64>::try_into(*entry.0).unwrap_or_log());
            args.add(TryInto::<i64>::try_into(entry.1.term).unwrap_or_log());
            args.add(to_string(&entry.1.data).unwrap_or_log());
            insert.query_with(args).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub fn reset_to(&mut self, term: Term, index: LogIndex) {
        self.entries = BTreeMap::from_iter(
            [(
                index,
                LogEntry {
                    term,
                    data: ClusterStateUpdate::Empty,
                },
            )]
            .into_iter(),
        );
        self.commit_index = index;
    }

    pub fn get_index(&self) -> LogIndex {
        return self
            .entries
            .last_key_value()
            .map(|x| *x.0)
            .unwrap_or(0.into());
    }

    pub fn last_log_term(&self) -> Term {
        self.entries
            .last_key_value()
            .map(|x| x.1.term)
            .unwrap_or(0.into())
    }

    /// check wether a certain log entry/term combination exists in the log
    pub fn contains(&self, index: LogIndex, term: Term) -> bool {
        self.entries.get(&index).map_or(false, |x| x.term == term)
    }
}

impl FromRow<'_, SqliteRow> for LogEntry {
    fn from_row(row: &SqliteRow) -> sqlx::Result<Self> {
        Ok(Self {
            term: row
                .try_get::<i64, &str>("term")?
                .try_into()
                .expect_or_log("Invalid log index"),
            data: from_str(row.try_get("data")?).expect_or_log("Error deserializing log data"),
        })
    }
}
