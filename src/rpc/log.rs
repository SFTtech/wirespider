use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteArguments;
use sqlx::{sqlite::SqliteRow, SqlitePool};
use tracing_unwrap::ResultExt;

use super::{ClusterStateUpdate, NodeState};
use serde_json::{from_str, to_string};
use sqlx::query;
use sqlx::{prelude::*, Arguments};
use std::collections::BTreeMap;
use thiserror::Error;
use getset::{CopyGetters, Setters};

#[derive(Debug, Default, CopyGetters, Setters)]
pub struct Log {
    #[getset(get_copy = "pub(crate)", set = "pub(crate)") ]
    commit_index: u64,
    #[getset(get_copy = "pub(crate)")]
    last_applied: u64,
    #[getset(skip)]
    entries: BTreeMap<u64, LogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    term: u64,
    data: LogData,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LogData {
    Command(ClusterStateUpdate),
    Snapshot(NodeState),
}

#[derive(Error, Debug)]
pub enum LogError {
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error("Could not deserialize state")]
    DeserializeError(#[from] serde_json::Error),
}

impl Log {
    pub async fn from_db(pool: &SqlitePool) -> Result<Log, LogError> {
        let mut connection = pool.acquire().await?;
        let last_applied = query("SELECT value FROM state WHERE key='last_applied'")
            .fetch_one(&mut connection)
            .await?
            .get::<i64, &str>("value")
            .try_into()
            .expect_or_log("Could not convert to u64, probably invalid data in DB");
        let entries = BTreeMap::new();
        Ok(Log {
            last_applied,
            commit_index: last_applied,
            entries,
        })
    }
    pub async fn store(&self, pool: &SqlitePool) -> Result<(), LogError> {
        let mut transaction = pool.begin().await?;
        query("DELETE FROM log").execute(&mut transaction).await?;
        let insert = pool
            .prepare("INSERT INTO log (index, term, value) VALUES (?, ?, ?)")
            .await?;
        for entry in &self.entries {
            let mut args = SqliteArguments::default();
            args.add(TryInto::<i64>::try_into(*entry.0).unwrap_or_log());
            args.add(TryInto::<i64>::try_into(entry.1.term).unwrap_or_log());
            args.add(to_string(&entry.1.data).unwrap_or_log());
            insert.query_with(args).execute(&mut transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub fn get_index(&self) -> u64 {
        return self.entries.last_key_value().map(|x| *x.0).unwrap_or(0);
    }

    pub fn last_log_term(&self) -> u64 {
        self.entries.last_key_value().map(|x| x.1.term).unwrap_or(0)
    }

    pub fn contains(&self, index: u64, term: u64) -> bool {
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
