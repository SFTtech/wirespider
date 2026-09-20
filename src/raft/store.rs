use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::LogFlushed;
use openraft::storage::LogState;
use openraft::storage::RaftLogReader;
use openraft::storage::RaftLogStorage;
use openraft::AnyError;
use openraft::LogId;
use openraft::OptionalSend;
use openraft::RaftTypeConfig;
use openraft::StorageError;
use openraft::StorageIOError;
use openraft::Vote;
use serde::de::DeserializeOwned;
use serde_json::from_slice;
use serde_json::to_vec;
use sqlx::Row;
use tokio::sync::Mutex;

use super::NodeId;
use super::TypeConfig;

pub type StoreError = StorageError<NodeId>;

/// openraft log storage backed by SQLite.
///
/// Every write is committed with `PRAGMA synchronous = FULL` before its
/// completion callback fires, so acknowledged log IO survives power loss.
/// All mutating log IO is serialized through one mutex, as openraft requires:
/// vote and log writes must not be reordered.
#[derive(Debug, Clone)]
pub struct RaftLogStore {
    pool: sqlx::SqlitePool,
    /// Serializes all mutating log IO (append/truncate/purge/vote).
    io_lock: Arc<Mutex<()>>,
}

impl RaftLogStore {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self {
            pool,
            io_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn read_meta<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        let row = sqlx::query("SELECT value FROM raft_meta WHERE key=?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::IO {
                source: StorageIOError::read(AnyError::new(&e)),
            })?;
        match row {
            None => Ok(None),
            Some(row) => {
                let bytes: Vec<u8> = row.try_get("value").map_err(|e| StorageError::IO {
                    source: StorageIOError::read(AnyError::new(&e)),
                })?;
                from_slice(&bytes).map(Some).map_err(|e| StorageError::IO {
                    source: StorageIOError::read(AnyError::new(&e)),
                })
            }
        }
    }

    async fn set_meta<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), StoreError> {
        let data = to_vec(value).map_err(|e| StorageError::IO {
            source: StorageIOError::write(AnyError::new(&e)),
        })?;
        sqlx::query("INSERT INTO raft_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            .bind(key)
            .bind(data)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::IO {
                source: StorageIOError::write(AnyError::new(&e)),
            })?;
        Ok(())
    }

    /// Read the log id stored in the last present entry (or purged/None).
    async fn last_entry_log_id(&self) -> Result<Option<LogId<NodeId>>, StoreError> {
        let row = sqlx::query(r#"SELECT entry FROM raft_log ORDER BY "index" DESC LIMIT 1"#)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(AnyError::new(&e)),
            })?;
        if let Some(row) = row {
            let bytes: Vec<u8> = row.try_get("entry").map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(AnyError::new(&e)),
            })?;
            let entry: openraft::Entry<TypeConfig> =
                from_slice(&bytes).map_err(|e| StorageError::IO {
                    source: StorageIOError::read_logs(AnyError::new(&e)),
                })?;
            return Ok(Some(entry.log_id));
        }
        self.read_meta::<LogId<NodeId>>("last_purged").await
    }
}

impl RaftLogReader<TypeConfig> for RaftLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<<TypeConfig as RaftTypeConfig>::Entry>, StoreError> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(x) => *x as i64,
            std::ops::Bound::Excluded(x) => *x as i64 + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let stop = match range.end_bound() {
            std::ops::Bound::Included(x) => *x as i64 + 1,
            std::ops::Bound::Excluded(x) => *x as i64,
            std::ops::Bound::Unbounded => i64::MAX,
        };
        let rows = sqlx::query(
            r#"SELECT entry FROM raft_log WHERE "index" >= ? AND "index" < ? ORDER BY "index""#,
        )
        .bind(start)
        .bind(stop)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(AnyError::new(&e)),
        })?;
        rows.into_iter()
            .map(|row| {
                let bytes: Vec<u8> = row.try_get("entry").map_err(|e| StorageError::IO {
                    source: StorageIOError::read_logs(AnyError::new(&e)),
                })?;
                from_slice(&bytes).map_err(|e| StorageError::IO {
                    source: StorageIOError::read_logs(AnyError::new(&e)),
                })
            })
            .collect()
    }
}

impl RaftLogStorage<TypeConfig> for RaftLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StoreError> {
        let last_purged: Option<LogId<NodeId>> = self.read_meta("last_purged").await?;
        let last = self.last_entry_log_id().await?;
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StoreError> {
        let _guard = self.io_lock.lock().await;
        self.set_meta("vote", vote).await
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StoreError> {
        self.read_meta("vote").await
    }

    async fn save_committed(&mut self, committed: Option<LogId<NodeId>>) -> Result<(), StoreError> {
        let _guard = self.io_lock.lock().await;
        self.set_meta("committed", &committed).await
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StoreError> {
        self.read_meta("committed").await
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StoreError>
    where
        I: IntoIterator<Item = <TypeConfig as RaftTypeConfig>::Entry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let _guard = self.io_lock.lock().await;
        let mut transaction = self.pool.begin().await.map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(AnyError::new(&e)),
        })?;
        for entry in entries {
            let index: i64 = entry.log_id.index.try_into().map_err(|_| StoreError::IO {
                source: StorageIOError::write_logs(AnyError::error("log index overflow")),
            })?;
            let term: i64 = entry
                .log_id
                .leader_id
                .term
                .try_into()
                .map_err(|_| StoreError::IO {
                    source: StorageIOError::write_logs(AnyError::error("log term overflow")),
                })?;
            let payload = to_vec(&entry).map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(AnyError::new(&e)),
            })?;
            sqlx::query(r#"INSERT INTO raft_log ("index", term, entry) VALUES (?, ?, ?)"#)
                .bind(index)
                .bind(term)
                .bind(payload)
                .execute(&mut *transaction)
                .await
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_logs(AnyError::new(&e)),
                })?;
        }
        transaction.commit().await.map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(AnyError::new(&e)),
        })?;
        // SQLite committed with synchronous=FULL: the entries are on disk.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StoreError> {
        let _guard = self.io_lock.lock().await;
        sqlx::query(r#"DELETE FROM raft_log WHERE "index" >= ?"#)
            .bind(log_id.index as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(AnyError::new(&e)),
            })?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StoreError> {
        let _guard = self.io_lock.lock().await;
        let mut transaction = self.pool.begin().await.map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(AnyError::new(&e)),
        })?;
        sqlx::query(r#"DELETE FROM raft_log WHERE "index" <= ?"#)
            .bind(log_id.index as i64)
            .execute(&mut *transaction)
            .await
            .map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(AnyError::new(&e)),
            })?;
        let data = to_vec(&log_id).map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(AnyError::new(&e)),
        })?;
        sqlx::query(
            "INSERT INTO raft_meta (key, value) VALUES ('last_purged', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        )
        .bind(data)
        .execute(&mut *transaction)
        .await
        .map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(AnyError::new(&e)),
        })?;
        transaction.commit().await.map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(AnyError::new(&e)),
        })?;
        Ok(())
    }
}
