use std::io::Cursor;
use std::net::IpAddr;

use ipnet::IpNet;
use openraft::entry::EntryPayload;
use openraft::storage::RaftSnapshotBuilder;
use openraft::storage::RaftStateMachine as StateMachineTrait;
use openraft::storage::Snapshot;
use openraft::storage::SnapshotMeta;
use openraft::AnyError;
use openraft::BasicNode;
use openraft::LogId;
use openraft::OptionalSend;
use openraft::RaftTypeConfig;
use openraft::StorageIOError;
use openraft::StoredMembership;
use serde::Deserialize;
use serde::Serialize;
use serde_json::from_slice;
use serde_json::to_vec;
use sqlx::Row;

use super::entry::AppliedChange;
use super::entry::AppliedEvent;
use super::entry::Mutation;
use super::entry::MutationResponse;
use super::state_reader::peer_proto;
use super::NodeId;
use super::StoreError;
use super::TypeConfig;

/// State machine over the live SQLite schema.
///
/// `apply()` runs every committed mutation inside one SQLite transaction and
/// notifies the event hub of the resulting changes. Because every node applies
/// the same mutations in the same order, all nodes converge to identical state.
pub struct RaftStateMachine {
    pool: sqlx::SqlitePool,
    /// Event hub: gets one notification per applied change. `None` in tests.
    events: Option<tokio::sync::mpsc::UnboundedSender<AppliedEvent>>,
}

/// Serializable dump of the state machine, used as snapshot payload.
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotBlob {
    last_log_id: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, BasicNode>,
    users: Vec<SnapshotUserRow>,
    peers: Vec<SnapshotPeerRow>,
    networks: Vec<SnapshotNetworkRow>,
    addresses: Vec<SnapshotAddressRow>,
    routes: Vec<SnapshotRouteRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotPeerRow {
    peerid: i64,
    peer_name: String,
    token: Vec<u8>,
    pubkey: Option<Vec<u8>>,
    permissions: i32,
    current_endpoint: Option<String>,
    nat_type: i32,
    monitor: bool,
    relay: bool,
    local_ips: Option<String>,
    local_port: Option<i64>,
    user_id: Option<i64>,
    raft_pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotUserRow {
    userid: i64,
    user_name: String,
    permissions: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotNetworkRow {
    networkid: i64,
    network: String,
    ipv6: bool,
    network_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotAddressRow {
    addressid: i64,
    networkid: i64,
    peerid: i64,
    ip_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotRouteRow {
    addressid: i64,
    destination: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSnapshot {
    meta: openraft::SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

/// Maximum routes announced via one peer. Prevents route churn from
/// flooding the raft log; the cap is enforced in apply() on every node.
const ROUTES_PER_PEER_LIMIT: usize = 1000;

fn write_err(e: sqlx::Error) -> StoreError {
    StoreError::IO {
        source: StorageIOError::write_state_machine(AnyError::new(&e)),
    }
}

fn read_err(e: sqlx::Error) -> StoreError {
    StoreError::IO {
        source: StorageIOError::read_state_machine(AnyError::new(&e)),
    }
}

fn ser_err(e: serde_json::Error) -> StoreError {
    StoreError::IO {
        source: StorageIOError::write_state_machine(AnyError::new(&e)),
    }
}

impl RaftStateMachine {
    pub fn new(
        pool: sqlx::SqlitePool,
        events: Option<tokio::sync::mpsc::UnboundedSender<AppliedEvent>>,
    ) -> Self {
        Self { pool, events }
    }

    /// Apply one mutation inside a transaction. Returns the response and the
    /// changes to report to the event hub.
    async fn apply_mutation(
        tx: &mut sqlx::SqliteConnection,
        mutation: &Mutation,
    ) -> Result<(MutationResponse, Vec<AppliedChange>), StoreError> {
        match mutation {
            Mutation::Noop => Ok((MutationResponse::default(), Vec::new())),

            Mutation::CreateUser { name, permissions } => {
                sqlx::query("INSERT OR IGNORE INTO users (user_name, permissions) VALUES (?, ?)")
                    .bind(name)
                    .bind(permissions)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::SetUserPermissions {
                user_id,
                permissions,
            } => {
                sqlx::query("UPDATE users SET permissions=? WHERE userid=?")
                    .bind(permissions)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::DeleteUser { user_id } => {
                // ownership link is dropped (ON DELETE SET NULL); nodes keep
                // running, their tokens stay valid until the node is deleted
                sqlx::query("DELETE FROM users WHERE userid=?")
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::RecordRaftNode {
                raft_pubkey,
                advertise,
            } => {
                // Upsert by raft pubkey: re-joining updates the address.
                // Server nodes have no wireguard key or enrollment token.
                sqlx::query(
                    "INSERT INTO peers (peer_name, token, permissions, raft_pubkey) VALUES (?, ?, 0, ?) \
                     ON CONFLICT(raft_pubkey) DO UPDATE SET current_endpoint=excluded.current_endpoint",
                )
                .bind(format!("raft-{}", NodeId::from_bytes(*raft_pubkey).short()))
                .bind(uuid::Uuid::new_v4())
                .bind(raft_pubkey.to_vec())
                .bind(advertise)
                .execute(&mut *tx)
                .await
                .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::AddPeer {
                user_id,
                name,
                token,
                permissions,
                addresses,
            } => {
                // The permission cap is re-checked at apply time so the log
                // can never contain a node more powerful than its owner.
                let owner_permissions: Option<i32> = match user_id {
                    Some(user_id) => {
                        let row = sqlx::query("SELECT permissions FROM users WHERE userid=?")
                            .bind(user_id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(write_err)?;
                        match row {
                            Some(row) => Some(row.try_get("permissions").map_err(write_err)?),
                            None => return Ok((MutationResponse::default(), Vec::new())),
                        }
                    }
                    None => None,
                };
                let permissions = match owner_permissions {
                    Some(owner) if owner < *permissions => owner,
                    _ => *permissions,
                };
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO peers (peer_name, token, permissions, user_id) VALUES (?, ?, ?, ?)",
                )
                .bind(name)
                .bind(token)
                .bind(permissions)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(write_err)?;
                let peerid = result.last_insert_rowid();
                for addr in addresses {
                    let net = addr.trunc();
                    let Some(row) =
                        sqlx::query("SELECT networkid FROM networks WHERE network=? AND ipv6=?")
                            .bind(net.to_string())
                            .bind(matches!(net, ipnet::IpNet::V6(_)))
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(write_err)?
                    else {
                        continue;
                    };
                    let networkid: i64 = row.try_get("networkid").map_err(write_err)?;
                    sqlx::query(
                        "INSERT OR IGNORE INTO addresses (peerid, networkid, ip_address) VALUES (?, ?, ?)",
                    )
                    .bind(peerid)
                    .bind(networkid)
                    .bind(addr.addr().to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                }
                Ok((
                    MutationResponse {
                        token: Some(*token),
                    },
                    Vec::new(),
                ))
            }

            Mutation::DeletePeer { peer_id } => {
                let old = peer_proto(&mut *tx, *peer_id).await.map_err(write_err)?;
                sqlx::query("DELETE FROM routes WHERE addressid IN (SELECT addressid FROM addresses WHERE peerid=?)")
                    .bind(peer_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                sqlx::query("DELETE FROM peers WHERE peerid=?")
                    .bind(peer_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                let changes = old
                    .map(|p| vec![AppliedChange::PeerDeleted(*peer_id, p)])
                    .unwrap_or_default();
                Ok((MutationResponse::default(), changes))
            }

            Mutation::SetPeerPermissions {
                peer_id,
                permissions,
            } => {
                sqlx::query("UPDATE peers SET permissions=? WHERE peerid=?")
                    .bind(permissions)
                    .bind(peer_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::SetPeerOwner { peer_id, user_id } => {
                // Deterministic no-op if the user does not exist (FK would
                // fail otherwise).
                let exists = sqlx::query("SELECT 1 FROM users WHERE userid=?")
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(write_err)?
                    .is_some();
                if exists {
                    sqlx::query("UPDATE peers SET user_id=? WHERE peerid=?")
                        .bind(user_id)
                        .bind(peer_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(write_err)?;
                }
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::SetPeerEndpoint { peer_id, endpoint } => {
                sqlx::query("UPDATE peers SET current_endpoint=? WHERE peerid=?")
                    .bind(endpoint)
                    .bind(peer_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                let peer = peer_proto(&mut *tx, *peer_id).await.map_err(write_err)?;
                Ok((
                    MutationResponse::default(),
                    peer.map(|p| vec![AppliedChange::PeerChanged(p)])
                        .unwrap_or_default(),
                ))
            }

            Mutation::UpdatePeerState {
                peer_id,
                pubkey,
                endpoint,
                nat_type,
                monitor,
                relay,
                local_ips,
                local_port,
            } => {
                let old = peer_state_row(tx, *peer_id).await?;
                let new_key: Option<Vec<u8>> = pubkey.map(|k| k.to_vec());
                let key_changed =
                    new_key.is_some() && old.as_ref().and_then(|o| o.pubkey.clone()) != new_key;
                let old_peer = if key_changed {
                    peer_proto(&mut *tx, *peer_id).await.map_err(write_err)?
                } else {
                    None
                };

                sqlx::query(
                    "UPDATE peers SET pubkey=?, nat_type=?, monitor=?, relay=?, current_endpoint=?, local_ips=?, local_port=? WHERE peerid=?",
                )
                .bind(new_key)
                .bind(nat_type)
                .bind(monitor)
                .bind(relay)
                .bind(endpoint)
                .bind(local_ips.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(","))
                .bind(local_port.map(i64::from))
                .bind(peer_id)
                .execute(&mut *tx)
                .await
                .map_err(write_err)?;

                let mut changes = Vec::new();
                if key_changed {
                    if let Some(old) = old_peer {
                        changes.push(AppliedChange::PeerDeleted(*peer_id, old));
                    }
                    if let Some(new) = peer_proto(&mut *tx, *peer_id).await.map_err(write_err)? {
                        changes.push(AppliedChange::PeerNew(*peer_id, new));
                    }
                } else {
                    let state_changed = match &old {
                        None => false,
                        Some(old) => {
                            old.endpoint != *endpoint
                                || old.nat_type != *nat_type
                                || old.monitor != *monitor
                                || old.relay != *relay
                        }
                    };
                    if state_changed {
                        if let Some(new) =
                            peer_proto(&mut *tx, *peer_id).await.map_err(write_err)?
                        {
                            changes.push(AppliedChange::PeerChanged(new));
                        }
                    }
                }
                Ok((MutationResponse::default(), changes))
            }

            Mutation::AddRoute {
                destination,
                via_ip,
            } => {
                // Apply-time validation: the via address must belong to a
                // peer of this cluster. Every node enforces this identically,
                // so the log can never contain a dangling route.
                let Some(addressid) =
                    sqlx::query("SELECT addressid FROM addresses WHERE ip_address=?")
                        .bind(via_ip.to_string())
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(write_err)?
                        .and_then(|row| row.try_get::<i64, _>("addressid").ok())
                else {
                    return Ok((MutationResponse::default(), Vec::new()));
                };
                // Per-owner route cap: prevent route churn from flooding the
                // log. The owner is the peer holding the via address.
                let peer_id: Option<i64> =
                    sqlx::query("SELECT peerid FROM addresses WHERE addressid=?")
                        .bind(addressid)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(write_err)?
                        .and_then(|row| row.try_get("peerid").ok());
                if let Some(peer_id) = peer_id {
                    let count: i64 = sqlx::query(
                        "SELECT COUNT(*) FROM routes WHERE addressid IN (SELECT addressid FROM addresses WHERE peerid=?)",
                    )
                    .bind(peer_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(write_err)?
                    .try_get(0)
                    .map_err(write_err)?;
                    if count >= ROUTES_PER_PEER_LIMIT as i64 {
                        // deterministic no-op: the cap is hit
                        return Ok((MutationResponse::default(), Vec::new()));
                    }
                }
                sqlx::query("INSERT OR IGNORE INTO routes (addressid, destination) VALUES (?, ?)")
                    .bind(addressid)
                    .bind(destination.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                Ok((
                    MutationResponse::default(),
                    vec![AppliedChange::RouteAdded(route_proto(
                        *destination,
                        *via_ip,
                    ))],
                ))
            }

            Mutation::DeleteRoute {
                destination,
                via_ip,
            } => {
                let result = sqlx::query(
                    "DELETE FROM routes WHERE addressid=(SELECT addressid FROM addresses WHERE ip_address=?) AND destination=?",
                )
                .bind(via_ip.to_string())
                .bind(destination.to_string())
                .execute(&mut *tx)
                .await
                .map_err(write_err)?;
                let changes = if result.rows_affected() > 0 {
                    vec![AppliedChange::RouteDeleted(route_proto(
                        *destination,
                        *via_ip,
                    ))]
                } else {
                    Vec::new()
                };
                Ok((MutationResponse::default(), changes))
            }

            Mutation::AddNetwork { net, network_type } => {
                sqlx::query(
                    "INSERT OR IGNORE INTO networks (network, ipv6, network_type) VALUES (?, ?, ?)",
                )
                .bind(net.to_string())
                .bind(matches!(net, ipnet::IpNet::V6(_)))
                .bind(network_type.as_str())
                .execute(&mut *tx)
                .await
                .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }

            Mutation::DeleteNetwork { net } => {
                let _ipv6 = matches!(net, IpNet::V6(_));
                sqlx::query("DELETE FROM routes WHERE addressid IN (SELECT addressid FROM addresses WHERE networkid IN (SELECT networkid FROM networks WHERE network=? AND ipv6=?))")
                    .bind(net.to_string())
                    .bind(matches!(net, IpNet::V6(_)))
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                sqlx::query("DELETE FROM addresses WHERE networkid IN (SELECT networkid FROM networks WHERE network=? AND ipv6=?)")
                    .bind(net.to_string())
                    .bind(matches!(net, IpNet::V6(_)))
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                sqlx::query("DELETE FROM networks WHERE network=? AND ipv6=?")
                    .bind(net.to_string())
                    .bind(matches!(net, ipnet::IpNet::V6(_)))
                    .execute(&mut *tx)
                    .await
                    .map_err(write_err)?;
                Ok((MutationResponse::default(), Vec::new()))
            }
        }
    }
}

/// Old state of a peer row, for deciding which events an update produces.
struct PeerStateRow {
    pubkey: Option<Vec<u8>>,
    endpoint: Option<String>,
    nat_type: i32,
    monitor: bool,
    relay: bool,
}

async fn peer_state_row(
    tx: &mut sqlx::SqliteConnection,
    peerid: i64,
) -> Result<Option<PeerStateRow>, StoreError> {
    let Some(row) = sqlx::query(
        "SELECT pubkey, current_endpoint, nat_type, monitor, relay FROM peers WHERE peerid=?",
    )
    .bind(peerid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(write_err)?
    else {
        return Ok(None);
    };
    Ok(Some(PeerStateRow {
        pubkey: row.try_get("pubkey").map_err(write_err)?,
        endpoint: row.try_get("current_endpoint").map_err(write_err)?,
        nat_type: row.try_get("nat_type").map_err(write_err)?,
        monitor: row.try_get("monitor").map_err(write_err)?,
        relay: row.try_get("relay").map_err(write_err)?,
    }))
}

fn route_proto(destination: IpNet, via_ip: IpAddr) -> crate::protocol::Route {
    crate::protocol::Route {
        to: Some(destination.into()),
        via: Some(via_ip.into()),
    }
}

impl StateMachineTrait<TypeConfig> for RaftStateMachine {
    type SnapshotBuilder = StateMachineSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StoreError> {
        let last_applied = read_meta(&self.pool, "last_applied").await?;
        let membership = read_meta(&self.pool, "last_membership")
            .await?
            .unwrap_or_default();
        Ok((last_applied, membership))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<MutationResponse>, StoreError>
    where
        I: IntoIterator<Item = <TypeConfig as RaftTypeConfig>::Entry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut tx = self.pool.begin().await.map_err(write_err)?;
        let mut responses = Vec::new();
        let mut events = Vec::new();
        let mut applied_indexes: Vec<u64> = Vec::new();
        for entry in entries {
            let log_id = entry.log_id;
            applied_indexes.push(log_id.index);
            let (response, changes) = match entry.payload {
                EntryPayload::Blank => (MutationResponse::default(), Vec::new()),
                EntryPayload::Membership(membership) => {
                    let stored = StoredMembership::new(Some(log_id), membership);
                    write_meta(&mut tx, "last_membership", &stored).await?;
                    (MutationResponse::default(), Vec::new())
                }
                EntryPayload::Normal(mutation) => Self::apply_mutation(&mut tx, &mutation).await?,
            };
            write_meta(&mut tx, "last_applied", &log_id).await?;
            for change in changes {
                events.push(AppliedEvent {
                    index: log_id.index,
                    change,
                });
            }
            responses.push(response);
        }
        tx.commit().await.map_err(write_err)?;
        tracing::debug!(indexes = ?applied_indexes, "apply batch committed");
        if let Some(hub) = &self.events {
            for event in events {
                let _ = hub.send(event);
            }
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        StateMachineSnapshotBuilder {
            pool: self.pool.clone(),
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, StoreError> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StoreError> {
        // Staleness guard: never restore a snapshot older than the applied
        // state. A lagging sender can offer an outdated snapshot; restoring
        // it would roll back committed state (observed as "data disappears"
        // on a learner). openraft tolerates an Ok response here and
        // continues with log replication.
        let current: Option<openraft::LogId<NodeId>> =
            read_meta(&self.pool, "last_applied").await?;
        if let (Some(current), Some(snapshot_last)) = (&current, &meta.last_log_id) {
            if snapshot_last <= current {
                tracing::info!(
                    "ignoring stale snapshot at {:?}; applied is {:?}",
                    snapshot_last,
                    current
                );
                return Ok(());
            }
        }
        let blob: SnapshotBlob = from_slice(snapshot.get_ref()).map_err(ser_err)?;
        let mut tx = self.pool.begin().await.map_err(write_err)?;
        restore_snapshot(&mut tx, &blob).await?;
        write_meta(&mut tx, "last_applied", &blob.last_log_id).await?;
        write_meta(&mut tx, "last_membership", &blob.membership).await?;
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: snapshot.get_ref().clone(),
        };
        write_meta(&mut tx, "snapshot", &stored).await?;
        tx.commit().await.map_err(write_err)?;
        let peers_restored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM peers")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(-1);
        tracing::info!(
            snapshot_index = meta.last_log_id.as_ref().map(|l| l.index),
            peers_restored,
            "snapshot installed"
        );
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TypeConfig>>, StoreError> {
        let stored: Option<StoredSnapshot> = read_meta(&self.pool, "snapshot").await?;
        Ok(stored.map(|stored| Snapshot {
            meta: stored.meta,
            snapshot: Box::new(Cursor::new(stored.data)),
        }))
    }
}

/// Builds a consistent snapshot of the state machine tables.
pub struct StateMachineSnapshotBuilder {
    pool: sqlx::SqlitePool,
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StoreError> {
        let blob = dump_snapshot(&self.pool).await?;
        let index = blob.last_log_id.as_ref().map(|x| x.index).unwrap_or(0);
        let data = to_vec(&blob).map_err(ser_err)?;
        let meta = SnapshotMeta {
            last_log_id: blob.last_log_id,
            last_membership: blob.membership.clone(),
            snapshot_id: format!("{:020}", index),
        };
        // Persist the snapshot so get_current_snapshot returns it, per the
        // RaftStateMachine contract.
        let mut tx = self.pool.begin().await.map_err(write_err)?;
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        write_meta(&mut tx, "snapshot", &stored).await?;
        tx.commit().await.map_err(write_err)?;
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

async fn read_meta<T: serde::de::DeserializeOwned>(
    pool: &sqlx::SqlitePool,
    key: &str,
) -> Result<Option<T>, StoreError> {
    let row = sqlx::query("SELECT value FROM raft_meta WHERE key=?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(read_err)?;
    match row {
        None => Ok(None),
        Some(row) => {
            let bytes: Vec<u8> = row.try_get("value").map_err(read_err)?;
            from_slice(&bytes).map(Some).map_err(ser_err)
        }
    }
}

async fn write_meta<T: serde::Serialize>(
    tx: &mut sqlx::SqliteConnection,
    key: &str,
    value: &T,
) -> Result<(), StoreError> {
    let data = to_vec(value).map_err(ser_err)?;
    sqlx::query("INSERT INTO raft_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(key)
        .bind(data)
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    Ok(())
}

async fn dump_snapshot(pool: &sqlx::SqlitePool) -> Result<SnapshotBlob, StoreError> {
    let mut tx = pool.begin().await.map_err(read_err)?;
    let mut users = Vec::new();
    let user_rows = sqlx::query("SELECT userid, user_name, permissions FROM users")
        .fetch_all(&mut *tx)
        .await
        .map_err(read_err)?;
    for row in user_rows {
        users.push(SnapshotUserRow {
            userid: row.try_get("userid").map_err(read_err)?,
            user_name: row.try_get("user_name").map_err(read_err)?,
            permissions: row.try_get("permissions").map_err(read_err)?,
        });
    }

    let mut peers = Vec::new();
    let rows = sqlx::query(
        "SELECT peerid, peer_name, token, pubkey, permissions, current_endpoint, nat_type, monitor, relay, local_ips, local_port, user_id, raft_pubkey FROM peers",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(read_err)?;
    for row in rows {
        peers.push(SnapshotPeerRow {
            peerid: row.try_get("peerid").map_err(read_err)?,
            peer_name: row.try_get("peer_name").map_err(read_err)?,
            token: row.try_get("token").map_err(read_err)?,
            pubkey: row.try_get("pubkey").map_err(read_err)?,
            permissions: row.try_get("permissions").map_err(read_err)?,
            current_endpoint: row.try_get("current_endpoint").map_err(read_err)?,
            nat_type: row.try_get("nat_type").map_err(read_err)?,
            monitor: row.try_get("monitor").map_err(read_err)?,
            relay: row.try_get("relay").map_err(read_err)?,
            local_ips: row.try_get("local_ips").map_err(read_err)?,
            local_port: row.try_get("local_port").map_err(read_err)?,
            user_id: row.try_get("user_id").map_err(read_err)?,
            raft_pubkey: row.try_get("raft_pubkey").map_err(read_err)?,
        });
    }

    let mut networks = Vec::new();
    let rows = sqlx::query("SELECT networkid, network, ipv6, network_type FROM networks")
        .fetch_all(&mut *tx)
        .await
        .map_err(read_err)?;
    for row in rows {
        networks.push(SnapshotNetworkRow {
            networkid: row.try_get("networkid").map_err(read_err)?,
            network: row.try_get("network").map_err(read_err)?,
            ipv6: row.try_get("ipv6").map_err(read_err)?,
            network_type: row.try_get("network_type").map_err(read_err)?,
        });
    }

    let mut addresses = Vec::new();
    let rows = sqlx::query("SELECT addressid, networkid, peerid, ip_address FROM addresses")
        .fetch_all(&mut *tx)
        .await
        .map_err(read_err)?;
    for row in rows {
        addresses.push(SnapshotAddressRow {
            addressid: row.try_get("addressid").map_err(read_err)?,
            networkid: row.try_get("networkid").map_err(read_err)?,
            peerid: row.try_get("peerid").map_err(read_err)?,
            ip_address: row.try_get("ip_address").map_err(read_err)?,
        });
    }

    let mut routes = Vec::new();
    let rows = sqlx::query("SELECT routeid, addressid, destination FROM routes")
        .fetch_all(&mut *tx)
        .await
        .map_err(read_err)?;
    for row in rows {
        routes.push(SnapshotRouteRow {
            addressid: row.try_get("addressid").map_err(read_err)?,
            destination: row.try_get("destination").map_err(read_err)?,
        });
    }

    // Read last_applied INSIDE the same transaction as the tables, so the
    // snapshot content and its log position are consistent.
    let last_log_id: Option<openraft::LogId<NodeId>> =
        sqlx::query("SELECT value FROM raft_meta WHERE key='last_applied'")
            .fetch_optional(&mut *tx)
            .await
            .map_err(read_err)?
            .map(|row| {
                let bytes: Vec<u8> = row.try_get("value").map_err(read_err)?;
                from_slice(&bytes).map_err(|e| StoreError::IO {
                    source: openraft::StorageIOError::read_state_machine(openraft::AnyError::new(
                        &e,
                    )),
                })
            })
            .transpose()?;
    let membership = read_meta(pool, "last_membership")
        .await?
        .unwrap_or_default();
    Ok(SnapshotBlob {
        last_log_id,
        membership,
        users,
        peers,
        networks,
        addresses,
        routes,
    })
}

async fn restore_snapshot(
    tx: &mut sqlx::SqliteConnection,
    blob: &SnapshotBlob,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM routes")
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    sqlx::query("DELETE FROM addresses")
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    sqlx::query("DELETE FROM networks")
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    sqlx::query("DELETE FROM peers")
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    sqlx::query("DELETE FROM users")
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;

    for user in &blob.users {
        sqlx::query("INSERT INTO users (userid, user_name, permissions) VALUES (?, ?, ?)")
            .bind(user.userid)
            .bind(&user.user_name)
            .bind(user.permissions)
            .execute(&mut *tx)
            .await
            .map_err(write_err)?;
    }
    for peer in &blob.peers {
        sqlx::query("INSERT INTO peers (peerid, peer_name, token, pubkey, permissions, current_endpoint, nat_type, monitor, relay, local_ips, local_port, user_id, raft_pubkey) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(peer.peerid)
            .bind(&peer.peer_name)
            .bind(&peer.token)
            .bind(&peer.pubkey)
            .bind(peer.permissions)
            .bind(&peer.current_endpoint)
            .bind(peer.nat_type)
            .bind(peer.monitor)
            .bind(peer.relay)
            .bind(&peer.local_ips)
            .bind(peer.local_port)
            .bind(peer.user_id)
            .bind(&peer.raft_pubkey)
            .execute(&mut *tx)
            .await
            .map_err(write_err)?;
    }
    for network in &blob.networks {
        sqlx::query(
            "INSERT INTO networks (networkid, network, ipv6, network_type) VALUES (?, ?, ?, ?)",
        )
        .bind(network.networkid)
        .bind(&network.network)
        .bind(network.ipv6)
        .bind(&network.network_type)
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    }
    for address in &blob.addresses {
        sqlx::query(
            "INSERT INTO addresses (addressid, networkid, peerid, ip_address) VALUES (?, ?, ?, ?)",
        )
        .bind(address.addressid)
        .bind(address.networkid)
        .bind(address.peerid)
        .bind(&address.ip_address)
        .execute(&mut *tx)
        .await
        .map_err(write_err)?;
    }
    for route in &blob.routes {
        sqlx::query("INSERT INTO routes (addressid, destination) VALUES (?, ?)")
            .bind(route.addressid)
            .bind(&route.destination)
            .execute(&mut *tx)
            .await
            .map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::entry::Mutation;
    type EntryOf = openraft::Entry<TypeConfig>;

    async fn setup() -> (RaftStateMachine, sqlx::SqlitePool) {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory db");
        crate::raft::run_migrations(&pool).await;
        (RaftStateMachine::new(pool.clone(), None), pool)
    }

    /// The permission cap: a node requested with higher permissions than its
    /// owner is clamped to the owner's level at apply time.
    #[tokio::test]
    async fn add_peer_caps_permissions_at_owner() {
        let (mut sm, pool) = setup().await;
        sm.apply([EntryOf {
            log_id: openraft::LogId::new(
                openraft::CommittedLeaderId::new(1, crate::raft::NodeId::from(1u64)),
                1,
            ),
            payload: openraft::entry::EntryPayload::Normal(Mutation::CreateUser {
                name: "alice".into(),
                permissions: 25,
            }),
        }])
        .await
        .expect("create user");
        sm.apply([EntryOf {
            log_id: openraft::LogId::new(
                openraft::CommittedLeaderId::new(1, crate::raft::NodeId::from(1u64)),
                2,
            ),
            payload: openraft::entry::EntryPayload::Normal(Mutation::AddPeer {
                user_id: Some(1),
                name: "alice-node".into(),
                token: uuid::Uuid::new_v4(),
                // requested above the owner's level
                permissions: 100,
                addresses: Vec::new(),
            }),
        }])
        .await
        .expect("add peer");

        let permissions: i32 =
            sqlx::query_scalar("SELECT permissions FROM peers WHERE peer_name='alice-node'")
                .fetch_one(&pool)
                .await
                .expect("peer row");
        assert_eq!(permissions, 25, "node permissions capped at owner's");
    }

    /// A node without an owner keeps its requested permissions.
    #[tokio::test]
    async fn add_peer_without_owner_keeps_permissions() {
        let (mut sm, pool) = setup().await;
        sm.apply([EntryOf {
            log_id: openraft::LogId::new(
                openraft::CommittedLeaderId::new(1, crate::raft::NodeId::from(1u64)),
                1,
            ),
            payload: openraft::entry::EntryPayload::Normal(Mutation::AddPeer {
                user_id: None,
                name: "orphan".into(),
                token: uuid::Uuid::new_v4(),
                permissions: 50,
                addresses: Vec::new(),
            }),
        }])
        .await
        .expect("add peer");
        let permissions: i32 =
            sqlx::query_scalar("SELECT permissions FROM peers WHERE peer_name='orphan'")
                .fetch_one(&pool)
                .await
                .expect("peer row");
        assert_eq!(permissions, 50);
    }

    /// Route validation: a route whose via address is not a peer address is
    /// dropped deterministically.
    #[tokio::test]
    async fn add_route_requires_existing_via() {
        let (mut sm, pool) = setup().await;
        sm.apply([EntryOf {
            log_id: openraft::LogId::new(
                openraft::CommittedLeaderId::new(1, crate::raft::NodeId::from(1u64)),
                1,
            ),
            payload: openraft::entry::EntryPayload::Normal(Mutation::AddRoute {
                destination: "10.88.0.0/24".parse().unwrap(),
                via_ip: "10.99.0.99".parse().unwrap(), // no such peer address
            }),
        }])
        .await
        .expect("apply");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM routes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "route with unknown via must be dropped");
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::raft::entry::Mutation;
    use openraft::EntryPayload;
    type E = openraft::Entry<TypeConfig>;

    fn log_id(index: u64) -> openraft::LogId<crate::raft::NodeId> {
        openraft::LogId::new(
            openraft::CommittedLeaderId::new(1, crate::raft::NodeId::from(1u64)),
            index,
        )
    }

    fn entry(index: u64, mutation: Mutation) -> E {
        E {
            log_id: log_id(index),
            payload: EntryPayload::Normal(mutation),
        }
    }

    async fn db() -> sqlx::SqlitePool {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::raft::run_migrations(&pool).await;
        pool
    }

    /// Install a snapshot, then apply later log entries: the applied rows
    /// must survive, i.e. a snapshot restore must not roll back newer
    /// applied state.
    #[tokio::test]
    async fn apply_after_install_keeps_state() {
        let pool = db().await;
        let mut sm = RaftStateMachine::new(pool.clone(), None);

        // Build a snapshot from a state machine that applied entries 1..10.
        sm.apply([
            entry(
                1,
                Mutation::CreateUser {
                    name: "u1".into(),
                    permissions: 100,
                },
            ),
            entry(
                2,
                Mutation::AddPeer {
                    user_id: None,
                    name: "early".into(),
                    token: uuid::Uuid::new_v4(),
                    permissions: 0,
                    addresses: Vec::new(),
                },
            ),
        ])
        .await
        .expect("apply early");

        let mut builder = sm.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.expect("snapshot");
        let meta = snapshot.meta.clone();
        let data: Vec<u8> = snapshot.snapshot.get_ref().clone();
        let data_for_reinstall = data.clone();

        // Fresh learner installs the snapshot
        let learner_pool = db().await;
        let mut learner = RaftStateMachine::new(learner_pool.clone(), None);
        learner
            .install_snapshot(&meta, Box::new(std::io::Cursor::new(data)))
            .await
            .expect("install");
        let (applied, _) = learner.applied_state().await.expect("applied");
        assert_eq!(applied.map(|l| l.index), Some(2));

        // Now apply entries 3..4 on the learner (as replication would)
        learner
            .apply([
                entry(
                    3,
                    Mutation::AddPeer {
                        user_id: None,
                        name: "late-3".into(),
                        token: uuid::Uuid::new_v4(),
                        permissions: 0,
                        addresses: Vec::new(),
                    },
                ),
                entry(
                    4,
                    Mutation::AddPeer {
                        user_id: None,
                        name: "late-4".into(),
                        token: uuid::Uuid::new_v4(),
                        permissions: 0,
                        addresses: Vec::new(),
                    },
                ),
            ])
            .await
            .expect("apply late");

        let names: Vec<String> =
            sqlx::query_scalar("SELECT peer_name FROM peers ORDER BY peer_name")
                .fetch_all(&learner_pool)
                .await
                .expect("rows");
        assert!(
            names.contains(&"late-3".to_string()),
            "late-3 present: {names:?}"
        );
        assert!(
            names.contains(&"late-4".to_string()),
            "late-4 present: {names:?}"
        );

        // Re-install the SAME (older) snapshot: must be ignored
        learner
            .install_snapshot(&meta, Box::new(std::io::Cursor::new(data_for_reinstall)))
            .await
            .expect("stale install");
        let names: Vec<String> =
            sqlx::query_scalar("SELECT peer_name FROM peers ORDER BY peer_name")
                .fetch_all(&learner_pool)
                .await
                .expect("rows");
        assert!(
            names.contains(&"late-3".to_string()),
            "stale install must not roll back: {names:?}"
        );
    }

    /// Snapshot must carry users: an AddPeer after snapshot restore links to
    /// its owning user (FK). The users table is therefore part of every
    /// snapshot; an owned AddPeer must insert even right after a snapshot
    /// restore.
    #[tokio::test]
    async fn snapshot_restores_users() {
        let pool = db().await;
        let mut sm = RaftStateMachine::new(pool.clone(), None);
        sm.apply([
            entry(
                1,
                Mutation::CreateUser {
                    name: "owner".into(),
                    permissions: 100,
                },
            ),
            entry(
                2,
                Mutation::AddPeer {
                    user_id: Some(1),
                    name: "owned".into(),
                    token: uuid::Uuid::new_v4(),
                    permissions: 0,
                    addresses: Vec::new(),
                },
            ),
        ])
        .await
        .expect("apply");

        let mut builder = sm.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.expect("snapshot");
        let meta = snapshot.meta.clone();
        let data: Vec<u8> = snapshot.snapshot.get_ref().clone();

        let learner_pool = db().await;
        let mut learner = RaftStateMachine::new(learner_pool.clone(), None);
        learner
            .install_snapshot(&meta, Box::new(std::io::Cursor::new(data)))
            .await
            .expect("install");
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&learner_pool)
            .await
            .expect("users");
        assert_eq!(users, 1, "snapshot must restore users");
        let owned: Option<i64> =
            sqlx::query_scalar("SELECT user_id FROM peers WHERE peer_name='owned'")
                .fetch_one(&learner_pool)
                .await
                .expect("owned");
        assert_eq!(owned, Some(1), "ownership link restored");
        // FK-linked AddPeer after restore must insert
        learner
            .apply([entry(
                3,
                Mutation::AddPeer {
                    user_id: Some(1),
                    name: "after-snapshot".into(),
                    token: uuid::Uuid::new_v4(),
                    permissions: 0,
                    addresses: Vec::new(),
                },
            )])
            .await
            .expect("apply after");
        let after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM peers WHERE peer_name='after-snapshot'")
                .fetch_one(&learner_pool)
                .await
                .expect("count");
        assert_eq!(after, 1, "owned AddPeer after snapshot restore must insert");
    }
}
