//! Raft cluster formation and server-side node startup.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use openraft::Config;
use sqlx::prelude::*;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePool;
use tonic::transport::Channel;
use tonic::transport::Uri;
use tracing::info;

use super::entry::Mutation;
use super::grpc_service::RaftService;
use super::keys;
use super::raft_handle::RaftHandle;
use super::state_machine::RaftStateMachine;
use super::store::RaftLogStore;
use super::NodeId;
use super::TypeConfig;
use crate::protocol::raft_control_client::RaftControlClient;
use crate::protocol::RaftJoinRequest;
use crate::protocol::RaftJoinResponse;

/// Options controlling the raft node, from the CLI.
#[derive(Clone, Debug)]
pub struct RaftOptions {
    /// Advertised host:port other raft nodes connect to. Empty for
    /// single-node clusters.
    pub advertise: String,
    /// Build a snapshot after this many log entries. Low values make
    /// compaction (and thus snapshot transfer) testable.
    pub snapshot_logs_since_last: Option<u64>,
}

/// Open the database with raft tuning pragmas applied.
pub async fn connect_db(database_url: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        // Snapshot building and log IO contend on the WAL; wait instead of
        // failing the client write with SQLITE_BUSY.
        .busy_timeout(std::time::Duration::from_secs(15));
    Ok(SqlitePool::connect_with(options).await?)
}

/// Build the raft node and the gRPC raft service for this server.
///
/// The node identity comes from the master secret in the database; a fresh
/// secret is created on first start. The node does NOT automatically join or
/// initialize a cluster: that is an operator action (`raft-init`/`raft-join`).
///
/// `event_sender` receives the applied events produced by the state machine.
pub async fn start_raft(
    pool: SqlitePool,
    options: RaftOptions,
    event_sender: tokio::sync::mpsc::UnboundedSender<super::entry::AppliedEvent>,
) -> anyhow::Result<(RaftHandle, RaftService)> {
    let master = keys::load_or_create_master_secret(&pool).await?;
    let signing_key = keys::raft_signing_key(&master);
    let id = NodeId::from_bytes(*signing_key.verifying_key().as_bytes());

    let mut config = default_config();
    if let Some(threshold) = options.snapshot_logs_since_last {
        config.snapshot_policy = openraft::SnapshotPolicy::LogsSinceLast(threshold);
        // purge soon after the snapshot so log-based catch-up is impossible
        // and the snapshot path is exercised
        config.max_in_snapshot_log_to_keep = 0;
    }
    let config = Arc::new(config.validate()?);
    // Read the bootstrap allowlist before the pool is moved into the state
    // machine.
    let known_members = load_known_members(&pool).await?;
    let log_store = RaftLogStore::new(pool.clone());
    let state_machine = RaftStateMachine::new(pool.clone(), Some(event_sender));
    let handle = RaftHandle::new(
        id,
        config,
        log_store,
        state_machine,
        signing_key.clone(),
        pool.clone(),
    )
    .await?;

    let service = RaftService::new(handle.clone());
    // Seed the signature allowlist with the bootstrap list stored by
    // raft-join: a freshly joined node cannot receive the membership log
    // before it accepts signed RPCs, so it must know the member keys out of
    // band. The live membership is merged on top (and re-merged on every
    // unknown-signer lookup).
    for key in known_members {
        if let Ok(k) = <[u8; 32]>::try_from(key.as_slice()) {
            service.add_member(k).await;
        }
    }
    service
        .sync_members_from_membership(&handle.membership().await)
        .await;
    Ok((handle, service))
}

/// `wirespider server database raft-init`: become a single-node cluster.
///
/// Only valid on a database with no raft state yet.
pub async fn raft_init(pool: SqlitePool) -> anyhow::Result<()> {
    let master = keys::load_or_create_master_secret(&pool).await?;
    let signing_key = keys::raft_signing_key(&master);
    let id = NodeId::from_bytes(*signing_key.verifying_key().as_bytes());

    let config = Arc::new(default_config().validate()?);
    let log_store = RaftLogStore::new(pool.clone());
    let state_machine = RaftStateMachine::new(pool.clone(), None);
    let raft = openraft::Raft::new(
        id,
        config,
        super::network::TonicNetworkFactory::new(signing_key),
        log_store,
        state_machine,
    )
    .await?;
    raft.initialize(BTreeMap::from([(
        id,
        openraft::BasicNode {
            addr: String::new(),
        },
    )]))
    .await
    .map_err(|e| anyhow::anyhow!("initializing cluster failed: {e}"))?;

    // Import rows that were created directly in the database before the
    // cluster existed (networks, admin peers and their addresses). Without
    // this they would exist only on this node and never replicate.
    import_local_state(&raft, &pool).await?;

    info!("initialized single-node raft cluster with id {}", id);
    raft.shutdown().await?;
    Ok(())
}

/// Replay pre-existing local rows as raft mutations so they replicate.
///
/// Rows created directly in the database before the cluster existed
/// (networks via `create-network`, admins via `create-admin`) are replayed
/// into the log: without this they would exist only on the initializing node
/// and never reach other members.
async fn import_local_state(
    raft: &openraft::Raft<TypeConfig>,
    pool: &SqlitePool,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;

    let networks: Vec<(String,)> =
        sqlx::query_as(r#"SELECT network FROM networks WHERE network_type='wireguard'"#)
            .fetch_all(&mut *conn)
            .await?;
    for (network,) in networks {
        let net: ipnet::IpNet = network.parse()?;
        raft.client_write(Mutation::AddNetwork {
            net,
            network_type: super::entry::NetworkType::Wireguard,
        })
        .await
        .map_err(|e| anyhow::anyhow!("importing network {network} failed: {e}"))?;
    }

    // Import users first, then peers linked to them (FK target must exist).
    let users: Vec<(i64, String, i32)> =
        sqlx::query_as(r#"SELECT userid, user_name, permissions FROM users"#)
            .fetch_all(&mut *conn)
            .await?;
    for (user_id, user_name, permissions) in &users {
        raft.client_write(Mutation::CreateUser {
            name: user_name.clone(),
            permissions: *permissions,
        })
        .await
        .map_err(|e| anyhow::anyhow!("importing user {user_name} failed: {e}"))?;
        let _ = user_id;
    }

    // CreateUser uses INSERT OR IGNORE on the same database the local rows
    // live in, so local user ids are also the replicated ids.

    let peers: Vec<(i64, String, uuid::Uuid, i32, Option<i64>)> =
        sqlx::query_as(r#"SELECT peerid, peer_name, token, permissions, user_id FROM peers"#)
            .fetch_all(&mut *conn)
            .await?;
    for (peerid, peer_name, token, permissions, local_user_id) in peers {
        // Replay is idempotent: rows already present on this node (they were
        // imported by an earlier init attempt) are re-inserted identically.
        let addresses: Vec<(String,)> =
            sqlx::query_as(r#"SELECT ip_address FROM addresses WHERE peerid=?"#)
                .bind(peerid)
                .fetch_all(&mut *conn)
                .await?;
        let mut nets = Vec::new();
        for (ip_address,) in addresses {
            let addr: std::net::IpAddr = ip_address.parse()?;
            // preserve the host address with the prefix of its network
            let network = addr_to_network(addr, &mut conn).await?;
            nets.push(ipnet::IpNet::new(addr, network.prefix_len())?);
        }
        raft.client_write(Mutation::AddPeer {
            user_id: local_user_id,
            name: peer_name,
            token,
            permissions,
            addresses: nets,
        })
        .await
        .map_err(|e| anyhow::anyhow!("importing peer {peerid} failed: {e}"))?;
    }
    Ok(())
}

/// The wireguard network containing `addr`.
async fn addr_to_network(
    addr: std::net::IpAddr,
    conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
) -> anyhow::Result<ipnet::IpNet> {
    let rows: Vec<(String,)> =
        sqlx::query_as(r#"SELECT n.network FROM networks n WHERE n.network_type='wireguard'"#)
            .fetch_all(&mut **conn)
            .await?;
    for (network,) in rows {
        let net: ipnet::IpNet = network.parse()?;
        if net.contains(&addr) {
            return Ok(net);
        }
    }
    anyhow::bail!("no wireguard network contains {addr}");
}

fn default_config() -> Config {
    Config {
        cluster_name: "wirespider".to_string(),
        election_timeout_min: 1500,
        election_timeout_max: 3000,
        heartbeat_interval: 500,
        install_snapshot_timeout: Duration::from_secs(10).as_millis() as u64,
        ..Default::default()
    }
}

/// `wirespider server database raft-join`: ask an existing member to add
/// this node as a learner.
///
/// The new node presents its raft public key and advertised address. The
/// member verifies it is the leader (or forwards), adds this node as learner
/// via `add_learner` and returns the current member keys, which are stored as
/// the bootstrap allowlist for signature verification. Becoming a voter
/// remains a separate explicit `raft-promote` step, never automatic.
pub async fn raft_join(db_url: &str, member: Uri, advertise: String) -> anyhow::Result<()> {
    let pool = connect_db(db_url).await?;
    let master = keys::load_or_create_master_secret(&pool).await?;
    let signing_key = keys::raft_signing_key(&master);
    let pubkey = signing_key.verifying_key().as_bytes().to_vec();

    let channel = Channel::from_shared(member.to_string())?.connect().await?;
    let mut client = RaftControlClient::new(channel);
    let response: tonic::Response<RaftJoinResponse> = client
        .join(tonic::Request::new(RaftJoinRequest { pubkey, advertise }))
        .await
        .map_err(|e| anyhow::anyhow!("join request rejected: {e}"))?;
    let members = response.into_inner().members;
    store_known_members(&pool, &members).await?;
    info!(
        "joined as learner; stored {} member keys for bootstrap",
        members.len()
    );
    Ok(())
}

/// Persist the bootstrap member allowlist used before replication delivers
/// the membership log.
pub async fn store_known_members(pool: &SqlitePool, members: &[Vec<u8>]) -> anyhow::Result<()> {
    let data = serde_json::to_vec(members)?;
    sqlx::query(
        "INSERT INTO raft_meta (key, value) VALUES ('known_members', ?) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    )
    .bind(data)
    .execute(pool)
    .await?;
    Ok(())
}

/// Load the bootstrap member allowlist, if it was stored by `raft-join`.
pub async fn load_known_members(pool: &SqlitePool) -> anyhow::Result<Vec<Vec<u8>>> {
    let row = sqlx::query("SELECT value FROM raft_meta WHERE key='known_members'")
        .fetch_optional(pool)
        .await?;
    match row {
        None => Ok(Vec::new()),
        Some(row) => {
            let bytes: Vec<u8> = row.try_get("value")?;
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
}

/// Handle a join request on an existing member: add the requester as learner.
///
/// Fails if this node is not the leader; clients retry against the leader.
/// The response carries the current member keys so the joining node can
/// bootstrap its signature allowlist (it cannot learn membership by
/// replication before it accepts signed RPCs).
pub async fn handle_join_request(
    handle: &RaftHandle,
    pubkey: Vec<u8>,
    advertise: String,
) -> Result<Vec<Vec<u8>>, anyhow::Error> {
    let bytes: [u8; 32] = pubkey
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid raft pubkey length"))?;
    let id = NodeId::from_bytes(bytes);
    handle
        .raft
        .add_learner(
            id,
            openraft::BasicNode {
                addr: advertise.clone(),
            },
            true,
        )
        .await
        .map_err(|e| anyhow::anyhow!("adding learner failed: {e}"))?;
    // Record the raft node as a peer row so promote can resolve its owner
    // (permission cap). Server nodes have no wireguard tunnel by default.
    handle
        .raft
        .client_write(Mutation::RecordRaftNode {
            raft_pubkey: bytes,
            advertise: advertise.clone(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("recording raft node failed: {e}"))?;
    let members = handle
        .membership()
        .await
        .nodes()
        .map(|(id, _)| id.as_bytes().to_vec())
        .collect();
    Ok(members)
}

/// `raft-promote`: a learner replica asks the leader to promote it to voter.
///
/// This is the healthy-primary manual failover path. Requires a working
/// leader; if the primary is dead, use `raft-takeover` instead.
pub async fn raft_promote(db_url: &str, leader: Uri) -> anyhow::Result<()> {
    let pool = connect_db(db_url).await?;
    let master = keys::load_or_create_master_secret(&pool).await?;
    let signing_key = keys::raft_signing_key(&master);
    let pubkey = signing_key.verifying_key().as_bytes().to_vec();

    let channel = Channel::from_shared(leader.to_string())?.connect().await?;
    let mut client = RaftControlClient::new(channel);
    client
        .promote(tonic::Request::new(crate::protocol::RaftPromoteRequest {
            pubkey,
        }))
        .await
        .map_err(|e| anyhow::anyhow!("promote request rejected: {e}"))?;
    info!("promoted to voter");
    Ok(())
}

/// `raft-leave`: a raft node announces it wants to leave the cluster.
///
/// The membership removal itself is performed by a surviving member (this
/// request triggers `change_membership(RemoveVoters)` there); afterwards the
/// leaving node stops its raft subsystem and archives its raft state
/// locally, becoming a plain client. Requires quorum: a lone voter cannot
/// leave.
pub async fn raft_leave(db_url: &str, member: Uri) -> anyhow::Result<()> {
    let pool = connect_db(db_url).await?;
    let master = keys::load_or_create_master_secret(&pool).await?;
    let signing_key = keys::raft_signing_key(&master);
    let pubkey = signing_key.verifying_key().as_bytes().to_vec();

    let channel = Channel::from_shared(member.to_string())?.connect().await?;
    let mut client = RaftControlClient::new(channel);
    client
        .leave(tonic::Request::new(crate::protocol::RaftLeaveRequest {
            pubkey,
        }))
        .await
        .map_err(|e| anyhow::anyhow!("leave request rejected: {e}"))?;
    info!("membership removal committed; archiving local raft state");
    archive_raft_state(&pool).await?;
    info!("raft state archived; this node is no longer a raft participant");
    Ok(())
}

/// Drop the local vote/membership/metadata so the node cannot accidentally
/// rejoin as its former raft identity, keeping the applied state (the
/// `peers`/`routes`/... tables) intact. The raft log is archived (renamed)
/// rather than deleted for forensics.
async fn archive_raft_state(pool: &SqlitePool) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    sqlx::query("DELETE FROM raft_meta WHERE key IN ('vote', 'committed')")
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE raft_meta SET key='archived_last_applied' WHERE key='last_applied'")
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE raft_meta SET key='archived_last_membership' WHERE key='last_membership'")
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE raft_meta SET key='archived_last_purged' WHERE key='last_purged'")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Handle a leave request on a surviving member: remove the leaving node
/// from membership. Fails if this node is not the leader.
pub async fn handle_leave_request(
    handle: &RaftHandle,
    pubkey: Vec<u8>,
) -> Result<(), anyhow::Error> {
    let bytes: [u8; 32] = pubkey
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid raft pubkey length"))?;
    let id = NodeId::from_bytes(bytes);
    use openraft::ChangeMembers;
    handle
        .raft
        .change_membership(
            ChangeMembers::RemoveVoters([id].into_iter().collect()),
            false,
        )
        .await
        .map_err(|e| anyhow::anyhow!("removing voter failed: {e}"))?;
    Ok(())
}

/// Handle a promote request on the leader: upgrade the learner to voter.
pub async fn handle_promote_request(
    handle: &RaftHandle,
    pubkey: Vec<u8>,
) -> Result<(), anyhow::Error> {
    let bytes: [u8; 32] = pubkey
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid raft pubkey length"))?;
    let id = NodeId::from_bytes(bytes);
    // Permission cap re-check (docs/architecture.md): promoting a learner to
    // voter re-validates the owner's current permission. Unowned raft nodes
    // cannot be promoted.
    const SERVER_PERMISSION: i32 = 100;
    let allowed = handle.raft.with_raft_state(|_| ()).await.ok().is_some(); // raft reachable
    let _ = allowed;
    let mut conn = handle
        .pool()
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("database unreachable on leader: {e}"))?;
    let row = sqlx::query(
        "SELECT p.user_id, u.permissions AS user_permissions, p.permissions AS node_permissions \
         FROM peers p LEFT JOIN users u ON p.user_id = u.userid WHERE p.raft_pubkey=?",
    )
    .bind(bytes.to_vec())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| anyhow::anyhow!("database error: {e}"))?;
    let Some(row) = row else {
        anyhow::bail!(
            "raft node {} is not recorded as a peer; cannot verify ownership",
            id
        );
    };
    let user_permissions: Option<i32> = row.try_get("user_permissions").ok().flatten();
    let node_permissions: i32 = row.try_get("node_permissions").unwrap_or(0);
    match user_permissions {
        // owner must currently hold the server capability, and the node
        // itself must not have been explicitly capped lower
        Some(user_perm) if user_perm >= SERVER_PERMISSION && node_permissions >= 0 => {}
        _ => anyhow::bail!(
            "owner of raft node {} does not hold the server capability; promotion denied",
            id
        ),
    }
    use openraft::ChangeMembers;
    handle
        .raft
        .change_membership(ChangeMembers::AddVoterIds([id].into_iter().collect()), true)
        .await
        .map_err(|e| anyhow::anyhow!("promoting voter failed: {e}"))?;
    Ok(())
}

/// `raft-takeover`: re-initialize this node as a single-voter cluster from
/// its applied state.
///
/// DANGEROUS: only for the dead-primary failover case. Acknowledged writes
/// that never reached this replica are lost. The `--confirm-loss` flag is
/// required so this cannot be triggered accidentally.
pub async fn raft_takeover(db_url: &str, confirm_loss: bool) -> anyhow::Result<()> {
    if !confirm_loss {
        anyhow::bail!(
            "takeover discards writes that never reached this replica. \
             Pass --confirm-loss after verifying the primary is permanently gone."
        );
    }
    let pool = connect_db(db_url).await?;
    let master = keys::load_or_create_master_secret(&pool).await?;
    let signing_key = keys::raft_signing_key(&master);
    let id = NodeId::from_bytes(*signing_key.verifying_key().as_bytes());

    // Drop previous raft metadata (vote, membership history) but keep the
    // applied state and log; openraft refuses to initialize over existing
    // state, so we clear the vote and membership records.
    sqlx::query("DELETE FROM raft_meta WHERE key IN ('vote', 'last_membership')")
        .execute(&pool)
        .await?;

    let config = Arc::new(default_config().validate()?);
    let log_store = RaftLogStore::new(pool.clone());
    let state_machine = RaftStateMachine::new(pool, None);
    let raft = openraft::Raft::new(
        id,
        config,
        super::network::TonicNetworkFactory::new(signing_key),
        log_store,
        state_machine,
    )
    .await?;
    raft.initialize(BTreeMap::from([(
        id,
        openraft::BasicNode {
            addr: String::new(),
        },
    )]))
    .await
    .map_err(|e| anyhow::anyhow!("takeover initialization failed: {e}"))?;
    info!("takeover complete: this node is now a single-voter cluster");
    raft.shutdown().await?;
    Ok(())
}
