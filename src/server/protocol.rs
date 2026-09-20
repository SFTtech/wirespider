//! The client-facing gRPC service, backed by the raft cluster.
//!
//! All state changes go through the raft log (`client_write`); reads are
//! served from the applied state machine. On the leader reads are
//! linearizable (`ensure_linearizable`); on a learner they are eventually
//! consistent by design.

use futures::Stream;
use sqlx::sqlite::SqliteConnection;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::convert::TryInto;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use tonic::metadata::MetadataMap;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::instrument;
use uuid::Uuid;

use wirespider::protocol::wirespider_server::Wirespider;
use wirespider::protocol::*;
use wirespider::WireguardKey;

use wirespider::raft::entry::Mutation;
use wirespider::raft::event_hub::EventHub;
use wirespider::raft::raft_handle::RaftHandle;
use wirespider::raft::state_reader;

type EventStream = Pin<Box<dyn Stream<Item = Result<Event, Status>> + Send + Sync>>;

#[derive(Clone)]
pub struct WirespiderServerState {
    sqlite_pool: SqlitePool,
    raft: RaftHandle,
    events: Arc<EventHub>,
}

#[derive(Debug)]
struct AuthenticatedPeer {
    peerid: i64,
    permissions: i32,
    user_id: Option<i64>,
}

/// Convert a raft client write error into a tonic status, mapping
/// ForwardToLeader to UNAVAILABLE with the leader address hint.
fn write_error_to_status(
    e: openraft::error::RaftError<
        wirespider::raft::NodeId,
        openraft::error::ClientWriteError<wirespider::raft::NodeId, openraft::BasicNode>,
    >,
) -> Status {
    match e.forward_to_leader() {
        Some(forward) => {
            let leader = forward
                .leader_node
                .as_ref()
                .map(|n| n.addr.clone())
                .unwrap_or_default();
            Status::unavailable(format!("not leader; leader at: {leader}"))
        }
        None => {
            error!("raft write error: {e:?}");
            Status::internal(format!("raft error: {e}"))
        }
    }
}

impl WirespiderServerState {
    #[instrument(skip_all)]
    pub async fn new(
        sqlite_pool: SqlitePool,
        raft: RaftHandle,
        events: Arc<EventHub>,
    ) -> Result<WirespiderServerState, sqlx::Error> {
        Ok(WirespiderServerState {
            sqlite_pool,
            raft,
            events,
        })
    }

    #[instrument(skip_all)]
    async fn authenticate(
        &self,
        metadata: &MetadataMap,
        permission_level: i32,
    ) -> Result<AuthenticatedPeer, Status> {
        let auth = metadata
            .get("Authorization")
            .ok_or_else(|| Status::permission_denied("Authorization missing"))?;
        let auth_str = auth
            .to_str()
            .map_err(|_| Status::permission_denied("Invalid authorization"))?;
        if auth_str.len() != 43 {
            // examle "Bearer f179db1a-ee3b-4ede-b593-6f423c1ca7d4"
            return Err(Status::permission_denied("Invalid authorization"));
        }
        let (_, token) = auth_str.split_at(7);
        let uuid = Uuid::from_str(token)
            .map_err(|_| Status::permission_denied("Invalid authorization"))?;
        let mut conn = self.sqlite_pool.acquire().await.map_err(|e| {
            error!("SQL Error: {e}");
            Status::internal("SQL Error")
        })?;
        let result = sqlx::query(
            r#"SELECT p.peerid, p.permissions, p.user_id FROM peers p WHERE p.token=?"#,
        )
        .bind(uuid)
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| Status::permission_denied("Invalid authorization"))?;
        if result.get::<i32, &str>("permissions") >= permission_level {
            Ok(AuthenticatedPeer {
                peerid: result.get("peerid"),
                permissions: result.get("permissions"),
                user_id: result.get("user_id"),
            })
        } else {
            Err(Status::permission_denied("Insufficient Permissions"))
        }
    }

    /// The user owning this node, for permission-cap and ownership checks.
    async fn owner_user_id(&self, peerid: i64) -> Result<Option<i64>, Status> {
        let mut conn = self.conn().await?;
        let row = sqlx::query(r#"SELECT user_id FROM peers WHERE peerid=?"#)
            .bind(peerid)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| {
                error!("SQL Error: {e}");
                Status::internal("SQL Error")
            })?;
        row.try_get("user_id").map_err(|e| {
            error!("SQL Error: {e}");
            Status::internal("SQL Error")
        })
    }

    /// The id of a user by name.
    async fn lookup_user_id(&self, name: &str) -> Result<i64, Status> {
        let mut conn = self.conn().await?;
        let row = sqlx::query(r#"SELECT userid FROM users WHERE user_name=?"#)
            .bind(name)
            .fetch_one(&mut *conn)
            .await
            .map_err(|_| Status::invalid_argument("User not found"))?;
        row.try_get("userid").map_err(|e| {
            error!("SQL Error: {e}");
            Status::internal("SQL Error")
        })
    }

    /// If this node is not the leader but knows one, connect to the leader
    /// and invoke `call` with a client carrying the caller's auth metadata.
    /// Returns the leader's response. `Ok(None)` means "handle locally".
    ///
    /// The forwarding node never elevates privileges: the leader
    /// re-authenticates the original caller.
    async fn forward_with<R>(
        &self,
        metadata: tonic::metadata::MetadataMap,
        call: impl FnOnce(
            wirespider::protocol::wirespider_client::WirespiderClient<tonic::transport::Channel>,
            tonic::metadata::MetadataMap,
        ) -> futures::future::BoxFuture<'static, Result<Response<R>, Status>>,
    ) -> Result<Option<Response<R>>, Status>
    where
        R: prost::Message + Default + 'static,
    {
        let metrics = self.raft.raft.metrics().borrow().clone();
        let Some(leader_id) = metrics.current_leader else {
            return Ok(None);
        };
        if leader_id == metrics.id {
            return Ok(None);
        }
        let Some(addr) = metrics
            .membership_config
            .membership()
            .get_node(&leader_id)
            .map(|n| n.addr.clone())
        else {
            return Ok(None);
        };
        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .map_err(|e| Status::internal(e.to_string()))?
            .connect()
            .await
            .map_err(|e| Status::unavailable(format!("leader at {addr} unreachable: {e}")))?;
        let client = wirespider::protocol::wirespider_client::WirespiderClient::new(channel);
        let fut = call(client, metadata);
        let response = fut.await?;
        Ok(Some(response))
    }

    #[instrument(skip_all)]
    async fn get_peerid_from_identifier(&self, id: PeerIdentifier) -> Result<i64, Status> {
        let mut conn = self.conn().await?;
        get_peerid_from_identifier(&mut conn, id).await
    }

    async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, Status> {
        self.sqlite_pool.acquire().await.map_err(|e| {
            error!("SQL Error: {e}");
            Status::internal("SQL Error")
        })
    }

    /// A gRPC client for the current leader, for forwarding write requests
    /// from a learner replica. None if the leader is unknown.
    async fn leader_client(
        &self,
    ) -> Result<
        Option<
            wirespider::protocol::wirespider_client::WirespiderClient<tonic::transport::Channel>,
        >,
        Status,
    > {
        let metrics = self.raft.raft.metrics().borrow().clone();
        let Some(leader_id) = metrics.current_leader else {
            return Ok(None);
        };
        // the leader is this node: no forwarding needed (callers check id first)
        if leader_id == metrics.id {
            return Ok(None);
        }
        let Some(addr) = metrics
            .membership_config
            .membership()
            .get_node(&leader_id)
            .map(|n| n.addr.clone())
        else {
            return Ok(None);
        };
        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .map_err(|e| Status::internal(e.to_string()))?
            .connect()
            .await
            .map_err(|e| Status::unavailable(format!("leader at {addr} unreachable: {e}")))?;
        Ok(Some(
            wirespider::protocol::wirespider_client::WirespiderClient::new(channel),
        ))
    }

    /// Read the applied state of a peer (self reported columns).
    async fn peer_state(
        &self,
        peerid: i64,
    ) -> Result<
        Option<(
            Option<Vec<u8>>,
            Option<String>,
            i32,
            bool,
            bool,
            Option<String>,
            Option<i64>,
        )>,
        Status,
    > {
        let mut conn = self.conn().await?;
        let row = sqlx::query(
            "SELECT pubkey, current_endpoint, nat_type, monitor, relay, local_ips, local_port FROM peers WHERE peerid=?",
        )
        .bind(peerid)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            error!("SQL Error: {e}");
            Status::internal("SQL Error")
        })?;
        Ok(row.map(|row| {
            (
                row.try_get("pubkey").ok().flatten(),
                row.try_get("current_endpoint").ok().flatten(),
                row.try_get("nat_type").unwrap_or(0),
                row.try_get("monitor").unwrap_or(false),
                row.try_get("relay").unwrap_or(false),
                row.try_get("local_ips").ok().flatten(),
                row.try_get("local_port").ok().flatten(),
            )
        }))
    }
}

async fn get_peerid_from_identifier(
    conn: &mut SqliteConnection,
    id: PeerIdentifier,
) -> Result<i64, Status> {
    match id.identifier {
        Some(peer_identifier::Identifier::Name(name)) => {
            let result = sqlx::query(r#"SELECT peerid FROM peers WHERE peer_name=?"#)
                .bind(name)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| Status::invalid_argument("Peer not found"))?;
            result.try_get("peerid").map_err(|e| {
                error!("SQL Error: {e}");
                Status::internal("SQL Error")
            })
        }
        Some(peer_identifier::Identifier::Token(token)) => {
            let result = sqlx::query(r#"SELECT peerid FROM peers WHERE token=?"#)
                .bind(Uuid::from_bytes(
                    token
                        .try_into()
                        .map_err(|_| Status::invalid_argument("Invalid token"))?,
                ))
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| Status::permission_denied("Invalid authorization"))?;
            result.try_get("peerid").map_err(|e| {
                error!("SQL Error: {e}");
                Status::internal("SQL Error")
            })
        }
        Some(peer_identifier::Identifier::PublicKey(key)) => {
            let result = sqlx::query(r#"SELECT peerid FROM peers WHERE pubkey=?"#)
                .bind(key)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| Status::permission_denied("Invalid authorization"))?;
            result.try_get("peerid").map_err(|e| {
                error!("SQL Error: {e}");
                Status::internal("SQL Error")
            })
        }
        _ => Err(Status::invalid_argument("Missing identifier")),
    }
}

use sqlx::Row as _;

/// Copy the authorization metadata onto a forwarded request so the receiving
/// node authenticates the original caller.
fn forward_metadata<T>(metadata: &MetadataMap, request: &mut Request<T>) {
    for key in ["Authorization"] {
        if let Some(value) = metadata.get(key) {
            if let Ok(v) = value.to_str() {
                request.metadata_mut().insert(key, v.parse().unwrap());
            }
        }
    }
}

#[tonic::async_trait]
impl Wirespider for WirespiderServerState {
    type getEventsStream = EventStream;

    /// Hot path: authenticate, diff the self-reported state against the
    /// applied state, and if anything changed submit one raft write. Then
    /// read the allowed addresses from the applied state (linearizable on
    /// the leader).
    #[instrument(skip(self, request))]
    async fn get_addresses(
        &self,
        request: Request<AddressRequest>,
    ) -> Result<Response<AddressReply>, Status> {
        let request_metadata = request.metadata().clone();
        let auth_peer = self.authenticate(request.metadata(), 0).await?;
        let request = request.get_ref();

        let requested_nat_type = NatType::try_from(request.nat_type)
            .map_err(|_| Status::invalid_argument("Invalid NatType"))?;
        let requested_node_flags = request
            .node_flags
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Invalid NodeType"))?;
        if requested_node_flags.monitor && auth_peer.permissions < 25 {
            return Err(Status::permission_denied("Not allowed to monitor"));
        }
        if requested_node_flags.relay && auth_peer.permissions < 50 {
            return Err(Status::permission_denied("Not allowed to relay"));
        }

        if request.wg_public_key.len() != 32 {
            return Err(Status::new(Code::InvalidArgument, "Wrong key length"));
        }
        let publickey: WireguardKey = request
            .wg_public_key
            .clone()
            .try_into()
            .map_err(|_| Status::internal("invalid key"))?;

        let local_port: u16 = request
            .local_port
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid local port"))?;

        // diff current applied state vs. the request
        let (old_pubkey, old_endpoint, old_nat, old_monitor, old_relay, old_local_ips, old_port) =
            self.peer_state(auth_peer.peerid)
                .await?
                .ok_or_else(|| Status::permission_denied("Invalid authorization"))?;

        let endpoint: Option<String> = request
            .endpoint
            .clone()
            .and_then(|x| x.try_into().ok())
            .map(|s: SocketAddr| s.to_string());
        let local_ips: Vec<IpAddr> = request
            .local_ips
            .iter()
            .map(|x| x.try_into())
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(|_| Status::internal("Invalid local ip provided"))?;

        let pubkey_changed = old_pubkey.as_deref() != Some(&publickey[..]);
        let state_changed = old_endpoint != endpoint
            || old_nat != requested_nat_type as i32
            || old_monitor != requested_node_flags.monitor
            || old_relay != requested_node_flags.relay;
        let old_ips_set: HashSet<IpAddr> = old_local_ips
            .unwrap_or_default()
            .split(',')
            .filter(|x| !x.is_empty())
            .filter_map(|x| IpAddr::from_str(x).ok())
            .collect();
        let new_ips_set: HashSet<IpAddr> = local_ips.iter().copied().collect();
        let ips_changed = old_ips_set != new_ips_set;
        let port_changed = old_port != Some(local_port as i64);

        debug!(
            pubkey_changed,
            state_changed, ips_changed, port_changed, "checking peer update"
        );

        // Only write when something actually changed: an unchanged reconnect
        // costs zero log entries.
        if pubkey_changed || state_changed || ips_changed || port_changed {
            // On a learner replica: forward the client's update to the leader
            // and return the leader's (linearizable) reply, so clients work
            // transparently against any node.
            if let Some(mut leader) = self.leader_client().await? {
                info!("forwarding get_addresses update to leader");
                let mut forwarded = Request::new(request.clone());
                forward_metadata(&request_metadata, &mut forwarded);
                return leader.get_addresses(forwarded).await;
            }
            let mutation = Mutation::UpdatePeerState {
                peer_id: auth_peer.peerid,
                pubkey: if pubkey_changed {
                    Some(publickey)
                } else {
                    None
                },
                endpoint: endpoint.clone(),
                nat_type: requested_nat_type as i32,
                monitor: requested_node_flags.monitor,
                relay: requested_node_flags.relay,
                local_ips,
                local_port: Some(local_port),
            };
            self.raft
                .write(mutation)
                .await
                .map_err(write_error_to_status)?;
            if pubkey_changed {
                info!(peerid = auth_peer.peerid, "peer re-enrolled with new key");
            }
        }

        // Build the reply from the (now applied) state.
        let mut conn = self.conn().await?;
        let addresses = wireguard_addresses(&mut conn, auth_peer.peerid)
            .await
            .map_err(|e| {
                error!("SQL Error: {e}");
                Status::internal("SQL Error")
            })?;
        let overlay_ips = state_reader::overlay_ips(&mut conn, auth_peer.peerid)
            .await
            .map_err(|e| {
                error!("SQL Error: {e}");
                Status::internal("SQL Error")
            })?;
        Ok(Response::new(AddressReply::new(&addresses, &overlay_ips)))
    }

    /// Event stream with raft-index-based resume cursor.
    #[instrument(skip(self, request))]
    async fn get_events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<Self::getEventsStream>, Status> {
        let auth_peer = self.authenticate(request.metadata(), 0).await?;
        let start_event = request.into_inner().start_event;
        let initial_events = if start_event == 0 {
            self.get_initial_events(&auth_peer).await?
        } else {
            Vec::new()
        };
        let stream = self
            .events
            .register(auth_peer.peerid, start_event, initial_events)
            .await;
        Ok(Response::new(stream))
    }

    /// Create a user. Admin-only (permission 100).
    #[instrument(skip(self, request))]
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.create_user(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        self.authenticate(request.metadata(), 100).await?;
        let request = request.into_inner();
        let mutation = Mutation::CreateUser {
            name: request.name,
            permissions: request.permissions as i32,
        };
        self.raft
            .write(mutation)
            .await
            .map_err(write_error_to_status)?;
        Ok(Response::new(CreateUserReply {}))
    }

    /// Delete a user. Admin-only. Owned nodes lose the ownership link but
    /// keep running.
    #[instrument(skip(self, request))]
    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.delete_user(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        self.authenticate(request.metadata(), 100).await?;
        let request = request.into_inner();
        let user_id = self.lookup_user_id(&request.name).await?;
        let mutation = Mutation::DeleteUser { user_id };
        self.raft
            .write(mutation)
            .await
            .map_err(write_error_to_status)?;
        Ok(Response::new(DeleteUserReply {}))
    }

    /// Change a user (currently: permission level). Admin-only.
    #[instrument(skip(self, request))]
    async fn change_user(
        &self,
        request: Request<ChangeUserRequest>,
    ) -> Result<Response<ChangeUserReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.change_user(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        self.authenticate(request.metadata(), 100).await?;
        let request = request.into_inner();
        let user_id = self.lookup_user_id(&request.name).await?;
        match request.what {
            Some(change_user_request::What::PermissionLevel(level)) => {
                let mutation = Mutation::SetUserPermissions {
                    user_id,
                    permissions: level as i32,
                };
                self.raft
                    .write(mutation)
                    .await
                    .map_err(write_error_to_status)?;
            }
            _ => return Err(Status::invalid_argument("Invalid what")),
        }
        Ok(Response::new(ChangeUserReply {}))
    }

    /// Add a peer; must reach the leader. The enrollment token is generated
    /// here on the leader and carried in the log entry. The node is linked
    /// to the acting user; the permission cap is applied at apply time.
    #[instrument(skip(self, request))]
    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.add_peer(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        let metadata = request.metadata();
        let auth_peer = self.authenticate(metadata, 1).await?;
        let request = request.get_ref();
        if request.permissions > 0 {
            self.authenticate(metadata, request.permissions + 1).await?;
        }
        let user_id = self.owner_user_id(auth_peer.peerid).await?;
        let token = Uuid::new_v4();
        // Requested addresses with their prefixes; the state machine stores
        // the host address and looks the network row up by the truncated
        // subnet.
        let addresses: Vec<ipnet::IpNet> = request
            .internal_ip
            .iter()
            .filter_map(|x| x.clone().try_into().ok())
            .collect();

        let mutation = Mutation::AddPeer {
            user_id,
            name: request.name.clone(),
            token,
            permissions: request.permissions,
            addresses,
        };
        let response = self
            .raft
            .write(mutation)
            .await
            .map_err(write_error_to_status)?;
        let reply_token = response
            .token
            .expect("AddPeer response always carries a token");
        Ok(Response::new(AddPeerReply {
            token: reply_token.as_bytes().to_vec(),
        }))
    }

    #[instrument(skip(self, request))]
    async fn delete_peer(
        &self,
        request: Request<DeletePeerRequest>,
    ) -> Result<Response<DeletePeerReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.delete_peer(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        self.authenticate(request.metadata(), 1).await?;
        let request = request.into_inner();
        let peerid = self
            .get_peerid_from_identifier(
                request
                    .id
                    .ok_or_else(|| Status::invalid_argument("Identifier missing"))?,
            )
            .await?;

        let mutation = Mutation::DeletePeer { peer_id: peerid };
        self.raft
            .write(mutation)
            .await
            .map_err(write_error_to_status)?;
        self.events.remove(peerid).await;
        Ok(Response::new(DeletePeerReply {}))
    }

    #[instrument(skip(self, request))]
    async fn change_peer(
        &self,
        request: Request<ChangePeerRequest>,
    ) -> Result<Response<ChangePeerReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.change_peer(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        let auth_peer = self.authenticate(request.metadata(), 0).await?;
        let request = request.into_inner();
        let peerid = self
            .get_peerid_from_identifier(
                request
                    .id
                    .ok_or_else(|| Status::invalid_argument("invalid identifier"))?,
            )
            .await?;
        match request.what {
            Some(change_peer_request::What::PermissionLevel(level)) => {
                if auth_peer.permissions < 100 {
                    return Err(Status::permission_denied(
                        "Only admins can change permission",
                    ));
                }
                let mutation = Mutation::SetPeerPermissions {
                    peer_id: peerid,
                    permissions: level as i32,
                };
                self.raft
                    .write(mutation)
                    .await
                    .map_err(write_error_to_status)?;
            }
            Some(change_peer_request::What::Owner(user_name)) => {
                // Transfer node ownership; admin-only. The permission cap
                // re-applies at the node's next role operation.
                if auth_peer.permissions < 100 {
                    return Err(Status::permission_denied(
                        "Only admins can change ownership",
                    ));
                }
                let user_id = self.lookup_user_id(&user_name).await?;
                let mutation = Mutation::SetPeerOwner {
                    peer_id: peerid,
                    user_id,
                };
                self.raft
                    .write(mutation)
                    .await
                    .map_err(write_error_to_status)?;
            }
            Some(change_peer_request::What::Endpoint(endpoint)) => {
                if auth_peer.peerid != peerid && auth_peer.permissions < 50 {
                    return Err(Status::permission_denied("Permission level too low"));
                }
                let sockaddr: SocketAddr = endpoint
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid endpoint"))?;
                let mutation = Mutation::SetPeerEndpoint {
                    peer_id: peerid,
                    endpoint: sockaddr.to_string(),
                };
                self.raft
                    .write(mutation)
                    .await
                    .map_err(write_error_to_status)?;
            }
            _ => return Err(Status::invalid_argument("Invalid what")),
        }
        Ok(Response::new(ChangePeerReply {}))
    }

    #[instrument(skip(self, request))]
    async fn add_route(&self, request: Request<Route>) -> Result<Response<AddRouteReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.add_route(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        self.authenticate(request.metadata(), 1).await?;
        let route = request.into_inner();
        let to: IpNet = route
            .to
            .ok_or_else(|| Status::invalid_argument("destination missing"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid destination Network"))?;
        let via: IpAddr = route
            .via
            .ok_or_else(|| Status::invalid_argument("via missing"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid via address"))?;

        let mutation = Mutation::AddRoute {
            destination: to,
            via_ip: via,
        };
        self.raft
            .write(mutation)
            .await
            .map_err(write_error_to_status)?;
        Ok(Response::new(AddRouteReply {}))
    }

    #[instrument(skip(self, request))]
    async fn del_route(&self, request: Request<Route>) -> Result<Response<DelRouteReply>, Status> {
        let request_metadata = request.metadata().clone();
        let inner = request.get_ref().clone();
        if let Some(response) = self
            .forward_with(request_metadata, |mut client, metadata| {
                let mut request = Request::new(inner);
                forward_metadata(&metadata, &mut request);
                Box::pin(async move { client.del_route(request).await })
            })
            .await?
        {
            return Ok(response);
        }
        self.authenticate(request.metadata(), 1).await?;
        let route = request.into_inner();
        let to: IpNet = route
            .to
            .ok_or_else(|| Status::invalid_argument("destination missing"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid destination Network"))?;
        let via: IpAddr = route
            .via
            .ok_or_else(|| Status::invalid_argument("via missing"))?
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid via address"))?;

        let mutation = Mutation::DeleteRoute {
            destination: to,
            via_ip: via,
        };
        self.raft
            .write(mutation)
            .await
            .map_err(write_error_to_status)?;
        Ok(Response::new(DelRouteReply {}))
    }
}

impl WirespiderServerState {
    /// Initial event dump for a fresh event stream: all enrolled peers except
    /// the requesting one, plus all routes.
    async fn get_initial_events(
        &self,
        auth_peer: &AuthenticatedPeer,
    ) -> Result<Vec<Event>, Status> {
        let mut conn = self.conn().await?;
        let mut events = Vec::new();
        let results =
            sqlx::query(r#"SELECT peerid FROM peers WHERE peerid!=? AND pubkey IS NOT NULL"#)
                .bind(auth_peer.peerid)
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| {
                    error!("SQL Error: {e}");
                    Status::internal("SQL Error")
                })?;
        for row in results {
            let peerid: i64 = row.get("peerid");
            if let Some(peer) = state_reader::peer_proto(&mut conn, peerid)
                .await
                .map_err(|e| {
                    error!("SQL Error: {e}");
                    Status::internal("SQL Error")
                })?
            {
                events.push(Event::from_peer(0, EventType::New, peer));
            }
        }
        let routes = sqlx::query(
            r#"
            SELECT r.destination, a.ip_address FROM routes r
            LEFT JOIN addresses a USING(addressid)
            LEFT JOIN peers p USING(peerid)
            WHERE a.peerid!=? AND p.pubkey IS NOT NULL"#,
        )
        .bind(auth_peer.peerid)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            error!("SQL Error: {e}");
            Status::internal("SQL Error")
        })?;
        for row in routes {
            let destination: String = row.get("destination");
            let via: String = row.get("ip_address");
            if let (Ok(dest), Ok(via)) = (IpNet::from_str(&destination), IpAddr::from_str(&via)) {
                events.push(Event::from_route(0, EventType::New, Route::new(dest, via)));
            }
        }
        Ok(events)
    }
}

/// wireguard networks containing the peer's addresses, for the reply.
async fn wireguard_addresses(
    conn: &mut SqliteConnection,
    peerid: i64,
) -> Result<Vec<IpNet>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT a.ip_address, n.network, n.ipv6 FROM addresses a LEFT JOIN networks n USING(networkid) WHERE a.peerid=? and n.network_type='wireguard'"#,
    )
    .bind(peerid)
    .fetch_all(&mut *conn)
    .await?;
    let mut nets = Vec::new();
    for row in &rows {
        let Ok(net) = state_reader::parse_network(row) else {
            continue;
        };
        let Ok(address) = row.try_get::<String, _>("ip_address") else {
            continue;
        };
        let Ok(address) = IpAddr::from_str(&address) else {
            continue;
        };
        if net.contains(&address) {
            nets.push(narrow(&net, &address));
        }
    }
    Ok(nets)
}

fn narrow(net: &IpNet, address: &IpAddr) -> IpNet {
    match (net, address) {
        (IpNet::V4(net), IpAddr::V4(addr)) => Ipv4Net::new(*addr, net.prefix_len())
            .map(IpNet::V4)
            .unwrap_or(IpNet::V4(*net)),
        (IpNet::V6(net), IpAddr::V6(addr)) => Ipv6Net::new(*addr, net.prefix_len())
            .map(IpNet::V6)
            .unwrap_or(IpNet::V6(*net)),
        _ => unreachable!("network and address are of different families"),
    }
}

use ipnet::IpNet;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
