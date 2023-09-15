use futures::future::join_all;
use futures::Stream;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use sqlx::error::Error as SqlxError;
use sqlx::prelude::*;
use sqlx::sqlite::SqlitePool;
use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::{
    borrow::Borrow,
    cmp::max,
    collections::{HashMap, VecDeque},
    convert::TryInto,
    mem,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    usize,
};
use std::{cmp, env};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::RwLock;
use tracing_unwrap::ResultExt;
use uuid::Uuid;
use wirespider::WireguardKey;

use tonic::{metadata::MetadataMap, Code, Request, Response, Status};

use wirespider::protocol::wirespider_server::Wirespider;

use wirespider::protocol::*;

//logging
use tracing::{debug, error, info, instrument};

//iterators
use itertools::Itertools;

const EVENT_DEQUE_MAX_CAPACITY: usize = 1000;

type EventStream = Pin<Box<dyn Stream<Item = Result<Event, Status>> + Send + Sync>>;

#[derive(Debug)]
pub struct WirespiderServerState {
    sqlite_pool: SqlitePool,
    event_listeners: RwLock<HashMap<i64, Sender<Result<Event, Status>>>>,
    event_list: RwLock<VecDeque<Event>>,
    current_eventid: AtomicU64,
}

#[derive(Debug)]
struct AuthenticatedPeer {
    peerid: i64,
    permissions: i32,
    nat_type: i32,
    monitor: bool,
    relay: bool,
}

trait TracingIntoStatusExt<T> {
    fn into_status(self) -> Result<T, Status>;
}

impl<T> TracingIntoStatusExt<T> for Result<T, SqlxError> {
    fn into_status(self) -> Result<T, Status> {
        match self {
            Err(sql_error) => {
                error!("SQL Error: {:?}", sql_error);
                Err(Status::internal("SQL Error"))
            }
            Ok(x) => Ok(x),
        }
    }
}

async fn send_event_to_single_peer(
    peerid: i64,
    sender: &Sender<Result<Event, Status>>,
    event: Event,
) -> Result<(), i64> {
    if let Err(_err) = sender.send(Ok(event.clone())).await {
        return Err(peerid);
    }
    Ok(())
}

impl WirespiderServerState {
    #[instrument]
    pub async fn new() -> Result<WirespiderServerState, SqlxError> {
        let sqlite_pool =
            SqlitePool::connect(&env::var("DATABASE_URL").expect("Please set DATABASE_URL"))
                .await?;
        Ok(WirespiderServerState {
            sqlite_pool,
            event_listeners: RwLock::default(),
            event_list: RwLock::default(),
            current_eventid: AtomicU64::new(1),
        })
    }

    #[instrument]
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
        let result = sqlx::query(
            r#"SELECT peerid,permissions,nat_type,monitor,relay FROM peers WHERE token=?"#,
        )
        .bind(uuid)
        .fetch_one(&self.sqlite_pool)
        .await
        .map_err(|_| Status::permission_denied("Invalid authorization"))?;
        if result.get::<i32, &str>("permissions") >= permission_level {
            Ok(AuthenticatedPeer {
                peerid: result.get("peerid"),
                permissions: result.get("permissions"),
                nat_type: result.get("nat_type"),
                monitor: result.get("monitor"),
                relay: result.get("relay"),
            })
        } else {
            Err(Status::permission_denied("Insufficient Permissions"))
        }
    }

    #[instrument]
    async fn get_peerid_from_identifier(&self, id: PeerIdentifier) -> Result<i64, Status> {
        match id.identifier {
            Some(peer_identifier::Identifier::Name(name)) => {
                let result = sqlx::query(r#"SELECT peerid FROM peers WHERE peer_name=?"#)
                    .bind(name)
                    .fetch_one(&self.sqlite_pool)
                    .await
                    .into_status()?;
                result.try_get("peerid").into_status()
            }
            Some(peer_identifier::Identifier::Token(token)) => {
                let result = sqlx::query(r#"SELECT peerid FROM peers WHERE token=?"#)
                    .bind(Uuid::from_bytes(
                        token
                            .try_into()
                            .map_err(|_| Status::invalid_argument("Invalid token"))?,
                    ))
                    .fetch_one(&self.sqlite_pool)
                    .await
                    .into_status()?;
                result.try_get("peerid").into_status()
            }
            Some(peer_identifier::Identifier::PublicKey(key)) => {
                let result = sqlx::query(r#"SELECT peerid FROM peers WHERE pubkey=?"#)
                    .bind(key)
                    .fetch_one(&self.sqlite_pool)
                    .await
                    .map_err(|_| Status::permission_denied("Invalid authorization"))?;
                result.try_get("peerid").into_status()
            }
            _ => Err(Status::invalid_argument("Missing identifier")),
        }
    }

    #[instrument]
    async fn get_peer_from_peerid(&self, peerid: i64) -> Result<Option<Peer>, Status> {
        let peer_data = sqlx::query(
            r#"SELECT peer_name,pubkey,current_endpoint,nat_type,monitor,relay,local_ips,local_port FROM peers WHERE peerid=?"#,
        )
        .bind(peerid)
        .fetch_one(&self.sqlite_pool)
        .await
        .map_err(|_| {
            Status::internal(
                "SQL error: Could not get peer from peerid",
            )
        })?;
        let pubkey: Option<Vec<u8>> = peer_data.get("pubkey");
        if pubkey.is_none() {
            return Ok(None);
        }
        let endpoint_unparsed: Option<String> = peer_data.get("current_endpoint");
        let endpoint = match endpoint_unparsed {
            Some(data) => Some(
                data.parse()
                    .map_err(|_| Status::internal("Endpoint error"))?,
            ),
            None => None,
        };
        let pubkey: WireguardKey = pubkey
            .unwrap()
            .try_into()
            .map_err(|_| Status::internal("Key error"))?;

        let allowed_ips = self
            .get_allowed_ips(peerid)
            .await
            .map_err(|_| Status::internal("allowed IP error"))?;

        let overlay_ips = self
            .get_overlay_ips(peerid)
            .await
            .map_err(|_| Status::internal("overlay IP error"))?;

        let tunnel_ips = self
            .get_tunnel_ips(peerid)
            .await
            .map_err(|_| Status::internal("tunnel IP error"))?;

        let local_ips = peer_data
            .get::<&str, &str>("local_ips")
            .split(',')
            .filter(|x| !x.is_empty())
            .map(IpAddr::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Status::internal("local IP error"))?;

        let peer_builder = Peer::builder()
            .wg_public_key(pubkey)
            .name(peer_data.get("peer_name"))
            .endpoint(endpoint)
            .tunnel_ips(tunnel_ips)
            .allowed_ips(allowed_ips)
            .overlay_ips(overlay_ips)
            .node_flags(peer_data.get("monitor"), peer_data.get("relay"))
            .nat_type(peer_data.get("nat_type"))
            .local_ips(local_ips)
            .local_port(peer_data.get("local_port"));
        Ok(Some(peer_builder.build()))
    }

    #[instrument]
    async fn send_event(&self, event: Event) -> () {
        let disconnected_peers: Vec<i64> = {
            let listener_guard = self.event_listeners.read().await;
            let mut join_handles = Vec::new();
            for (&peerid, sender) in listener_guard.borrow().iter() {
                join_handles.push(send_event_to_single_peer(peerid, sender, event.clone()));
            }
            join_all(join_handles).await
        }
        .into_iter()
        .filter_map(Result::err)
        .collect();
        if !disconnected_peers.is_empty() {
            let mut listener_guard = self.event_listeners.write().await;
            for x in disconnected_peers {
                listener_guard.borrow_mut().remove(&x);
            }
        }
        // TODO: remove peer from routing?
    }

    #[instrument]
    async fn send_peer_event(&self, event_type: EventType, peer: Peer) -> () {
        let mut lockguard = self.event_list.write().await;
        let eventid = self.current_eventid.fetch_add(1, Relaxed);
        let event = Event::from_peer(eventid, event_type, peer);
        lockguard.push_back(event.clone());
        while lockguard.len() > EVENT_DEQUE_MAX_CAPACITY {
            lockguard.pop_front();
        }
        mem::drop(lockguard);
        self.send_event(event).await;
    }

    #[instrument]
    async fn send_route_event(&self, event_type: EventType, route: Route) -> () {
        let mut lockguard = self.event_list.write().await;
        let eventid = self.current_eventid.fetch_add(1, Relaxed);
        let event = Event::from_route(eventid, event_type, route);
        lockguard.push_back(event.clone());
        while lockguard.len() > EVENT_DEQUE_MAX_CAPACITY {
            lockguard.pop_front();
        }
        mem::drop(lockguard);
        self.send_event(event).await;
    }

    #[instrument]
    async fn get_initial_events(
        &self,
        auth_peer: &AuthenticatedPeer,
    ) -> Result<Vec<Event>, Status> {
        let mut events = Vec::new();
        let results = sqlx::query(r#"SELECT peerid, peer_name, pubkey, current_endpoint, nat_type, monitor, relay, local_ips, local_port FROM peers WHERE peerid!=? AND pubkey IS NOT NULL"#)
            .bind(auth_peer.peerid)
            .fetch_all(&self.sqlite_pool).await.map_err(|_| Status::internal("sql error"))?;

        for result in results {
            let pubkey: Vec<u8> = result.get("pubkey");
            let allowed_ips = self.get_allowed_ips(result.get("peerid")).await?;
            let overlay_ips = self.get_overlay_ips(result.get("peerid")).await?;
            let tunnel_ips = self.get_tunnel_ips(result.get("peerid")).await?;
            let local_ips = result
                .get::<&str, &str>("local_ips")
                .split(',')
                .filter(|x| !x.is_empty())
                .map(IpAddr::from_str)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Status::internal("local IP error"))?;
            let peer_builder = Peer::builder()
                .wg_public_key(
                    pubkey
                        .as_slice()
                        .try_into()
                        .map_err(|_| Status::internal("Invalid pubkey"))?,
                )
                .name(result.get("peer_name"))
                .endpoint(
                    result
                        .try_get("current_endpoint")
                        .ok()
                        .and_then(|x| SocketAddr::from_str(x).ok()),
                ) //TODO: use current endpoint IP if connected via wireguard to server);
                .tunnel_ips(tunnel_ips)
                .allowed_ips(allowed_ips)
                .overlay_ips(overlay_ips)
                .node_flags(result.get("monitor"), result.get("relay"))
                .nat_type(result.get("nat_type"))
                .local_ips(local_ips)
                .local_port(result.get("local_port"));
            events.push(Event::from_peer(0, EventType::New, peer_builder.build()));
        }
        info!("Events: {:?}", events);

        events.extend(
            sqlx::query(
                r#"
            SELECT r.destination,a.ip_address FROM routes r
            LEFT JOIN addresses a USING(addressid)
            LEFT JOIN peers p USING(peerid)
            WHERE a.peerid!=? AND p.pubkey IS NOT NULL"#,
            )
            .bind(auth_peer.peerid)
            .fetch_all(&self.sqlite_pool)
            .await
            .map_err(|_| Status::internal("SQL error when getting routes"))?
            .into_iter()
            .map(|x| {
                Route::new(
                    str::parse(x.get("destination")).unwrap(),
                    str::parse(x.get("ip_address")).unwrap(),
                )
            })
            .map(|route| Event::from_route(0, EventType::New, route)),
        );

        info!("Events: {:?}", events);

        Ok(events)
    }

    #[instrument]
    async fn get_overlay_ips(&self, peerid: i64) -> Result<Vec<IpNet>, Status> {
        let results = sqlx::query(r#"SELECT a.ip_address, n.network FROM addresses a LEFT JOIN networks n USING(networkid) WHERE a.peerid=? AND n.network_type='vxlan'"#)
            .bind(peerid)
            .fetch_all(&self.sqlite_pool).await.map_err(|_| Status::internal("SQL error: Could not get allowed ips"))?;
        let mut final_addresses = Vec::new();
        for result in results {
            let net = IpNet::from_str(result.get("network"))
                .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?;
            let address = IpAddr::from_str(result.get("ip_address"))
                .map_err(|_| Status::new(Code::InvalidArgument, "Invalid address"))?;
            if net.contains(&address) {
                final_addresses.push(match (&net, &address) {
                    (IpNet::V4(net), IpAddr::V4(addr)) => Ipv4Net::new(*addr, net.prefix_len())
                        .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?
                        .into(),
                    (IpNet::V6(net), IpAddr::V6(addr)) => Ipv6Net::new(*addr, net.prefix_len())
                        .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?
                        .into(),
                    _ => unreachable!(),
                });
            }
        }
        Ok(final_addresses)
    }

    #[instrument]
    async fn get_tunnel_ips(&self, peerid: i64) -> Result<Vec<IpAddr>, Status> {
        let results = sqlx::query(r#"SELECT ip_address FROM addresses a LEFT JOIN networks n USING(networkid) WHERE a.peerid=? AND n.network_type='wireguard'"#)
            .bind(peerid)
            .fetch_all(&self.sqlite_pool)
            .await
            .map_err(|_| Status::internal("SQL error: Could not get allowed ips"))?;
        Ok(results
            .into_iter()
            .map(|x| IpAddr::from_str(x.get("ip_address")).unwrap_or_log())
            .collect())
    }

    #[instrument]
    async fn get_allowed_ips(&self, peerid: i64) -> Result<Vec<IpNet>, Status> {
        let results = sqlx::query(r#"SELECT a.ip_address, p.nat_type, p.monitor, p.relay, n.network FROM addresses a LEFT JOIN networks n USING(networkid) LEFT JOIN peers p USING(peerid) WHERE a.peerid=? AND n.network_type='wireguard'"#)
            .bind(peerid)
            .fetch_all(&self.sqlite_pool).await.map_err(|_| Status::internal("SQL error: Could not get allowed ips"))?;
        let mut final_addresses = Vec::new();
        for result in results {
            let net = IpNet::from_str(result.get("network"))
                .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?;
            let address = IpAddr::from_str(result.get("ip_address"))
                .map_err(|_| Status::new(Code::InvalidArgument, "Invalid address"))?;
            if net.contains(&address) {
                if result.get("monitor") || result.get("relay") {
                    final_addresses.push(net)
                } else {
                    final_addresses.push(match (&net, &address) {
                        (IpNet::V4(_net), IpAddr::V4(addr)) => Ipv4Net::new(*addr, 32)
                            .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?
                            .into(),
                        (IpNet::V6(_net), IpAddr::V6(addr)) => Ipv6Net::new(*addr, 128)
                            .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?
                            .into(),
                        _ => unreachable!(),
                    });
                }
            }
        }
        let route_ips = sqlx::query(
            r#"
        SELECT destination FROM routes
            LEFT JOIN addresses a USING(addressid)
            WHERE a.peerid=?"#,
        )
        .bind(peerid)
        .fetch_all(&self.sqlite_pool)
        .await
        .into_status()?;

        Ok(final_addresses
            .into_iter()
            .chain(
                // Also allow route destinations (allow reverse path)
                route_ips
                    .into_iter()
                    .filter_map(|x| str::parse(x.get("destination")).ok()),
            )
            .collect())
    }
}

#[tonic::async_trait]
impl Wirespider for WirespiderServerState {
    type getEventsStream = EventStream;
    #[instrument]
    async fn get_addresses(
        &self,
        request: Request<AddressRequest>,
    ) -> Result<Response<AddressReply>, Status> {
        let mut auth_peer = self.authenticate(request.metadata(), 0).await?;
        let mut updated = false;
        let mut eventtype = EventType::Changed;

        let requested_nat_type = NatType::try_from(request.get_ref().nat_type)
            .map_err(|_| Status::invalid_argument("Invalid NatType"))?;
        let requested_node_flags = request
            .get_ref()
            .node_flags
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Invalid NodeType"))?;
        if requested_node_flags.monitor && auth_peer.permissions < 25 {
            return Err(Status::permission_denied("Not allowed to monitor"));
        }
        if requested_node_flags.relay && auth_peer.permissions < 50 {
            return Err(Status::permission_denied("Not allowed to relay"));
        }

        if auth_peer.nat_type != requested_nat_type.into() {
            updated = true;
            auth_peer.nat_type = requested_nat_type.into();
        }

        if auth_peer.monitor != requested_node_flags.monitor {
            updated = true;
            auth_peer.monitor = requested_node_flags.monitor;
        }

        if auth_peer.relay != requested_node_flags.relay {
            updated = true;
            auth_peer.relay = requested_node_flags.relay;
        }

        if request.get_ref().wg_public_key.len() != 32 {
            return Err(Status::new(Code::InvalidArgument, "Wrong key length"));
        }
        let publickey: WireguardKey = request
            .get_ref()
            .wg_public_key
            .clone()
            .try_into()
            .map_err(|_| Status::internal("invalid key"))?;

        let local_port: u16 = request
            .get_ref()
            .local_port
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid local port"))?;

        // TODO: do not allow updating key to be the same as an existing entry
        debug!("getting peer data");
        let peer_query = sqlx::query(
            r#"SELECT pubkey, current_endpoint, local_ips, local_port, nat_type FROM peers WHERE peerid=?"#,
        )
        .bind(auth_peer.peerid)
        .fetch_one(&self.sqlite_pool)
        .await
        .into_status()?;
        let old_pubkey = peer_query.get::<Option<&[u8]>, &str>("pubkey");
        if old_pubkey != Some(&publickey[0..32]) {
            debug!("updating peer data");
            updated = true;
            eventtype = EventType::New;
            if old_pubkey.is_some() {
                //delete the old peer
                let peer = self
                    .get_peer_from_peerid(auth_peer.peerid)
                    .await?
                    .ok_or_else(|| Status::internal("peer deleted"))?;
                self.send_peer_event(EventType::Deleted, peer.clone()).await;
            }
            //update database
            sqlx::query(
                r#"UPDATE peers SET pubkey=?, nat_type=?, relay=?, monitor=?  WHERE peerid=?"#,
            )
            .bind(&publickey[0..32])
            .bind(auth_peer.nat_type)
            .bind(auth_peer.relay)
            .bind(auth_peer.monitor)
            .bind(auth_peer.peerid)
            .execute(&self.sqlite_pool)
            .await
            .into_status()?;
        }

        debug!("checking local_port");
        let old_local_port = peer_query
            .try_get::<u16, &str>("local_port")
            .into_status()?;
        if old_local_port != local_port {
            // no need to send update to peers, so do not set updated flag
            sqlx::query(r#"UPDATE peers SET local_port=? WHERE peerid=?"#)
                .bind(local_port)
                .bind(auth_peer.peerid)
                .execute(&self.sqlite_pool)
                .await
                .into_status()?;
        }
        let old_endpoint = peer_query
            .get::<Option<&str>, &str>("current_endpoint")
            .and_then(|x| SocketAddr::from_str(x).ok());
        let new_enpoint = request
            .get_ref()
            .endpoint
            .clone()
            .and_then(|x| x.try_into().ok());
        if let Some(endpoint) = new_enpoint {
            if Some(endpoint) != old_endpoint {
                updated = true;
                let endpoint = endpoint.to_string();
                //update database
                sqlx::query(r#"UPDATE peers SET current_endpoint=? WHERE peerid=?"#)
                    .bind(endpoint)
                    .bind(auth_peer.peerid)
                    .execute(&self.sqlite_pool)
                    .await
                    .into_status()?;
            }
        }

        let old_nat_type = NatType::try_from(peer_query.get::<i32, &str>("nat_type"));
        let new_nat_type = request.get_ref().nat_type;

        if let Ok(old_nat_type) = old_nat_type {
            if new_nat_type != old_nat_type as i32 {
                updated = true;
                //update database
                sqlx::query(r#"UPDATE peers SET nat_type=? WHERE peerid=?"#)
                    .bind(new_nat_type)
                    .bind(auth_peer.peerid)
                    .execute(&self.sqlite_pool)
                    .await
                    .into_status()?;
            }
        }

        // local ips
        debug!("checking local_ips");
        let old_local_ips = peer_query
            .get::<&str, &str>("local_ips")
            .split(',')
            .filter(|x| !x.is_empty()) // do not try to map empty strings
            .map(IpAddr::from_str)
            .collect::<Result<HashSet<IpAddr>, _>>()
            .map_err(|_| Status::internal("Invalid local ip (internal server error)"))?;
        let mut new_local_ips = request
            .get_ref()
            .local_ips
            .iter()
            .map(|x| x.try_into())
            .collect::<Result<HashSet<IpAddr>, _>>()
            .map_err(|_| Status::internal("Invalid local ip provided"))?;
        let mut ip4range = IpRange::new();
        let mut ip6range = IpRange::new();

        let results = sqlx::query(r#"SELECT a.ip_address, n.network FROM addresses a LEFT JOIN networks n USING(networkid) WHERE a.peerid=? and n.network_type='wireguard'"#)
            .bind(auth_peer.peerid)
            .fetch_all(&self.sqlite_pool).await.map_err(|_| Status::internal("SQL error: Could not get addresses"))?;
        let mut final_addresses = Vec::new();
        for result in results {
            let net = IpNet::from_str(result.get("network"))
                .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?;

            match net {
                IpNet::V4(net) => {
                    ip4range.add(net);
                }
                IpNet::V6(net) => {
                    ip6range.add(net);
                }
            }

            let address = IpAddr::from_str(result.get("ip_address"))
                .map_err(|_| Status::new(Code::InvalidArgument, "Invalid address"))?;
            if net.contains(&address) {
                final_addresses.push(match (&net, &address) {
                    (IpNet::V4(net), IpAddr::V4(addr)) => Ipv4Net::new(*addr, net.prefix_len())
                        .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?
                        .into(),
                    (IpNet::V6(net), IpAddr::V6(addr)) => Ipv6Net::new(*addr, net.prefix_len())
                        .map_err(|_| Status::new(Code::InvalidArgument, "Invalid network"))?
                        .into(),
                    _ => unreachable!(),
                });
            }
            debug!(
                auth_peer.peerid,
                "Address: {:?}",
                result.get::<&str, &str>("ip_address")
            );
            debug!(
                auth_peer.peerid,
                "Network: {:?}",
                result.get::<&str, &str>("network")
            );
        }
        debug!("comparing local_ips to networks");
        new_local_ips.retain(|x| !match x {
            IpAddr::V4(net) => ip4range.contains(net),
            IpAddr::V6(net) => ip6range.contains(net),
        });
        debug!("final local ips: {:?}", new_local_ips);
        if new_local_ips != old_local_ips {
            debug!("updating local ips");
            sqlx::query(r#"UPDATE peers SET local_ips=? WHERE peerid=?"#)
                .bind(new_local_ips.iter().map(IpAddr::to_string).join(","))
                .bind(auth_peer.peerid)
                .execute(&self.sqlite_pool)
                .await
                .into_status()?;
            // sending peer update is not needed so we do net set updated to true.
        }
        let overlay_ips = self
            .get_overlay_ips(auth_peer.peerid)
            .await
            .map_err(|_| Status::internal("allowed IP error"))?;
        let reply = AddressReply::new(&final_addresses, &overlay_ips);

        if updated {
            debug!("update triggered");
            let peer = self
                .get_peer_from_peerid(auth_peer.peerid)
                .await?
                .ok_or_else(|| Status::internal("Peer deleted"))?;
            self.send_peer_event(eventtype, peer.clone()).await;
        } else {
            debug!("No update sent!");
        }

        Ok(Response::new(reply))
    }

    #[instrument]
    async fn get_events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<Self::getEventsStream>, Status> {
        let auth_peer = self.authenticate(request.metadata(), 0).await?;
        let event_list_guard = self.event_list.read().await;
        let request = request.into_inner();
        let events = if request.start_event == 0 {
            info!("initial");
            self.get_initial_events(&auth_peer).await?
        } else if let Some(event) = event_list_guard.borrow().front() {
            match request.start_event.cmp(&event.id) {
                cmp::Ordering::Greater => {
                    info!("initial2");
                    self.get_initial_events(&auth_peer).await?
                }
                cmp::Ordering::Equal => {
                    info!("empty");
                    Vec::new()
                }
                cmp::Ordering::Less => {
                    info!("skip");
                    event_list_guard
                        .iter()
                        .skip_while(|x| x.id < request.start_event)
                        .cloned()
                        .collect()
                }
            }
        } else {
            info!("initial3");
            self.get_initial_events(&auth_peer).await?
        };
        let (tx, rx) = channel(max(
            EVENT_DEQUE_MAX_CAPACITY,
            events.len() + EVENT_DEQUE_MAX_CAPACITY / 2,
        ));
        {
            let mut guard = self.event_listeners.write().await;
            guard.borrow_mut().insert(auth_peer.peerid, tx.clone());
        };
        info!("sending");
        for event in events {
            info!("sending: {:?}", event);
            tx.send(Ok(event))
                .await
                .expect_or_log("Could not fill channel, should have capacity");
        }
        info!("sent");
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    #[instrument]
    #[allow(clippy::map_entry)]
    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerReply>, Status> {
        let metadata = request.metadata();
        self.authenticate(metadata, 1).await?;
        let request = request.get_ref();
        if request.permissions > 0 {
            self.authenticate(metadata, request.permissions + 1).await?;
        }
        let token = Uuid::new_v4();
        let addresses: Vec<IpNet> = request
            .internal_ip
            .iter()
            .filter_map(|x| x.try_into().ok())
            .collect();

        let mut networkid_map: HashMap<IpNet, i64> = HashMap::new();
        let mut addr_network_map: HashMap<IpNet, IpNet> = HashMap::new();
        for addr in addresses {
            let net = addr.clone().trunc();
            if !networkid_map.contains_key(&net) {
                let result =
                    sqlx::query("SELECT networkid FROM networks WHERE network=? AND ipv6=?")
                        .bind(net.to_string())
                        .bind(match net {
                            IpNet::V6(_) => true,
                            IpNet::V4(_) => false,
                        })
                        .fetch_one(&self.sqlite_pool)
                        .await
                        .map_err(|_| Status::internal("SQL error: Could not find network"))?;
                networkid_map.insert(net, result.get("networkid"));
            }
            addr_network_map.insert(addr, net);
        }

        let mut transaction = self
            .sqlite_pool
            .begin()
            .await
            .map_err(|_| Status::internal("SQL Error: could not start transaction"))?;
        let peerid =
            sqlx::query("INSERT INTO peers (peer_name, token, permissions) VALUES (?, ?, ?)")
                .bind(&request.name)
                .bind(token)
                .bind(request.permissions)
                .execute(&mut *transaction)
                .await
                .into_status()?
                .last_insert_rowid();

        for net in addr_network_map.keys() {
            sqlx::query("INSERT INTO addresses (peerid, networkid, ip_address) VALUES (?, ?, ?)")
                .bind(peerid)
                .bind(networkid_map[&addr_network_map[net]])
                .bind(net.addr().to_string())
                .execute(&mut *transaction)
                .await
                .into_status()?;
        }
        transaction.commit().await.into_status()?;

        let reply = AddPeerReply {
            token: token.as_bytes().to_vec(),
        };
        Ok(Response::new(reply))
    }

    #[instrument]
    async fn delete_peer(
        &self,
        request: Request<DeletePeerRequest>,
    ) -> Result<Response<DeletePeerReply>, Status> {
        self.authenticate(request.metadata(), 1).await?;

        let request = request.into_inner();
        let peerid = self
            .get_peerid_from_identifier(
                request
                    .id
                    .ok_or_else(|| Status::invalid_argument("Identifier missing"))?,
            )
            .await?;

        let peer = self.get_peer_from_peerid(peerid).await?;

        sqlx::query(
            r#"
            DELETE FROM peers WHERE peerid=?
            "#,
        )
        .bind(peerid)
        .execute(&self.sqlite_pool)
        .await
        .into_status()?;

        if let Some(peer) = peer {
            self.send_peer_event(EventType::Deleted, peer.clone()).await;
        }

        //remove peer from senders, if the peer is in it, to prevent it from getting more info
        self.event_listeners
            .write()
            .await
            .borrow_mut()
            .remove(&peerid);

        let reply = DeletePeerReply {};
        Ok(Response::new(reply))
    }

    #[instrument]
    async fn change_peer(
        &self,
        request: Request<ChangePeerRequest>,
    ) -> Result<Response<ChangePeerReply>, Status> {
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
                sqlx::query(r#"UPDATE peers SET permissions=? WHERE peerid=?"#)
                    .bind(level)
                    .bind(peerid)
                    .execute(&self.sqlite_pool)
                    .await
                    .into_status()?;
            }
            Some(change_peer_request::What::Endpoint(endpoint)) => {
                if auth_peer.peerid != peerid && auth_peer.permissions < 50 {
                    return Err(Status::permission_denied("Permission level too low"));
                }
                let sockaddr: SocketAddr = endpoint
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid endpoint"))?;
                sqlx::query(r#"UPDATE peers SET current_endpoint=? WHERE peerid=?"#)
                    .bind(sockaddr.to_string())
                    .bind(peerid)
                    .execute(&self.sqlite_pool)
                    .await
                    .into_status()?;
                let peer = self
                    .get_peer_from_peerid(peerid)
                    .await?
                    .ok_or_else(|| Status::invalid_argument("peer not complete, login first?"))?;
                self.send_peer_event(EventType::Changed, peer).await;
            }
            _ => return Err(Status::invalid_argument("Invalid what")),
        }
        Ok(Response::new(ChangePeerReply {}))
    }

    #[instrument]
    async fn add_route(&self, request: Request<Route>) -> Result<Response<AddRouteReply>, Status> {
        self.authenticate(request.metadata(), 1).await?;

        let route = request.into_inner();
        let route_copy = route.clone();
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

        let addressid: i64 = sqlx::query("SELECT addressid FROM addresses WHERE ip_address=?")
            .bind(via.to_string())
            .fetch_one(&self.sqlite_pool)
            .await
            .into_status()?
            .try_get("addressid")
            .into_status()?;

        sqlx::query("INSERT INTO routes (addressid, destination) VALUES (?, ?)")
            .bind(addressid)
            .bind(to.to_string())
            .execute(&self.sqlite_pool)
            .await
            .into_status()?;

        self.send_route_event(EventType::New, route_copy.clone())
            .await;

        let reply = AddRouteReply {};
        Ok(Response::new(reply))
    }

    #[instrument]
    async fn del_route(&self, request: Request<Route>) -> Result<Response<DelRouteReply>, Status> {
        self.authenticate(request.metadata(), 1).await?;

        let route = request.into_inner();
        let route_copy = route.clone();
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

        let addressid: i64 = sqlx::query("SELECT addressid FROM addresses WHERE address=?")
            .bind(via.to_string())
            .fetch_one(&self.sqlite_pool)
            .await
            .into_status()?
            .try_get("addressid")
            .into_status()?;

        sqlx::query("DELETE FROM routes WHERE addressid=? AND destination=?")
            .bind(addressid)
            .bind(to.to_string())
            .execute(&self.sqlite_pool)
            .await
            .into_status()?;

        self.send_route_event(EventType::Deleted, route_copy.clone())
            .await;

        let reply = DelRouteReply {};
        Ok(Response::new(reply))
    }
}
