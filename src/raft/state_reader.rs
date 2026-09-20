//! Read helpers over the cluster state tables, shared between the gRPC
//! handlers and the raft state machine so both project peers identically.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

use ipnet::IpNet;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use sqlx::Row;

use crate::protocol::Peer;

fn decode_err(column: &str) -> sqlx::Error {
    sqlx::Error::ColumnDecode {
        index: column.to_string(),
        source: "invalid data in database".into(),
    }
}

/// wireguard tunnel ips of a peer: its addresses in wireguard networks.
async fn tunnel_ips(conn: &mut sqlx::SqliteConnection, peerid: i64) -> sqlx::Result<Vec<IpAddr>> {
    let rows = sqlx::query(
        r#"SELECT ip_address FROM addresses a LEFT JOIN networks n USING(networkid) WHERE a.peerid=? AND n.network_type='wireguard'"#,
    )
    .bind(peerid)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            row.try_get::<String, _>("ip_address")
                .ok()
                .and_then(|x| IpAddr::from_str(&x).ok())
        })
        .collect())
}

/// vxlan networks the peer has overlay addresses in, narrowed to the address.
pub async fn overlay_ips(
    conn: &mut sqlx::SqliteConnection,
    peerid: i64,
) -> sqlx::Result<Vec<IpNet>> {
    let rows = sqlx::query(
        r#"SELECT a.ip_address, n.network, n.ipv6 FROM addresses a LEFT JOIN networks n USING(networkid) WHERE a.peerid=? AND n.network_type='vxlan'"#,
    )
    .bind(peerid)
    .fetch_all(&mut *conn)
    .await?;
    let mut result = Vec::new();
    for row in &rows {
        let Ok(net) = parse_network(row) else {
            continue;
        };
        let Ok(address) = row
            .try_get::<String, _>("ip_address")
            .and_then(|x| IpAddr::from_str(&x).map_err(|_| decode_err("ip_address")))
        else {
            continue;
        };
        if net.contains(&address) {
            result.push(narrow(&net, &address));
        }
    }
    Ok(result)
}

/// wireguard allowed ips of a peer: its addresses (whole networks for
/// monitor/relay peers, host nets otherwise) plus routed destinations.
async fn allowed_ips(conn: &mut sqlx::SqliteConnection, peerid: i64) -> sqlx::Result<Vec<IpNet>> {
    let rows = sqlx::query(
        r#"SELECT a.ip_address, p.monitor, p.relay, n.network, n.ipv6 FROM addresses a LEFT JOIN networks n USING(networkid) LEFT JOIN peers p USING(peerid) WHERE a.peerid=? AND n.network_type='wireguard'"#,
    )
    .bind(peerid)
    .fetch_all(&mut *conn)
    .await?;
    let mut result = Vec::new();
    for row in &rows {
        let Ok(net) = parse_network(row) else {
            continue;
        };
        let Ok(address) = row.try_get::<String, _>("ip_address") else {
            continue;
        };
        let Ok(address) = IpAddr::from_str(&address) else {
            continue;
        };
        if !net.contains(&address) {
            continue;
        }
        if row.try_get::<bool, _>("monitor").unwrap_or(false)
            || row.try_get::<bool, _>("relay").unwrap_or(false)
        {
            result.push(net);
        } else {
            result.push(narrow_host(&net, &address));
        }
    }
    let routes = sqlx::query(
        r#"SELECT destination FROM routes LEFT JOIN addresses a USING(addressid) WHERE a.peerid=?"#,
    )
    .bind(peerid)
    .fetch_all(&mut *conn)
    .await?;
    for row in &routes {
        if let Some(net) = row
            .try_get::<String, _>("destination")
            .ok()
            .and_then(|x| IpNet::from_str(&x).ok())
        {
            result.push(net);
        }
    }
    Ok(result)
}

/// Build the client facing proto Peer for a peer id, if the peer exists and is
/// enrolled (has a pubkey). Returns None otherwise.
pub async fn peer_proto(
    conn: &mut sqlx::SqliteConnection,
    peerid: i64,
) -> Result<Option<Peer>, sqlx::Error> {
    let Some(row) = sqlx::query(
        r#"SELECT peer_name, pubkey, current_endpoint, nat_type, monitor, relay, local_ips, local_port FROM peers WHERE peerid=?"#,
    )
    .bind(peerid)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let Some(pubkey) = row.try_get::<Option<Vec<u8>>, _>("pubkey")? else {
        return Ok(None);
    };
    let pubkey: [u8; 32] = pubkey
        .as_slice()
        .try_into()
        .map_err(|_| decode_err("pubkey"))?;
    let endpoint = row
        .try_get::<Option<String>, _>("current_endpoint")?
        .and_then(|x| SocketAddr::from_str(&x).ok());
    let local_ips: Vec<IpAddr> = row
        .try_get::<Option<String>, _>("local_ips")?
        .unwrap_or_default()
        .split(',')
        .filter(|x| !x.is_empty())
        .filter_map(|x| IpAddr::from_str(x).ok())
        .collect();
    let nat_type: i32 = row.try_get("nat_type")?;
    let monitor: bool = row.try_get("monitor")?;
    let relay: bool = row.try_get("relay")?;
    let local_port: Option<i64> = row.try_get("local_port")?;
    Ok(Some(
        Peer::builder()
            .wg_public_key(pubkey)
            .name(row.try_get::<String, _>("peer_name")?)
            .endpoint(endpoint)
            .allowed_ips(allowed_ips(&mut *conn, peerid).await?)
            .overlay_ips(overlay_ips(&mut *conn, peerid).await?)
            .tunnel_ips(tunnel_ips(&mut *conn, peerid).await?)
            .node_flags(monitor, relay)
            .nat_type(nat_type)
            .local_ips(local_ips)
            .local_port(local_port.map(|p| p as u32).unwrap_or(0))
            .build(),
    ))
}

/// Parse a `network` TEXT column into an IpNet, checking the `ipv6` flag.
pub fn parse_network(row: &sqlx::sqlite::SqliteRow) -> Result<IpNet, sqlx::Error> {
    let network: String = row.try_get("network")?;
    let ipv6: bool = row.try_get("ipv6")?;
    let net = IpNet::from_str(&network).map_err(|_| decode_err("network"))?;
    debug_assert_eq!(ipv6, matches!(net, IpNet::V6(_)));
    Ok(net)
}

/// The truncated network an IP belongs to (its host network).
pub fn addr_to_net(addr: IpAddr) -> IpNet {
    IpNet::from(addr).trunc()
}

/// Narrow a network to the same prefix length but anchored at `address`.
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

/// Narrow to a single host net (/32 or /128).
fn narrow_host(net: &IpNet, address: &IpAddr) -> IpNet {
    match (net, address) {
        (IpNet::V4(net), IpAddr::V4(addr)) => Ipv4Net::new(*addr, 32)
            .map(IpNet::V4)
            .unwrap_or(IpNet::V4(*net)),
        (IpNet::V6(net), IpAddr::V6(addr)) => Ipv6Net::new(*addr, 128)
            .map(IpNet::V6)
            .unwrap_or(IpNet::V6(*net)),
        _ => unreachable!("network and address are of different families"),
    }
}
