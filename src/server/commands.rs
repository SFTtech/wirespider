use std::time::Duration;
use std::{net::SocketAddr, str::FromStr};

use crate::cli::{
    CreateAdminCommand, NetworkCommand, NetworkType, ServerDatabaseCommand, ServerRunCommand,
};
use crate::server::protocol::WirespiderServerState;

use anyhow::Context;
use tokio_graceful_shutdown::SubsystemHandle;
use tokio_graceful_shutdown::Toplevel;
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;

use std::{collections::HashMap, env};

use tonic::transport::Server;

use wirespider::protocol::wirespider_server::WirespiderServer;

use ipnet::IpNet;

use tracing::{debug, info, instrument};

use sqlx::sqlite::SqlitePool;
use sqlx::{prelude::*, sqlite::SqliteConnectOptions};
use uuid::Uuid;

use sqlx::migrate::Migrator;

static MIGRATOR: Migrator = sqlx::migrate!();

pub async fn server_run(opt: ServerRunCommand) -> anyhow::Result<()> {
    let log_level = if opt.base.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    // logging
    let subscriber = Registry::default()
        .with(log_level)
        .with(ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer());

    tracing::subscriber::set_global_default(subscriber)?;

    env::set_var("DATABASE_URL", &opt.base.db.database_url);
    debug!("Starting");

    Toplevel::new()
        .start("TonicService", move |handle| {
            tonic_service(handle, opt.bind)
        })
        .catch_signals()
        .handle_shutdown_requests(Duration::from_millis(1000))
        .await?;

    Ok(())
}

async fn tonic_service(subsys: SubsystemHandle, bind: SocketAddr) -> anyhow::Result<()> {
    let wirespider = WirespiderServer::new(WirespiderServerState::new().await?);

    info!("Starting Server on {:?}", bind);
    tokio::select! {
        _ = subsys.on_shutdown_requested() => {
            info!("Shutting down");
        },
        _ = Server::builder().add_service(wirespider).serve(bind) => {
            subsys.request_shutdown();
        }
    };
    Ok(())
}

#[instrument]
pub async fn server_manage(opt: ServerDatabaseCommand) -> anyhow::Result<()> {
    match opt {
        ServerDatabaseCommand::Migrate(db) => {
            let options = SqliteConnectOptions::from_str(&db.database_url)?.create_if_missing(true);
            let pool = SqlitePool::connect_with(options).await?;
            MIGRATOR.run(&pool).await?;
            Ok(())
        }
        ServerDatabaseCommand::CreateAdmin(CreateAdminCommand {
            name,
            addresses,
            db,
        }) => {
            SqliteConnectOptions::from_str(&db.database_url)?.create_if_missing(true);
            let options = SqliteConnectOptions::from_str(&db.database_url)?.create_if_missing(true);
            let pool = SqlitePool::connect_with(options).await?;
            // find networks for addresses
            let mut networkid_map: HashMap<IpNet, i64> = HashMap::new();
            let mut addr_network_map: HashMap<IpNet, IpNet> = HashMap::new();
            for addr in addresses {
                let net = addr.clone().trunc();
                if let std::collections::hash_map::Entry::Vacant(entry) = networkid_map.entry(net) {
                    let result =
                        sqlx::query("SELECT networkid FROM networks WHERE network=? AND ipv6=?")
                            .bind(net.to_string())
                            .bind(match net {
                                IpNet::V6(_) => true,
                                IpNet::V4(_) => false,
                            })
                            .fetch_one(&pool)
                            .await
                            .context(format!("Could not find network for IP: {}", addr))?;
                    entry.insert(result.get("networkid"));
                }
                addr_network_map.insert(addr, net);
            }
            //create user
            let uuid = Uuid::new_v4();
            let userid = sqlx::query(
                r#"
                        INSERT INTO peers (token, peer_name, permissions)
                        VALUES (?, ?, 100)
                        "#,
            )
            .bind(uuid)
            .bind(name)
            .execute(&pool)
            .await?
            .last_insert_rowid();
            for (addr, net) in &addr_network_map {
                sqlx::query(
                    "INSERT INTO addresses (networkid, peerid, ip_address) VALUES (?, ?, ?)",
                )
                .bind(networkid_map[net])
                .bind(userid)
                .bind(addr.addr().to_string())
                .execute(&pool)
                .await?;
            }
            println!("Created admin with token: {}", uuid);
            Ok(())
        }
        ServerDatabaseCommand::Network(NetworkCommand::Create(x)) => {
            let options =
                SqliteConnectOptions::from_str(&x.db.database_url)?.create_if_missing(true);
            let pool = SqlitePool::connect_with(options).await?;
            let network_type = match x.network_type {
                NetworkType::Vxlan => "vxlan",
                NetworkType::Wireguard => "wireguard",
            };
            let query = sqlx::query(
                r#"
                            INSERT INTO networks (network_type, network, ipv6)
                            VALUES (?, ?, ?)
                        "#,
            )
            .bind(network_type);
            match x.network {
                IpNet::V4(x) => {
                    query.bind(x.to_string()).bind(false).execute(&pool).await?;
                }
                IpNet::V6(x) => {
                    query.bind(x.to_string()).bind(true).execute(&pool).await?;
                }
            }
            println!("Created network {}", x.network);
            Ok(())
        }
        ServerDatabaseCommand::Network(NetworkCommand::Delete(x)) => {
            let options =
                SqliteConnectOptions::from_str(&x.db.database_url)?.create_if_missing(true);
            let pool = SqlitePool::connect_with(options).await?;
            let query = sqlx::query(
                r#"
                            DELETE FROM networks WHERE network=? AND ipv6=?
                        "#,
            );
            match x.ipnet.ipnet {
                IpNet::V4(x) => {
                    query.bind(x.to_string()).bind(false).execute(&pool).await?;
                }
                IpNet::V6(x) => {
                    query.bind(x.to_string()).bind(true).execute(&pool).await?;
                }
            }
            Ok(())
        }
    }
}
