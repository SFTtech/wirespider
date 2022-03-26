use std::time::Duration;
use std::{net::SocketAddr, str::FromStr};

use crate::server::protocol::WirespiderServerState;

use anyhow::Context;
use clap::{ArgEnum, Args, Subcommand};
use tokio_graceful_shutdown::SubsystemHandle;
use tokio_graceful_shutdown::Toplevel;
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::Registry;
use tracing_subscriber::prelude::*;

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

#[derive(Debug, Args)]
pub struct RunCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(short, long, default_value = "0.0.0.0:49582")]
    pub bind: SocketAddr,
}

#[derive(Debug, Subcommand)]
pub enum ManageCommand {
    #[clap(name = "create-admin")]
    CreateAdmin(CreateAdminCommand),

    #[clap(name = "network", subcommand)]
    Network(NetworkCommand),

    #[clap(name = "migrate")]
    Migrate,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "snake")]
pub enum NetworkCommand {
    Create(CreateNetworkCommand),
    Delete(ParamIPNet),
}

#[derive(Debug, Args)]
#[clap(rename_all = "snake")]
pub struct CreateNetworkCommand {
    network: IpNet,
    #[clap(arg_enum, default_value_t = NetworkType::Wireguard)]
    network_type: NetworkType,
}

#[derive(Copy, Clone, PartialEq, Eq, ArgEnum, Debug)]
enum NetworkType {
    Wireguard,
    Vxlan,
}

#[derive(Debug, Args)]
pub struct ParamIPNet {
    #[clap(required = true, parse(try_from_str))]
    pub ipnet: IpNet,
}

#[derive(Debug, Args)]
pub struct CreateAdminCommand {
    #[clap(required = true)]
    pub name: String,
    #[clap(required = true, min_values = 1)]
    pub addresses: Vec<IpNet>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[clap(name = "run")]
    Run(RunCommand),
    #[clap(name = "manage", subcommand)]
    Manage(ManageCommand),
}

#[derive(Debug, Args)]
pub struct BaseOptions {
    // enable debug
    #[clap(long)]
    pub debug: bool,

    #[clap(short('d'), long, env = "DATABASE_URL")]
    pub database_url: String,
}



pub async fn server_run(opt: RunCommand) -> anyhow::Result<()> {
    let log_level = if opt.base.debug {LevelFilter::DEBUG} else {LevelFilter::INFO};
    // logging
    let subscriber = Registry::default()
        .with(log_level)
        .with(ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer());
    
  
    tracing::subscriber::set_global_default(subscriber)?;

    env::set_var("DATABASE_URL", &opt.base.database_url);
    debug!("Starting");

    Toplevel::new()
        .start("TonicService", move |handle| tonic_service(handle, opt.bind.clone()))
        .catch_signals()
        .handle_shutdown_requests(Duration::from_millis(1000)).await?;

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
pub async fn server_manage(opt: ManageCommand) -> anyhow::Result<()> {
    let options =
        SqliteConnectOptions::from_str(&env::var("DATABASE_URL").unwrap())?.create_if_missing(true);
    let pool = SqlitePool::connect_with(options).await?;
    match opt {
        ManageCommand::Migrate => {
            MIGRATOR.run(&pool).await?;
            Ok(())
        }
        ManageCommand::CreateAdmin(CreateAdminCommand { name, addresses }) => {
            // find networks for addresses
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
                            .fetch_one(&pool)
                            .await
                            .context(format!("Could not find network for IP: {}", addr))?;
                    networkid_map.insert(net, result.get("networkid"));
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
        ManageCommand::Network(NetworkCommand::Create(x)) => {
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
        ManageCommand::Network(NetworkCommand::Delete(x)) => {
            let query = sqlx::query(
                r#"
                            DELETE FROM networks WHERE network=? AND ipv6=?
                        "#,
            );
            match x.ipnet {
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
