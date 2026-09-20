use std::str::FromStr;
use std::time::Duration;

use crate::cli::{
    CreateAdminCommand, NetworkCommand, NetworkType, ServerDatabaseCommand, ServerRunCommand,
};
use crate::server::protocol::WirespiderServerState;

use anyhow::Context;
use tokio_graceful_shutdown::Toplevel;
use tokio_graceful_shutdown::{SubsystemBuilder, SubsystemHandle};
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

    Toplevel::new(async move |s: &mut SubsystemHandle| {
        s.start(SubsystemBuilder::new(
            "TonicService",
            async move |handle: &mut SubsystemHandle| tonic_service(handle, opt.clone()).await,
        ));
    })
    .catch_signals()
    .handle_shutdown_requests(Duration::from_millis(1000))
    .await?;

    Ok(())
}

async fn tonic_service(
    subsys: &mut SubsystemHandle,
    run: crate::cli::ServerRunCommand,
) -> anyhow::Result<()> {
    let database_url = env::var("DATABASE_URL")?;
    let pool = wirespider::raft::startup::connect_db(&database_url).await?;
    wirespider::raft::run_migrations(&pool).await;

    // Connect the state machine's applied events to the client event hub.
    let event_hub = std::sync::Arc::new(wirespider::raft::event_hub::EventHub::new());
    let event_sender = event_hub.spawn_pump();

    let (raft_handle, raft_service) = wirespider::raft::startup::start_raft(
        pool.clone(),
        wirespider::raft::startup::RaftOptions {
            advertise: run.bind.to_string(),
            snapshot_logs_since_last: run.base.raft_snapshot_logs_since_last,
        },
        event_sender,
    )
    .await?;
    let raft = wirespider::protocol::raft_server::RaftServer::new(raft_service);
    let raft_control =
        wirespider::protocol::raft_control_server::RaftControlServer::new(RaftControlService {
            raft: raft_handle.clone(),
        });

    let wirespider = WirespiderServer::new(
        WirespiderServerState::new(pool, raft_handle.clone(), event_hub).await?,
    );

    info!("Starting Server on {:?}", run.bind);
    tokio::select! {
        _ = subsys.on_shutdown_requested() => {
            info!("Shutting down");
        },
        _ = Server::builder()
            .add_service(wirespider)
            .add_service(raft)
            .add_service(raft_control)
            .serve(run.bind) =>
        {
            subsys.request_shutdown();
        }
    };
    Ok(())
}

/// gRPC service handling operator join requests.
struct RaftControlService {
    raft: wirespider::raft::raft_handle::RaftHandle,
}

#[tonic::async_trait]
impl wirespider::protocol::raft_control_server::RaftControl for RaftControlService {
    async fn join(
        &self,
        request: tonic::Request<wirespider::protocol::RaftJoinRequest>,
    ) -> Result<tonic::Response<wirespider::protocol::RaftJoinResponse>, tonic::Status> {
        let request = request.into_inner();
        let members = wirespider::raft::startup::handle_join_request(
            &self.raft,
            request.pubkey,
            request.advertise,
        )
        .await
        .map_err(|e| tonic::Status::failed_precondition(e.to_string()))?;
        Ok(tonic::Response::new(
            wirespider::protocol::RaftJoinResponse {
                added: true,
                members,
            },
        ))
    }

    async fn promote(
        &self,
        request: tonic::Request<wirespider::protocol::RaftPromoteRequest>,
    ) -> Result<tonic::Response<wirespider::protocol::RaftPromoteResponse>, tonic::Status> {
        let request = request.into_inner();
        wirespider::raft::startup::handle_promote_request(&self.raft, request.pubkey)
            .await
            .map_err(|e| tonic::Status::failed_precondition(e.to_string()))?;
        Ok(tonic::Response::new(
            wirespider::protocol::RaftPromoteResponse {},
        ))
    }

    async fn leave(
        &self,
        request: tonic::Request<wirespider::protocol::RaftLeaveRequest>,
    ) -> Result<tonic::Response<wirespider::protocol::RaftLeaveResponse>, tonic::Status> {
        let request = request.into_inner();
        wirespider::raft::startup::handle_leave_request(&self.raft, request.pubkey)
            .await
            .map_err(|e| tonic::Status::failed_precondition(e.to_string()))?;
        Ok(tonic::Response::new(
            wirespider::protocol::RaftLeaveResponse {},
        ))
    }
}

#[instrument]
pub async fn server_manage(opt: ServerDatabaseCommand) -> anyhow::Result<()> {
    let options =
        SqliteConnectOptions::from_str(&env::var("DATABASE_URL").unwrap())?.create_if_missing(true);
    let pool = SqlitePool::connect_with(options).await?;
    match opt {
        ServerDatabaseCommand::Migrate(db) => {
            env::set_var("DATABASE_URL", &db.database_url);
            MIGRATOR.run(&pool).await?;
            Ok(())
        }
        ServerDatabaseCommand::CreateAdmin(CreateAdminCommand {
            name,
            addresses,
            db,
        }) => {
            env::set_var("DATABASE_URL", &db.database_url);
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
            // Create the admin USER and its first node directly in the local
            // database. This command is only valid BEFORE `raft-init`; the
            // import in raft-init replays both rows into the log so they
            // replicate.
            let uuid = Uuid::new_v4();
            let user_id =
                sqlx::query(r#"INSERT INTO users (user_name, permissions) VALUES (?, 100)"#)
                    .bind(format!("{name}-user"))
                    .execute(&pool)
                    .await?
                    .last_insert_rowid();
            let peerid = sqlx::query(
                r#"
                        INSERT INTO peers (token, peer_name, permissions, user_id)
                        VALUES (?, ?, 100, ?)
                        "#,
            )
            .bind(uuid)
            .bind(name)
            .bind(user_id)
            .execute(&pool)
            .await?
            .last_insert_rowid();
            for (addr, net) in &addr_network_map {
                sqlx::query(
                    "INSERT INTO addresses (networkid, peerid, ip_address) VALUES (?, ?, ?)",
                )
                .bind(networkid_map[net])
                .bind(peerid)
                .bind(addr.addr().to_string())
                .execute(&pool)
                .await?;
            }
            println!("Created admin with token: {}", uuid);
            Ok(())
        }
        ServerDatabaseCommand::Network(NetworkCommand::Create(x)) => {
            env::set_var("DATABASE_URL", &x.db.database_url);
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
            env::set_var("DATABASE_URL", &x.db.database_url);
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
        ServerDatabaseCommand::RaftInit(db) => {
            env::set_var("DATABASE_URL", &db.database_url);
            MIGRATOR.run(&pool).await?;
            let pool = wirespider::raft::startup::connect_db(&db.database_url).await?;
            wirespider::raft::startup::raft_init(pool).await
        }
        ServerDatabaseCommand::RaftJoin(join) => {
            env::set_var("DATABASE_URL", &join.db.database_url);
            MIGRATOR.run(&pool).await?;
            wirespider::raft::startup::raft_join(&join.db.database_url, join.member, join.advertise)
                .await
        }
        ServerDatabaseCommand::RaftPromote(promote) => {
            env::set_var("DATABASE_URL", &promote.db.database_url);
            MIGRATOR.run(&pool).await?;
            wirespider::raft::startup::raft_promote(&promote.db.database_url, promote.leader).await
        }
        ServerDatabaseCommand::RaftLeave(leave) => {
            env::set_var("DATABASE_URL", &leave.db.database_url);
            MIGRATOR.run(&pool).await?;
            wirespider::raft::startup::raft_leave(&leave.db.database_url, leave.member).await
        }
        ServerDatabaseCommand::RaftTakeover(takeover) => {
            env::set_var("DATABASE_URL", &takeover.db.database_url);
            MIGRATOR.run(&pool).await?;
            wirespider::raft::startup::raft_takeover(
                &takeover.db.database_url,
                takeover.confirm_loss,
            )
            .await
        }
    }
}
