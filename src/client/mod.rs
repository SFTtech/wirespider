use std::sync::LazyLock;
use std::time::Duration;

mod client_state;
mod endpoint;
mod event_loop;
mod interface;
mod local_ip_detection;
mod monitor;
mod nat;

use crate::cli::{
    BaseOptions, ClientManageCommand, ClientManagePeerCommand, ClientManageRouteCommand,
    ClientStartCommand,
};
use crate::client::event_loop::event_loop;
use crate::transport::connect;
use client_state::ClientState;
use interface::{DefaultOverlayInterface, DefaultWireguardInterface};
use tokio_graceful_shutdown::{SubsystemBuilder, SubsystemHandle, Toplevel};
use tonic::Request;
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::Registry;
use tracing_subscriber::prelude::*;
use wirespider::protocol::*;

static CLIENT_STATE: LazyLock<ClientState> = LazyLock::new(ClientState::default);

fn set_loglevel(opt: &BaseOptions) -> Result<(), tracing::dispatcher::SetGlobalDefaultError> {
    let log_level = if opt.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    // logging
    let subscriber = Registry::default()
        .with(log_level)
        .with(ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer());

    tracing::subscriber::set_global_default(subscriber)
}

pub async fn client_start(start_opts: ClientStartCommand) -> anyhow::Result<()> {
    set_loglevel(&start_opts.base)?;
    let client = connect(start_opts.connection.clone()).await?;
    Toplevel::new(async |s: &mut SubsystemHandle| {
        s.start(SubsystemBuilder::new(
            "Eventloop",
            async move |subsys: &mut SubsystemHandle| event_loop(subsys, client, start_opts).await,
        ));
    })
    .catch_signals()
    .handle_shutdown_requests(Duration::from_millis(1000))
    .await?;
    Ok(())
}

pub async fn client_manage(manage_opts: ClientManageCommand) -> anyhow::Result<()> {
    match manage_opts {
        ClientManageCommand::Peer(peer_opts) => match peer_opts {
            ClientManagePeerCommand::Add(command) => {
                let client = connect(command.connection).await?;
                let result = client
                    .add_peer(Request::new(AddPeerRequest {
                        name: command.name,
                        internal_ip: command.addresses.into_iter().map(|x| x.into()).collect(),
                        permissions: command.permission_level,
                    }))
                    .await?;
                println!(
                    "Peer created. Token: {}",
                    uuid::Uuid::from_slice(&result.into_inner().token)?
                );
            }
            ClientManagePeerCommand::Delete(command) => {
                let client = connect(command.connection).await?;
                let result = client
                    .delete_peer(Request::new(DeletePeerRequest {
                        id: Some(command.peer.try_into()?),
                    }))
                    .await?;
                println!("{:?}", result.into_inner());
            }
            ClientManagePeerCommand::Change(change) => {
                let client = connect(change.connection).await?;
                let result = client
                    .change_peer(Request::new(ChangePeerRequest {
                        id: Some(change.peer.try_into()?),
                        what: Some(change_peer_request::What::Endpoint(
                            change.new_endpoint.into(),
                        )),
                    }))
                    .await?;
                println!("{:?}", result.into_inner());
            }
        },
        ClientManageCommand::Route(route_command) => match route_command {
            ClientManageRouteCommand::Add(add) => {
                let client = connect(add.connection).await?;
                let result = client
                    .add_route(Request::new(Route::new(add.net, add.via)))
                    .await?;
                println!("{:?}", result.into_inner());
            }
            ClientManageRouteCommand::Delete(delete) => {
                let client = connect(delete.connection).await?;
                let result = client
                    .del_route(Request::new(Route::new(delete.net, delete.via)))
                    .await?;
                println!("{:?}", result.into_inner());
            }
        },
    }
    Ok(())
}
