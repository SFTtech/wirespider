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
    ClientStartCommand, ConnectionOptions,
};
use crate::client::event_loop::event_loop;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use client_state::ClientState;
use interface::{DefaultOverlayInterface, DefaultWireguardInterface};
use peer_identifier::Identifier;
use thiserror::Error;
use tokio_graceful_shutdown::Toplevel;
use tonic::codegen::InterceptedService;
use tonic::metadata::Ascii;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use tonic::{metadata::MetadataValue, transport::Endpoint};
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;
use tracing_unwrap::ResultExt;
use wirespider::protocol::wirespider_client::WirespiderClient;
use wirespider::protocol::*;
use lazy_static::lazy_static;

lazy_static! {
    static ref CLIENT_STATE: ClientState = ClientState::default();
}

#[derive(Clone)]
pub struct WirespiderInterceptor {
    token: MetadataValue<Ascii>,
}

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error(transparent)]
    TransportError(#[from] tonic::transport::Error),
}

impl Interceptor for WirespiderInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        Ok(request)
    }
}

pub async fn connect(
    conn: ConnectionOptions,
) -> Result<WirespiderClient<InterceptedService<Channel, WirespiderInterceptor>>, ConnectionError> {
    let endpoint = Endpoint::from(conn.endpoint)
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(25 * 60));
    let channel = endpoint.connect().await?;
    let token = format!("Bearer {}", conn.token)
        .as_str()
        .parse()
        .unwrap_or_log();
    Ok(WirespiderClient::with_interceptor(
        channel,
        WirespiderInterceptor { token },
    ))
}

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
    Toplevel::new()
        .catch_signals()
        .start("Eventloop", |subsys| event_loop(subsys, start_opts))
        .handle_shutdown_requests(Duration::from_millis(1000))
        .await?;
    Ok(())
}

pub async fn client_manage(manage_opts: ClientManageCommand) -> anyhow::Result<()> {
    match manage_opts {
        ClientManageCommand::Peer(peer_opts) => match peer_opts {
            ClientManagePeerCommand::Add(command) => {
                let mut client = connect(command.connection).await?;
                let request = AddPeerRequest {
                    name: command.name,
                    internal_ip: command.addresses.into_iter().map(|x| x.into()).collect(),
                    permissions: command.permission_level,
                };
                let result = client.add_peer(request).await?;
                println!(
                    "Peer created. Token: {}",
                    uuid::Uuid::from_slice(&result.into_inner().token)?
                );
            }
            ClientManagePeerCommand::Delete(command) => {
                let id = if let Some(name) = command.peer.name_id {
                    PeerIdentifier {
                        identifier: Some(Identifier::Name(name)),
                    }
                } else if let Some(token) = command.peer.token_id {
                    PeerIdentifier {
                        identifier: Some(Identifier::Token(token.as_bytes().to_vec())),
                    }
                } else if let Some(pubkey) = command.peer.public_key_id {
                    PeerIdentifier {
                        identifier: Some(Identifier::PublicKey(
                            BASE64_STANDARD.decode(pubkey).expect("Could not decode base64 of public key"),
                        )),
                    }
                } else {
                    unreachable!()
                };
                let request = DeletePeerRequest { id: Some(id) };
                let mut client = connect(command.connection).await?;
                let result = client.delete_peer(request).await?;
                println!("{:?}", result.into_inner());
            }
            ClientManagePeerCommand::Change(change) => {
                let id = if let Some(name) = change.peer.name_id {
                    PeerIdentifier {
                        identifier: Some(Identifier::Name(name)),
                    }
                } else if let Some(token) = change.peer.token_id {
                    PeerIdentifier {
                        identifier: Some(Identifier::Token(token.as_bytes().to_vec())),
                    }
                } else if let Some(pubkey) = change.peer.public_key_id {
                    PeerIdentifier {
                        identifier: Some(Identifier::PublicKey(
                            BASE64_STANDARD.decode(pubkey).expect("Could not decode base64 of public key"),
                        )),
                    }
                } else {
                    unreachable!()
                };

                let request = ChangePeerRequest {
                    id: Some(id),
                    what: Some(change_peer_request::What::Endpoint(
                        change.new_endpoint.into(),
                    )),
                };
                let mut client = connect(change.connection).await?;
                let result = client.change_peer(request).await?;
                println!("{:?}", result.into_inner());
            }
        },
        ClientManageCommand::Route(route_command) => match route_command {
            ClientManageRouteCommand::Add(add) => {
                let request = Route {
                    to: Some(add.net.into()),
                    via: Some(add.via.into()),
                };
                let mut client = connect(add.connection).await?;
                let result = client.add_route(request).await?;
                println!("{:?}", result.into_inner());
            }
            ClientManageRouteCommand::Delete(delete) => {
                let request = Route {
                    to: Some(delete.net.into()),
                    via: Some(delete.via.into()),
                };
                let mut client = connect(delete.connection).await?;
                let result = client.del_route(request).await?;
                println!("{:?}", result.into_inner());
            }
        },
    }
    Ok(())
}
