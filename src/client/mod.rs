use std::net::SocketAddr;
use std::time::Duration;
use std::{net::IpAddr, num::NonZeroU16};

mod client_state;
mod endpoint;
mod event_loop;
mod interface;
mod monitor;
mod nat;

use crate::client::event_loop::event_loop;
use base64::decode;
use clap::{ArgGroup, Args, Subcommand, ValueHint};
use client_state::ClientState;
use interface::{DefaultOverlayInterface, DefaultWireguardInterface};
use ipnet::IpNet;
use peer_identifier::Identifier;
use thiserror::Error;
use tokio_graceful_shutdown::Toplevel;
use tonic::codegen::InterceptedService;
use tonic::metadata::Ascii;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use tonic::{
    metadata::MetadataValue,
    transport::{Endpoint, Uri},
};
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;
use tracing_unwrap::ResultExt;
use uuid::Uuid;
use wirespider::protocol::wirespider_client::WirespiderClient;
use wirespider::protocol::*;

lazy_static! {
    static ref CLIENT_STATE: ClientState = ClientState::default();
}

#[derive(Debug, Args)]
pub struct BaseOptions {
    /// enable debug
    #[clap(short, long)]
    debug: bool,
}

#[derive(Debug, Args)]
pub struct ConnectionOptions {
    #[clap(short, long, parse(try_from_str), env = "WS_ENDPOINT")]
    endpoint: Uri,

    /// Token for authentication
    #[clap(short, long, parse(try_from_str), env = "WS_TOKEN")]
    token: Uuid,
}

#[derive(Debug, Args)]
pub struct StartCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(flatten)]
    connection: ConnectionOptions,
    #[clap(required = true, short, long, env = "WS_DEVICE")]
    device: String,
    #[clap(short = 'k', long, default_value = "privkey", value_hint = ValueHint::FilePath, env = "WS_PRIVATE_KEY")]
    private_key: String,
    #[clap(long, env = "WS_NODE_MONITOR")]
    monitor: bool,
    #[clap(long, env = "WS_NODE_RELAY")]
    relay: bool,
    #[clap(long, default_value = "25", env = "WS_KEEP_ALIVE")]
    keep_alive: NonZeroU16,
    #[clap(short, long, env = "WS_LISTEN_PORT")]
    port: Option<NonZeroU16>,
    #[clap(
        long,
        env = "WS_STUN_HOST",
        default_value = "stun.stunprotocol.org:3478"
    )]
    stun_host: String,
    #[clap(long, env = "WS_FIXED_ENDPOINT")]
    fixed_endpoint: Option<SocketAddr>,
}

#[derive(Debug, Subcommand)]
pub enum ManageCommand {
    #[clap(subcommand)]
    Peer(ManagePeerCommand),
    #[clap(subcommand)]
    Route(ManageRouteCommand),
}

#[derive(Debug, Subcommand)]
pub enum ManagePeerCommand {
    Add(AddPeerCommand),
    Change(ChangePeerCommand),
    Delete(DeletePeerCommand),
}

#[derive(Debug, Subcommand)]
pub enum ManageRouteCommand {
    Add(AddRouteCommand),
    Delete(DeleteRouteCommand),
}

#[derive(Debug, Args)]
#[clap(group = ArgGroup::new("peer_identifier").required(true))]
pub struct CliPeerIdentifier {
    #[clap(long, group = "peer_identifier")]
    name: Option<String>,
    #[clap(long, group = "peer_identifier")]
    token: Option<Uuid>,
    #[clap(long, group = "peer_identifier")]
    public_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddPeerCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(flatten)]
    connection: ConnectionOptions,
    #[clap(short, long, default_value = "0")]
    permission_level: i32,
    name: String,
    #[clap(required = true, min_values = 1)]
    addresses: Vec<IpNet>,
}

#[derive(Debug, Args)]
pub struct ChangePeerCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(flatten)]
    connection: ConnectionOptions,
    #[clap(flatten)]
    peer: CliPeerIdentifier,
    endpoint: SocketAddr,
}

#[derive(Debug, Args)]
pub struct DeletePeerCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(flatten)]
    connection: ConnectionOptions,
    #[clap(flatten)]
    peer: CliPeerIdentifier,
}

#[derive(Debug, Args)]
pub struct AddRouteCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(flatten)]
    connection: ConnectionOptions,
    net: IpNet,
    via: IpAddr,
}

#[derive(Debug, Args)]
pub struct DeleteRouteCommand {
    #[clap(flatten)]
    base: BaseOptions,
    #[clap(flatten)]
    connection: ConnectionOptions,
    net: IpNet,
    via: IpAddr,
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
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
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
    let token = MetadataValue::from_str(format!("Bearer {}", conn.token).as_str()).unwrap_or_log();
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

pub async fn client_start(start_opts: StartCommand) -> anyhow::Result<()> {
    set_loglevel(&start_opts.base)?;
    Toplevel::new()
        .catch_signals()
        .start("Eventloop", |subsys| event_loop(subsys, start_opts))
        .handle_shutdown_requests(Duration::from_millis(1000))
        .await?;
    Ok(())
}

pub async fn client_manage(manage_opts: ManageCommand) -> anyhow::Result<()> {
    match manage_opts {
        ManageCommand::Peer(peer_opts) => match peer_opts {
            ManagePeerCommand::Add(command) => {
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
            ManagePeerCommand::Delete(command) => {
                let id = if let Some(name) = command.peer.name {
                    PeerIdentifier {
                        identifier: Some(Identifier::Name(name)),
                    }
                } else if let Some(token) = command.peer.token {
                    PeerIdentifier {
                        identifier: Some(Identifier::Token(token.as_bytes().to_vec())),
                    }
                } else if let Some(pubkey) = command.peer.public_key {
                    PeerIdentifier {
                        identifier: Some(Identifier::PublicKey(
                            decode(pubkey).expect("Could not decode base64 of public key"),
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
            ManagePeerCommand::Change(change) => {
                let id = if let Some(name) = change.peer.name {
                    PeerIdentifier {
                        identifier: Some(Identifier::Name(name)),
                    }
                } else if let Some(token) = change.peer.token {
                    PeerIdentifier {
                        identifier: Some(Identifier::Token(token.as_bytes().to_vec())),
                    }
                } else if let Some(pubkey) = change.peer.public_key {
                    PeerIdentifier {
                        identifier: Some(Identifier::PublicKey(
                            decode(pubkey).expect("Could not decode base64 of public key"),
                        )),
                    }
                } else {
                    unreachable!()
                };

                let request = ChangePeerRequest {
                    id: Some(id),
                    what: Some(change_peer_request::What::Endpoint(change.endpoint.into())),
                };
                let mut client = connect(change.connection).await?;
                let result = client.change_peer(request).await?;
                println!("{:?}", result.into_inner());
            }
        },
        ManageCommand::Route(route_command) => match route_command {
            ManageRouteCommand::Add(add) => {
                let request = Route {
                    to: Some(add.net.into()),
                    via: Some(add.via.into()),
                };
                let mut client = connect(add.connection).await?;
                let result = client.add_route(request).await?;
                println!("{:?}", result.into_inner());
            }
            ManageRouteCommand::Delete(delete) => {
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
