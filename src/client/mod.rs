use std::net::SocketAddr;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr, num::NonZeroU16};

mod client_state;
mod endpoint;
mod event_loop;
mod interface;
mod monitor;
mod nat;

use backoff::future::retry;
use base64::{decode, encode};
use clap::Parser;
use clap::{ArgGroup, Args, Subcommand, ValueHint};
use client_state::ClientState;
use eui48::MacAddress;
use futures::TryStreamExt;
use interface::{WireguardManagementInterface, OverlayManagementInterface, DefaultWireguardInterface, DefaultOverlayInterface};
use ipnet::IpNet;
use peer_identifier::Identifier;
use rand::rngs::OsRng;
use rand::Rng;
use tokio_graceful_shutdown::Toplevel;
use tonic::{
    metadata::MetadataValue,
    transport::{Endpoint, Uri},
    Request,
};
use tracing::metadata::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Registry;
use tracing_unwrap::ResultExt;
use uuid::Uuid;
use wirespider::protocol::*;
use wirespider::{protocol::wirespider_client::WirespiderClient, WireguardKey};
use x25519_dalek_ng::{PublicKey, StaticSecret};
use local_ip_address::list_afinet_netifas;

use tracing::{error, debug};

use crate::client::nat::get_nat_type;

lazy_static! {
    static ref CLIENT_STATE: ClientState = ClientState::default();
}

#[derive(Parser, Debug)]
pub struct ClientCli {
    /// Uri of the server endpoint
    #[clap(short, long, parse(try_from_str), env = "WS_ENDPOINT")]
    endpoint: Uri,

    /// Token for authentication
    #[clap(short, long, parse(try_from_str), env = "WS_TOKEN")]
    token: Uuid,
    /// enable debug
    #[clap(short, long)]
    debug: bool,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[clap(name = "start")]
    Start(StartCommand),
    #[clap(subcommand)]
    Manage(ManageCommand),
}

#[derive(Debug, Args)]
struct StartCommand {
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
    #[clap(long, env = "WS_STUN_HOST", default_value = "stun.stunprotocol.org:3478")]
    stun_host: String,
    #[clap(long, env = "WS_FIXED_ENDPOINT")]
    fixed_endpoint: Option<SocketAddr>,
}

#[derive(Debug, Subcommand)]
enum ManageCommand {
    #[clap(subcommand)]
    Peer(ManagePeerCommand),
    #[clap(subcommand)]
    Route(ManageRouteCommand),
}

#[derive(Debug, Subcommand)]
enum ManagePeerCommand {
    Add(AddPeerCommand),
    Change(ChangePeerCommand),
    Delete(DeletePeerCommand),
}

#[derive(Debug, Subcommand)]
enum ManageRouteCommand {
    Add(AddRouteCommand),
    Delete(DeleteRouteCommand),
}

#[derive(Debug, Args)]
#[clap(group = ArgGroup::new("peer_identifier").required(true))]
struct CliPeerIdentifier {
    #[clap(long, group = "peer_identifier")]
    name: Option<String>,
    #[clap(long, group = "peer_identifier")]
    token: Option<Uuid>,
    #[clap(long, group = "peer_identifier")]
    public_key: Option<String>,
}

#[derive(Debug, Args)]
struct AddPeerCommand {
    #[clap(short, long, default_value = "0")]
    permission_level: i32,
    name: String,
    #[clap(required = true, min_values = 1)]
    addresses: Vec<IpNet>,
}

#[derive(Debug, Args)]
struct ChangePeerCommand {
    #[clap(flatten)]
    peer: CliPeerIdentifier,
    endpoint: SocketAddr,
}

#[derive(Debug, Args)]
struct DeletePeerCommand {
    #[clap(flatten)]
    peer: CliPeerIdentifier,
}

#[derive(Debug, Args)]
struct AddRouteCommand {
    net: IpNet,
    via: IpAddr,
}

#[derive(Debug, Args)]
struct DeleteRouteCommand {
    net: IpNet,
    via: IpAddr,
}

pub async fn client(opt: ClientCli) -> Result<(), Box<dyn std::error::Error>> {
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

    tracing::subscriber::set_global_default(subscriber)?;

    let mut rng = OsRng::default();
    let endpoint = Endpoint::from(opt.endpoint)
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(25*60));
    let channel = endpoint.connect().await?;
    let token = MetadataValue::from_str(format!("Bearer {}", opt.token).as_str())?;
    let mut client = WirespiderClient::with_interceptor(channel, move |mut req: Request<()>| {
        req.metadata_mut().insert("authorization", token.clone());
        Ok(req)
    });
    match opt.command {
        Command::Start(start_opts) => {
            Toplevel::new()
                .start("Eventloop", subsys1)
                .catch_signals()
                .handle_shutdown_requests(Duration::from_millis(1000))
                .await
        },
        Command::Manage(manage_opts) => match manage_opts {
            ManageCommand::Peer(peer_opts) => match peer_opts {
                ManagePeerCommand::Add(command) => {
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
                    let result = client.add_route(request).await?;
                    println!("{:?}", result.into_inner());
                }
                ManageRouteCommand::Delete(delete) => {
                    let request = Route {
                        to: Some(delete.net.into()),
                        via: Some(delete.via.into()),
                    };
                    let result = client.del_route(request).await?;
                    println!("{:?}", result.into_inner());
                }
            },
        },
    }
    Ok(())
}
