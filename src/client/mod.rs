use std::net::SocketAddr;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr, num::NonZeroU16};

mod client_state;
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
            // delete the existing device, so we do not disturb the nat detection
            DefaultWireguardInterface::delete_device_if_exists(&start_opts.device);
            let backoff= backoff::ExponentialBackoffBuilder::new()
                .with_max_interval(Duration::from_secs(60))
                .build();

            let port = start_opts
                .port
                .unwrap_or_else(|| rng.gen_range(49152..=65535).try_into().unwrap());

            let device_name = start_opts.device;

            let nat_backoff = backoff.clone();
            let nat_detection = tokio::spawn(async move {
                if let Some(endpoint) = start_opts.fixed_endpoint {
                    Ok((Some(endpoint), NatType::NoNat))
                } else {
                    let backoff = nat_backoff.clone();
                    let stun_host = start_opts.stun_host.clone();
                    retry(backoff, || async {
                        get_nat_type(&stun_host, port).await.map_err(|x| x.into())
                    }).await
                }
            });

            let private_key = if std::path::Path::new(&start_opts.private_key).exists() {
                let private_key_encoded = tokio::fs::read_to_string(start_opts.private_key)
                    .await
                    .expect("Could not read private key");
                let private_key =
                    decode(private_key_encoded).expect("Could not decode private key");
                if private_key.len() != 32 {
                    panic!("Private key has wrong length");
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&private_key[0..32]);
                StaticSecret::from(key_bytes)
            } else {
                let private_key = StaticSecret::new(&mut rng);
                let encoded = encode(private_key.to_bytes());
                tokio::fs::write(&start_opts.private_key, &encoded).await?;
                private_key
            };
            let (external_address, nat_type) = nat_detection
                .await
                .unwrap_or_log()
                .expect("Could not determine NAT, are you connected to the internet?");
            let address_reply = client
                .get_addresses(AddressRequest {
                    wg_public_key: PublicKey::from(&private_key).to_bytes().to_vec(),
                    nat_type: nat_type.into(),
                    node_flags: Some(NodeFlags {
                        monitor: start_opts.monitor,
                        relay: start_opts.relay,
                    }),
                    endpoint: external_address.map(|x| x.into()),
                })
                .await?
                .into_inner();
            debug!("{:?}", address_reply);
            let address_list: Vec<IpNet> = address_reply
                .address
                .iter()
                .map(|x| x.try_into().unwrap())
                .collect();

            let interface = DefaultWireguardInterface::create_wireguard_device(
                device_name.clone(),
                private_key.to_bytes(),
                Some(port),
                &address_list,
            )
            .expect("Could not set up wireguard device");

            if start_opts.monitor {
                let monitor = monitor::Monitor::new(device_name.clone());
                let mut monitor_client = client.clone();
                tokio::spawn(async move {
                    monitor.monitor(&CLIENT_STATE, &mut monitor_client).await;
                });
            }

            let overlay_address_list = address_reply
                .overlay_ips
                .into_iter()
                .map(|x| x.try_into().unwrap())
                .collect();
            
            let mut mac_bytes = Vec::with_capacity(6);
            mac_bytes.push(0xaa);
            mac_bytes.extend_from_slice(&PublicKey::from(&private_key).to_bytes()[0..5]);
            let mac_addr = MacAddress::from_bytes(&mac_bytes).unwrap();
            let overlay_interface = DefaultOverlayInterface::create_overlay_device(
                format!("{}-vxlan", device_name), &device_name, &address_list[0].addr(), overlay_address_list, mac_addr)
                .expect("could not create overlay device");

            let mut event_counter = 0;
            loop {
                let backoff = backoff.clone();
                let mut events_stream = retry(backoff, || async {
                        client.clone()
                        .get_events(EventsRequest {
                            start_event: event_counter,
                        }).await.map_err(|x| x.into())
                }).await?.into_inner();
                loop {
                    let event = match events_stream.try_next().await {
                        Ok(Some(event)) => event,
                        Err(error) => {
                            error!("got error in main loop: {}", error);
                            break;
                        }
                        _ => break,
                    };
                    debug!("Event: {:?}", &event);
                    CLIENT_STATE.update(&event).await;
                    let event_type = EventType::from_i32(event.r#type).expect("Invalid event type");
                    match event.target {
                        Some(event::Target::Peer(peer)) => match event_type {
                            EventType::New | EventType::Changed => {
                                let endpoint = peer.endpoint.map(|x| match x {
                                    peer::Endpoint::Addr(x) => x.try_into().unwrap(),
                                });
                                let pubkey: WireguardKey = peer.wg_public_key.try_into().unwrap();
                                let mut mac_bytes = Vec::with_capacity(6);
                                mac_bytes.push(0xaa);
                                mac_bytes.extend_from_slice(&pubkey[0..5]);
                                let mac_addr = MacAddress::from_bytes(&mac_bytes).unwrap();

                                let allowed_ips: Vec<IpNet> = peer
                                    .allowed_ips
                                    .into_iter()
                                    .map(|x| x.try_into().unwrap())
                                    .collect();
                                let peer_flags = peer.node_flags.unwrap_or(NodeFlags {
                                    monitor: false,
                                    relay: false,
                                });
                                let peer_nat_type =
                                    NatType::from_i32(peer.nat_type).unwrap_or(NatType::NoNat);
                                let keep_alive = if peer_flags.monitor {
                                    Some(start_opts.keep_alive)
                                } else {
                                    match nat_type {
                                        NatType::NoNat => None,
                                        _ => Some(start_opts.keep_alive),
                                    }
                                };
                                let create = if start_opts.monitor || start_opts.relay {
                                    true
                                } else {
                                    match (nat_type, peer_nat_type) {
                                        (
                                            NatType::Symmetric,
                                            NatType::Symmetric | NatType::PortRestrictedCone,
                                        ) => false,
                                        (NatType::PortRestrictedCone, NatType::Symmetric) => false,
                                        (_, _) => true,
                                    }
                                };
                                if create {
                                    interface
                                        .set_peer(pubkey, endpoint, keep_alive, &allowed_ips)
                                        .unwrap();
                                }
                                let destination_ip = peer.tunnel_ips.into_iter().next().map(|x| x.try_into()).unwrap().unwrap();
                                let overlay_ip = peer.overlay_ips.into_iter().next();
                                if let Some(dest_net) = overlay_ip {
                                    overlay_interface.set_peer(mac_addr, dest_net.try_into()?, destination_ip).unwrap();
                                }
                            }
                            EventType::Deleted => {
                                let pubkey: WireguardKey = peer.wg_public_key.try_into().unwrap_or_log();
                                let mut mac_bytes = Vec::with_capacity(6);
                                mac_bytes.push(0xaa);
                                mac_bytes.extend_from_slice(&pubkey[0..5]);
                                let mac_addr = MacAddress::from_bytes(&mac_bytes).unwrap_or_log();
                                overlay_interface.remove_peer(mac_addr).unwrap_or_log();
                                interface
                                    .remove_peer(pubkey)
                                    .unwrap();
                            }
                        },
                        Some(event::Target::Route(route)) => match event_type {
                            EventType::New => {
                                interface
                                    .add_route(
                                        route.to.unwrap().try_into().unwrap(),
                                        route.via.unwrap().try_into().unwrap(),
                                    )
                                    .unwrap();
                            }
                            EventType::Deleted => {
                                interface
                                    .remove_route(
                                        route.to.unwrap().try_into().unwrap(),
                                        route.via.unwrap().try_into().unwrap(),
                                    )
                                    .unwrap();
                            }
                            _ => {
                                println!("Got invalid route change event");
                            }
                        },
                        _ => {
                            println!("Got invalid event target: {:?}", event.target);
                        }
                    }
                    if event_counter < event.id {
                        event_counter = event.id;
                    }
                    if event_counter == 0 {
                        event_counter = 1;
                    }                    
                }
            }
        }
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
