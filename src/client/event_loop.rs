use std::time::Duration;

use backoff::future::retry;
use base64::{decode, encode};
use eui48::MacAddress;
use ipnet::IpNet;
use local_ip_address::list_afinet_netifas;
use rand::{rngs::OsRng, Rng};
use tokio_graceful_shutdown::SubsystemHandle;
use tracing::{debug, error};
use tracing_unwrap::ResultExt;
use wirespider::{
    protocol::{event, peer, AddressRequest, EventType, EventsRequest, NatType, NodeFlags},
    WireguardKey,
};
use x25519_dalek_ng::{PublicKey, StaticSecret};

use crate::client::{DefaultOverlayInterface, connect, interface::OverlayManagementInterface};
use crate::client::{
    interface::WireguardManagementInterface, monitor, nat::get_nat_type, DefaultWireguardInterface,
    CLIENT_STATE,
};
use futures::TryStreamExt;

use super::StartCommand;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EventLoopError {
    #[error(transparent)]
    TransportError(#[from] tonic::transport::Error),
    #[error(transparent)]
    ConnectionError(#[from] crate::client::ConnectionError),
    #[error(transparent)]
    StatusError(#[from] tonic::Status),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

pub async fn event_loop(subsys: SubsystemHandle, start_opts: StartCommand) -> Result<(), EventLoopError> {
    let mut client = connect(start_opts.connection).await?;
    let mut rng = OsRng::default();
    // delete the existing device, so we do not disturb the nat detection
    DefaultWireguardInterface::delete_device_if_exists(&start_opts.device);
    let backoff = backoff::ExponentialBackoffBuilder::new()
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
            })
            .await
        }
    });

    let private_key = if std::path::Path::new(&start_opts.private_key).exists() {
        let private_key_encoded = tokio::fs::read_to_string(start_opts.private_key)
            .await
            .expect("Could not read private key");
        let private_key = decode(private_key_encoded).expect("Could not decode private key");
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
    let local_ips = list_afinet_netifas()
        .unwrap_or_log()
        .into_iter()
        .map(|(_, ip)| ip.into())
        .collect();
    let address_reply = client
        .get_addresses(AddressRequest {
            wg_public_key: PublicKey::from(&private_key).to_bytes().to_vec(),
            nat_type: nat_type.into(),
            node_flags: Some(NodeFlags {
                monitor: start_opts.monitor,
                relay: start_opts.relay,
            }),
            endpoint: external_address.map(|x| x.into()),
            local_ips,
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
        format!("{}-vxlan", device_name),
        &device_name,
        &address_list[0].addr(),
        overlay_address_list,
        mac_addr,
    )
    .expect("could not create overlay device");
    let mut event_counter = 0;
    loop {
        let backoff = backoff::ExponentialBackoffBuilder::new()
            .with_max_interval(Duration::from_secs(60))
            .build();
        let mut events_stream = retry(backoff, || async {
            client
                .clone()
                .get_events(EventsRequest {
                    start_event: event_counter,
                })
                .await
                .map_err(|x| x.into())
        })
        .await?
        .into_inner();
        loop {
            tokio::select! {
                event = events_stream.try_next() => {
                    let event = match event {
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
                                let destination_ip = peer
                                    .tunnel_ips
                                    .into_iter()
                                    .next()
                                    .map(|x| x.try_into())
                                    .unwrap()
                                    .unwrap();
                                let overlay_ip = peer.overlay_ips.into_iter().next();
                                if let Some(dest_net) = overlay_ip {
                                    overlay_interface
                                        .set_peer(mac_addr, dest_net.try_into()?, destination_ip)
                                        .unwrap();
                                }
                            }
                            EventType::Deleted => {
                                let pubkey: WireguardKey = peer.wg_public_key.try_into().unwrap_or_log();
                                let mut mac_bytes = Vec::with_capacity(6);
                                mac_bytes.push(0xaa);
                                mac_bytes.extend_from_slice(&pubkey[0..5]);
                                let mac_addr = MacAddress::from_bytes(&mac_bytes).unwrap_or_log();
                                overlay_interface.remove_peer(mac_addr).unwrap_or_log();
                                interface.remove_peer(pubkey).unwrap();
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
                },
                _ = subsys.on_shutdown_requested() => {
                    break;
                }
            };
        }
    }
}
