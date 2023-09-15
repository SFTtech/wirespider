use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::{net::SocketAddr, time::Duration};

use backoff::future::retry;
use base64::prelude::{Engine, BASE64_STANDARD};
use macaddr::MacAddr6;
use ipnet::IpNet;
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use rand::{rngs::OsRng, Rng};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_graceful_shutdown::SubsystemHandle;
use tracing::{debug, error, warn};
use tracing_unwrap::ResultExt;
use wirespider::protocol::{
    event, peer, AddressRequest, EventType, EventsRequest, NatType, NodeFlags,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::client::{
    connect, interface::OverlayManagementInterface, local_ip_detection::check_local_ips,
    DefaultOverlayInterface,
};
use crate::client::{
    interface::WireguardManagementInterface, monitor, nat::get_nat_type, DefaultWireguardInterface,
    CLIENT_STATE,
};
use futures::TryStreamExt;

use crate::cli::ClientStartCommand;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EventLoopError {
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
    #[error(transparent)]
    Connection(#[from] crate::client::ConnectionError),
    #[error(transparent)]
    Status(#[from] tonic::Status),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("Shutting down")]
    Shutdown,
}

pub async fn event_loop(
    subsys: SubsystemHandle,
    start_opts: ClientStartCommand,
) -> Result<(), EventLoopError> {
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
            Ok((Some(endpoint), start_opts.nat_type.into()))
        } else {
            let backoff = nat_backoff.clone();
            let stun_host = start_opts.stun_host.clone();
            retry(backoff, || async {
                get_nat_type(&stun_host, port).await.map_err(|x| x.into())
            })
            .await
        }
    });
    debug!("Nat detection started");

    let private_key = if std::path::Path::new(&start_opts.private_key).exists() {
        let private_key_encoded = tokio::fs::read_to_string(start_opts.private_key)
            .await
            .expect("Could not read private key");
        let secret_key_bytes: [u8; 32] = BASE64_STANDARD
            .decode(private_key_encoded)
            .expect("Could not decode private key")
            .try_into()
            .unwrap();
        StaticSecret::from(secret_key_bytes)
    } else {
        let private_key = StaticSecret::random_from_rng(OsRng::default());
        tokio::fs::write(
            &start_opts.private_key,
            BASE64_STANDARD.encode(private_key.to_bytes()),
        )
        .await?;
        private_key
    };
    let pubkey = PublicKey::from(&private_key);

    let (external_address, nat_type) = nat_detection
        .await
        .unwrap_or_log()
        .expect("Could not determine NAT, are you connected to the internet?");

    let local_ips = NetworkInterface::show()
        .unwrap_or_log()
        .into_iter()
        .filter(|x| x.addr.is_some())
        .map(|x| match x.addr.unwrap() {
            network_interface::Addr::V4(x) => IpAddr::from(x.ip).into(),
            network_interface::Addr::V6(x) => IpAddr::from(x.ip).into(),
        })
        .collect();
    debug!("local ips: {local_ips:?}");
    let address_reply = client
        .get_addresses(AddressRequest {
            wg_public_key: Vec::from(pubkey.as_bytes().as_ref()),
            nat_type: nat_type.into(),
            node_flags: Some(NodeFlags {
                monitor: start_opts.monitor,
                relay: start_opts.relay,
            }),
            endpoint: external_address.map(|x| x.into()),
            local_ips,
            local_port: port.get().into(),
        })
        .await
        .unwrap_or_log()
        .into_inner();
    debug!("{:?}", address_reply);
    let address_list: Vec<IpNet> = address_reply
        .address
        .iter()
        .map(|x| x.try_into().unwrap())
        .collect();

    let interface = Arc::new(Mutex::new(
        DefaultWireguardInterface::create_wireguard_device(
            device_name.clone(),
            private_key.clone(),
            Some(port),
            &address_list,
        )
        .expect("Could not set up wireguard device"),
    ));

    let monitor_interface = interface.clone();
    let monitor_client = client.clone();
    let monitor = monitor::Monitor::new(monitor_interface, start_opts.monitor);
    subsys.start("monitor", move |subsys| {
        monitor.monitor(subsys, &CLIENT_STATE, monitor_client)
    });

    let overlay_address_list = address_reply
        .overlay_ips
        .into_iter()
        .map(|x| x.try_into().unwrap())
        .collect();

    // TODO: only create overlay interface when overlay ips are present
    let mut mac_bytes = Vec::with_capacity(6);
    mac_bytes.push(0xaa);
    mac_bytes.extend_from_slice(&PublicKey::from(&private_key).as_bytes().as_ref()[0..5]);
    let mac_addr = MacAddr6::from(<&[u8] as TryInto<[u8; 6]>>::try_into(&mac_bytes).unwrap());
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
        let events_stream = retry(backoff, || async {
                let mut client = client.clone();
                tokio::select! {
                    _ = subsys.on_shutdown_requested() => Err(backoff::Error::Permanent(EventLoopError::Shutdown)),
                    event = client.get_events(EventsRequest {
                            start_event: event_counter,
                        }) => event.map_err(|x| backoff::Error::transient(x.into()))
                }
            })
        .await;
        let mut events_stream = match events_stream {
            Ok(x) => x.into_inner(),
            Err(EventLoopError::Shutdown) => return Ok(()),
            Err(e) => return Err(e),
        };
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
                    let event_type = EventType::try_from(event.r#type).expect("Invalid event type");
                    match event.target {
                        Some(event::Target::Peer(peer)) => match event_type {
                            EventType::New | EventType::Changed => {
                                let endpoint = peer.endpoint.map(|x| match x {
                                    peer::Endpoint::Addr(x) => x.try_into().unwrap(),
                                });
                                let peer_publivkey_array : [u8; 32] = peer.wg_public_key.as_slice().try_into().expect_or_log("Invalid key length");
                                let peer_pubkey = PublicKey::from(peer_publivkey_array);
                                let mut mac_bytes = Vec::with_capacity(6);
                                mac_bytes.push(0xaa);
                                mac_bytes.extend_from_slice(&peer_pubkey.as_bytes()[0..5]);
                                let mac_addr = MacAddr6::from(<&[u8] as TryInto<[u8; 6]>>::try_into(&mac_bytes).unwrap());
                                let peer_port : u16 = peer.local_port.try_into().expect("Invalid port");

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
                                    NatType::try_from(peer.nat_type).unwrap_or(NatType::NoNat);
                                let keep_alive = if peer_flags.monitor {
                                    Some(start_opts.keep_alive)
                                } else {
                                    match nat_type {
                                        NatType::NoNat => None,
                                        _ => Some(start_opts.keep_alive),
                                    }
                                };
                                let mut create = if start_opts.monitor || start_opts.relay {
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
                                // get a primary ip
                                let destination_ip : IpAddr = peer
                                    .tunnel_ips
                                    .into_iter()
                                    .next()
                                    .map(|x| x.try_into())
                                    .unwrap()
                                    .unwrap();
                                // create the peer anyways and try to check for local ips
                                interface
                                    .lock()
                                    .await
                                    .set_peer(peer_pubkey, endpoint, keep_alive, &allowed_ips)
                                    .unwrap_or_log();
                                debug!("getting local ips");
                                let local_sock_addrs = peer.local_ips.iter().map(|x| x.try_into().map(|x : IpAddr| SocketAddr::from((x, peer_port)))).collect::<Result<Vec<_>,_>>().unwrap_or_log();
                                let local_endpoint = check_local_ips(&local_sock_addrs, private_key.clone(), peer_pubkey).await.unwrap_or_log();
                                debug!("Got local endpoint: {:?}", local_endpoint);
                                if local_endpoint.is_some() && local_endpoint != endpoint {
                                    interface.lock().await.set_peer(peer_pubkey, local_endpoint, keep_alive, &allowed_ips).unwrap_or_log();
                                    create = true;
                                    // send a single packet to this peer to redo the handshake
                                    if let Ok(socket) = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED,0))).await {
                                        debug!("Sending packet to initiate handshake to {:?}", destination_ip);
                                        if let Err(e) = socket.send_to("wirespider".as_bytes(), SocketAddr::from((destination_ip, 1337))).await {
                                            warn!("Error sending packet: {:?}", e);
                                        }
                                    } else {
                                        warn!("Could not bind to udp socket");
                                    }
                                }
                                if !create {
                                    // we could not find a local ip and the nat setup would prevent direct connection so we remove all allowed ips.
                                    // This allows discovery of this peer when the other peer later joins the same lan.
                                    // The monitor component will check for handshakes and if successfull handshakes are discovered
                                    // it will set the actual allowed ips.
                                    debug!("removing allowed ips");
                                    interface.lock().await.remove_peer(peer_pubkey).unwrap_or_log();
                                    interface.lock().await.set_peer(peer_pubkey, None, keep_alive, &[]).unwrap_or_log();
                                }
                                let overlay_ip = peer.overlay_ips.into_iter().next();
                                if let Some(dest_net) = overlay_ip {
                                    overlay_interface
                                        .set_peer(mac_addr, dest_net.try_into()?, destination_ip)
                                        .unwrap();
                                }
                            }
                            EventType::Deleted => {
                                let peer_publivkey_array : [u8; 32] = peer.wg_public_key.as_slice().try_into().unwrap();
                                let peer_pubkey = PublicKey::from(peer_publivkey_array);
                                let mut mac_bytes = Vec::with_capacity(6);
                                mac_bytes.push(0xaa);
                                mac_bytes.extend_from_slice(&pubkey.as_bytes()[0..5]);
                                let mac_addr = MacAddr6::from(<&[u8] as TryInto<[u8; 6]>>::try_into(&mac_bytes).unwrap_or_log());
                                overlay_interface.remove_peer(mac_addr).unwrap_or_log();
                                interface.lock().await.remove_peer(peer_pubkey).unwrap();
                            }
                        },
                        Some(event::Target::Route(route)) => match event_type {
                            EventType::New => {
                                interface.lock().await
                                    .add_route(
                                        route.to.unwrap().try_into().unwrap(),
                                        route.via.unwrap().try_into().unwrap(),
                                    )
                                    .unwrap();
                            }
                            EventType::Deleted => {
                                interface.lock().await
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
