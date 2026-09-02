use super::interface_trait::WireguardManagementInterface;

use futures::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::{new_connection, Handle, LinkUnspec, LinkWireguard, RouteMessageBuilder};
use std::{net::SocketAddr, num::NonZeroU16};
use thiserror::Error;
use wireguard_uapi::{
    get::Device as GetDevice,
    set::{Device as SetDevice, Peer as SetPeer, WgPeerF},
    DeviceInterface, WgSocket,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct WireguardUapiInterface {
    device_name: String,
    addresses: Vec<IpNet>,
    wg_socket: WgSocket,
    rt_handle: Handle,
}

#[derive(Debug, Error)]
pub enum WireguardUapiInterfaceError {
    #[error("Error getting wireguard device")]
    GetDevice(#[from] wireguard_uapi::err::GetDeviceError),
    #[error("Error connecting to wireguard control socket")]
    ControlConnection(#[from] wireguard_uapi::err::ConnectError),
    #[error("Error setting wireguard device")]
    SetDevice(#[from] wireguard_uapi::err::SetDeviceError),
    #[error("Error connecting to rtnetlink socket")]
    RtnetlinkConnection(#[from] std::io::Error),
    #[error("Error executing rtnetlink request")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("Interface {0} not found")]
    InterfaceNotFound(String),
}

async fn get_link_index(
    handle: &Handle,
    device_name: &str,
) -> Result<u32, WireguardUapiInterfaceError> {
    let mut links = handle
        .link()
        .get()
        .match_name(device_name.to_string())
        .execute();
    let link = links
        .try_next()
        .await?
        .ok_or_else(|| WireguardUapiInterfaceError::InterfaceNotFound(device_name.to_string()))?;
    Ok(link.header.index)
}

impl WireguardManagementInterface for WireguardUapiInterface {
    type Error = WireguardUapiInterfaceError;

    async fn create_wireguard_device(
        device_name: String,
        privkey: StaticSecret,
        port: Option<NonZeroU16>,
        addresses: &[IpNet],
    ) -> Result<Self, Self::Error> {
        let mut wg_socket = WgSocket::connect()?;
        let (connection, rt_handle, _) = new_connection()?;
        tokio::spawn(connection);

        // create interface
        // mtu 1432 for ipv4+pppoe, needs to be changed when ipv6 support is ready
        rt_handle
            .link()
            .add(LinkWireguard::new(&device_name).mtu(1432).build())
            .execute()
            .await?;

        let privkey_bytes = privkey.to_bytes();
        let device = SetDevice {
            flags: vec![],
            fwmark: None,
            interface: DeviceInterface::Name(device_name.clone().into()),
            listen_port: port.map(NonZeroU16::into),
            peers: vec![],
            private_key: Some(&privkey_bytes),
        };
        wg_socket.set_device(device)?;

        let link_index = get_link_index(&rt_handle, &device_name).await?;

        for address in addresses {
            rt_handle
                .address()
                .add(link_index, address.addr(), address.prefix_len())
                .execute()
                .await?;
        }

        rt_handle
            .link()
            .set(LinkUnspec::new_with_index(link_index).up().build())
            .execute()
            .await?;

        Ok(WireguardUapiInterface {
            device_name,
            addresses: addresses.to_vec(),
            wg_socket,
            rt_handle,
        })
    }

    async fn set_peer(
        &mut self,
        pubkey: PublicKey,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: Option<NonZeroU16>,
        allowed_ips: &[IpNet],
    ) -> Result<(), Self::Error> {
        let mut device = SetDevice::from_ifname(self.device_name.clone());
        let pubkey_arr = pubkey.as_bytes();
        let mut peer = SetPeer::from_public_key(pubkey_arr);

        let endpoint_ref = endpoint.as_ref();
        if let Some(endpoint) = endpoint_ref {
            peer = peer.endpoint(endpoint);
        }

        if let Some(persistent_keepalive) = persistent_keepalive {
            peer = peer.persistent_keepalive_interval(persistent_keepalive.into());
        }
        let allowed_ips = allowed_ips
            .iter()
            .map(|x| (x.addr(), x.prefix_len()))
            .collect::<Vec<_>>();
        peer = peer.allowed_ips(
            allowed_ips
                .iter()
                .map(|x| wireguard_uapi::set::AllowedIp {
                    ipaddr: &x.0,
                    cidr_mask: Some(x.1),
                })
                .collect(),
        );

        device = device.peers(vec![peer]);
        self.wg_socket
            .set_device(device)
            .map_err(WireguardUapiInterfaceError::from)
    }

    async fn remove_peer(&mut self, pubkey: PublicKey) -> Result<(), Self::Error> {
        let mut device = SetDevice::from_ifname(self.device_name.clone());
        let pubkey = pubkey.as_bytes();
        let mut peer = SetPeer::from_public_key(pubkey);
        peer = peer.flags(vec![WgPeerF::RemoveMe]);
        device = device.peers(vec![peer]);
        self.wg_socket
            .set_device(device)
            .map_err(WireguardUapiInterfaceError::from)
    }

    async fn add_route(
        &mut self,
        network: IpNet,
        via: std::net::IpAddr,
    ) -> Result<(), Self::Error> {
        let src = self
            .addresses
            .iter()
            .find(|x| via.is_ipv4() == x.addr().is_ipv4())
            .map(|x| x.addr());
        let mut builder = RouteMessageBuilder::<std::net::IpAddr>::new()
            .destination_prefix(network.addr(), network.prefix_len())
            .and_then(|builder| builder.gateway(via));
        if let Some(src) = src {
            builder = builder.and_then(|builder| builder.pref_source(src));
        }
        let route = builder
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
            .build();
        self.rt_handle.route().add(route).execute().await?;
        Ok(())
    }

    async fn remove_route(
        &mut self,
        network: IpNet,
        via: std::net::IpAddr,
    ) -> Result<(), Self::Error> {
        let route = RouteMessageBuilder::<std::net::IpAddr>::new()
            .destination_prefix(network.addr(), network.prefix_len())
            .and_then(|builder| builder.gateway(via))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
            .build();
        self.rt_handle.route().del(route).execute().await?;
        Ok(())
    }

    async fn delete_device_if_exists(device_name: &str) {
        if let Ok((connection, handle, _)) = new_connection() {
            tokio::spawn(connection);
            let mut links = handle
                .link()
                .get()
                .match_name(device_name.to_string())
                .execute();
            match links.try_next().await {
                Ok(Some(link)) => {
                    if let Err(e) = handle.link().del(link.header.index).execute().await {
                        tracing::error!("Error deleting interface {}: {:?}", device_name, e);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!("Error getting interface {}: {:?}", device_name, e);
                }
            }
        }
    }

    async fn get_device(&mut self) -> Result<GetDevice, Self::Error> {
        self.wg_socket
            .get_device(DeviceInterface::from_name(&self.device_name))
            .map_err(WireguardUapiInterfaceError::from)
    }
}

impl Drop for WireguardUapiInterface {
    fn drop(&mut self) {
        let handle = self.rt_handle.clone();
        let device_name = self.device_name.clone();
        tokio::spawn(async move {
            let mut links = handle
                .link()
                .get()
                .match_name(device_name.clone())
                .execute();
            match links.try_next().await {
                Ok(Some(link)) => {
                    if let Err(e) = handle
                        .link()
                        .set(LinkUnspec::new_with_index(link.header.index).down().build())
                        .execute()
                        .await
                    {
                        tracing::error!("Error setting interface {} down: {:?}", device_name, e);
                    }
                    if let Err(e) = handle.link().del(link.header.index).execute().await {
                        tracing::error!("Error deleting interface {}: {:?}", device_name, e);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!("Error getting interface {}: {:?}", device_name, e);
                }
            }
        });
    }
}
