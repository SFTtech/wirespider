use super::interface_trait::WireguardManagementInterface;

use ipnet::IpNet;
use std::{net::SocketAddr, num::NonZeroU16, process::Command};
use thiserror::Error;
use tracing::debug;
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
}

#[derive(Debug, Error)]
pub enum WireguardUapiInterfaceError {
    #[error("Error getting wireguard device")]
    GetDevice(#[from] wireguard_uapi::err::GetDeviceError),
    #[error("Error connecting to wireguard control socket")]
    ControlConnection(#[from] wireguard_uapi::err::ConnectError),
    #[error("Error setting wireguard device")]
    SetDevice(#[from] wireguard_uapi::err::SetDeviceError),
}

impl WireguardManagementInterface for WireguardUapiInterface {
    type Error = WireguardUapiInterfaceError;

    fn create_wireguard_device(
        device_name: String,
        privkey: StaticSecret,
        port: Option<NonZeroU16>,
        addresses: &[IpNet],
    ) -> Result<Self, Self::Error> {
        let mut wg_socket = WgSocket::connect()?;

        // create interface
        let output = Command::new("ip")
            // mtu 1432 for ipv4+pppoe, needs to be changed when ipv6 support is ready
            .args([
                "link",
                "add",
                &device_name,
                "mtu",
                "1432",
                "type",
                "wireguard",
            ])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

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

        for address in addresses {
            let ip_str = address.to_string();
            let output = Command::new("ip")
                .args(["address", "add", "dev", &device_name, &ip_str])
                .output()
                .expect("failed to execute process");
            debug!("{:?}", output);
        }

        let output = Command::new("ip")
            .args(["link", "set", &device_name, "up"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        Ok(WireguardUapiInterface {
            device_name,
            addresses: addresses.to_vec(),
            wg_socket,
        })
    }

    fn set_peer(
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

    fn remove_peer(&mut self, pubkey: PublicKey) -> Result<(), Self::Error> {
        let mut device = SetDevice::from_ifname(self.device_name.clone());
        let pubkey = pubkey.as_bytes();
        let mut peer = SetPeer::from_public_key(pubkey);
        peer = peer.flags(vec![WgPeerF::RemoveMe]);
        device = device.peers(vec![peer]);
        self.wg_socket
            .set_device(device)
            .map_err(WireguardUapiInterfaceError::from)
    }

    fn add_route(&mut self, network: IpNet, via: std::net::IpAddr) -> Result<(), Self::Error> {
        let net_str = network.to_string();
        let via_str = via.to_string();
        let src_str = self
            .addresses
            .iter()
            .find(|x| via.is_ipv4() == x.addr().is_ipv4())
            .map(|x| x.addr().to_string())
            .unwrap_or_default();
        let mut cmd_args = vec!["route", "add", net_str.as_str(), "via", via_str.as_str()];
        if !src_str.is_empty() {
            cmd_args.extend_from_slice(&["src", src_str.as_str()]);
        }

        let output = Command::new("ip")
            .args(&cmd_args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        Ok(())
    }

    fn remove_route(&mut self, network: IpNet, via: std::net::IpAddr) -> Result<(), Self::Error> {
        let net_str = network.to_string();
        let via_str = via.to_string();
        let args = ["route", "del", net_str.as_str(), "via", via_str.as_str()];

        let output = Command::new("ip")
            .args(args)
            .output()
            .expect("failed to execute process");

        debug!("{:?}", output);
        Ok(())
    }

    fn delete_device_if_exists(device_name: &str) {
        let output = Command::new("ip")
            .args(["link", "del", device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }

    fn get_device(&mut self) -> Result<GetDevice, Self::Error> {
        self.wg_socket
            .get_device(DeviceInterface::from_name(&self.device_name))
            .map_err(WireguardUapiInterfaceError::from)
    }
}

impl Drop for WireguardUapiInterface {
    fn drop(&mut self) {
        let output = Command::new("ip")
            .args(["link", "set", &self.device_name, "down"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        let output = Command::new("ip")
            .args(["link", "del", &self.device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }
}
