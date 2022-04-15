use eui48::MacAddress;
use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
};
use wirespider::WireguardKey;

pub trait WireguardManagementInterface: Sized {
    type Error;
    fn delete_device_if_exists(device_name: &str);
    fn create_wireguard_device(
        device_name: String,
        privkey: WireguardKey,
        port: Option<NonZeroU16>,
        addresses: &[IpNet],
    ) -> Result<Self, Self::Error>;
    fn set_peer(
        &self,
        pubkey: WireguardKey,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: Option<NonZeroU16>,
        allowed_ips: &[IpNet],
    ) -> Result<(), Self::Error>;
    fn remove_peer(&self, pubkey: WireguardKey) -> Result<(), Self::Error>;
    fn add_route(&self, network: IpNet, via: IpAddr) -> Result<(), Self::Error>;
    fn remove_route(&self, network: IpNet, via: IpAddr) -> Result<(), Self::Error>;
}

pub trait OverlayManagementInterface: Sized {
    type Error;
    fn delete_device_if_exists(device_name: &str);
    fn create_overlay_device(
        device_name: String,
        listen_device: &str,
        listen_addr: &IpAddr,
        addresses: Vec<IpNet>,
        mac_addr: MacAddress,
    ) -> Result<Self, Self::Error>;
    fn set_peer(&self, mac_addr: MacAddress, net: IpNet, remote: IpAddr)
        -> Result<(), Self::Error>;
    fn remove_peer(&self, mac_addr: MacAddress) -> Result<(), Self::Error>;
}
