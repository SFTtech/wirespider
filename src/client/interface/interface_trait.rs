use ipnet::IpNet;
use wirespider::WireguardKey;
use std::{net::{IpAddr, SocketAddr}, num::NonZeroU16};

pub trait ManagementInterface : Sized {
    type Error;
    fn create_device(device_name: String, privkey: WireguardKey, port: Option<NonZeroU16>, addresses: Vec<IpNet>) -> Result<Self,Self::Error>;
    fn set_peer(&self, pubkey: WireguardKey, endpoint: Option<SocketAddr>, persistent_keepalive: Option<NonZeroU16>, allowed_ips: &[IpNet]) -> Result<(),Self::Error>;
    fn remove_peer(&self, pubkey: WireguardKey) -> Result<(),Self::Error>;
    fn add_route(&self, network: IpNet, via: IpAddr) -> Result<(),Self::Error>;
    fn remove_route(&self, network: IpNet, via: IpAddr) -> Result<(),Self::Error>;
    fn shutdown(&self);
}