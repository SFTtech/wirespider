pub type WireguardKey = [u8; 32];

pub mod protocol {
    #![allow(non_camel_case_types)]
    tonic::include_proto!("wirespider"); // The string specified here must match the proto package name

    use std::net::SocketAddr;
    use std::{convert::TryInto, net::{IpAddr, Ipv4Addr, Ipv6Addr}};
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use tonic::Status;
    use crate::WireguardKey;
    

    impl TryInto<IpAddr> for &Ip {
        type Error = Status;

        fn try_into(self) -> Result<IpAddr, Self::Error> {
            match &self.r#type {
                Some(ip::Type::Ipv4(x)) => Ok(IpAddr::V4(Ipv4Addr::from(*x))),
                Some(ip::Type::Ipv6(x)) if x.len() == 16 => Ok(IpAddr::V6(
                    Ipv6Addr::from([
                        x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
                        x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]
                        ]))
                ),
                _ => Err(Status::invalid_argument("Invalid IP"))
            }
        }
    }

    impl TryInto<IpAddr> for Ip {
        type Error = Status;
        fn try_into(self) -> Result<IpAddr, Self::Error> {
            (&self).try_into()
        }
    }

    impl From<&IpAddr> for Ip {
        fn from(ip: &IpAddr) -> Self {
            match ip {
                IpAddr::V4(x) => Ip {r#type: Some(ip::Type::Ipv4((*x).into()))},
                IpAddr::V6(x) => Ip {r#type: Some(ip::Type::Ipv6(x.octets().to_vec()))}
            }
        }
    }

    impl From<IpAddr> for Ip {
        fn from(ip: IpAddr) -> Self {
            (&ip).into()
        }
    }

    impl Route {
        pub fn new(to: IpNet, via: IpAddr) -> Route {
            Route {
                to: Some(to.into()),
                via: Some(via.into())
            }
        }
    }

    impl TryInto<SocketAddr> for Endpoint {
        type Error = Status;

        fn try_into(self) -> Result<SocketAddr, Self::Error> {
            let port = self.port.try_into().map_err(|_| Status::invalid_argument("Invalid IP"))?;
            let ip = self.ip.ok_or_else(|| Status::invalid_argument("Invalid IP"))?.try_into()?;
            Ok(SocketAddr::new(ip, port))
        }
    }

    impl From<SocketAddr> for Endpoint {
        fn from(socket_addr: SocketAddr) -> Self {
            Endpoint {
                ip: Some(socket_addr.ip().into()),
                port: socket_addr.port().into()
            }
        }
    }


    impl TryInto<IpNet> for &Network {
        type Error = Status;

        fn try_into(self) -> Result<IpNet, Self::Error> {
            let ip = self.ip.as_ref().ok_or_else(|| Status::invalid_argument("Invalid IP"))?
                                .try_into()?;
            let prefix_len = self.prefix_len;
            match ip {
                IpAddr::V4(x) if prefix_len <= 32 => Ok(IpNet::V4(Ipv4Net::new(x, prefix_len.try_into().unwrap())
                                                                .map_err(|_| Status::invalid_argument("Invalid IP"))?)),
                IpAddr::V6(x) if prefix_len <= 128 => Ok(IpNet::V6(Ipv6Net::new(x, prefix_len.try_into().unwrap())
                                                                .map_err(|_| Status::invalid_argument("Invalid IP"))?)),
                _ => Err(Status::invalid_argument("Invalid Network prefix"))
            }
        }
    }


    impl TryInto<IpNet> for Network {
        type Error = Status;

        fn try_into(self) -> Result<IpNet, Self::Error> {
            (&self).try_into()
        }
    }

    impl From<IpNet> for Network {
        fn from(network: IpNet) -> Self {
            Network {
                ip: Some(network.addr().into()),
                prefix_len: network.prefix_len().into(),
            }
        }
    }

    impl AddressReply {
        pub fn new(net: &[IpNet], overlay: &[IpNet]) -> AddressReply {
            AddressReply {
                address: net.iter().map(|x| (*x).into()).collect::<Vec<Network>>(),
                overlay_ips: overlay.iter().map(|x| (*x).into()).collect::<Vec<Network>>()
            }
        }
    }

    // impl PeerBuilder {
    //     pub fn pubkey(&mut self, pub_key: WireguardKey) {
    //         self.wg_public_key = Some(pub_key.to_vec());
    //     }

    //     pub fn allowed_ips(&mut self, allowed_ips: Vec<IpNet>) {
    //         self.allowed_ips = Some(allowed_ips.into_iter().map(Network::from).collect());
    //     }

    //     pub fn endpoint(&mut self, endpoint: Option<SocketAddr>) {
    //         self.endpoint = Some(endpoint.map(|x| peer::Endpoint::Addr(Endpoint::from(x))));
    //     }

    //     pub fn overlay_ips(&mut self, overlay_ips: Vec<IpNet>) {
    //         self.overlay_ips = Some(overlay_ips.into_iter().map(Network::from).collect());
    //     }

    //     pub fn node_flags(&mut self, monitor: bool, relay: bool) {
    //         self.node_flags = Some(Some(NodeFlags{monitor, relay}));
    //     }

    //     pub fn tunnel_ips(&mut self, tunnel_ips: Vec<IpAddr>) {
    //         self.tunnel_ips = Some(tunnel_ips.into_iter().map(Ip::from).collect());
    //     }

    //     pub fn local_ips(&mut self, local_ips: Vec<IpAddr>) {
    //         self.local_ips = Some(local_ips.into_iter().map(Ip::from).collect());
    //     }
    // }
    
    impl Peer {

        pub fn pub_key(&self) -> WireguardKey {
            if self.wg_public_key.len() != 32 {
                panic!("Invalid wireguard public key length: {}", self.wg_public_key.len());
            }
            self.wg_public_key.as_slice().try_into().unwrap()
        }
    }

    impl From<Peer> for event::Target {
        fn from(peer: Peer) -> Self {
            event::Target::Peer(peer)
        }
    }

    impl From<Route> for event::Target {
        fn from(route: Route) -> Self {
            event::Target::Route(route)
        }
    }

    impl PeersReply {
        pub fn new(peers: Vec<Peer>) -> PeersReply {
            PeersReply {
                peers
            }
        }
    }

    impl Event {
        pub fn from_peer(id: u64, event_type: EventType, peer: Peer) -> Event {
            Event {
                id,
                r#type: event_type.into(),
                target: Some(peer.into())

            }
        }

        pub fn from_route(id: u64, event_type: EventType, route: Route) -> Event {
            Event {
                id,
                r#type: event_type.into(),
                target: Some(route.into())

            }
        }
    }
}

