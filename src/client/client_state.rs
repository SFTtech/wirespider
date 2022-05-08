use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use ipnet::IpNet;
use tokio::sync::RwLock;
use wirespider::protocol::*;
use wirespider::WireguardKey;

#[derive(Debug, Default)]
pub(crate) struct ClientState {
    peers: RwLock<HashMap<WireguardKey, Peer>>,
}

impl ClientState {
    pub async fn update(&self, event: &Event) {
        let mut peer_data = self.peers.write().await;
        let target = event.target.clone();
        let event_type = EventType::from_i32(event.r#type).expect("Invalid event type");
        if let Some(event::Target::Peer(peer)) = target {
            match event_type {
                EventType::New => {
                    peer_data.borrow_mut().insert(peer.pub_key(), peer);
                }
                EventType::Changed => {
                    peer_data.borrow_mut().insert(peer.pub_key(), peer);
                }
                EventType::Deleted => {
                    peer_data.borrow_mut().remove(&peer.pub_key());
                }
            }
        }
    }

    pub async fn endpoint_compare(
        &self,
        peer_list: HashMap<WireguardKey, SocketAddr>,
    ) -> HashMap<WireguardKey, SocketAddr> {
        let peer_data = self.peers.read().await;
        let mut result = HashMap::new();
        for (key, peer) in peer_data.borrow().iter() {
            let sock_addr = peer.endpoint.as_ref().map(|peer::Endpoint::Addr(addr)| {
                addr.clone().try_into().expect("Invalid Endpoint")
            });
            if peer_list.contains_key(key) && Some(peer_list[key]) != sock_addr {
                result.insert(*key, peer_list[key]);
            }
        }
        result
    }

    pub async fn get_allowed_ips(&self, key: WireguardKey) -> Option<Vec<IpNet>>{
        let peer_data = self.peers.read().await;
        peer_data.get(&key).map(|x| x.allowed_ips.iter().map(TryInto::try_into).collect::<Result<Vec<_>,_>>().unwrap())
    }
}
