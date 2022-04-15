use std::collections::HashMap;
use tonic::codegen::InterceptedService;
use tonic::transport::Channel;
use wirespider::protocol::change_peer_request::What;
use wirespider::protocol::peer_identifier::Identifier;
use wirespider::protocol::wirespider_client::WirespiderClient;
use wirespider::protocol::ChangePeerRequest;
use wirespider::protocol::PeerIdentifier;

use crate::client::client_state::ClientState;
use futures::StreamExt;
use tokio::task;
use tokio::time::{interval, Duration};
use tokio_stream::wrappers::IntervalStream;
use wireguard_uapi::DeviceInterface;
use wireguard_uapi::WgSocket;

use super::WirespiderInterceptor;

pub(crate) struct Monitor {
    interface: String,
}

impl Monitor {
    pub fn new(interface: String) -> Monitor {
        Monitor { interface }
    }

    pub async fn monitor(
        &self,
        state: &ClientState,
        client: &mut WirespiderClient<InterceptedService<Channel, WirespiderInterceptor>>,
    ) {
        let mut stream = IntervalStream::new(interval(Duration::from_secs(1)));
        while stream.next().await.is_some() {
            let interface = self.interface.clone();
            let device = task::spawn_blocking(move || {
                let mut socket = WgSocket::connect().unwrap();
                socket
                    .get_device(DeviceInterface::from_name(interface))
                    .unwrap()
            })
            .await
            .unwrap();
            let mut peer_endpoint_map = HashMap::new();
            for peer in device.peers.iter() {
                if peer.endpoint.is_some() {
                    peer_endpoint_map.insert(peer.public_key, peer.endpoint.unwrap());
                }
            }
            let diff = state.endpoint_compare(peer_endpoint_map).await;
            for (key, endpoint) in diff {
                if client
                    .change_peer(ChangePeerRequest {
                        id: Some(PeerIdentifier {
                            identifier: Some(Identifier::PublicKey(key.into())),
                        }),
                        what: Some(What::Endpoint(endpoint.into())),
                    })
                    .await
                    .is_err()
                {
                    println!("Error with change peer command")
                }
            }
        }
    }
}
