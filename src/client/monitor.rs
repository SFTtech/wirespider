use std::collections::HashMap;
use tonic::codegen::Body;
use tonic::codegen::StdError;
use wirespider::protocol::change_peer_request::What;
use wirespider::protocol::wirespider_client::WirespiderClient;
use wirespider::protocol::peer_identifier::Identifier;
use wirespider::protocol::ChangePeerRequest;
use wirespider::protocol::PeerIdentifier;

use crate::client::client_state::ClientState;
use futures::StreamExt;
use tokio::task;
use tokio::time::{interval, Duration};
use tokio_stream::wrappers::IntervalStream;
use wireguard_uapi::DeviceInterface;
use wireguard_uapi::WgSocket;

pub(crate) struct Monitor {
    interface: String,
}

impl Monitor {
    pub fn new(interface: String) -> Monitor {
        Monitor { interface }
    }

    pub async fn monitor<T>(&self, state: &ClientState, client: &mut WirespiderClient<T>)
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        let mut stream = IntervalStream::new(interval(Duration::from_millis(10)));
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
