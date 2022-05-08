use std::collections::HashMap;
use std::num::NonZeroU16;
use std::sync::Arc;
use boringtun::crypto::X25519PublicKey;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_graceful_shutdown::SubsystemHandle;
use tonic::codegen::InterceptedService;
use tonic::transport::Channel;
use tracing::error;
use tracing_unwrap::ResultExt;
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

use super::interface::WireguardManagementInterface;
use super::WirespiderInterceptor;

pub(crate) struct Monitor<T: WireguardManagementInterface + Send> {
    interface: Arc<Mutex<T>>,
    peer_updates: bool,
}

#[derive(Debug, Error)]
pub(crate) enum MonitorError {}

impl<T: 'static + WireguardManagementInterface + Send> Monitor<T> {
    pub fn new(interface: Arc<Mutex<T>>, peer_updates: bool) -> Monitor<T> {
        Monitor {
            interface,
            peer_updates,
        }
    }

    pub async fn monitor(
        self,
        subsys: SubsystemHandle,
        state: &ClientState,
        mut client: WirespiderClient<InterceptedService<Channel, WirespiderInterceptor>>,
    ) -> Result<(), MonitorError> {
        let mut stream = IntervalStream::new(interval(Duration::from_secs(5)));

        loop {
            tokio::select! {
                _ = subsys.on_shutdown_requested() => {
                    return Ok(())
                },
                _ = stream.next() => {
                    let interface = self.interface.clone();
                    let device = task::spawn_blocking(move || {
                        interface.blocking_lock().get_device()
                    }).await
                    .unwrap().unwrap();

                    // check if we got a connection to a peer and add the allowed IPs
                    for peer in device.peers.iter() {
                        if peer.endpoint.is_some() {
                            let allowed_ips = state.get_allowed_ips(peer.public_key).await;
                            if let Some(allowed_ips) = allowed_ips {
                                if allowed_ips.len() != peer.allowed_ips.len() {
                                    let persistent_keepalive_interval = NonZeroU16::new(peer.persistent_keepalive_interval);
                                    let pub_key = peer.public_key;
                                    let endpoint = peer.endpoint;
                                    let interface = self.interface.clone();
                                    task::spawn_blocking(move || {
                                        interface.blocking_lock().set_peer(Arc::new(X25519PublicKey::from(pub_key.as_slice())), endpoint, persistent_keepalive_interval, &allowed_ips)
                                    }).await
                                    .unwrap().unwrap_or_log();
                                }
                            }
                        }
                    }

                    if self.peer_updates {
                        let mut peer_endpoint_map = HashMap::new();
                        for peer in device.peers.iter() {
                            if peer.endpoint.is_some() {
                                peer_endpoint_map.insert(peer.public_key, peer.endpoint.unwrap());
                            }
                        }
                        let diff = state.endpoint_compare(peer_endpoint_map).await;
                        for (key, endpoint) in diff {
                            let response = client
                                .change_peer(ChangePeerRequest {
                                        id: Some(PeerIdentifier {
                                        identifier: Some(Identifier::PublicKey(key.into())),
                                    }),
                                    what: Some(What::Endpoint(endpoint.into())),
                                })
                                .await;
                            if let Err(x) = response {
                                error!("Error with change peer command: {:?}", x);
                            }
                        }
                    }
                }
            };
        }
    }
}
