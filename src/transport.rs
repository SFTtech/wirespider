use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tonic::codegen::InterceptedService;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};
use tracing_unwrap::ResultExt;
use wirespider::protocol::wirespider_client::WirespiderClient;
use wirespider::protocol::wirespider_server::Wirespider;
use wirespider::protocol::*;

use crate::cli::ConnectionOptions;

/// Everything talking to a realm goes through this, whether the realm is remote or in this process.
pub type Transport = Arc<dyn Wirespider<getEventsStream = EventStream>>;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error(transparent)]
    TransportError(#[from] tonic::transport::Error),
}

#[derive(Clone)]
struct AuthInterceptor {
    token: MetadataValue<Ascii>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        Ok(request)
    }
}

struct GrpcTransport {
    client: WirespiderClient<InterceptedService<Channel, AuthInterceptor>>,
}

pub async fn connect(conn: ConnectionOptions) -> Result<Transport, ConnectionError> {
    let endpoint = Endpoint::from(conn.endpoint)
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(25 * 60));
    let channel = endpoint.connect().await?;
    let token = format!("Bearer {}", conn.token)
        .as_str()
        .parse()
        .unwrap_or_log();
    Ok(Arc::new(GrpcTransport {
        client: WirespiderClient::with_interceptor(channel, AuthInterceptor { token }),
    }))
}

#[tonic::async_trait]
impl Wirespider for GrpcTransport {
    type getEventsStream = EventStream;

    async fn get_addresses(
        &self,
        request: Request<AddressRequest>,
    ) -> Result<Response<AddressReply>, Status> {
        self.client.clone().get_addresses(request).await
    }

    async fn get_events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<EventStream>, Status> {
        let events = self.client.clone().get_events(request).await?.into_inner();
        Ok(Response::new(Box::pin(events)))
    }

    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerReply>, Status> {
        self.client.clone().add_peer(request).await
    }

    async fn delete_peer(
        &self,
        request: Request<DeletePeerRequest>,
    ) -> Result<Response<DeletePeerReply>, Status> {
        self.client.clone().delete_peer(request).await
    }

    async fn change_peer(
        &self,
        request: Request<ChangePeerRequest>,
    ) -> Result<Response<ChangePeerReply>, Status> {
        self.client.clone().change_peer(request).await
    }

    async fn add_route(&self, request: Request<Route>) -> Result<Response<AddRouteReply>, Status> {
        self.client.clone().add_route(request).await
    }

    async fn del_route(&self, request: Request<Route>) -> Result<Response<DelRouteReply>, Status> {
        self.client.clone().del_route(request).await
    }
}
