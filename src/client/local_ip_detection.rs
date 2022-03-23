use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;
use tokio_graceful_shutdown::SubsystemHandle;
use futures::future::join_all;
use tokio::io::Error;
use tracing::instrument;
use tracing_unwrap::ResultExt;
use wirespider::WireguardKey;

const MESSAGE : &str = "wirespider";

pub async fn local_ip_detection_service(subsys: SubsystemHandle, key: WireguardKey) -> Result<(),Error> {
    let socket = UdpSocket::bind("0.0.0.0:27212").await.unwrap_or_log();
    let mut buf = [0u8; MESSAGE.len()];
    loop{
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (length, from) = recv.unwrap_or_log();
                if length != MESSAGE.len() {
                    continue;
                }
                socket.send_to(&key, from).await.unwrap_or_log();
            }
            _ = subsys.on_shutdown_requested() => {
                return Ok(());
            }
        };
    }
}

#[instrument]
pub async fn check_local_ips(ips: &[IpAddr], key: WireguardKey) -> Result<Option<IpAddr>,Error> {
    let results = join_all(ips.iter().map(|x| check_ip(*x, key))).await;
    for result in results {
        match result? {
            Some(ip) => return Ok(Some(ip)),
            None => continue,
        };
    }
    Ok(None)
}

#[instrument]
async fn check_ip(ip: IpAddr, key: WireguardKey) -> Result<Option<IpAddr>,Error> {
    if ip.is_ipv6() {
        return Ok(None); // not supported for now
    }
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(SocketAddr::from((ip, 27212))).await?;
    socket.send(MESSAGE.as_bytes()).await?;
    let mut buffer : WireguardKey = [0; 32];
    match socket.recv(&mut buffer).await {
        Ok(size) if size == 32 && buffer == key => Ok(Some(ip)),
        _ => Ok(None)
    }
}