use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::future::join_all;
use tokio::io::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::instrument;
use tracing_unwrap::ResultExt;

use boringtun::crypto::X25519PublicKey;
use boringtun::crypto::X25519SecretKey;
use boringtun::noise::Tunn;

#[instrument]
pub async fn check_local_ips(
    destinations: &[SocketAddr],
    priv_key: Arc<X25519SecretKey>,
    pub_key: Arc<X25519PublicKey>,
) -> Result<Option<SocketAddr>, Error> {
    let results = join_all(
        destinations
            .iter()
            .map(|x| check_ip(*x, priv_key.clone(), pub_key.clone())),
    )
    .await;
    for result in results {
        match result? {
            Some(ip) => return Ok(Some(ip)),
            None => continue,
        };
    }
    Ok(None)
}

#[instrument]
async fn check_ip(
    dest: SocketAddr,
    priv_key: Arc<X25519SecretKey>,
    pub_key: Arc<X25519PublicKey>,
) -> Result<Option<SocketAddr>, Error> {
    if dest.is_ipv6() {
        return Ok(None); // not supported for now
    }
    if dest.ip().is_loopback() {
        return Ok(None);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(dest).await?;
    let mut buffer = [0u8; 148]; // size from boringtun::noise::HANDSHAKE_INIT_SZ
    let mut tun = Tunn::new(priv_key, pub_key, None, None, 1, None).unwrap_or_log();
    match tun.format_handshake_initiation(&mut buffer, false) {
        boringtun::noise::TunnResult::Err(_) => return Ok(None),
        boringtun::noise::TunnResult::WriteToNetwork(buf) => {
            let size = socket.send(buf).await?;
            if size != buf.len() {
                return Ok(None);
            };
        }
        _ => unreachable!(),
    };

    match timeout(Duration::from_millis(100), socket.recv(&mut buffer)).await {
        Ok(Ok(size)) => {
            let mut out_buf = [0u8; 92]; // size from boringtun::noise::HANDSHAKE_RESP_SZ
            let mut read_size = size;
            loop {
                match tun
                    .as_mut()
                    .decapsulate(Some(dest.ip()), &buffer[0..read_size], &mut out_buf)
                {
                    boringtun::noise::TunnResult::Done => return Ok(Some(dest)),
                    boringtun::noise::TunnResult::WriteToNetwork(_) => {
                        // we do not want to actually send an response. "Receive" empty datagrams until we reach Err or Done
                        read_size = 0;
                        continue;
                    }
                    _ => return Ok(None),
                }
            }
        }
        _ => Ok(None),
    }
}
