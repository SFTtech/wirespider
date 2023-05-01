use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::time::Duration;

use bytecodec::{DecodeExt, EncodeExt};
use rand::rngs::OsRng;
use rand::RngCore;

use stun_codec::define_attribute_enums;
use stun_codec::rfc5389::attributes::*;
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::rfc5780::attributes::*;
use stun_codec::MessageDecoder;
use stun_codec::MessageEncoder;
use stun_codec::TransactionId;
use stun_codec::{Message, MessageClass};

use tokio::net::lookup_host;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;
use tracing::instrument;
use tracing_unwrap::ResultExt;
use wirespider::protocol::NatType;

#[derive(Debug, PartialEq)]
enum NatMapping {
    NoNat,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, PartialEq)]
enum NatFiltering {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[instrument]
pub async fn get_nat_type(
    stun_host: &str,
    port: NonZeroU16,
) -> Result<(Option<SocketAddr>, NatType), ()> {
    debug!("getting nat type");
    let stun_host = lookup_host(stun_host)
        .await
        .or(Err(()))?
        .find(|x| x.is_ipv4())
        .ok_or(())?;
    debug!("Using {} for STUN", stun_host);
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), port.into())))
        .await
        .or(Err(()))?;

    debug!("getting nat mapping");
    let (addr, mapping) = get_nat_mapping_behaviour(socket, stun_host)
        .await
        .expect_or_log("Could not connect to STUN server, check internet connection.");

    // return early
    if mapping == NatMapping::NoNat {
        return Ok((addr, NatType::NoNat));
    }

    let mut socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), port.into())))
        .await
        .or(Err(()))?;

    debug!("getting nat filtering");
    let filtering = get_nat_filtering_behaviour(&mut socket, stun_host)
        .await
        .map_err(|_| ())?;
    Ok((
        addr,
        match (mapping, filtering) {
            (NatMapping::NoNat, _) => unreachable!(),
            (NatMapping::EndpointIndependent, NatFiltering::EndpointIndependent) => {
                NatType::FullCone
            }
            (NatMapping::EndpointIndependent, NatFiltering::AddressDependent) => {
                NatType::RestrictedCone
            }
            (NatMapping::EndpointIndependent, NatFiltering::AddressAndPortDependent) => {
                NatType::PortRestrictedCone
            }
            (_, _) => NatType::Symmetric,
        },
    ))
}

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [
        // RFC 5389
        MappedAddress,
        Username,
        MessageIntegrity,
        ErrorCode,
        UnknownAttributes,
        Realm,
        Nonce,
        XorMappedAddress,
        Software,
        AlternateServer,
        Fingerprint,
        // RFC 5780
        ChangeRequest,
        ResponseOrigin,
        ResponsePort,
        OtherAddress
    ]
);

#[instrument]
async fn run_nat_test(
    socket: &mut UdpSocket,
    stun_host: SocketAddr,
    from_alternative_ip: bool,
    from_alternative_port: bool,
) -> Result<Vec<Attribute>, ()> {
    let mut rng = OsRng::default();
    let mut transaction_id_data = [0; 12];
    rng.try_fill_bytes(&mut transaction_id_data).unwrap_or_log();
    let transaction_id = TransactionId::new(transaction_id_data);

    let mut encoder = MessageEncoder::new();
    let mut decoder = MessageDecoder::<Attribute>::new();
    let mut message = Message::new(MessageClass::Request, BINDING, transaction_id);
    message.add_attribute(ChangeRequest::new(
        from_alternative_ip,
        from_alternative_port,
    ));
    let bytes = encoder.encode_into_bytes(message).unwrap_or_log();
    socket.send_to(&bytes, stun_host).await.unwrap_or_log();

    let mut bytes = vec![0; 100];
    let size = timeout(Duration::from_secs(1), socket.recv(&mut bytes))
        .await
        .map_err(|_| ())?
        .unwrap_or_log();
    let message = decoder.decode_from_bytes(&bytes[0..size]).unwrap().unwrap();
    Ok(message.attributes().cloned().collect())
}

#[instrument]
async fn get_nat_mapping_behaviour(
    socket: UdpSocket,
    stun_host: SocketAddr,
) -> Result<(Option<SocketAddr>, NatMapping), String> {
    // we need to connect to get the external ip for local_addr()
    socket.connect(stun_host).await.unwrap();
    let local_addr = socket.local_addr().unwrap();
    // recreate socket, so udp packets from any destination can be received
    drop(socket);
    let mut socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, local_addr.port())))
        .await
        .unwrap();
    debug!(
        "Local socket: {}, after disconnect: {}",
        local_addr,
        socket.local_addr().unwrap()
    );

    let primary_address = stun_host.ip();
    let primary_port = stun_host.port();
    let mut alternative_address = stun_host.ip();
    let mut alternative_port = stun_host.port();
    let mut external_address = None;

    // test 1
    let attributes = run_nat_test(
        &mut socket,
        SocketAddr::new(primary_address, primary_port),
        false,
        false,
    )
    .await
    .map_err(|_| "connection problem".to_string())?;
    for attribute in attributes {
        match attribute {
            Attribute::XorMappedAddress(address) => {
                external_address = Some(address.address());
                if address.address() == local_addr {
                    return Ok((Some(address.address()), NatMapping::NoNat));
                }
            }
            Attribute::OtherAddress(address) => {
                alternative_address = address.address().ip();
                alternative_port = address.address().port();
            }
            _ => continue,
        }
    }

    let external_address = external_address.expect("Could not get external ip from stun server");

    //test 2
    let mut test2_endpoint = None;
    // same request, but to alternate host
    let attributes = run_nat_test(
        &mut socket,
        SocketAddr::new(alternative_address, primary_port),
        false,
        false,
    )
    .await
    .map_err(|_| "connection problem".to_string())?;
    for attribute in attributes {
        match attribute {
            Attribute::XorMappedAddress(address) => {
                test2_endpoint = Some(address.address());
                if address.address() == external_address {
                    return Ok((Some(external_address), NatMapping::EndpointIndependent));
                }
            }
            _ => continue,
        }
    }
    let test2_endpoint = test2_endpoint.expect("Could not get external ip from stun server");

    // test 3
    // same request, but to alternate host and alternate port
    let attributes = run_nat_test(
        &mut socket,
        SocketAddr::new(alternative_address, alternative_port),
        false,
        false,
    )
    .await
    .map_err(|_| "connection problem".to_string())?;
    for attribute in attributes {
        match attribute {
            Attribute::XorMappedAddress(address) => {
                if address.address() == test2_endpoint {
                    return Ok((None, NatMapping::AddressDependent));
                }
            }
            _ => continue,
        }
    }

    Ok((None, NatMapping::AddressAndPortDependent))
}

#[instrument]
async fn get_nat_filtering_behaviour(
    socket: &mut UdpSocket,
    stun_host: SocketAddr,
) -> Result<NatFiltering, String> {
    // test 1: normal response
    run_nat_test(socket, stun_host, false, false)
        .await
        .map_err(|_| "connection problem".to_string())?;
    // test 2: now with changed ip, port
    if run_nat_test(socket, stun_host, true, true).await.is_ok() {
        return Ok(NatFiltering::EndpointIndependent);
    }
    // test 3: now only with changed port
    if run_nat_test(socket, stun_host, false, true).await.is_ok() {
        return Ok(NatFiltering::AddressDependent);
    }

    Ok(NatFiltering::AddressAndPortDependent)
}

#[cfg(feature = "network-test")]
#[tokio::test]
async fn test_nat_behaviour() {
    let result = get_nat_type(
        "stunserver.stunprotocol.org:3478",
        NonZeroU16::new(51820).unwrap(),
    )
    .await
    .expect("Could not get NAT type");
    println!("Got address: {:?}, Nat type: {:?}", result.0, result.1);
}
