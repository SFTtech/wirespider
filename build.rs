use prost_build::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.type_attribute("wirespider.Peer", "#[derive(typed_builder::TypedBuilder)]");
    config.field_attribute("wirespider.Peer.wg_public_key", "#[builder(setter(transform = |x: WireguardKey| x.to_vec()))]");
    config.field_attribute("wirespider.Peer.endpoint", "#[builder(setter(!strip_option, transform = |endpoint: Option<SocketAddr>| endpoint.map(|x| peer::Endpoint::Addr(Endpoint::from(x)))))]");
    config.field_attribute("wirespider.Peer.allowed_ips", "#[builder(setter(transform = |allowed_ips: Vec<IpNet>| allowed_ips.into_iter().map(Network::from).collect()))]");
    config.field_attribute("wirespider.Peer.overlay_ips", "#[builder(setter(transform = |overlay_ips: Vec<IpNet>| overlay_ips.into_iter().map(Network::from).collect()))]");
    config.field_attribute("wirespider.Peer.node_flags", "#[builder(setter(!strip_option, transform = |monitor: bool, relay: bool| Some(NodeFlags{monitor, relay})))]");
    config.field_attribute("wirespider.Peer.tunnel_ips", "#[builder(setter(transform = |tunnel_ips: Vec<IpAddr>| tunnel_ips.into_iter().map(Ip::from).collect()))]");
    config.field_attribute("wirespider.Peer.local_ips", "#[builder(setter(transform = |local_ips: Vec<IpAddr>| local_ips.into_iter().map(Ip::from).collect()))]");
    tonic_build::configure().compile_with_config(config, &["proto/wirespider.proto"], &["proto/"]).expect("Could not compile proto files");
    Ok(())
}