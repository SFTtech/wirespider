use std::{net::{SocketAddr, IpAddr}, num::NonZeroU16};

use clap::{Parser, Args, Subcommand, ArgEnum, ValueHint, ArgGroup};
use clap_complete::Shell;
use ipnet::IpNet;
use tonic::transport::Uri;
use uuid::Uuid;



#[derive(Debug, Args)]
pub struct ServerRunCommand {
    #[clap(flatten)]
    pub base: ServerBaseOptions,
    #[clap(short, long, default_value = "0.0.0.0:49582", help = "IP:PORT to listen on")]
    pub bind: SocketAddr,
}

#[derive(Debug, Subcommand)]
pub enum ServerDatabaseCommand {
    #[clap(name = "create-admin")]
    CreateAdmin(CreateAdminCommand),

    #[clap(flatten)]
    Network(NetworkCommand),

    #[clap(name = "migrate", about = "Run database migrations")]
    Migrate,
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommand {
    #[clap(name = "create-network", about = "Create network")]
    Create(CreateNetworkCommand),
    #[clap(name = "delete-network", about = "Delete network")]
    Delete(ParamIPNet),
}

#[derive(Debug, Args)]
#[clap(about = "create a new network")]
pub struct CreateNetworkCommand {
    #[clap(help = "Network in CIDR notation (e.g. 192.168.1.0/24)")]
    pub network: IpNet,
    #[clap(arg_enum, default_value_t = NetworkType::Wireguard, help = "Network type")]
    pub network_type: NetworkType,
}

#[derive(Copy, Clone, PartialEq, Eq, ArgEnum, Debug)]
pub enum NetworkType {
    Wireguard,
    Vxlan,
}

#[derive(Debug, Args)]
pub struct ParamIPNet {
    #[clap(required = true, parse(try_from_str), help = "Network in CIDR notation (e.g. 192.168.1.0/24)")]
    pub ipnet: IpNet,
}

#[derive(Debug, Args)]
#[clap(about = "create a new admin account")]
pub struct CreateAdminCommand {
    #[clap(required = true, help = "Name of the admin")]
    pub name: String,
    #[clap(required = true, min_values = 1, help = "IPs to assign to this admin")]
    pub addresses: Vec<IpNet>,
}


#[derive(Debug, Args)]
pub struct ServerBaseOptions {
    // enable debug
    #[clap(long, help = "Enable debug output")]
    pub debug: bool,

    #[clap(short('d'), long, env, value_hint = ValueHint::Url, help = "URL to database. Needs to start with \"sqlite:\"")]
    pub database_url: String,
}



#[derive(Parser, Debug)]
#[clap(name = "spider")]
pub enum Cli {
    #[clap(name = "start-client", about = "Start the Wirespider client")]
    ClientStart(ClientStartCommand),
    #[clap(subcommand,name = "send-command", about = "Send commands to the server")]
    ClientManage(ClientManageCommand),
    #[clap(name = "start-server", about = "Start the Wirespider server")]
    ServerStart(ServerRunCommand),
    #[clap(subcommand,name = "database", about = "Manage the server database")]
    ServerManage(ServerDatabaseCommand),
    #[clap(name = "generate-completion", about = "Generate completion scripts for various shells")]
    Completion(CompletionCommand),
}


#[derive(Args, Debug)]
pub struct CompletionCommand {
    #[clap(help = "Shell type", possible_values = ["bash","elvish","fish","powershell","zsh"] )]
    pub shell: Shell,
}


#[derive(Debug, Args)]
pub struct BaseOptions {
    /// enable debug
    #[clap(short, long, help = "Enable debugging")]
    pub debug: bool,
}

#[derive(Debug, Args)]
pub struct ConnectionOptions {
    #[clap(short, long, parse(try_from_str), env = "WS_ENDPOINT", value_hint = ValueHint::Url, help = "Server endpoint (format: https://server:port)")]
    pub endpoint: Uri,

    /// Token for authentication
    #[clap(short, long, parse(try_from_str), env = "WS_TOKEN", help = "Token used for authentication")]
    pub token: Uuid,
}

#[derive(Debug, Args)]
pub struct ClientStartCommand {
    #[clap(flatten)]
    pub base: BaseOptions,
    #[clap(flatten)]
    pub connection: ConnectionOptions,
    #[clap(required = true, short = 'i', long, env = "WS_DEVICE", help = "Device name to use for wireguard.")]
    pub device: String,
    #[clap(short = 'k', long, default_value = "privkey", value_hint = ValueHint::FilePath, env = "WS_PRIVATE_KEY", help = "Path to wireguard private key")]
    pub private_key: String,
    #[clap(long, env = "WS_NODE_MONITOR", help = "Request monitor role in network")]
    pub monitor: bool,
    #[clap(long, env = "WS_NODE_RELAY", help = "Request relay role in network")]
    pub relay: bool,
    #[clap(long, default_value = "25", env = "WS_KEEP_ALIVE", help = "Keepalive for wireguard")]
    pub keep_alive: NonZeroU16,
    #[clap(short, long, env = "WS_LISTEN_PORT", help = "Wireguard listen port")]
    pub port: Option<NonZeroU16>,
    #[clap(
        long,
        env = "WS_STUN_HOST",
        default_value = "stun.stunprotocol.org:3478",
        help = "Stun server to use, must support RFC 5780"
    )]
    pub stun_host: String,
    #[clap(long, env = "WS_FIXED_ENDPOINT", help = "Skip NAT detection, report this endpoint and send NAT type \"NoNAT\" to server")]
    pub fixed_endpoint: Option<SocketAddr>,
}

#[derive(Debug, Subcommand)]
pub enum ClientManageCommand {
    #[clap(flatten)]
    Peer(ClientManagePeerCommand),
    #[clap(flatten)]
    Route(ClientManageRouteCommand),
}

#[derive(Debug, Subcommand)]
pub enum ClientManagePeerCommand {
    #[clap(name = "add-peer", about = "Add peer")]
    Add(AddPeerCommand),
    #[clap(name = "change-peer", about = "Change peer properties")]
    Change(ChangePeerCommand),
    #[clap(name = "delete-peer", about = "Delete peer")]
    Delete(DeletePeerCommand),
}

#[derive(Debug, Subcommand)]
pub enum ClientManageRouteCommand {
    #[clap(name = "add-route", about = "Add new route")]
    Add(AddRouteCommand),
    #[clap(name = "delete-route", about = "Delete route")]
    Delete(DeleteRouteCommand),
}

#[derive(Debug, Args)]
#[clap(group = ArgGroup::new("peer_identifier").required(true))]
pub struct CliPeerIdentifier {
    #[clap(long, group = "peer_identifier", help = "Name of the target peer")]
    pub name_id: Option<String>,
    #[clap(long, group = "peer_identifier", help = "Token of the target peer")]
    pub token_id: Option<Uuid>,
    #[clap(long, group = "peer_identifier", help = "Public key (base64) of the target peer")]
    pub public_key_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddPeerCommand {
    #[clap(flatten)]
    pub base: BaseOptions,
    #[clap(flatten)]
    pub connection: ConnectionOptions,
    #[clap(short, long, default_value = "0", help = "Permission level of the new user", long_help = "Permission level of the new user (Admin: 100, Relay: 50, Monitor: 25, Normal users: 0)")]
    pub permission_level: i32,
    #[clap(help = "Name of the peer")]
    pub name: String,
    #[clap(required = true, min_values = 1, help = "IPs to assign to this peer")]
    pub addresses: Vec<IpNet>,
}

#[derive(Debug, Args)]
pub struct ChangePeerCommand {
    #[clap(flatten)]
    pub base: BaseOptions,
    #[clap(flatten)]
    pub connection: ConnectionOptions,
    #[clap(flatten)]
    pub peer: CliPeerIdentifier,
    #[clap(help = "Endpoint to report to other peers")]
    pub new_endpoint: SocketAddr,
}

#[derive(Debug, Args)]
pub struct DeletePeerCommand {
    #[clap(flatten)]
    pub base: BaseOptions,
    #[clap(flatten)]
    pub connection: ConnectionOptions,
    #[clap(flatten)]
    pub peer: CliPeerIdentifier,
}

#[derive(Debug, Args)]
pub struct AddRouteCommand {
    #[clap(flatten)]
    pub base: BaseOptions,
    #[clap(flatten)]
    pub connection: ConnectionOptions,
    #[clap(help = "Network to route")]
    pub net: IpNet,
    #[clap(help = "Destination IP of this route")]
    pub via: IpAddr,
}

#[derive(Debug, Args)]
pub struct DeleteRouteCommand {
    #[clap(flatten)]
    pub base: BaseOptions,
    #[clap(flatten)]
    pub connection: ConnectionOptions,
    #[clap(help = "Network to route")]
    pub net: IpNet,
    #[clap(help = "Destination IP of this route")]
    pub via: IpAddr,
}