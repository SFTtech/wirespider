use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
};

use clap::{ValueEnum, ArgGroup, Args, Parser, Subcommand, ValueHint};
use clap_complete::Shell;
use ipnet::IpNet;
use tonic::transport::Uri;
use uuid::Uuid;

#[derive(Debug, Args)]
pub struct ServerRunCommand {
    #[command(flatten)]
    pub base: ServerBaseOptions,
    #[arg(
        short,
        long,
        default_value = "0.0.0.0:49582",
        help = "IP:PORT to listen on"
    )]
    pub bind: SocketAddr,
}

#[derive(Debug, ValueEnum, Clone)]
pub enum NatType {
    #[value(name = "no-nat")]
    NoNat,
    #[value(name = "full-cone")]
    FullCone,
    #[value(name = "restricted-cone")]
    RestrictedCone,
    #[value(name = "port-restricted-cone")]
    PortRestrictedCone,
    #[value(name = "symmetric")]
    Symmetric,
}

#[derive(Debug, Subcommand)]
pub enum ServerDatabaseCommand {
    #[command(name = "create-admin")]
    CreateAdmin(CreateAdminCommand),

    #[command(flatten)]
    Network(NetworkCommand),

    #[command(name = "migrate", about = "Run database migrations")]
    Migrate(DatabaseOptions),
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommand {
    #[command(name = "create-network", about = "Create network")]
    Create(CreateNetworkCommand),
    #[command(name = "delete-network", about = "Delete network")]
    Delete(DeleteNetworkCommand),
}

#[derive(Debug, Args)]
#[command(about = "create a new network")]
pub struct CreateNetworkCommand {
    #[command(flatten)]
    pub db: DatabaseOptions,
    #[arg(help = "Network in CIDR notation (e.g. 192.168.1.0/24)")]
    pub network: IpNet,
    #[arg(value_enum, default_value_t = NetworkType::Wireguard, help = "Network type")]
    pub network_type: NetworkType,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum NetworkType {
    Wireguard,
    Vxlan,
}

#[derive(Debug, Args)]
pub struct DeleteNetworkCommand {
    #[command(flatten)]
    pub db: DatabaseOptions,
    #[command(flatten)]
    pub ipnet: ParamIPNet,
}

#[derive(Debug, Args)]
pub struct ParamIPNet {
    #[arg(
        required = true,
        help = "Network in CIDR notation (e.g. 192.168.1.0/24)"
    )]
    pub ipnet: IpNet,
}

#[derive(Debug, Args)]
#[command(about = "create a new admin account")]
pub struct CreateAdminCommand {
    #[command(flatten)]
    pub db: DatabaseOptions,
    #[arg(required = true, help = "Name of the admin")]
    pub name: String,
    #[arg(required = true, num_args = 1.., help = "IPs to assign to this admin")]
    pub addresses: Vec<IpNet>,
}

#[derive(Debug, Args)]
pub struct ServerBaseOptions {
    // enable debug
    #[arg(long, help = "Enable debug output")]
    pub debug: bool,
    #[command(flatten)]
    pub db: DatabaseOptions,
}

#[derive(Debug, Args)]
pub struct DatabaseOptions {
    #[arg(short('d'), long, env, value_hint = ValueHint::Url, help = "URL to database. Needs to start with \"sqlite:\"")]
    pub database_url: String,
}

#[derive(Parser, Debug)]
#[command(name = "spider")]
pub enum Cli {
    #[command(name = "start-client", about = "Start the Wirespider client")]
    ClientStart(ClientStartCommand),
    #[command(
        subcommand,
        name = "send-command",
        about = "Send commands to the server"
    )]
    ClientManage(ClientManageCommand),
    #[command(name = "start-server", about = "Start the Wirespider server")]
    ServerStart(ServerRunCommand),
    #[command(subcommand, name = "database", about = "Manage the server database")]
    ServerManage(ServerDatabaseCommand),
    #[command(
        name = "generate-completion",
        about = "Generate completion scripts for various shells"
    )]
    Completion(CompletionCommand),
}

#[derive(Args, Debug)]
pub struct CompletionCommand {
    #[arg(help = "Shell type", value_parser = ["bash","elvish","fish","powershell","zsh"])]
    pub shell: Shell,
}

#[derive(Debug, Args)]
pub struct BaseOptions {
    /// enable debug
    #[arg(short, long, help = "Enable debugging")]
    pub debug: bool,
}

#[derive(Debug, Args)]
pub struct ConnectionOptions {
    #[arg(short, long, env = "WS_ENDPOINT", value_hint = ValueHint::Url, help = "Server endpoint (format: https://server:port)")]
    pub endpoint: Uri,

    /// Token for authentication
    #[arg(
        short,
        long,
        env = "WS_TOKEN",
        help = "Token used for authentication"
    )]
    pub token: Uuid,
}

#[derive(Debug, Args)]
pub struct ClientStartCommand {
    #[command(flatten)]
    pub base: BaseOptions,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[arg(
        required = true,
        short = 'i',
        long,
        env = "WS_DEVICE",
        help = "Device name to use for wireguard."
    )]
    pub device: String,
    #[arg(short = 'k', long, default_value = "privkey", value_hint = ValueHint::FilePath, env = "WS_PRIVATE_KEY", help = "Path to wireguard private key")]
    pub private_key: String,
    #[arg(
        long,
        env = "WS_NODE_MONITOR",
        help = "Request monitor role in network"
    )]
    pub monitor: bool,
    #[arg(long, env = "WS_NODE_RELAY", help = "Request relay role in network")]
    pub relay: bool,
    #[arg(
        long,
        default_value = "25",
        env = "WS_KEEP_ALIVE",
        help = "Keepalive for wireguard"
    )]
    pub keep_alive: NonZeroU16,
    #[arg(short, long, env = "WS_LISTEN_PORT", help = "Wireguard listen port")]
    pub port: Option<NonZeroU16>,
    #[arg(
        long,
        env = "WS_STUN_HOST",
        default_value = "stun.stunprotocol.org:3478",
        help = "Stun server to use, must support RFC 5780"
    )]
    pub stun_host: String,
    #[arg(
        long,
        env = "WS_FIXED_ENDPOINT",
        help = "Skip NAT detection, report this endpoint and send NAT type \"NoNAT\" to server unless another NAT type is specified"
    )]
    pub fixed_endpoint: Option<SocketAddr>,
    #[arg(
        long,
        value_enum,
        env = "WS_NAT_TYPE",
        default_value = "no-nat",
        help = "When using a fixed endpoint report this NAT type"
    )]
    pub nat_type: NatType,
}

#[derive(Debug, Subcommand)]
pub enum ClientManageCommand {
    #[command(flatten)]
    Peer(ClientManagePeerCommand),
    #[command(flatten)]
    Route(ClientManageRouteCommand),
}

#[derive(Debug, Subcommand)]
pub enum ClientManagePeerCommand {
    #[command(name = "add-peer", about = "Add peer")]
    Add(AddPeerCommand),
    #[command(name = "change-peer", about = "Change peer properties")]
    Change(ChangePeerCommand),
    #[command(name = "delete-peer", about = "Delete peer")]
    Delete(DeletePeerCommand),
}

#[derive(Debug, Subcommand)]
pub enum ClientManageRouteCommand {
    #[command(name = "add-route", about = "Add new route")]
    Add(AddRouteCommand),
    #[command(name = "delete-route", about = "Delete route")]
    Delete(DeleteRouteCommand),
}

#[derive(Debug, Args)]
#[command(group = ArgGroup::new("peer_identifier").required(true))]
pub struct CliPeerIdentifier {
    #[arg(long, group = "peer_identifier", help = "Name of the target peer")]
    pub name_id: Option<String>,
    #[arg(long, group = "peer_identifier", help = "Token of the target peer")]
    pub token_id: Option<Uuid>,
    #[arg(
        long,
        group = "peer_identifier",
        help = "Public key (base64) of the target peer"
    )]
    pub public_key_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddPeerCommand {
    #[command(flatten)]
    pub base: BaseOptions,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[arg(
        short,
        long,
        default_value = "0",
        help = "Permission level of the new user",
        long_help = "Permission level of the new user (Admin: 100, Relay: 50, Monitor: 25, Normal users: 0)"
    )]
    pub permission_level: i32,
    #[arg(help = "Name of the peer")]
    pub name: String,
    #[arg(required = true, num_args = 1.., help = "IPs to assign to this peer")]
    pub addresses: Vec<IpNet>,
}

#[derive(Debug, Args)]
pub struct ChangePeerCommand {
    #[command(flatten)]
    pub base: BaseOptions,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[command(flatten)]
    pub peer: CliPeerIdentifier,
    #[arg(help = "Endpoint to report to other peers")]
    pub new_endpoint: SocketAddr,
}

#[derive(Debug, Args)]
pub struct DeletePeerCommand {
    #[command(flatten)]
    pub base: BaseOptions,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[command(flatten)]
    pub peer: CliPeerIdentifier,
}

#[derive(Debug, Args)]
pub struct AddRouteCommand {
    #[command(flatten)]
    pub base: BaseOptions,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[arg(help = "Network to route")]
    pub net: IpNet,
    #[arg(help = "Destination IP of this route")]
    pub via: IpAddr,
}

#[derive(Debug, Args)]
pub struct DeleteRouteCommand {
    #[command(flatten)]
    pub base: BaseOptions,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[arg(help = "Network to route")]
    pub net: IpNet,
    #[arg(help = "Destination IP of this route")]
    pub via: IpAddr,
}
