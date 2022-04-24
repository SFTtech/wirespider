mod command_line_interface;
mod interface_trait;
mod wireguard_uapi_interface;

pub use interface_trait::OverlayManagementInterface;
pub use interface_trait::WireguardManagementInterface;

pub use wireguard_uapi_interface::WireguardUapiInterface as DefaultWireguardInterface;

pub use command_line_interface::OverlayCommandLineInterface as DefaultOverlayInterface;
