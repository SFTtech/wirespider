mod interface_trait;
mod command_interface;

pub use interface_trait::WireguardManagementInterface;
pub use interface_trait::OverlayManagementInterface;

pub use command_interface::WireguardCommandLineInterface as DefaultWireguardInterface;

pub use command_interface::OverlayCommandLineInterface as DefaultOverlayInterface;