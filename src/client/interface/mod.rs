mod command_interface;
mod interface_trait;

pub use interface_trait::OverlayManagementInterface;
pub use interface_trait::WireguardManagementInterface;

pub use command_interface::WireguardCommandLineInterface as DefaultWireguardInterface;

pub use command_interface::OverlayCommandLineInterface as DefaultOverlayInterface;
