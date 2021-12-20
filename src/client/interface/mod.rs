mod interface_trait;
mod command_interface;

pub use interface_trait::ManagementInterface;

pub use command_interface::CommandLineInterface as DefaultInterface;