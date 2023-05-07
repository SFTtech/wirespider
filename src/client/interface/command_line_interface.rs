use super::interface_trait::OverlayManagementInterface;

use advmac::MacAddr6;
use ipnet::IpNet;
use std::{net::IpAddr, process::Command};
use thiserror::Error;
use tracing::debug;

pub struct OverlayCommandLineInterface {
    device_name: String,
}

#[derive(Error, Debug)]
pub enum OverlayCommandLineInterfaceError {}

impl OverlayManagementInterface for OverlayCommandLineInterface {
    type Error = OverlayCommandLineInterfaceError;

    fn delete_device_if_exists(device_name: &str) {
        let output = Command::new("ip")
            .args(["link", "del", device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }

    fn create_overlay_device(
        device_name: String,
        listen_device: &str,
        listen_addr: &IpAddr,
        addresses: Vec<IpNet>,
        mac_addr: MacAddr6,
    ) -> Result<Self, Self::Error> {
        // create interface
        let args = &[
            "link",
            "add",
            &device_name,
            "address",
            &mac_addr.format_string(advmac::MacAddrFormat::ColonNotation).to_lowercase(),
            "mtu",
            "1378",
            "type",
            "vxlan",
            "id",
            "14523699",
            "dev",
            listen_device,
            "local",
            &listen_addr.to_string(),
            "dstport",
            "4789",
            "nol3miss",
            "nol2miss",
        ];
        debug!("running ip {}", args.join(" "));
        let output = Command::new("ip") // note: mtu is dependent on wireguard mtu
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        let output = Command::new("ip") // note: mtu is dependent on wireguard mtu
            .args(["link", "set", &device_name, "up"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        for address in &addresses {
            let ip_str = address.to_string();
            let output = Command::new("ip")
                .args(["address", "add", "dev", &device_name, &ip_str])
                .output()
                .expect("failed to execute process");
            debug!("{:?}", output);
        }

        Ok(OverlayCommandLineInterface { device_name })
    }

    fn set_peer(
        &self,
        mac_addr: MacAddr6,
        net: IpNet,
        remote: IpAddr,
    ) -> Result<(), Self::Error> {
        // delete existing entry
        let args = &[
            "fdb",
            "del",
            &mac_addr.format_string(advmac::MacAddrFormat::ColonNotation).to_lowercase(),
            "dev",
            &self.device_name,
        ];
        debug!("running: bridge {}", args.join(" "));
        let output = Command::new("bridge")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        // unicast endpoint to fdb
        let args = &[
            "fdb",
            "add",
            &mac_addr.format_string(advmac::MacAddrFormat::ColonNotation).to_lowercase(),
            "dev",
            &self.device_name,
            "self",
            "static",
            "dst",
            &remote.to_string(),
            "port",
            "4789",
        ];
        debug!("running: bridge {}", args.join(" "));
        let output = Command::new("bridge")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        // multicast/broadcast
        let args = &[
            "fdb",
            "append",
            "00:00:00:00:00:00",
            "dev",
            &self.device_name,
            "self",
            "static",
            "dst",
            &remote.to_string(),
            "port",
            "4789",
        ];
        debug!("running: bridge {}", args.join(" "));
        let output = Command::new("bridge")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        let args = &[
            "neigh",
            "replace",
            &net.addr().to_string(),
            "lladdr",
            &mac_addr.format_string(advmac::MacAddrFormat::ColonNotation).to_lowercase(),
            "dev",
            &self.device_name,
        ];
        debug!("running: ip {}", args.join(" "));
        let output = Command::new("ip")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        Ok(())
    }

    fn remove_peer(&self, mac_addr: MacAddr6) -> Result<(), Self::Error> {
        // TODO remove broadcast entry
        let output = Command::new("bridge")
            .args([
                "fdb",
                "del",
                &mac_addr.format_string(advmac::MacAddrFormat::ColonNotation).to_lowercase(),
                "dev",
                &self.device_name,
            ])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        Ok(())
    }
}

impl Drop for OverlayCommandLineInterface {
    fn drop(&mut self) {
        OverlayCommandLineInterface::delete_device_if_exists(&self.device_name);
    }
}
