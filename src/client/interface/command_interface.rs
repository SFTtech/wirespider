use super::interface_trait::ManagementInterface;

use base64::encode;
use ipnet::IpNet;
use std::{net::SocketAddr, num::NonZeroU16, process::Command};
use tempfile::NamedTempFile;
use tracing::debug;
use wirespider::WireguardKey;

pub struct CommandLineInterface {
    device_name: String,
    addresses: Vec<IpNet>,
}

impl ManagementInterface for CommandLineInterface {
    type Error = ();

    fn create_device(
        device_name: String,
        privkey: WireguardKey,
        port: Option<NonZeroU16>,
        addresses: Vec<IpNet>,
    ) -> Result<Self, Self::Error> {
        // create interface
        let output = Command::new("ip")
            .args(&["link", "add", &device_name, "type", "wireguard"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        let mut args = vec!["set", &device_name];
        let str_port;
        if let Some(port) = port {
            str_port = port.to_string();
            args.push("listen-port");
            args.push(&str_port);
        }
        let file = NamedTempFile::new().or(Err(()))?;
        std::fs::write(file.path(), encode(privkey)).or(Err(()))?;
        args.push("private-key");
        args.push(file.path().to_str().ok_or(())?);

        let output = Command::new("wg")
            .args(&args)
            .output()
            .expect("failed to execute wireguard. Please make sure wireguard is installed");

        debug!("{:?}", output);

        for address in &addresses {
            let ip_str = address.to_string();
            let output = Command::new("ip")
                .args(&["address", "add", "dev", &device_name, &ip_str])
                .output()
                .expect("failed to execute process");
            debug!("{:?}", output);
        }

        let output = Command::new("ip")
            .args(&["link", "set", &device_name, "up"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        Ok(CommandLineInterface {
            device_name,
            addresses,
        })
    }

    fn set_peer(
        &self,
        pubkey: WireguardKey,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: Option<NonZeroU16>,
        allowed_ips: &[IpNet],
    ) -> Result<(), Self::Error> {
        let mut args = vec!["set", &self.device_name, "peer"];
        let str_pubkey = encode(pubkey);
        args.push(&str_pubkey);

        let str_endpoint;
        if let Some(endpoint) = endpoint {
            str_endpoint = endpoint.to_string();
            args.push("endpoint");
            args.push(&str_endpoint);
        }

        let str_keepalive;
        if let Some(persistent_keepalive) = persistent_keepalive {
            str_keepalive = persistent_keepalive.to_string();
            args.push("persistent-keepalive");
            args.push(&str_keepalive);
        }

        let str_allowed_ips;
        if !allowed_ips.is_empty() {
            args.push("allowed-ips");
            str_allowed_ips = allowed_ips
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(",");
            args.push(&str_allowed_ips);
        }

        let output = Command::new("wg")
            .args(&args)
            .output()
            .expect("failed to execute process");
        debug!("wg {:?}", args);
        debug!("{:?}", output);
        Ok(())
    }

    fn remove_peer(&self, pubkey: wirespider::WireguardKey) -> Result<(), Self::Error> {
        let mut args = vec!["set", &self.device_name, "peer"];
        let str_pubkey = encode(pubkey);
        args.push(&str_pubkey);
        args.push("remove");
        let output = Command::new("wg")
            .args(&args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        Ok(())
    }

    fn add_route(&self, network: IpNet, via: std::net::IpAddr) -> Result<(), Self::Error> {
        let net_str = network.to_string();
        let via_str = via.to_string();
        let src_str = self
            .addresses
            .iter()
            .find(|x| via.is_ipv4() == x.addr().is_ipv4())
            .map(|x| x.to_string())
            .unwrap_or_default();
        let mut cmd_args = vec!["route", "add", net_str.as_str(), "via", via_str.as_str()];
        if !src_str.is_empty() {
            cmd_args.extend_from_slice(&["src", src_str.as_str()]);
        }

        let output = Command::new("ip")
            .args(&cmd_args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        Ok(())
    }

    fn remove_route(&self, network: IpNet, via: std::net::IpAddr) -> Result<(), Self::Error> {
        let net_str = network.to_string();
        let via_str = via.to_string();
        let args = ["route", "del", net_str.as_str(), "via", via_str.as_str()];

        let output = Command::new("ip")
            .args(&args)
            .output()
            .expect("failed to execute process");

        debug!("{:?}", output);
        Ok(())
    }

    fn shutdown(&self) {
        let output = Command::new("ip")
            .args(&["link", "set", &self.device_name, "down"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        let output = Command::new("ip")
            .args(&["link", "del", &self.device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }

    fn delete_device_if_exists(device_name: &str) {
        let output = Command::new("ip")
            .args(&["link", "del", device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }
}
