use super::interface_trait::{OverlayManagementInterface, WireguardManagementInterface};

use base64::encode;
use eui48::MacAddress;
use ipnet::IpNet;
use std::{net::{IpAddr, SocketAddr}, num::NonZeroU16, process::Command};
use tempfile::NamedTempFile;
use tracing::debug;
use wirespider::WireguardKey;

pub struct WireguardCommandLineInterface {
    device_name: String,
    addresses: Vec<IpNet>,
}

impl WireguardManagementInterface for WireguardCommandLineInterface {
    type Error = ();

    fn create_wireguard_device(
        device_name: String,
        privkey: WireguardKey,
        port: Option<NonZeroU16>,
        addresses: &[IpNet],
    ) -> Result<Self, Self::Error> {
        // create interface
        let output = Command::new("ip")
            // mtu 1432 for ipv4+pppoe, needs to be changed when ipv6 support is ready
            .args(&["link", "add", &device_name, "mtu", "1432", "type", "wireguard"])
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

        for address in addresses {
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

        Ok(WireguardCommandLineInterface {
            device_name,
            addresses: addresses.to_vec(),
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
            .map(|x| x.addr().to_string())
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

    fn delete_device_if_exists(device_name: &str) {
        let output = Command::new("ip")
            .args(&["link", "del", device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }
}

impl Drop for WireguardCommandLineInterface {
    fn drop(&mut self) {
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
}

pub struct OverlayCommandLineInterface {
    device_name: String,
}

impl OverlayManagementInterface for OverlayCommandLineInterface {
    type Error = ();

    fn delete_device_if_exists(device_name: &str) {
        let output = Command::new("ip")
            .args(&["link", "del", device_name])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
    }

    fn create_overlay_device(device_name: String, listen_device: &str, listen_addr: &IpAddr, addresses: Vec<IpNet>, mac_addr: MacAddress) -> Result<Self,Self::Error> {
        // create interface
        let args = &["link", "add", &device_name, "address", &mac_addr.to_hex_string(), "mtu", "1378", "type", "vxlan", "id", "14523699", "dev", listen_device, "local", &listen_addr.to_string(), "dstport", "4789", "nol3miss", "nol2miss"];
        debug!("running ip {}", args.join(" "));
        let output = Command::new("ip") // note: mtu is dependent on wireguard mtu
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        let output = Command::new("ip") // note: mtu is dependent on wireguard mtu
            .args(&["link", "set", &device_name, "up"])
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);

        for address in &addresses {
            let ip_str = address.to_string();
            let output = Command::new("ip")
                .args(&["address", "add", "dev", &device_name, &ip_str])
                .output()
                .expect("failed to execute process");
            debug!("{:?}", output);
        }

        Ok(OverlayCommandLineInterface { device_name })
    }

    fn set_peer(&self, mac_addr: MacAddress, net: IpNet, remote: IpAddr) -> Result<(),Self::Error> {
        // unicast endpoint to fdb
        let args = &["fdb", "add", &mac_addr.to_hex_string(), "dev", &self.device_name, "dst", &remote.to_string(), "port", "4789"];
        debug!("running: bridge {}", args.join(" "));
        let output = Command::new("bridge")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        // multicast/broadcast
        let args = &["fdb", "append", "00:00:00:00:00:00", "dev", &self.device_name, "dst", &remote.to_string(), "port", "4789"];
        debug!("running: bridge {}", args.join(" "));
        let output = Command::new("bridge")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        let args = &["neigh", "add", &net.addr().to_string(), "lladdr", &mac_addr.to_hex_string(), "dev", &self.device_name];
        debug!("running: ip {}", args.join(" "));
        let output = Command::new("ip")
            .args(args)
            .output()
            .expect("failed to execute process");
        debug!("{:?}", output);
        Ok(())
    }

    fn remove_peer(&self, mac_addr: eui48::MacAddress) -> Result<(), Self::Error> {
        // TODO remove broadcast entry
        let output = Command::new("bridge")
        .args(&["fdb", "del", &mac_addr.to_hex_string(), "dev", &self.device_name])
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