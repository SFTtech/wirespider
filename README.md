# Wirespider

Wirespider consists of a server and a client. The server is responsible of pushing the wireguard configuration and routes to the clients and helping with NAT hole punching. The client listens for configuration changes, and modifies the wireguard configuration and routes accordingly.

## Features
* Distribute Wireguard tunnel configuration
* Distribute routes to all clients
* Create VXLAN overlay network for layer 2 networking
* RFC 5780 NAT detection
* NAT hole punching or relay over other nodes when not possible
* detect other nodes in the same network

## Installation

An APT repository for wirespider is avaiable, to add it run the following commands:
```
sudo curl https://sfttech.github.io/wirespider/public.key -o /etc/apt/trusted.gpg.d/wirespider.key
echo "deb https://sfttech.github.io/wirespider/repo/ stable main" | sudo tee /etc/apt/sources.list.d/wirespider.list
```

There is an official wirespider AUR package as well (wirespider), and an ebuild for gentoo in the sft overlay.

Otherwise the deb and rpm can be downloaded from the releases page.


### Manual installation
```
cargo build --release
sudo cp target/release/wirespider /usr/bin
sudo mkdir -p /etc/wirespider/keys
sudo cp systemd/system/wirespider-client@.service /etc/systemd/system
# rename file to any other device name here
sudo cp systemd/wirespider/wg0 /etc/wirespider/wg0-example
# create a wirespider system user for the server
sudo adduser --system --group --home /var/lib/wirespider wirespider
```

## Running wirespider

To run the client:
```
sudo cp /etc/wirespider/wg0-example /etc/wirespider/wg0
# edit the file to fit your setup (use correct device name)
sudo nano /etc/wirespider/wg0
# enable auto start and start the tunnel
# use the same device name
sudo systemctl enable --now wirespider-client@wg0.service
```

## How to run the server
```
# create database
wirespider database migrate -d sqlite:/var/lib/wirespider/config.sqlite
# create a ip network for the clients
wirespider database create-network -d sqlite:/var/lib/wirespider/config.sqlite 10.1.2.0/24
# add admin with ip in this new network
# the command will return a token you can use with wirespider start-client and wirespider send-command
wirespider database create-admin -d sqlite:/var/lib/wirespider/config.sqlite admin 10.1.2.1/24


# enable auto start and start the server
sudo systemctl enable --now wirespider-server.service
```

The admin can now use the `wirespider send-command` commands to create other peers and routes

### Contact

If you have questions, suggestions, encounter any problem,
please join our Matrix channel and ask!

```
#sfttech:matrix.org
```

Of course, create [issues](https://github.com/SFTtech/wirespider/issues)
and [pull requests](https://github.com/SFTtech/wirespider/pulls).