# Wirespider

Wirespider consists of a server and a client. The server is responsible of pushing the wireguard configuration and routes to the clients and helping with NAT hole punching. The client listens for configuration changes, and modifies the wireguard configuration and routes accordingly.

## Features
* Distribute Wireguard tunnel configuration
* Distribute routes to all clients
* RFC 5780 NAT detection
* NAT hole punching or relay over other nodes when not possible


## How to run the client
```
cargo build --release
sudo cp target/release/wirespider /usr/bin
sudo mkdir -p /etc/wirespider/keys
sudo cp systemd/system/wirespider-client@.service /etc/systemd/system
# rename file to any other device name here
sudo cp systemd/wirespider/wg0 /etc/wirespider/wg0
# edit the file to fit your setup (use correct device name)
sudo nano /etc/wirespider/wg0
# enable auto start and start the tunnel
# use the same device name
sudo systemctl enable --now wirespider-client@wg0.service
```

## How to run the server
```
# same binary as the client
cargo build --release
sudo cp target/release/wirespider /usr/bin
# create a wirespider system user
sudo adduser --system --group --home /var/lib/wirespider wirespider

# create database
wirespider server -d sqlite:/var/lib/wirespider/config.sqlite manage migrate
# create a ip network for the clients
wirespider server -d sqlite:/var/lib/wirespider/config.sqlite manage network create 10.1.2.0/24
# add admin with ip in this new network
# the command will return a token you can use with wirespider client
wirespider server -d sqlite:/var/lib/wirespider/config.sqlite manage create-admin admin 10.1.2.1/24


sudo cp systemd/system/wirespider-server.service /etc/systemd/system
# enable auto start and start the server
sudo systemctl enable --now wirespider-server.service
```

The admin can now use the `wirespider client manage` commands to create other peers and routes

### Contact

If you have questions, suggestions, encounter any problem,
please join our Matrix channel and ask!

```
#sfttech:matrix.org
```

Of course, create [issues](https://github.com/SFTtech/wirespider/issues)
and [pull requests](https://github.com/SFTtech/wirespider/pulls).