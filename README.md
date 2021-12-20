# Wirespider

Wirespider consists of a server and a client. The server is responsible of pushing the wireguard configuration and routes to the clients and helping with NAT hole punching. The client listens for configuration changes, and modifies the wireguard configuration and routes accordingly.

## How to run the client
```
cargo build --release
sudo cp target/release/wirespider /usr/local/bin
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
sudo cp target/release/wirespider /usr/local/bin
# create a wirespider system user
sudo adduser --system --group --home /var/lib/wirespider wirespider 

sudo cp systemd/system/wirespider-server.service /etc/systemd/system
# enable auto start and start the server
sudo systemctl enable --now wirespider-server.service
```


### Contact

If you have questions, suggestions, encounter any problem,
please join our Matrix or IRC channel and ask!

```
#sfttech:matrix.org
irc.freenode.net #sfttech
```

Of course, create [issues](https://github.com/SFTtech/wirespider/issues)
and [pull requests](https://github.com/SFTtech/wirespider/pulls).