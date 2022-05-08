#!/bin/bash
export DATABASE_URL=sqlite:./data.db
export WS_ENDPOINT=http://172.17.0.1:49582
export RUST_BACKTRACE=full
export WS_LISTEN_PORT=22817
set -x



function start_server() {
    NETNS="${1}"
    ip netns exec "${NETNS}" wirespider start-server --debug --bind "${2}" &
}

function setup_server() {
    wirespider database migrate
    wirespider database create-network 10.1.2.0/24
    wirespider database create-network 10.1.3.0/24 vxlan
    wirespider database create-admin admin 10.1.2.1/24 | sed -e 's/Created admin with token: //' > ./admin-token
    truncate -s 36 ./admin-token
}

function create_user() {
    ip netns exec test1 wirespider send-command add-peer --token "$(<./admin-token)" --endpoint "http://172.17.0.1:49582" "$@" | sed -e 's/Peer created. Token: //' > "./token-${1}"
    truncate -s 36 "./token-${1}"
}

function run_client() {
    NETNS="${1}"
    export WS_DEVICE="$2"
    export WS_TOKEN=$(< "./token-${3}")
    export WS_PRIVATE_KEY="./privkey-${WS_DEVICE}"
    ip netns exec "${NETNS}" wirespider start-client -d --fixed-endpoint "1.2.3.4:$WS_LISTEN_PORT" --nat-type symmetric &
    export WS_LISTEN_PORT=$(expr $WS_LISTEN_PORT + 1)
}

function cleanup() {
    kill $(jobs -p)
    rm ./data.db*
    rm ./privkey-*
    rm ./admin-token
}

function setup_netns() {
    ip link add veth-one type veth peer name veth-two
    ip netns add test1
    ip netns add test2
    ip link set veth-one netns test1 up
    ip link set veth-two netns test2 up
    ip netns exec test1 ip link set lo up
    ip netns exec test1 ip address add 127.0.0.1/8 dev lo
    ip netns exec test2 ip link set lo up
    ip netns exec test1 ip address add 127.0.0.1/8 dev lo
    ip netns exec test1 ip address add 172.17.0.1/24 dev veth-one
    ip netns exec test2 ip address add 172.17.0.2/24 dev veth-two
}

function show_devices() {
    ip netns exec test1 ip l
    ip netns exec test1 ip a
    ip netns exec test2 ip l
    ip netns exec test2 ip a
    ip netns exec test1 wg show wg-test1
    ip netns exec test2 wg show wg-test2
}

#rm ./data.db*
#setup_server
setup_netns
start_server test1 172.17.0.1:49582
sleep 1
#create_user test1 10.1.2.2/24 10.1.3.2/24
#create_user test2 10.1.2.3/24 10.1.3.3/24

run_client test1 wg-test1 test1 172.17.0.1
sleep 5
show_devices
run_client test2 wg-test2 test2 172.17.0.2

sleep 5
show_devices


#sleep 10
#cleanup
#ip netns del test1
#ip netns del test2