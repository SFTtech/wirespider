//! Integration tests for wirespider.
//!
//! They start a real wirespider server and several client nodes in containers
//! and verify that the distributed wireguard configuration is correct and the
//! tunnels pass traffic. See `common` for details about the environment.

mod common;

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};

use common::{exec, exec_ok, Cluster, Node, ADMIN_IP, SERVER_PORT};

/// How long to wait for wireguard handshakes and event distribution.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(90);

/// Integration tests need a container runtime and a statically linked
/// wirespider binary, other test runners can set `WS_TEST_SKIP` to skip them.
fn skip_requested() -> bool {
    if std::env::var_os("WS_TEST_SKIP").is_some() {
        eprintln!("skipping: WS_TEST_SKIP is set");
        true
    } else {
        false
    }
}

/// Dump the server and all node logs, used to enrich test failures.
async fn dump_logs(cluster: &Cluster, nodes: &[Node]) {
    cluster.dump_server_log().await;
    for node in nodes {
        node.dump_log().await;
    }
}

/// Wait until a node has the expected number of wireguard peers configured.
async fn wait_for_peer_count(node: &Node, expected: usize) -> Result<()> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut last_count = 0;
    while last_count != expected {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{} has {} wireguard peers, expected {expected} within {HANDSHAKE_TIMEOUT:?}",
                node.name,
                last_count
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        last_count = node
            .wg_peer_count()
            .await
            .with_context(|| format!("could not read the wireguard peer count of {}", node.name))?;
    }
    Ok(())
}

/// Wait until the nodes `a` and `b` can ping each other over the tunnel.
///
/// Both directions are polled together because the endpoint of a wireguard
/// peer is only corrected once the other side sends traffic, so a single
/// direction can stay broken even though the tunnel works.
async fn wait_pair_pingable(a: &Node, b: &Node) -> Result<()> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let ab = exec(
            &a.container,
            &[
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                "-I",
                "wg0",
                &b.tunnel_ip.to_string(),
            ],
            &[],
        )
        .await?;
        let ba = exec(
            &b.container,
            &[
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                "-I",
                "wg0",
                &a.tunnel_ip.to_string(),
            ],
            &[],
        )
        .await?;
        if ab.2 == Some(0) && ba.2 == Some(0) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{} and {} cannot reach each other within {HANDSHAKE_TIMEOUT:?}\n\
                 {} -> {}: {ab:?}\n{} -> {}: {ba:?}",
                a.name,
                b.name,
                a.name,
                b.name,
                b.name,
                a.name
            );
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}

/// Run the test body and dump all logs on failure.
async fn with_logs_on_error(
    cluster: &Cluster,
    nodes: &[Node],
    body: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    match body.await {
        Ok(()) => Ok(()),
        Err(error) => {
            dump_logs(cluster, nodes).await;
            eprintln!("test error: {error:?}");
            Err(error)
        }
    }
}

#[tokio::test]
async fn nodes_form_a_fully_connected_mesh() -> Result<()> {
    if skip_requested() {
        return Ok(());
    }
    let cluster = Cluster::start().await?;
    let nodes: Vec<Node> = vec![
        cluster.add_node(0).await?,
        cluster.add_node(1).await?,
        cluster.add_node(2).await?,
    ];

    with_logs_on_error(&cluster, &nodes, async {
        // every node must have its tunnel address assigned to wg0
        for node in &nodes {
            let addresses = node.interface_addresses().await?;
            let expected = format!("inet {}/24", node.tunnel_ip);
            ensure!(
                addresses.contains(&expected),
                "wg0 of {} does not contain {expected}, got:\n{addresses}",
                node.name
            );
        }

        // every node must be configured with all other nodes as peers
        for node in &nodes {
            wait_for_peer_count(node, nodes.len() - 1).await?;
        }

        // the tunnels must pass traffic between all nodes
        for (i, a) in nodes.iter().enumerate() {
            for b in nodes.iter().skip(i + 1) {
                wait_pair_pingable(a, b).await?;
            }
        }

        // deleting a peer must remove it from the configuration of the other
        // nodes and make it unreachable
        cluster.delete_peer("node-1").await?;
        for node in [&nodes[0], &nodes[2]] {
            wait_for_peer_count(node, nodes.len() - 2).await?;
        }
        let ping = exec(
            &nodes[0].container,
            &[
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                "-I",
                "wg0",
                &nodes[1].tunnel_ip.to_string(),
            ],
            &[],
        )
        .await?;
        ensure!(
            ping.2 != Some(0),
            "{} can still reach the deleted {}",
            nodes[0].name,
            nodes[1].name
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn routes_are_programmed_on_all_clients() -> Result<()> {
    if skip_requested() {
        return Ok(());
    }
    let cluster = Cluster::start().await?;
    let nodes: Vec<Node> = vec![cluster.add_node(0).await?, cluster.add_node(1).await?];

    with_logs_on_error(&cluster, &nodes, async {
        // route to a network behind the admin peer. The admin has no client,
        // therefore no node will try to program a route to its own address.
        exec_ok(
            &cluster.server,
            &[
                "wirespider",
                "send-command",
                "add-route",
                "--endpoint",
                &format!("http://127.0.0.1:{SERVER_PORT}"),
                "--token",
                &cluster.admin_token,
                "10.88.0.0/24",
                ADMIN_IP,
            ],
            &[],
        )
        .await
        .context("could not add the route on the server")?;

        for node in &nodes {
            wait_for_route(node).await?;
        }
        Ok(())
    })
    .await
}

/// Wait until a node programmed the route distributed by the server.
async fn wait_for_route(node: &Node) -> Result<()> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let routes = node.routes().await?;
        if routes.contains("10.88.0.0/24 via 10.99.0.1") {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{} did not program the route within {HANDSHAKE_TIMEOUT:?}, routes:\n{routes}",
                node.name
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

