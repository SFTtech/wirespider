//! Shared harness for the wirespider integration tests.
//!
//! The tests start real wirespider nodes inside containers:
//! * one container runs the wirespider server (grpc + sqlite database)
//! * every node is a separate container running `wirespider start-client`,
//!   which manages its own kernel wireguard interface
//!
//! The containers are based on alpine, therefore the wirespider binary must be
//! a statically linked musl build. The harness looks for
//! `target/x86_64-unknown-linux-musl/{debug,release}/wirespider` (or the path
//! in `WS_TEST_BIN`) and builds it with cargo if it is missing.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use testcontainers::{
    core::ExecCommand,
    runners::{AsyncBuilder, AsyncRunner},
    ContainerAsync, GenericBuildableImage, GenericImage, ImageExt,
};
use tokio::sync::OnceCell;

/// gRPC port of the wirespider server.
pub const SERVER_PORT: u16 = 49582;
/// Wireguard network distributed to all peers.
pub const WG_NETWORK: &str = "10.99.0.0/24";
/// Tunnel address of the admin peer. The admin has no client, so its address
/// can safely be used as route target without any node routing to itself.
pub const ADMIN_IP: &str = "10.99.0.1";
/// Database location inside the server container.
const DB_URL: &str = "sqlite:/tmp/wirespider-test.db";
const IMAGE_NAME: &str = "wirespider-integration-test";
const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Cluster {
    image: GenericImage,
    pub server: ContainerAsync<GenericImage>,
    pub admin_token: String,
    server_ip: Ipv4Addr,
    /// The dedicated network is dropped after the server container so that
    /// the containers are removed before the network is deleted.
    network: ClusterNetwork,
}

/// A dedicated docker network for one test cluster.
///
/// The docker default bridge does not reliably expose container ips through
/// the docker api (podman), so every cluster gets its own user defined
/// network.
struct ClusterNetwork {
    name: String,
    docker: bollard::Docker,
}

impl ClusterNetwork {
    async fn create() -> Result<ClusterNetwork> {
        let docker = bollard::Docker::connect_with_defaults()
            .context("could not connect to the docker/podman daemon")?;
        let name = format!("wirespider-it-{}", uuid::Uuid::new_v4());
        docker
            .create_network(bollard::models::NetworkCreateRequest {
                name: name.clone(),
                driver: Some("bridge".to_string()),
                ..Default::default()
            })
            .await
            .with_context(|| format!("could not create the test network {name}"))?;
        Ok(ClusterNetwork { name, docker })
    }
}

impl Drop for ClusterNetwork {
    fn drop(&mut self) {
        // remove the network synchronously, the containers are removed first
        // by their own drop impls
        let docker = self.docker.clone();
        let name = self.name.clone();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("could not build a runtime for the network cleanup");
            if let Err(error) = runtime.block_on(docker.remove_network(&name)) {
                eprintln!("could not remove the test network {name}: {error}");
            }
        });
        let _ = worker.join();
    }
}

pub struct Node {
    pub name: String,
    pub tunnel_ip: Ipv4Addr,
    pub container: ContainerAsync<GenericImage>,
}

/// Locate (and if necessary build) a statically linked wirespider binary.
async fn wirespider_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("WS_TEST_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        bail!(
            "WS_TEST_BIN points to {}, but the file does not exist",
            path.display()
        );
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let existing = [
        manifest_dir.join(format!("target/{MUSL_TARGET}/debug/wirespider")),
        manifest_dir.join(format!("target/{MUSL_TARGET}/release/wirespider")),
    ]
    .into_iter()
    .find(|path| path.exists());
    if let Some(existing) = existing {
        return Ok(existing);
    }

    println!("no static wirespider binary found, building with cargo (this can take a while)");
    let build = tokio::task::spawn_blocking({
        let manifest_dir = manifest_dir.clone();
        move || {
            std::process::Command::new("cargo")
                .args(["build", "--target", MUSL_TARGET, "--bin", "wirespider"])
                .current_dir(&manifest_dir)
                .status()
                .context("could not run cargo")
        }
    })
    .await??;
    if !build.success() {
        bail!(
            "cargo could not build the statically linked wirespider binary. Install the musl \
             rust target (`rustup target add {MUSL_TARGET}`) and a musl C compiler \
             (e.g. `apt install musl-tools`, on nixpkgs \
             `nix-shell -p pkgsCross.musl64.stdenv.cc` with CC_{MUSL_TARGET} set to the musl gcc), \
             or point WS_TEST_BIN to a statically linked wirespider binary."
        );
    }
    let binary = manifest_dir.join(format!("target/{MUSL_TARGET}/debug/wirespider"));
    if !binary.exists() {
        bail!("cargo did not produce a binary at {}", binary.display());
    }
    Ok(binary)
}

/// Build the node image (once per test process).
///
/// It contains the statically linked wirespider binary, iproute2 (used by the
/// client for the vxlan overlay), wireguard-tools (`wg`, used by the tests to
/// inspect the interface) and iputils (`ping`).
async fn node_image() -> Result<GenericImage> {
    static NODE_IMAGE: OnceCell<GenericImage> = OnceCell::const_new();
    let image = NODE_IMAGE.get_or_try_init(build_node_image).await?;
    Ok(image.clone())
}

async fn build_node_image() -> Result<GenericImage> {
    let binary = wirespider_binary().await?;
    // fingerprint the binary so the image tag changes with it and the docker
    // build cache is used efficiently
    let fingerprint = tokio::task::spawn_blocking({
        let binary = binary.clone();
        move || -> Result<String> {
            use std::hash::{Hash, Hasher};
            let bytes = std::fs::read(&binary).context("could not read the wirespider binary")?;
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            bytes.len().hash(&mut hasher);
            hasher.write(&bytes);
            Ok(format!("{:016x}", hasher.finish()))
        }
    })
    .await??;

    let image = GenericBuildableImage::new(IMAGE_NAME, format!("it-{fingerprint}"))
        .with_dockerfile_string(
            r#"FROM docker.io/library/alpine:3.22
RUN apk add --no-cache iproute2 wireguard-tools iputils
COPY wirespider /usr/bin/wirespider
RUN chmod +x /usr/bin/wirespider && wirespider --help > /dev/null && wirespider generate-completion bash > /dev/null
"#
            .to_string(),
        )
        .with_file(&binary, "wirespider")
        .build_image()
        .await
        .context("could not build the wirespider test image")?;
    preflight_check(&image).await?;
    Ok(image)
}

/// Verify that the built image can actually run wirespider and create
/// wireguard interfaces, so tests fail with a helpful message instead of a
/// cryptic error deep inside a test.
async fn preflight_check(image: &GenericImage) -> Result<()> {
    let container = image
        .clone()
        .with_cmd(["tail", "-f", "/dev/null"])
        .with_cap_add("NET_ADMIN")
        .start()
        .await
        .context("could not start a container, is the docker/podman daemon reachable?")?;
    let result = async {
        exec_ok(&container, &["wirespider", "--help"], &[])
            .await
            .context("the wirespider binary does not run inside the container (is it statically linked?)")?;
        exec_ok(
            &container,
            &["sh", "-c", "ip link add ws-preflight type wireguard && ip link del ws-preflight"],
            &[],
        )
        .await
        .context("the host kernel does not support wireguard inside containers (is the wireguard kernel module available?)")?;
        Ok(())
    }
    .await;
    container.rm().await.ok();
    result
}

/// Read the ipv4 address of a container from the docker api.
///
/// `ContainerAsync::get_bridge_ip_address` requires that the container
/// `NetworkMode` matches the network name, which is not the case for podman,
/// so the ip is looked up directly from the container inspect response.
async fn container_ipv4(
    docker: &bollard::Docker,
    container: &ContainerAsync<GenericImage>,
) -> Result<Ipv4Addr> {
    let inspect = docker
        .inspect_container(container.id(), None)
        .await
        .context("could not inspect the container")?;
    let networks = inspect
        .network_settings
        .and_then(|settings| settings.networks)
        .context("the container has no network settings")?;
    let ip = networks
        .values()
        .find_map(|endpoint| endpoint.ip_address.clone())
        .context("the container has no ipv4 address")?;
    ip.parse()
        .context("the container has an invalid ipv4 address")
}

/// Execute a command inside a container, returns (stdout, stderr, exit code).
pub async fn exec(
    container: &ContainerAsync<GenericImage>,
    cmd: &[&str],
    env: &[(&str, &str)],
) -> Result<(String, String, Option<i64>)> {
    let command = ExecCommand::new(cmd.iter().copied()).with_env_vars(env.iter().copied());
    let mut result = tokio::time::timeout(EXEC_TIMEOUT, container.exec(command))
        .await
        .map_err(|_| anyhow!("executing {cmd:?} timed out"))?
        .with_context(|| format!("could not execute {cmd:?}"))?;
    let stdout = String::from_utf8_lossy(&result.stdout_to_vec().await?).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr_to_vec().await?).into_owned();
    let exit_code = result.exit_code().await?;
    Ok((stdout, stderr, exit_code))
}

/// Execute a command and return its stdout, failing if it does not exit with 0.
pub async fn exec_ok(
    container: &ContainerAsync<GenericImage>,
    cmd: &[&str],
    env: &[(&str, &str)],
) -> Result<String> {
    let (stdout, stderr, exit_code) = exec(container, cmd, env).await?;
    if exit_code != Some(0) {
        bail!(
            "command {cmd:?} failed with exit code {exit_code:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    Ok(stdout)
}

/// Execute a command repeatedly until it exits with 0 or the timeout elapses.
async fn exec_until_ok(
    container: &ContainerAsync<GenericImage>,
    cmd: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (stdout, stderr, exit_code) = exec(container, cmd, env).await?;
        if exit_code == Some(0) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "condition for {cmd:?} was not reached within {timeout:?}\n\
                 last exit code: {exit_code:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }
        tokio::time::sleep(interval).await;
    }
}

impl Cluster {
    /// Start a server container with an initialized database, start the
    /// server process and return the cluster with the admin token.
    pub async fn start() -> Result<Cluster> {
        let image = node_image().await?;
        let network = ClusterNetwork::create().await?;
        let server = image
            .clone()
            .with_cmd(["tail", "-f", "/dev/null"])
            .with_network(&network.name)
            .start()
            .await
            .context("could not start the wirespider server container")?;
        let server_ip = container_ipv4(&network.docker, &server).await?;

        // initialize the database. The database commands read the connection
        // url from the environment (see `server_manage`).
        let env = [("DATABASE_URL", DB_URL)];
        exec_ok(
            &server,
            &["wirespider", "database", "migrate", "-d", DB_URL],
            &env,
        )
        .await
        .context("could not migrate the wirespider database")?;
        exec_ok(
            &server,
            &[
                "wirespider",
                "database",
                "create-network",
                "-d",
                DB_URL,
                WG_NETWORK,
            ],
            &env,
        )
        .await
        .context("could not create the wireguard network")?;
        let output = exec_ok(
            &server,
            &[
                "wirespider",
                "database",
                "create-admin",
                "-d",
                DB_URL,
                "admin",
                // the prefix must match the network created above, the server
                // looks the network up by the truncated address
                &format!("{ADMIN_IP}/24"),
            ],
            &env,
        )
        .await
        .context("could not create the admin peer")?;
        let admin_token = output
            .rsplit("token: ")
            .next()
            .map(str::trim)
            .with_context(|| format!("could not parse the admin token from {output:?}"))?
            .to_string();

        // start the server process and wait for the grpc port
        exec_ok(
            &server,
            &[
                "sh",
                "-c",
                &format!(
                    "wirespider start-server --debug -d {DB_URL} --bind 0.0.0.0:{SERVER_PORT} \
                 >/var/log/server.log 2>&1 </dev/null &"
                ),
            ],
            &[],
        )
        .await?;
        exec_until_ok(
            &server,
            &["nc", "-z", "127.0.0.1", &SERVER_PORT.to_string()],
            &[],
            Duration::from_secs(60),
            Duration::from_millis(250),
        )
        .await
        .context("the wirespider server did not come up in time")?;

        Ok(Cluster {
            image,
            server,
            admin_token,
            server_ip,
            network,
        })
    }

    /// Create a peer on the server and start a client container for it.
    pub async fn add_node(&self, index: usize) -> Result<Node> {
        let name = format!("node-{index}");
        let tunnel_ip: Ipv4Addr = format!("10.99.0.{}", 11 + index).parse().unwrap();
        let wg_port = 51821 + index as u16;
        let token = self.add_peer(&name, &format!("{tunnel_ip}/24")).await?;

        let container = self
            .image
            .clone()
            .with_cmd(["tail", "-f", "/dev/null"])
            .with_cap_add("NET_ADMIN")
            .with_cap_add("NET_RAW")
            .with_network(&self.network.name)
            .start()
            .await
            .with_context(|| format!("could not start a container for {name}"))?;
        let container_ip = container_ipv4(&self.network.docker, &container).await?;
        // the client reports its own container address as fixed endpoint and
        // therefore skips stun detection completely
        let fixed_endpoint = SocketAddr::from((container_ip, wg_port));
        let server_ip = self.server_ip;
        exec_ok(
            &container,
            &[
                "sh",
                "-c",
                &format!(
                    "wirespider start-client --debug \
                     --endpoint http://{server_ip}:{SERVER_PORT} \
                     --token {token} \
                     --device wg0 \
                     --port {wg_port} \
                     --fixed-endpoint {fixed_endpoint} \
                     --private-key /tmp/{name}-privkey \
                     >/var/log/{name}.log 2>&1 </dev/null &"
                ),
            ],
            &[],
        )
        .await
        .with_context(|| format!("could not start the wirespider client for {name}"))?;

        Ok(Node {
            name,
            tunnel_ip,
            container,
        })
    }

    /// Delete a peer on the server via the admin token.
    pub async fn delete_peer(&self, name: &str) -> Result<()> {
        exec_ok(
            &self.server,
            &[
                "wirespider",
                "send-command",
                "delete-peer",
                "--endpoint",
                &format!("http://127.0.0.1:{SERVER_PORT}"),
                "--token",
                &self.admin_token,
                "--name-id",
                name,
            ],
            &[],
        )
        .await
        .with_context(|| format!("could not delete peer {name} on the server"))?;
        Ok(())
    }

    async fn add_peer(&self, name: &str, address: &str) -> Result<String> {
        let output = exec_ok(
            &self.server,
            &[
                "wirespider",
                "send-command",
                "add-peer",
                "--endpoint",
                &format!("http://127.0.0.1:{SERVER_PORT}"),
                "--token",
                &self.admin_token,
                name,
                address,
            ],
            &[],
        )
        .await
        .with_context(|| format!("could not create peer {name} on the server"))?;
        let token = output
            .split("Token:")
            .nth(1)
            .map(str::trim)
            .with_context(|| format!("could not parse the peer token from {output:?}"))?;
        Ok(token.to_string())
    }

    /// Print the server log, used to enrich test failures.
    pub async fn dump_server_log(&self) {
        eprintln!("===== server log =====");
        if let Ok((log, _, _)) = exec(&self.server, &["cat", "/var/log/server.log"], &[]).await {
            eprintln!("{log}");
        }
    }
}

impl Node {
    /// Number of peers currently configured on the wireguard interface.
    pub async fn wg_peer_count(&self) -> Result<usize> {
        let peers = exec_ok(
            &self.container,
            &["sh", "-c", "wg show wg0 peers | wc -l"],
            &[],
        )
        .await?;
        peers
            .trim()
            .parse()
            .context("unexpected `wg show wg0 peers` output")
    }

    /// Output of `ip -4 addr show dev wg0`.
    pub async fn interface_addresses(&self) -> Result<String> {
        exec_ok(
            &self.container,
            &["ip", "-4", "addr", "show", "dev", "wg0"],
            &[],
        )
        .await
    }

    /// Output of `ip route show`.
    pub async fn routes(&self) -> Result<String> {
        exec_ok(&self.container, &["ip", "route", "show"], &[]).await
    }

    /// Print the node log, used to enrich test failures.
    pub async fn dump_log(&self) {
        eprintln!("===== {} log =====", self.name);
        if let Ok((log, _, _)) = exec(
            &self.container,
            &["cat", &format!("/var/log/{}.log", self.name)],
            &[],
        )
        .await
        {
            eprintln!("{log}");
        }
    }
}
