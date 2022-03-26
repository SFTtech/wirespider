mod server;
mod client;
use clap::Parser;
use client::{ManageCommand as ClientManageCommand, StartCommand, client_manage, client_start};
use server::commands::{ManageCommand as ServerManageCommand, RunCommand as ServerRunCommand, server_manage, server_run};

#[macro_use]
extern crate lazy_static;

#[macro_use] extern crate trackable;

#[derive(Parser, Debug)]
#[clap(name = "spider")]
enum Cli {
    #[clap(name = "client-start")]
    ClientStart(StartCommand),
    #[clap(subcommand,name = "send-command")]
    ClientManage(ClientManageCommand),
    ServerStart(ServerRunCommand),
    #[clap(subcommand,name = "manage-server")]
    ServerManage(ServerManageCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::ClientStart(cli) => client_start(cli).await?,
        Cli::ClientManage(cli) => client_manage(cli).await?,
        Cli::ServerStart(cli) => server_run(cli).await?,
        Cli::ServerManage(cli) => server_manage(cli).await?,
    }
    Ok(())
}
