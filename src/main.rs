mod server;
mod client;
mod cli;
use clap::{IntoApp, Parser};
use cli::{Cli, CompletionCommand};
use client::{client_start, client_manage};
use server::commands::{server_run, server_manage};
use clap_complete::generate;

#[macro_use]
extern crate lazy_static;

#[macro_use] extern crate trackable;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut cmd = Cli::command();
    match cli {
        Cli::ClientStart(cli) => client_start(cli).await?,
        Cli::ClientManage(cli) => client_manage(cli).await?,
        Cli::ServerStart(cli) => server_run(cli).await?,
        Cli::ServerManage(cli) => server_manage(cli).await?,
        Cli::Completion(CompletionCommand {shell}) => generate(shell, &mut cmd, "wirespider", &mut std::io::stdout())
    }
    Ok(())
}
