mod cli;
mod client;
mod server;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use cli::{Cli, CompletionCommand};
use client::{client_manage, client_start};
use server::commands::{server_manage, server_run};
use wirespider::protocol::NatType;

#[macro_use]
extern crate lazy_static;

impl From<cli::NatType> for NatType {
    fn from(other: cli::NatType) -> NatType {
        match other {
            cli::NatType::NoNat => NatType::NoNat,
            cli::NatType::FullCone => NatType::FullCone,
            cli::NatType::RestrictedCone => NatType::RestrictedCone,
            cli::NatType::PortRestrictedCone => NatType::PortRestrictedCone,
            cli::NatType::Symmetric => NatType::Symmetric,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut cmd = Cli::command();
    match cli {
        Cli::ClientStart(cli) => client_start(cli).await?,
        Cli::ClientManage(cli) => client_manage(cli).await?,
        Cli::ServerStart(cli) => server_run(cli).await?,
        Cli::ServerManage(cli) => server_manage(cli).await?,
        Cli::Completion(CompletionCommand { shell }) => {
            generate(shell, &mut cmd, "wirespider", &mut std::io::stdout())
        }
    }
    Ok(())
}
