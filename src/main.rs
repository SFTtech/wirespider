mod cli;
mod client;
mod server;
mod transport;
use base64::prelude::{BASE64_STANDARD, Engine};
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use cli::{Cli, CompletionCommand};
use client::{client_manage, client_start};
use server::commands::{server_manage, server_run};
use wirespider::protocol::peer_identifier::Identifier;
use wirespider::protocol::{NatType, PeerIdentifier};

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

impl TryFrom<cli::CliPeerIdentifier> for PeerIdentifier {
    type Error = base64::DecodeError;

    fn try_from(other: cli::CliPeerIdentifier) -> Result<PeerIdentifier, Self::Error> {
        let identifier = if let Some(name) = other.name_id {
            Identifier::Name(name)
        } else if let Some(token) = other.token_id {
            Identifier::Token(token.as_bytes().to_vec())
        } else if let Some(public_key) = other.public_key_id {
            Identifier::PublicKey(BASE64_STANDARD.decode(public_key)?)
        } else {
            unreachable!("clap requires exactly one identifier")
        };
        Ok(PeerIdentifier {
            identifier: Some(identifier),
        })
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
