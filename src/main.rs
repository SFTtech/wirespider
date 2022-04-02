mod server;
mod client;
use clap::{Parser, Args, IntoApp};
use clap_complete::{Shell,generate};
use client::{ManageCommand as ClientManageCommand, StartCommand, client_manage, client_start};
use server::commands::{DatabaseCommand as ServerDatabaseCommand, RunCommand as ServerRunCommand, server_manage, server_run};

#[macro_use]
extern crate lazy_static;

#[macro_use] extern crate trackable;

#[derive(Parser, Debug)]
#[clap(name = "spider")]
enum Cli {
    #[clap(name = "start-client", about = "Start the Wirespider client")]
    ClientStart(StartCommand),
    #[clap(subcommand,name = "send-command", about = "Send commands to the server")]
    ClientManage(ClientManageCommand),
    #[clap(name = "start-server", about = "Start the Wirespider server")]
    ServerStart(ServerRunCommand),
    #[clap(subcommand,name = "database", about = "Manage the server database")]
    ServerManage(ServerDatabaseCommand),
    #[clap(name = "generate-completion", about = "Generate completion scripts for various shells")]
    Completion(CompletionCommand),
}


#[derive(Args, Debug)]
struct CompletionCommand {
    #[clap(help = "Shell type", possible_values = ["bash","elvish","fish","powershell","zsh"] )]
    shell: Shell,
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
        Cli::Completion(CompletionCommand {shell}) => generate(shell, &mut cmd, "wirespider", &mut std::io::stdout())
    }
    Ok(())
}
