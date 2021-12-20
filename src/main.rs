mod server;
mod client;
use clap::Parser;
use client::{client, ClientCli};
use server::{server, ServerCli};

#[macro_use]
extern crate lazy_static;

#[derive(Parser, Debug)]
#[clap(name = "spider")]
enum Cli {
    Client(ClientCli),
    Server(ServerCli)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli {
        Cli::Server(cli) => server(cli).await?,
        Cli::Client(cli) => client(cli).await?,
    }
    Ok(())
}
