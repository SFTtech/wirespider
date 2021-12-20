mod protocol;
pub mod commands;

pub use commands::ServerCli;
use tracing::debug;
use tracing_error::ErrorLayer;
use tracing_subscriber::{Registry, prelude::*, filter::LevelFilter};



use std::env;

pub async fn server(cli: ServerCli) -> Result<(), Box<dyn std::error::Error>> {  
    let log_level = if cli.debug {LevelFilter::DEBUG} else {LevelFilter::INFO};
    // logging
    let subscriber = Registry::default()
        .with(log_level)
        .with(ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer());
    
  
    tracing::subscriber::set_global_default(subscriber)?;

    env::set_var("DATABASE_URL", &cli.database_url);
    debug!("Starting");
    cli.run().await
}