mod key;
mod server;
mod utils;

use std::error::Error;

use clap::{Parser, Subcommand};
use key::KeyCommand;
use server::args::ServerArgs;
use tracing::Level;

/// CLI tool for discv5 node and secp256k1 key management
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Set the log level
    #[arg(short, long, default_value = "info", global = true)]
    log_level: Level,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the discv5 server
    Server(ServerArgs),

    /// Manage secp256k1 keys
    Key(KeyCommand),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    utils::logger::init_tracing(cli.log_level);

    match cli.command {
        Commands::Server(server_cmd) => server::run(server_cmd).await?,
        Commands::Key(key_cmd) => key::run(key_cmd)?,
    }
    Ok(())
}
