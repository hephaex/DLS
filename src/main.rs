use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting DLS Server on {}", cli.bind);
    warn!("This is a development build - not for production use");

    Ok(())
}