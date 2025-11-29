use anyhow::Result;
use clap::Parser;
use dls_server::config::Settings;
use dls_server::network::{NetworkConfig, NetworkManager};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser)]
#[command(
    author = "DLS Server Team",
    version,
    about = "CLAUDE Diskless Boot System Server",
    long_about = "Enterprise-grade diskless boot system providing DHCP, TFTP, iSCSI, and management services for diskless computing infrastructure"
)]
struct Cli {
    /// Network address to bind the management server to
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// Logging level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Run in production mode (disables development warnings)
    #[arg(short, long)]
    production: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing/logging subsystem
    initialize_logging(&cli.log_level)?;

    info!(
        "Starting CLAUDE Diskless Boot System v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Build mode: {}", if cli.production { "PRODUCTION" } else { "DEVELOPMENT" });

    if !cli.production {
        warn!("⚠️  Running in DEVELOPMENT mode - not recommended for production use");
        warn!("   Use --production flag for production deployments");
    }

    // Load configuration
    let settings = load_configuration(&cli.config)?;
    info!("Configuration loaded from: {}", cli.config);
    info!("  - DHCP range: {} - {}", settings.network.dhcp_range_start, settings.network.dhcp_range_end);
    info!("  - TFTP root: {}", settings.network.tftp_root);
    info!("  - iSCSI target: {}", settings.network.iscsi_target_name);
    info!("  - Management bind: {}", cli.bind);

    // Create network configuration from settings
    let network_config = create_network_config(&settings)?;

    // Initialize network manager
    let network_manager = NetworkManager::new(network_config);
    let network_manager = Arc::new(RwLock::new(network_manager));

    // Start all services
    info!("🚀 Starting all DLS services...");
    {
        let mut manager = network_manager.write().await;
        if let Err(e) = manager.start_all_services().await {
            error!("Failed to start services: {}", e);
            return Err(e.into());
        }
    }

    info!("✓ All services started successfully");
    info!("System ready - serving diskless clients");
    info!("Management interface: http://{}", cli.bind);

    // Setup graceful shutdown handler
    let shutdown_manager = network_manager.clone();
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutdown signal received - initiating graceful shutdown...");
                let mut manager = shutdown_manager.write().await;
                if let Err(e) = manager.stop_all_services().await {
                    error!("Error during shutdown: {}", e);
                } else {
                    info!("All services stopped successfully");
                }
                std::process::exit(0);
            }
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
            }
        }
    });

    // Keep the main task alive
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        // Periodic health check logging
        let manager = network_manager.read().await;
        let mut active_services = Vec::new();

        if manager.get_dhcp_server().is_some() {
            active_services.push("DHCP");
        }
        if manager.get_tftp_server().is_some() {
            active_services.push("TFTP");
        }
        if manager.get_iscsi_target().is_some() {
            active_services.push("iSCSI");
        }
        if manager.get_web_server().is_some() {
            active_services.push("Web");
        }
        if manager.get_cluster_manager().is_some() {
            active_services.push("Cluster");
        }
        if manager.get_analytics_engine().is_some() {
            active_services.push("Analytics");
        }

        info!("Health check - Active services: {}", active_services.join(", "));
    }
}

/// Initialize the tracing/logging subsystem with structured logging
fn initialize_logging(log_level: &str) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_level(true)
                .with_ansi(true)
        )
        .init();

    Ok(())
}

/// Load configuration from file or use defaults
fn load_configuration(config_path: &str) -> Result<Settings> {
    if std::path::Path::new(config_path).exists() {
        info!("Loading configuration from file: {}", config_path);
        Settings::from_file(config_path)
            .map_err(|e| anyhow::anyhow!("Configuration error: {}", e))
    } else {
        warn!("Configuration file not found: {}", config_path);
        warn!("Using default configuration - suitable for development only");
        Ok(Settings::default())
    }
}

/// Create NetworkConfig from Settings
fn create_network_config(settings: &Settings) -> Result<NetworkConfig> {
    let dhcp_start: Ipv4Addr = settings.network.dhcp_range_start.parse()
        .map_err(|e| anyhow::anyhow!("Invalid DHCP start address: {}", e))?;

    let dhcp_end: Ipv4Addr = settings.network.dhcp_range_end.parse()
        .map_err(|e| anyhow::anyhow!("Invalid DHCP end address: {}", e))?;

    Ok(NetworkConfig {
        dhcp_range_start: dhcp_start,
        dhcp_range_end: dhcp_end,
        tftp_root: settings.network.tftp_root.clone(),
        iscsi_target_name: settings.network.iscsi_target_name.clone(),
    })
}
