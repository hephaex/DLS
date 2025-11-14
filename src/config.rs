use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub auth: AuthConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub workers: Option<usize>,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageConfig {
    pub zfs_pool: String,
    pub image_path: String,
    pub backup_path: String,
    pub max_image_size_gb: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub dhcp_range_start: String,
    pub dhcp_range_end: String,
    pub tftp_root: String,
    pub iscsi_target_name: String,
    pub pxe_boot_file: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry_hours: u64,
    pub admin_password_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitoringConfig {
    pub prometheus_bind: String,
    pub prometheus_port: u16,
    pub log_file: Option<String>,
    pub metrics_interval_seconds: u64,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name(&format!("config/{run_mode}")).required(false))
            .add_source(File::with_name("config/local").required(false))
            .add_source(Environment::with_prefix("DLS"))
            .build()?;

        s.try_deserialize()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::from(path.as_ref()))
            .add_source(Environment::with_prefix("DLS"))
            .build()?;

        s.try_deserialize()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            server: ServerConfig {
                bind_address: "0.0.0.0".to_string(),
                port: 8080,
                workers: None,
                log_level: "info".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://localhost/dls_server".to_string(),
                max_connections: 10,
                min_connections: 1,
                connect_timeout: 30,
            },
            storage: StorageConfig {
                zfs_pool: "tank".to_string(),
                image_path: "/tank/images".to_string(),
                backup_path: "/tank/backups".to_string(),
                max_image_size_gb: 100,
            },
            network: NetworkConfig {
                dhcp_range_start: "192.168.1.100".to_string(),
                dhcp_range_end: "192.168.1.200".to_string(),
                tftp_root: "/var/lib/tftpboot".to_string(),
                iscsi_target_name: "iqn.2024-01.com.example:dls".to_string(),
                pxe_boot_file: "pxelinux.0".to_string(),
            },
            auth: AuthConfig {
                jwt_secret: "change-me-in-production".to_string(),
                token_expiry_hours: 24,
                admin_password_hash: "$argon2id$v=19$m=65536,t=3,p=4$...".to_string(),
            },
            monitoring: MonitoringConfig {
                prometheus_bind: "127.0.0.1".to_string(),
                prometheus_port: 9090,
                log_file: None,
                metrics_interval_seconds: 30,
            },
        }
    }
}
