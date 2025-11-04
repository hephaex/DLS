use crate::error::{DlsError, Result};
use prometheus::{Counter, Gauge, Histogram, Registry, TextEncoder};
use std::collections::HashMap;
use std::sync::Arc;
// Note: Duration import removed as it's currently unused
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug)]
pub struct Metrics {
    // Network service metrics
    pub dhcp_requests: Counter,
    pub tftp_requests: Counter,
    pub iscsi_connections: Counter,
    pub dhcp_errors: Counter,
    pub tftp_errors: Counter,
    pub iscsi_errors: Counter,

    // Client and session metrics
    pub active_clients: Gauge,
    pub boot_sessions_total: Counter,
    pub boot_failures: Counter,
    pub boot_time_histogram: Histogram,

    // Storage and image metrics
    pub disk_images_total: Gauge,
    pub storage_used_bytes: Gauge,
    pub storage_available_bytes: Gauge,
    pub zfs_snapshots_total: Gauge,
    pub image_operations: Counter,

    // Authentication metrics
    pub auth_requests: Counter,
    pub auth_failures: Counter,
    pub active_sessions: Gauge,
    pub token_refreshes: Counter,

    // System performance metrics
    pub cpu_usage_percent: Gauge,
    pub memory_usage_bytes: Gauge,
    pub memory_available_bytes: Gauge,
    pub network_throughput_bytes: Gauge,
    pub disk_io_bytes: Counter,

    // Database metrics
    pub database_connections: Gauge,
    pub database_queries: Counter,
    pub database_errors: Counter,
    pub database_query_duration: Histogram,

    // Health and uptime metrics
    pub uptime_seconds: Gauge,
    pub health_checks: Counter,
    pub service_restarts: Counter,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let dhcp_requests = Counter::new("dhcp_requests_total", "Total DHCP requests received")
            .map_err(|e| DlsError::Internal(format!("Failed to create DHCP counter: {}", e)))?;

        let tftp_requests = Counter::new("tftp_requests_total", "Total TFTP requests received")
            .map_err(|e| DlsError::Internal(format!("Failed to create TFTP counter: {}", e)))?;

        let iscsi_connections = Counter::new("iscsi_connections_total", "Total iSCSI connections")
            .map_err(|e| DlsError::Internal(format!("Failed to create iSCSI counter: {}", e)))?;

        let active_clients = Gauge::new("active_clients", "Number of active diskless clients")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create active clients gauge: {}", e))
            })?;

        let disk_images_total = Gauge::new("disk_images_total", "Total number of disk images")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create disk images gauge: {}", e))
            })?;

        let storage_used_bytes = Gauge::new("storage_used_bytes", "Storage space used in bytes")
            .map_err(|e| DlsError::Internal(format!("Failed to create storage gauge: {}", e)))?;

        let boot_time_histogram = Histogram::with_opts(
            prometheus::HistogramOpts::new("boot_time_seconds", "Client boot time in seconds")
                .buckets(vec![10.0, 30.0, 60.0, 90.0, 120.0, 180.0, 300.0]),
        )
        .map_err(|e| DlsError::Internal(format!("Failed to create boot time histogram: {}", e)))?;

        let dhcp_errors = Counter::new("dhcp_errors_total", "Total DHCP errors").map_err(|e| {
            DlsError::Internal(format!("Failed to create DHCP errors counter: {}", e))
        })?;

        let tftp_errors = Counter::new("tftp_errors_total", "Total TFTP errors").map_err(|e| {
            DlsError::Internal(format!("Failed to create TFTP errors counter: {}", e))
        })?;

        let iscsi_errors =
            Counter::new("iscsi_errors_total", "Total iSCSI errors").map_err(|e| {
                DlsError::Internal(format!("Failed to create iSCSI errors counter: {}", e))
            })?;

        let boot_sessions_total =
            Counter::new("boot_sessions_total", "Total boot sessions initiated").map_err(|e| {
                DlsError::Internal(format!("Failed to create boot sessions counter: {}", e))
            })?;

        let boot_failures =
            Counter::new("boot_failures_total", "Total boot failures").map_err(|e| {
                DlsError::Internal(format!("Failed to create boot failures counter: {}", e))
            })?;

        let storage_available_bytes = Gauge::new(
            "storage_available_bytes",
            "Storage space available in bytes",
        )
        .map_err(|e| {
            DlsError::Internal(format!("Failed to create storage available gauge: {}", e))
        })?;

        let zfs_snapshots_total =
            Gauge::new("zfs_snapshots_total", "Total number of ZFS snapshots").map_err(|e| {
                DlsError::Internal(format!("Failed to create snapshots gauge: {}", e))
            })?;

        let image_operations = Counter::new("image_operations_total", "Total image operations")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create image operations counter: {}", e))
            })?;

        let auth_requests = Counter::new("auth_requests_total", "Total authentication requests")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create auth requests counter: {}", e))
            })?;

        let auth_failures = Counter::new("auth_failures_total", "Total authentication failures")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create auth failures counter: {}", e))
            })?;

        let active_sessions = Gauge::new("active_sessions", "Number of active user sessions")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create active sessions gauge: {}", e))
            })?;

        let token_refreshes = Counter::new("token_refreshes_total", "Total token refreshes")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create token refreshes counter: {}", e))
            })?;

        let cpu_usage_percent = Gauge::new("cpu_usage_percent", "CPU usage percentage")
            .map_err(|e| DlsError::Internal(format!("Failed to create CPU usage gauge: {}", e)))?;

        let memory_usage_bytes = Gauge::new("memory_usage_bytes", "Memory usage in bytes")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create memory usage gauge: {}", e))
            })?;

        let memory_available_bytes =
            Gauge::new("memory_available_bytes", "Available memory in bytes").map_err(|e| {
                DlsError::Internal(format!("Failed to create memory available gauge: {}", e))
            })?;

        let network_throughput_bytes = Gauge::new(
            "network_throughput_bytes_per_sec",
            "Network throughput in bytes per second",
        )
        .map_err(|e| DlsError::Internal(format!("Failed to create throughput gauge: {}", e)))?;

        let disk_io_bytes = Counter::new("disk_io_bytes_total", "Total disk I/O in bytes")
            .map_err(|e| DlsError::Internal(format!("Failed to create disk I/O counter: {}", e)))?;

        let database_connections = Gauge::new(
            "database_connections",
            "Number of active database connections",
        )
        .map_err(|e| {
            DlsError::Internal(format!(
                "Failed to create database connections gauge: {}",
                e
            ))
        })?;

        let database_queries = Counter::new("database_queries_total", "Total database queries")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create database queries counter: {}", e))
            })?;

        let database_errors = Counter::new("database_errors_total", "Total database errors")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create database errors counter: {}", e))
            })?;

        let database_query_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "database_query_duration_seconds",
                "Database query duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0]),
        )
        .map_err(|e| {
            DlsError::Internal(format!(
                "Failed to create database duration histogram: {}",
                e
            ))
        })?;

        let uptime_seconds = Gauge::new("uptime_seconds", "System uptime in seconds")
            .map_err(|e| DlsError::Internal(format!("Failed to create uptime gauge: {}", e)))?;

        let health_checks = Counter::new("health_checks_total", "Total health checks performed")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create health checks counter: {}", e))
            })?;

        let service_restarts = Counter::new("service_restarts_total", "Total service restarts")
            .map_err(|e| {
                DlsError::Internal(format!("Failed to create service restarts counter: {}", e))
            })?;

        Ok(Self {
            dhcp_requests,
            tftp_requests,
            iscsi_connections,
            dhcp_errors,
            tftp_errors,
            iscsi_errors,
            active_clients,
            boot_sessions_total,
            boot_failures,
            boot_time_histogram,
            disk_images_total,
            storage_used_bytes,
            storage_available_bytes,
            zfs_snapshots_total,
            image_operations,
            auth_requests,
            auth_failures,
            active_sessions,
            token_refreshes,
            cpu_usage_percent,
            memory_usage_bytes,
            memory_available_bytes,
            network_throughput_bytes,
            disk_io_bytes,
            database_connections,
            database_queries,
            database_errors,
            database_query_duration,
            uptime_seconds,
            health_checks,
            service_restarts,
        })
    }

    pub fn register_all(&self, registry: &Registry) -> Result<()> {
        registry
            .register(Box::new(self.dhcp_requests.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register DHCP counter: {}", e)))?;

        registry
            .register(Box::new(self.tftp_requests.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register TFTP counter: {}", e)))?;

        registry
            .register(Box::new(self.iscsi_connections.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register iSCSI counter: {}", e)))?;

        registry
            .register(Box::new(self.dhcp_errors.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register DHCP errors: {}", e)))?;

        registry
            .register(Box::new(self.tftp_errors.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register TFTP errors: {}", e)))?;

        registry
            .register(Box::new(self.iscsi_errors.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register iSCSI errors: {}", e)))?;

        registry
            .register(Box::new(self.active_clients.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register active clients: {}", e)))?;

        registry
            .register(Box::new(self.boot_sessions_total.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register boot sessions: {}", e)))?;

        registry
            .register(Box::new(self.boot_failures.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register boot failures: {}", e)))?;

        registry
            .register(Box::new(self.boot_time_histogram.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register boot time: {}", e)))?;

        registry
            .register(Box::new(self.disk_images_total.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register disk images: {}", e)))?;

        registry
            .register(Box::new(self.storage_used_bytes.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register storage used: {}", e)))?;

        registry
            .register(Box::new(self.storage_available_bytes.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register storage available: {}", e))
            })?;

        registry
            .register(Box::new(self.zfs_snapshots_total.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register ZFS snapshots: {}", e)))?;

        registry
            .register(Box::new(self.image_operations.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register image operations: {}", e))
            })?;

        registry
            .register(Box::new(self.auth_requests.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register auth requests: {}", e)))?;

        registry
            .register(Box::new(self.auth_failures.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register auth failures: {}", e)))?;

        registry
            .register(Box::new(self.active_sessions.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register active sessions: {}", e))
            })?;

        registry
            .register(Box::new(self.token_refreshes.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register token refreshes: {}", e))
            })?;

        registry
            .register(Box::new(self.cpu_usage_percent.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register CPU usage: {}", e)))?;

        registry
            .register(Box::new(self.memory_usage_bytes.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register memory usage: {}", e)))?;

        registry
            .register(Box::new(self.memory_available_bytes.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register memory available: {}", e))
            })?;

        registry
            .register(Box::new(self.network_throughput_bytes.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register network throughput: {}", e))
            })?;

        registry
            .register(Box::new(self.disk_io_bytes.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register disk I/O: {}", e)))?;

        registry
            .register(Box::new(self.database_connections.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register database connections: {}", e))
            })?;

        registry
            .register(Box::new(self.database_queries.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register database queries: {}", e))
            })?;

        registry
            .register(Box::new(self.database_errors.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register database errors: {}", e))
            })?;

        registry
            .register(Box::new(self.database_query_duration.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register database query duration: {}", e))
            })?;

        registry
            .register(Box::new(self.uptime_seconds.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register uptime: {}", e)))?;

        registry
            .register(Box::new(self.health_checks.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register health checks: {}", e)))?;

        registry
            .register(Box::new(self.service_restarts.clone()))
            .map_err(|e| {
                DlsError::Internal(format!("Failed to register service restarts: {}", e))
            })?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct MonitoringManager {
    metrics: Arc<Metrics>,
    registry: Registry,
    client_sessions: Arc<RwLock<HashMap<String, ClientSession>>>,
}

#[derive(Debug, Clone)]
pub struct ClientSession {
    pub client_id: String,
    pub ip_address: String,
    pub boot_start_time: chrono::DateTime<chrono::Utc>,
    pub status: ClientStatus,
}

#[derive(Debug, Clone)]
pub enum ClientStatus {
    BootRequested,
    ImageLoading,
    Booting,
    Ready,
    Disconnected,
}

impl MonitoringManager {
    pub fn new() -> Result<Self> {
        let metrics = Arc::new(Metrics::new()?);
        let registry = Registry::new();

        metrics.register_all(&registry)?;

        Ok(Self {
            metrics,
            registry,
            client_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn get_metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    pub async fn export_metrics(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();

        encoder
            .encode_to_string(&metric_families)
            .map_err(|e| DlsError::Internal(format!("Failed to encode metrics: {}", e)))
    }

    pub async fn record_dhcp_request(&self) {
        self.metrics.dhcp_requests.inc();
    }

    pub async fn record_tftp_request(&self) {
        self.metrics.tftp_requests.inc();
    }

    pub async fn record_iscsi_connection(&self) {
        self.metrics.iscsi_connections.inc();
    }

    pub async fn record_boot_time(&self, duration_seconds: f64) {
        self.metrics.boot_time_histogram.observe(duration_seconds);
    }

    pub async fn update_active_clients(&self, count: f64) {
        self.metrics.active_clients.set(count);
    }

    pub async fn update_disk_images_count(&self, count: f64) {
        self.metrics.disk_images_total.set(count);
    }

    pub async fn update_storage_used(&self, bytes: f64) {
        self.metrics.storage_used_bytes.set(bytes);
    }

    pub async fn update_network_throughput(&self, bytes_per_sec: f64) {
        self.metrics.network_throughput_bytes.set(bytes_per_sec);
    }

    pub async fn record_dhcp_error(&self) {
        self.metrics.dhcp_errors.inc();
    }

    pub async fn record_tftp_error(&self) {
        self.metrics.tftp_errors.inc();
    }

    pub async fn record_iscsi_error(&self) {
        self.metrics.iscsi_errors.inc();
    }

    pub async fn record_boot_session_start(&self) {
        self.metrics.boot_sessions_total.inc();
    }

    pub async fn record_boot_failure(&self) {
        self.metrics.boot_failures.inc();
    }

    pub async fn update_storage_available(&self, bytes: f64) {
        self.metrics.storage_available_bytes.set(bytes);
    }

    pub async fn update_zfs_snapshots_count(&self, count: f64) {
        self.metrics.zfs_snapshots_total.set(count);
    }

    pub async fn record_image_operation(&self) {
        self.metrics.image_operations.inc();
    }

    pub async fn record_auth_request(&self) {
        self.metrics.auth_requests.inc();
    }

    pub async fn record_auth_failure(&self) {
        self.metrics.auth_failures.inc();
    }

    pub async fn update_active_sessions(&self, count: f64) {
        self.metrics.active_sessions.set(count);
    }

    pub async fn record_token_refresh(&self) {
        self.metrics.token_refreshes.inc();
    }

    pub async fn update_cpu_usage(&self, percent: f64) {
        self.metrics.cpu_usage_percent.set(percent);
    }

    pub async fn update_memory_usage(&self, bytes: f64) {
        self.metrics.memory_usage_bytes.set(bytes);
    }

    pub async fn update_memory_available(&self, bytes: f64) {
        self.metrics.memory_available_bytes.set(bytes);
    }

    pub async fn record_disk_io(&self, bytes: f64) {
        self.metrics.disk_io_bytes.inc_by(bytes);
    }

    pub async fn update_database_connections(&self, count: f64) {
        self.metrics.database_connections.set(count);
    }

    pub async fn record_database_query(&self, duration_seconds: f64) {
        self.metrics.database_queries.inc();
        self.metrics
            .database_query_duration
            .observe(duration_seconds);
    }

    pub async fn record_database_error(&self) {
        self.metrics.database_errors.inc();
    }

    pub async fn update_uptime(&self, seconds: f64) {
        self.metrics.uptime_seconds.set(seconds);
    }

    pub async fn record_health_check(&self) {
        self.metrics.health_checks.inc();
    }

    pub async fn record_service_restart(&self) {
        self.metrics.service_restarts.inc();
    }

    pub async fn start_client_session(&self, client_id: String, ip_address: String) -> Result<()> {
        let session = ClientSession {
            client_id: client_id.clone(),
            ip_address,
            boot_start_time: chrono::Utc::now(),
            status: ClientStatus::BootRequested,
        };

        let mut sessions = self.client_sessions.write().await;
        sessions.insert(client_id, session);

        self.update_active_clients(sessions.len() as f64).await;

        Ok(())
    }

    pub async fn update_client_status(&self, client_id: &str, status: ClientStatus) -> Result<()> {
        let mut sessions = self.client_sessions.write().await;

        if let Some(session) = sessions.get_mut(client_id) {
            session.status = status;

            if matches!(session.status, ClientStatus::Ready) {
                let boot_duration = chrono::Utc::now()
                    .signed_duration_since(session.boot_start_time)
                    .num_seconds() as f64;

                self.record_boot_time(boot_duration).await;
                info!(
                    "Client {} booted in {:.2} seconds",
                    client_id, boot_duration
                );
            }
        }

        Ok(())
    }

    pub async fn end_client_session(&self, client_id: &str) -> Result<()> {
        let mut sessions = self.client_sessions.write().await;
        sessions.remove(client_id);

        self.update_active_clients(sessions.len() as f64).await;

        Ok(())
    }

    pub async fn get_client_sessions(&self) -> HashMap<String, ClientSession> {
        self.client_sessions.read().await.clone()
    }

    pub async fn start_monitoring(&self, interval_seconds: u64) {
        let metrics = self.metrics.clone();
        let client_sessions = self.client_sessions.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_seconds));

            loop {
                interval.tick().await;

                let sessions = client_sessions.read().await;
                let active_count = sessions.len() as f64;
                metrics.active_clients.set(active_count);

                info!("Monitoring update - Active clients: {}", active_count);
            }
        });
    }
}
