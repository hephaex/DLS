use crate::error::{DlsError, Result};
use prometheus::{Counter, Gauge, Histogram, Registry, TextEncoder, Encoder};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Debug)]
pub struct Metrics {
    pub dhcp_requests: Counter,
    pub tftp_requests: Counter,
    pub iscsi_connections: Counter,
    pub active_clients: Gauge,
    pub disk_images_total: Gauge,
    pub storage_used_bytes: Gauge,
    pub boot_time_histogram: Histogram,
    pub network_throughput: Gauge,
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
            .map_err(|e| DlsError::Internal(format!("Failed to create active clients gauge: {}", e)))?;
        
        let disk_images_total = Gauge::new("disk_images_total", "Total number of disk images")
            .map_err(|e| DlsError::Internal(format!("Failed to create disk images gauge: {}", e)))?;
        
        let storage_used_bytes = Gauge::new("storage_used_bytes", "Storage space used in bytes")
            .map_err(|e| DlsError::Internal(format!("Failed to create storage gauge: {}", e)))?;
        
        let boot_time_histogram = Histogram::with_opts(
            prometheus::HistogramOpts::new("boot_time_seconds", "Client boot time in seconds")
                .buckets(vec![10.0, 30.0, 60.0, 90.0, 120.0, 180.0, 300.0])
        ).map_err(|e| DlsError::Internal(format!("Failed to create boot time histogram: {}", e)))?;
        
        let network_throughput = Gauge::new("network_throughput_mbps", "Network throughput in Mbps")
            .map_err(|e| DlsError::Internal(format!("Failed to create throughput gauge: {}", e)))?;

        Ok(Self {
            dhcp_requests,
            tftp_requests,
            iscsi_connections,
            active_clients,
            disk_images_total,
            storage_used_bytes,
            boot_time_histogram,
            network_throughput,
        })
    }

    pub fn register_all(&self, registry: &Registry) -> Result<()> {
        registry.register(Box::new(self.dhcp_requests.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register DHCP counter: {}", e)))?;
        
        registry.register(Box::new(self.tftp_requests.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register TFTP counter: {}", e)))?;
        
        registry.register(Box::new(self.iscsi_connections.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register iSCSI counter: {}", e)))?;
        
        registry.register(Box::new(self.active_clients.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register active clients: {}", e)))?;
        
        registry.register(Box::new(self.disk_images_total.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register disk images: {}", e)))?;
        
        registry.register(Box::new(self.storage_used_bytes.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register storage: {}", e)))?;
        
        registry.register(Box::new(self.boot_time_histogram.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register boot time: {}", e)))?;
        
        registry.register(Box::new(self.network_throughput.clone()))
            .map_err(|e| DlsError::Internal(format!("Failed to register throughput: {}", e)))?;

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
        
        encoder.encode_to_string(&metric_families)
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

    pub async fn update_network_throughput(&self, mbps: f64) {
        self.metrics.network_throughput.set(mbps);
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
                info!("Client {} booted in {:.2} seconds", client_id, boot_duration);
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
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(interval_seconds)
            );
            
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