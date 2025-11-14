use crate::boot::{BootSession, BootStage};
use crate::error::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientState {
    Unknown,
    Discovered,
    DhcpAssigned,
    TftpRequested,
    KernelLoading,
    IscsiConnected,
    BootCompleted,
    Failed,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientType {
    LegacyBios,
    UefiBios,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientArchitecture {
    X86,
    X64,
    Arm32,
    Arm64,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub mac_address: [u8; 6],
    pub ip_address: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub vendor_id: Option<String>,
    pub client_type: ClientType,
    pub architecture: ClientArchitecture,
    pub state: ClientState,
    pub first_seen: u64,
    pub last_seen: u64,
    pub boot_count: u32,
    pub successful_boots: u32,
    pub failed_boots: u32,
    pub total_boot_time: u64,   // in milliseconds
    pub average_boot_time: u64, // in milliseconds
    pub current_boot_session: Option<String>,
    pub assigned_profile: Option<String>,
    pub lease_expires: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientBootMetrics {
    pub client_id: String,
    pub boot_session_id: String,
    pub boot_start_time: u64,
    pub boot_completion_time: Option<u64>,
    pub dhcp_response_time: Option<u64>,
    pub tftp_transfer_time: Option<u64>,
    pub kernel_load_time: Option<u64>,
    pub iscsi_connect_time: Option<u64>,
    pub total_boot_time: Option<u64>,
    pub boot_stages: Vec<BootStageMetric>,
    pub errors: Vec<BootError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootStageMetric {
    pub stage: BootStage,
    pub timestamp: u64,
    pub duration_from_start: u64, // milliseconds from boot start
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootError {
    pub timestamp: u64,
    pub stage: BootStage,
    pub error_code: String,
    pub error_message: String,
    pub recovery_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFilter {
    pub state: Option<ClientState>,
    pub client_type: Option<ClientType>,
    pub architecture: Option<ClientArchitecture>,
    pub online_only: bool,
    pub failed_only: bool,
    pub recent_hours: Option<u32>,
}

#[derive(Debug)]
pub struct ClientManager {
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
    boot_metrics: Arc<RwLock<HashMap<String, ClientBootMetrics>>>,
    mac_to_client_id: Arc<RwLock<HashMap<[u8; 6], String>>>,
    config: ClientManagerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientManagerConfig {
    pub enabled: bool,
    pub session_timeout: u64, // seconds
    pub metrics_retention_days: u32,
    pub auto_cleanup_interval: u64, // seconds
    pub max_clients: usize,
    pub boot_timeout: u64,      // seconds
    pub offline_threshold: u64, // seconds since last seen
}

impl ClientManager {
    pub fn new(config: ClientManagerConfig) -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            boot_metrics: Arc::new(RwLock::new(HashMap::new())),
            mac_to_client_id: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if !self.config.enabled {
            info!("Client manager is disabled");
            return Ok(());
        }

        info!("Starting client boot management and session tracking");

        // Start cleanup task
        self.start_cleanup_task().await;

        info!("Client manager started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping client manager");

        // Clear active sessions
        let mut clients = self.clients.write().await;
        clients.clear();

        info!("Client manager stopped");
        Ok(())
    }

    pub async fn register_client(
        &self,
        mac_address: [u8; 6],
        client_arch: Option<u16>,
        vendor_id: Option<String>,
    ) -> Result<String> {
        let client_id = self.generate_client_id(mac_address);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (client_type, architecture) = self.detect_client_capabilities(client_arch);

        let mut clients = self.clients.write().await;
        let mut mac_mapping = self.mac_to_client_id.write().await;

        // Check if client already exists
        if let Some(existing_client) = clients.get_mut(&client_id) {
            existing_client.last_seen = current_time;
            existing_client.state = ClientState::Discovered;
            existing_client.vendor_id = vendor_id.or(existing_client.vendor_id.clone());
            return Ok(client_id);
        }

        // Create new client
        let client_info = ClientInfo {
            client_id: client_id.clone(),
            mac_address,
            ip_address: None,
            hostname: None,
            vendor_id,
            client_type,
            architecture,
            state: ClientState::Discovered,
            first_seen: current_time,
            last_seen: current_time,
            boot_count: 0,
            successful_boots: 0,
            failed_boots: 0,
            total_boot_time: 0,
            average_boot_time: 0,
            current_boot_session: None,
            assigned_profile: None,
            lease_expires: None,
        };

        clients.insert(client_id.clone(), client_info);
        mac_mapping.insert(mac_address, client_id.clone());

        info!(
            "Registered new client: {} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            client_id,
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5]
        );

        Ok(client_id)
    }

    pub async fn update_client_ip(
        &self,
        mac_address: [u8; 6],
        ip_address: Ipv4Addr,
        lease_expires: Option<u64>,
    ) -> Result<()> {
        let mac_mapping = self.mac_to_client_id.read().await;
        if let Some(client_id) = mac_mapping.get(&mac_address) {
            let mut clients = self.clients.write().await;
            if let Some(client) = clients.get_mut(client_id) {
                client.ip_address = Some(ip_address);
                client.lease_expires = lease_expires;
                client.state = ClientState::DhcpAssigned;
                client.last_seen = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                debug!("Updated client {client_id} IP address to {ip_address}");
            }
        }
        Ok(())
    }

    pub async fn start_boot_session(
        &self,
        client_id: &str,
        boot_session: &BootSession,
    ) -> Result<()> {
        let mut clients = self.clients.write().await;
        let mut boot_metrics = self.boot_metrics.write().await;

        if let Some(client) = clients.get_mut(client_id) {
            client.boot_count += 1;
            client.current_boot_session = Some(boot_session.session_id.clone());
            client.assigned_profile = Some(boot_session.assigned_profile.profile_id.clone());
            client.state = ClientState::TftpRequested;
            client.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Initialize boot metrics
            let boot_metric = ClientBootMetrics {
                client_id: client_id.to_string(),
                boot_session_id: boot_session.session_id.clone(),
                boot_start_time: boot_session.created_at,
                boot_completion_time: None,
                dhcp_response_time: None,
                tftp_transfer_time: None,
                kernel_load_time: None,
                iscsi_connect_time: None,
                total_boot_time: None,
                boot_stages: vec![BootStageMetric {
                    stage: BootStage::Initial,
                    timestamp: boot_session.created_at,
                    duration_from_start: 0,
                }],
                errors: vec![],
            };

            boot_metrics.insert(boot_session.session_id.clone(), boot_metric);

            info!(
                "Started boot session {} for client {}",
                boot_session.session_id, client_id
            );
        }

        Ok(())
    }

    pub async fn update_boot_stage(&self, session_id: &str, stage: BootStage) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut boot_metrics = self.boot_metrics.write().await;
        let mut clients = self.clients.write().await;

        if let Some(metric) = boot_metrics.get_mut(session_id) {
            let duration_from_start = current_time - metric.boot_start_time;

            metric.boot_stages.push(BootStageMetric {
                stage,
                timestamp: current_time,
                duration_from_start,
            });

            // Update client state based on boot stage
            if let Some(client) = clients.get_mut(&metric.client_id) {
                client.state = match stage {
                    BootStage::Initial => ClientState::Discovered,
                    BootStage::ProfileAssigned => ClientState::DhcpAssigned,
                    BootStage::PxeLoaderSent => ClientState::TftpRequested,
                    BootStage::KernelLoading => ClientState::KernelLoading,
                    BootStage::IscsiConnecting => ClientState::IscsiConnected,
                    BootStage::BootComplete => {
                        client.successful_boots += 1;
                        client.total_boot_time += duration_from_start;
                        client.average_boot_time =
                            client.total_boot_time / client.successful_boots as u64;
                        ClientState::BootCompleted
                    }
                    BootStage::Failed => {
                        client.failed_boots += 1;
                        ClientState::Failed
                    }
                };
                client.last_seen = current_time / 1000; // Convert to seconds
            }

            // Record stage-specific timing
            match stage {
                BootStage::ProfileAssigned => {
                    metric.dhcp_response_time = Some(duration_from_start);
                }
                BootStage::PxeLoaderSent => {
                    metric.tftp_transfer_time = Some(duration_from_start);
                }
                BootStage::KernelLoading => {
                    metric.kernel_load_time = Some(duration_from_start);
                }
                BootStage::IscsiConnecting => {
                    metric.iscsi_connect_time = Some(duration_from_start);
                }
                BootStage::BootComplete => {
                    metric.boot_completion_time = Some(current_time);
                    metric.total_boot_time = Some(duration_from_start);
                }
                _ => {}
            }

            debug!(
                "Updated boot session {session_id} to stage {stage:?} ({duration_from_start}ms from start)"
            );
        }

        Ok(())
    }

    pub async fn record_boot_error(
        &self,
        session_id: &str,
        stage: BootStage,
        error_code: &str,
        error_message: &str,
    ) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut boot_metrics = self.boot_metrics.write().await;

        if let Some(metric) = boot_metrics.get_mut(session_id) {
            let boot_error = BootError {
                timestamp: current_time,
                stage,
                error_code: error_code.to_string(),
                error_message: error_message.to_string(),
                recovery_action: None,
            };

            metric.errors.push(boot_error);

            warn!(
                "Boot error in session {session_id}: {error_code} - {error_message}"
            );
        }

        Ok(())
    }

    pub async fn get_client_info(&self, client_id: &str) -> Result<Option<ClientInfo>> {
        let clients = self.clients.read().await;
        Ok(clients.get(client_id).cloned())
    }

    pub async fn get_client_by_mac(&self, mac_address: [u8; 6]) -> Result<Option<ClientInfo>> {
        let mac_mapping = self.mac_to_client_id.read().await;
        if let Some(client_id) = mac_mapping.get(&mac_address) {
            let clients = self.clients.read().await;
            Ok(clients.get(client_id).cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn list_clients(&self, filter: Option<ClientFilter>) -> Result<Vec<ClientInfo>> {
        let clients = self.clients.read().await;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut result = Vec::new();

        for client in clients.values() {
            // Apply filters
            if let Some(ref f) = filter {
                if let Some(state) = f.state {
                    if client.state != state {
                        continue;
                    }
                }

                if let Some(client_type) = f.client_type {
                    if client.client_type != client_type {
                        continue;
                    }
                }

                if let Some(architecture) = f.architecture {
                    if client.architecture != architecture {
                        continue;
                    }
                }

                if f.online_only {
                    let offline_threshold = current_time - self.config.offline_threshold;
                    if client.last_seen < offline_threshold {
                        continue;
                    }
                }

                if f.failed_only
                    && client.failed_boots == 0 {
                        continue;
                    }

                if let Some(recent_hours) = f.recent_hours {
                    let recent_threshold = current_time - (recent_hours as u64 * 3600);
                    if client.last_seen < recent_threshold {
                        continue;
                    }
                }
            }

            result.push(client.clone());
        }

        // Sort by last seen time (most recent first)
        result.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        Ok(result)
    }

    pub async fn get_boot_metrics(&self, session_id: &str) -> Result<Option<ClientBootMetrics>> {
        let boot_metrics = self.boot_metrics.read().await;
        Ok(boot_metrics.get(session_id).cloned())
    }

    pub async fn get_client_boot_history(
        &self,
        client_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<ClientBootMetrics>> {
        let boot_metrics = self.boot_metrics.read().await;

        let mut client_metrics: Vec<_> = boot_metrics
            .values()
            .filter(|m| m.client_id == client_id)
            .cloned()
            .collect();

        // Sort by boot start time (most recent first)
        client_metrics.sort_by(|a, b| b.boot_start_time.cmp(&a.boot_start_time));

        if let Some(limit) = limit {
            client_metrics.truncate(limit);
        }

        Ok(client_metrics)
    }

    pub async fn get_system_stats(&self) -> Result<ClientSystemStats> {
        let clients = self.clients.read().await;
        let boot_metrics = self.boot_metrics.read().await;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let total_clients = clients.len();
        let mut online_clients = 0;
        let mut booting_clients = 0;
        let mut failed_clients = 0;
        let mut total_boots = 0;
        let mut successful_boots = 0;
        let mut failed_boots = 0;
        let mut total_boot_time = 0u64;

        let offline_threshold = current_time - self.config.offline_threshold;

        for client in clients.values() {
            if client.last_seen >= offline_threshold {
                online_clients += 1;
            }

            match client.state {
                ClientState::TftpRequested
                | ClientState::KernelLoading
                | ClientState::IscsiConnected => {
                    booting_clients += 1;
                }
                ClientState::Failed => {
                    failed_clients += 1;
                }
                _ => {}
            }

            total_boots += client.boot_count;
            successful_boots += client.successful_boots;
            failed_boots += client.failed_boots;
            total_boot_time += client.total_boot_time;
        }

        let average_boot_time = if successful_boots > 0 {
            total_boot_time / successful_boots as u64
        } else {
            0
        };

        let boot_success_rate = if total_boots > 0 {
            (successful_boots as f64 / total_boots as f64) * 100.0
        } else {
            0.0
        };

        let active_boot_sessions = boot_metrics.len();

        Ok(ClientSystemStats {
            total_clients,
            online_clients,
            offline_clients: total_clients - online_clients,
            booting_clients,
            failed_clients,
            total_boot_sessions: total_boots,
            successful_boot_sessions: successful_boots,
            failed_boot_sessions: failed_boots,
            boot_success_rate,
            average_boot_time,
            active_boot_sessions,
        })
    }

    fn generate_client_id(&self, mac_address: [u8; 6]) -> String {
        format!(
            "client-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5]
        )
    }

    fn detect_client_capabilities(
        &self,
        client_arch: Option<u16>,
    ) -> (ClientType, ClientArchitecture) {
        if let Some(arch) = client_arch {
            match arch {
                0x0000 | 0x0001 => (ClientType::LegacyBios, ClientArchitecture::X86),
                0x0002 => (ClientType::UefiBios, ClientArchitecture::X64),
                0x0006 => (ClientType::UefiBios, ClientArchitecture::X86),
                0x0007 => (ClientType::UefiBios, ClientArchitecture::Unknown),
                0x0009 => (ClientType::UefiBios, ClientArchitecture::X64),
                0x000B => (ClientType::UefiBios, ClientArchitecture::Arm32),
                0x000C => (ClientType::UefiBios, ClientArchitecture::Arm64),
                _ => (ClientType::Unknown, ClientArchitecture::Unknown),
            }
        } else {
            (ClientType::Unknown, ClientArchitecture::Unknown)
        }
    }

    async fn start_cleanup_task(&self) {
        let _clients_clone = Arc::clone(&self.clients);
        let boot_metrics_clone = Arc::clone(&self.boot_metrics);
        let _mac_mapping_clone = Arc::clone(&self.mac_to_client_id);
        let cleanup_interval = self.config.auto_cleanup_interval;
        let metrics_retention_seconds = self.config.metrics_retention_days as u64 * 24 * 3600;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(cleanup_interval));

            loop {
                interval.tick().await;

                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Clean up old boot metrics
                let mut boot_metrics_guard = boot_metrics_clone.write().await;
                let initial_metrics_count = boot_metrics_guard.len();
                let cutoff_time = current_time - metrics_retention_seconds;

                boot_metrics_guard.retain(|_, metric| metric.boot_start_time / 1000 > cutoff_time);

                let cleaned_metrics = initial_metrics_count - boot_metrics_guard.len();
                drop(boot_metrics_guard);

                // Clean up offline clients (optional - keep them for historical purposes)
                // This could be made configurable

                if cleaned_metrics > 0 {
                    info!("Cleaned up {cleaned_metrics} old boot metrics");
                }
            }
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSystemStats {
    pub total_clients: usize,
    pub online_clients: usize,
    pub offline_clients: usize,
    pub booting_clients: usize,
    pub failed_clients: usize,
    pub total_boot_sessions: u32,
    pub successful_boot_sessions: u32,
    pub failed_boot_sessions: u32,
    pub boot_success_rate: f64,
    pub average_boot_time: u64, // milliseconds
    pub active_boot_sessions: usize,
}

impl Default for ClientManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_timeout: 3600, // 1 hour
            metrics_retention_days: 30,
            auto_cleanup_interval: 3600, // 1 hour
            max_clients: 1000,
            boot_timeout: 600,      // 10 minutes
            offline_threshold: 300, // 5 minutes
        }
    }
}

impl ClientInfo {
    pub fn is_online(&self, current_time: u64, offline_threshold: u64) -> bool {
        current_time - self.last_seen < offline_threshold
    }

    pub fn get_boot_success_rate(&self) -> f64 {
        if self.boot_count > 0 {
            (self.successful_boots as f64 / self.boot_count as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn get_status_description(&self) -> String {
        match self.state {
            ClientState::Unknown => "Unknown state".to_string(),
            ClientState::Discovered => "Discovered via network".to_string(),
            ClientState::DhcpAssigned => "IP address assigned".to_string(),
            ClientState::TftpRequested => "Downloading boot files".to_string(),
            ClientState::KernelLoading => "Loading operating system".to_string(),
            ClientState::IscsiConnected => "Connected to storage".to_string(),
            ClientState::BootCompleted => "Boot completed successfully".to_string(),
            ClientState::Failed => "Boot failed".to_string(),
            ClientState::Offline => "Client offline".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_info_creation() {
        let client_info = ClientInfo {
            client_id: "test-client".to_string(),
            mac_address: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ip_address: Some(Ipv4Addr::new(192, 168, 1, 100)),
            hostname: Some("test-host".to_string()),
            vendor_id: Some("Test Vendor".to_string()),
            client_type: ClientType::UefiBios,
            architecture: ClientArchitecture::X64,
            state: ClientState::BootCompleted,
            first_seen: 1640000000,
            last_seen: 1640000100,
            boot_count: 5,
            successful_boots: 4,
            failed_boots: 1,
            total_boot_time: 120000,  // 2 minutes total
            average_boot_time: 30000, // 30 seconds average
            current_boot_session: None,
            assigned_profile: Some("uefi-linux-ubuntu".to_string()),
            lease_expires: Some(1640003600),
        };

        assert_eq!(client_info.client_id, "test-client");
        assert_eq!(client_info.get_boot_success_rate(), 80.0);
        assert_eq!(client_info.state, ClientState::BootCompleted);
    }

    #[tokio::test]
    async fn test_client_manager_creation() {
        let config = ClientManagerConfig::default();
        let client_manager = ClientManager::new(config);

        let stats = client_manager.get_system_stats().await.unwrap();
        assert_eq!(stats.total_clients, 0);
        assert_eq!(stats.online_clients, 0);
    }

    #[tokio::test]
    async fn test_client_registration() {
        let config = ClientManagerConfig::default();
        let client_manager = ClientManager::new(config);

        let mac_address = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_id = client_manager
            .register_client(mac_address, Some(0x0009), Some("Test Vendor".to_string()))
            .await
            .unwrap();

        assert!(client_id.starts_with("client-"));

        let client_info = client_manager.get_client_info(&client_id).await.unwrap();
        assert!(client_info.is_some());

        let info = client_info.unwrap();
        assert_eq!(info.mac_address, mac_address);
        assert_eq!(info.client_type, ClientType::UefiBios);
        assert_eq!(info.architecture, ClientArchitecture::X64);
    }

    #[test]
    fn test_client_capability_detection() {
        let config = ClientManagerConfig::default();
        let client_manager = ClientManager::new(config);

        // Test Legacy BIOS detection
        let (client_type, arch) = client_manager.detect_client_capabilities(Some(0x0000));
        assert_eq!(client_type, ClientType::LegacyBios);
        assert_eq!(arch, ClientArchitecture::X86);

        // Test UEFI x64 detection
        let (client_type, arch) = client_manager.detect_client_capabilities(Some(0x0009));
        assert_eq!(client_type, ClientType::UefiBios);
        assert_eq!(arch, ClientArchitecture::X64);

        // Test ARM64 detection
        let (client_type, arch) = client_manager.detect_client_capabilities(Some(0x000C));
        assert_eq!(client_type, ClientType::UefiBios);
        assert_eq!(arch, ClientArchitecture::Arm64);
    }

    #[test]
    fn test_client_filter() {
        let filter = ClientFilter {
            state: Some(ClientState::BootCompleted),
            client_type: Some(ClientType::UefiBios),
            architecture: Some(ClientArchitecture::X64),
            online_only: true,
            failed_only: false,
            recent_hours: Some(24),
        };

        assert_eq!(filter.state.unwrap(), ClientState::BootCompleted);
        assert_eq!(filter.client_type.unwrap(), ClientType::UefiBios);
        assert!(filter.online_only);
    }

    #[test]
    fn test_boot_metrics_creation() {
        let boot_metrics = ClientBootMetrics {
            client_id: "test-client".to_string(),
            boot_session_id: "boot-session-123".to_string(),
            boot_start_time: 1640000000,
            boot_completion_time: Some(1640000030),
            dhcp_response_time: Some(2000),
            tftp_transfer_time: Some(15000),
            kernel_load_time: Some(25000),
            iscsi_connect_time: Some(28000),
            total_boot_time: Some(30000),
            boot_stages: vec![],
            errors: vec![],
        };

        assert_eq!(boot_metrics.client_id, "test-client");
        assert_eq!(boot_metrics.total_boot_time.unwrap(), 30000);
    }

    #[test]
    fn test_client_state_transitions() {
        assert_ne!(ClientState::Unknown, ClientState::Discovered);
        assert_ne!(ClientState::DhcpAssigned, ClientState::TftpRequested);
        assert_ne!(ClientState::BootCompleted, ClientState::Failed);
    }

    #[test]
    fn test_client_id_generation() {
        let config = ClientManagerConfig::default();
        let client_manager = ClientManager::new(config);

        let mac_address = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_id = client_manager.generate_client_id(mac_address);

        assert_eq!(client_id, "client-001122334455");
    }

    #[test]
    fn test_client_manager_config_default() {
        let config = ClientManagerConfig::default();

        assert!(config.enabled);
        assert_eq!(config.session_timeout, 3600);
        assert_eq!(config.metrics_retention_days, 30);
        assert_eq!(config.max_clients, 1000);
    }
}
