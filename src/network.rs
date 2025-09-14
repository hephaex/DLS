pub mod dhcp;
pub mod tftp;
pub mod iscsi;

use crate::error::Result;
use crate::boot::{PxeOrchestrator, BootOrchestratorConfig};
use crate::client::{ClientManager, ClientManagerConfig};
use crate::web::WebServer;
use crate::provisioning::ProvisioningManager;
use crate::performance::PerformanceMonitor;
use crate::cluster::{ClusterManager, ClusterConfig};
use crate::security::{SecurityManager, ZeroTrustConfig};
use crate::tenant::{TenantManager, Tenant};
use std::net::IpAddr;

pub use dhcp::DhcpServer;
pub use tftp::TftpServer;
pub use iscsi::IscsiTarget;

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub dhcp_range_start: std::net::Ipv4Addr,
    pub dhcp_range_end: std::net::Ipv4Addr,
    pub tftp_root: String,
    pub iscsi_target_name: String,
}

pub struct NetworkManager {
    config: NetworkConfig,
    dhcp_server: Option<DhcpServer>,
    tftp_server: Option<TftpServer>,
    iscsi_target: Option<IscsiTarget>,
    pxe_orchestrator: Option<PxeOrchestrator>,
    client_manager: Option<ClientManager>,
    web_server: Option<WebServer>,
    provisioning_manager: Option<ProvisioningManager>,
    performance_monitor: Option<PerformanceMonitor>,
    cluster_manager: Option<ClusterManager>,
    security_manager: Option<SecurityManager>,
    tenant_manager: Option<TenantManager>,
}

impl NetworkManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            dhcp_server: None,
            tftp_server: None,
            iscsi_target: None,
            pxe_orchestrator: None,
            client_manager: None,
            web_server: None,
            provisioning_manager: None,
            performance_monitor: None,
            cluster_manager: None,
            security_manager: None,
            tenant_manager: None,
        }
    }

    pub async fn start_all_services(&mut self) -> Result<()> {
        self.start_tenant_manager().await?;
        self.start_security_manager().await?;
        self.start_cluster_manager().await?;
        self.start_performance_monitor().await?;
        self.start_client_manager().await?;
        self.start_pxe_orchestrator().await?;
        self.start_dhcp().await?;
        self.start_tftp().await?;
        self.start_iscsi().await?;
        self.start_provisioning_manager().await?;
        self.start_web_server().await?;
        Ok(())
    }

    pub async fn start_dhcp(&mut self) -> Result<()> {
        let options = dhcp::DhcpOptions {
            server_ip: std::net::Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![std::net::Ipv4Addr::new(8, 8, 8, 8)],
            domain_name: Some("dls.local".to_string()),
            lease_time: 3600,
            tftp_server: Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            boot_filename: Some("pxelinux.0".to_string()),
            vendor_class_identifier: None,
        };
        
        let mut server = DhcpServer::new(
            self.config.dhcp_range_start,
            self.config.dhcp_range_end,
            options,
        );
        server.start().await?;
        self.dhcp_server = Some(server);
        Ok(())
    }

    pub async fn start_tftp(&mut self) -> Result<()> {
        let mut server = TftpServer::new(self.config.tftp_root.clone());
        server.start().await?;
        self.tftp_server = Some(server);
        Ok(())
    }

    pub async fn start_iscsi(&mut self) -> Result<()> {
        let mut target = IscsiTarget::new(self.config.iscsi_target_name.clone());
        target.start().await?;
        self.iscsi_target = Some(target);
        Ok(())
    }

    pub async fn start_client_manager(&mut self) -> Result<()> {
        let config = ClientManagerConfig::default();
        
        let mut manager = ClientManager::new(config);
        manager.start().await?;
        self.client_manager = Some(manager);
        Ok(())
    }

    pub async fn start_pxe_orchestrator(&mut self) -> Result<()> {
        let config = BootOrchestratorConfig {
            enabled: true,
            tftp_root: std::path::PathBuf::from(&self.config.tftp_root),
            ..Default::default()
        };
        
        let mut orchestrator = PxeOrchestrator::new(config);
        orchestrator.start().await?;
        self.pxe_orchestrator = Some(orchestrator);
        Ok(())
    }

    pub async fn stop_all_services(&mut self) -> Result<()> {
        if let Some(mut web) = self.web_server.take() {
            web.stop().await?;
        }
        if let Some(mut provisioning) = self.provisioning_manager.take() {
            provisioning.stop().await?;
        }
        if let Some(performance) = self.performance_monitor.take() {
            performance.stop().await?;
        }
        if let Some(cluster) = self.cluster_manager.take() {
            cluster.stop().await?;
        }
        if let Some(security) = self.security_manager.take() {
            security.stop().await?;
        }
        if let Some(tenant_mgr) = self.tenant_manager.take() {
            tenant_mgr.stop().await?;
        }
        if let Some(mut client_mgr) = self.client_manager.take() {
            client_mgr.stop().await?;
        }
        if let Some(mut pxe) = self.pxe_orchestrator.take() {
            pxe.stop().await?;
        }
        if let Some(mut dhcp) = self.dhcp_server.take() {
            dhcp.stop().await?;
        }
        if let Some(mut tftp) = self.tftp_server.take() {
            tftp.stop().await?;
        }
        if let Some(mut iscsi) = self.iscsi_target.take() {
            iscsi.stop().await?;
        }
        Ok(())
    }

    pub fn get_pxe_orchestrator(&self) -> Option<&PxeOrchestrator> {
        self.pxe_orchestrator.as_ref()
    }

    pub fn get_client_manager(&self) -> Option<&ClientManager> {
        self.client_manager.as_ref()
    }

    pub async fn start_web_server(&mut self) -> Result<()> {
        let mut server = WebServer::new("0.0.0.0".to_string(), 8080);
        server.start().await?;
        self.web_server = Some(server);
        Ok(())
    }

    pub fn get_web_server(&self) -> Option<&WebServer> {
        self.web_server.as_ref()
    }

    pub async fn start_provisioning_manager(&mut self) -> Result<()> {
        let provisioning_dir = std::path::PathBuf::from(&self.config.tftp_root).join("provisioning");
        let mut manager = ProvisioningManager::new(provisioning_dir, 4);
        manager.start().await?;
        self.provisioning_manager = Some(manager);
        Ok(())
    }

    pub fn get_provisioning_manager(&self) -> Option<&ProvisioningManager> {
        self.provisioning_manager.as_ref()
    }

    pub async fn start_performance_monitor(&mut self) -> Result<()> {
        let monitor = PerformanceMonitor::default();
        monitor.start().await?;
        self.performance_monitor = Some(monitor);
        Ok(())
    }

    pub fn get_performance_monitor(&self) -> Option<&PerformanceMonitor> {
        self.performance_monitor.as_ref()
    }

    pub async fn start_security_manager(&mut self) -> Result<()> {
        let zero_trust_config = ZeroTrustConfig::default();
        
        let manager = SecurityManager::new(zero_trust_config).await?;
        manager.start().await?;
        self.security_manager = Some(manager);
        Ok(())
    }

    pub async fn start_cluster_manager(&mut self) -> Result<()> {
        let cluster_config = ClusterConfig {
            node_name: format!("{}-cluster", self.config.iscsi_target_name),
            listen_addr: "0.0.0.0:7777".parse().unwrap(),
            ..Default::default()
        };
        
        let manager = ClusterManager::new(cluster_config);
        manager.start().await?;
        self.cluster_manager = Some(manager);
        Ok(())
    }

    pub fn get_security_manager(&self) -> Option<&SecurityManager> {
        self.security_manager.as_ref()
    }

    pub async fn evaluate_network_access(&self, ip: std::net::IpAddr, segment: &str) -> Result<bool> {
        if let Some(security_manager) = &self.security_manager {
            security_manager.evaluate_network_access(ip, segment).await
        } else {
            Ok(true) // Allow if security manager is not enabled
        }
    }

    pub async fn get_security_events(&self, limit: Option<usize>) -> Vec<crate::security::SecurityEvent> {
        if let Some(security_manager) = &self.security_manager {
            security_manager.get_security_events(limit).await
        } else {
            Vec::new()
        }
    }

    pub async fn get_network_segments(&self) -> std::collections::HashMap<String, crate::security::NetworkSegment> {
        if let Some(security_manager) = &self.security_manager {
            security_manager.get_network_segments().await
        } else {
            std::collections::HashMap::new()
        }
    }

    pub fn get_cluster_manager(&self) -> Option<&ClusterManager> {
        self.cluster_manager.as_ref()
    }

    pub async fn initiate_cluster_failover(&self, failed_node_id: &str) -> Result<()> {
        if let Some(cluster_manager) = &self.cluster_manager {
            cluster_manager.initiate_failover(failed_node_id).await?;
        }
        Ok(())
    }

    pub async fn get_cluster_status(&self) -> Option<crate::cluster::ClusterStatus> {
        if let Some(cluster_manager) = &self.cluster_manager {
            Some(cluster_manager.get_cluster_status().await)
        } else {
            None
        }
    }

    pub async fn start_tenant_manager(&mut self) -> Result<()> {
        let manager = TenantManager::new();
        manager.start().await?;
        self.tenant_manager = Some(manager);
        Ok(())
    }

    pub fn get_tenant_manager(&self) -> Option<&TenantManager> {
        self.tenant_manager.as_ref()
    }

    pub async fn register_tenant_client(&self, client_ip: IpAddr, tenant_id: uuid::Uuid) -> Result<()> {
        if let Some(tenant_manager) = &self.tenant_manager {
            tenant_manager.register_client_connection(client_ip, tenant_id).await
        } else {
            Err(crate::error::Error::Internal("Tenant manager not initialized".to_string()))
        }
    }

    pub async fn unregister_tenant_client(&self, client_ip: IpAddr) -> Result<()> {
        if let Some(tenant_manager) = &self.tenant_manager {
            tenant_manager.unregister_client_connection(client_ip).await
        } else {
            Err(crate::error::Error::Internal("Tenant manager not initialized".to_string()))
        }
    }

    pub fn get_client_tenant(&self, client_ip: &IpAddr) -> Option<uuid::Uuid> {
        self.tenant_manager
            .as_ref()
            .and_then(|tm| tm.get_tenant_for_client(client_ip))
    }

    pub async fn validate_tenant_access(&self, client_ip: IpAddr, requested_resource: &str) -> Result<bool> {
        if let Some(tenant_manager) = &self.tenant_manager {
            if let Some(tenant_id) = tenant_manager.get_tenant_for_client(&client_ip) {
                if let Some(tenant) = tenant_manager.get_tenant(&tenant_id) {
                    if !tenant.is_active() {
                        return Ok(false);
                    }

                    // Additional access validation based on tenant policies
                    // This could include resource-specific checks, network segment validation, etc.
                    
                    // Example: Check if client is in allowed network ranges
                    if let Some(security_manager) = &self.security_manager {
                        let network_segment = format!("tenant-{}", tenant.namespace);
                        return security_manager.evaluate_network_access(client_ip, &network_segment).await;
                    }

                    return Ok(true);
                }
            }
            Ok(false) // No tenant found for client
        } else {
            Ok(true) // Allow if tenant manager is not enabled
        }
    }

    pub async fn get_tenant_resource_usage(&self, tenant_id: &uuid::Uuid) -> Option<crate::tenant::ResourceUsage> {
        self.tenant_manager
            .as_ref()
            .and_then(|tm| tm.get_resource_usage(tenant_id))
    }

    pub async fn list_tenant_clients(&self) -> std::collections::HashMap<IpAddr, uuid::Uuid> {
        if let Some(tenant_manager) = &self.tenant_manager {
            tenant_manager.client_connections
                .iter()
                .map(|entry| (*entry.key(), *entry.value()))
                .collect()
        } else {
            std::collections::HashMap::new()
        }
    }
}