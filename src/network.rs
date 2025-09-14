pub mod dhcp;
pub mod tftp;
pub mod iscsi;

use crate::error::Result;
use crate::boot::{PxeOrchestrator, BootOrchestratorConfig};
use crate::client::{ClientManager, ClientManagerConfig};
use crate::web::WebServer;
use crate::provisioning::ProvisioningManager;

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
        }
    }

    pub async fn start_all_services(&mut self) -> Result<()> {
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
}