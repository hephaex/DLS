pub mod dhcp;
pub mod tftp;
pub mod iscsi;

use crate::error::Result;

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
}

impl NetworkManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            dhcp_server: None,
            tftp_server: None,
            iscsi_target: None,
        }
    }

    pub async fn start_all_services(&mut self) -> Result<()> {
        self.start_dhcp().await?;
        self.start_tftp().await?;
        self.start_iscsi().await?;
        Ok(())
    }

    pub async fn start_dhcp(&mut self) -> Result<()> {
        let mut server = DhcpServer::new(
            self.config.dhcp_range_start,
            self.config.dhcp_range_end,
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

    pub async fn stop_all_services(&mut self) -> Result<()> {
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
}