use crate::error::{DlsError, Result};
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Debug)]
pub struct TftpServer {
    root_path: PathBuf,
    running: bool,
}

impl TftpServer {
    pub fn new(root_path: String) -> Self {
        Self {
            root_path: PathBuf::from(root_path),
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(DlsError::Network("TFTP server already running".to_string()));
        }

        if !self.root_path.exists() {
            tokio::fs::create_dir_all(&self.root_path).await?;
        }

        info!("Starting TFTP server with root: {:?}", self.root_path);
        
        let root_path = self.root_path.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::run_tftp_server(root_path).await {
                error!("TFTP server error: {}", e);
            }
        });

        self.running = true;
        info!("TFTP server started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        self.running = false;
        info!("TFTP server stopped");
        Ok(())
    }

    async fn run_tftp_server(root_path: PathBuf) -> Result<()> {
        let bind_addr = "0.0.0.0:69";
        
        info!("TFTP server listening on {}", bind_addr);
        
        let socket = tokio::net::UdpSocket::bind(bind_addr).await
            .map_err(|e| DlsError::Network(format!("Failed to bind TFTP socket: {}", e)))?;

        let mut buf = [0u8; 1024];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    info!("TFTP request from {}: {} bytes", addr, len);
                    
                    let response = b"TFTP not fully implemented yet";
                    if let Err(e) = socket.send_to(response, addr).await {
                        error!("Failed to send TFTP response: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to receive TFTP request: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
}