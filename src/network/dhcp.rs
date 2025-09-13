use crate::error::{DlsError, Result};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct DhcpServer {
    range_start: Ipv4Addr,
    range_end: Ipv4Addr,
    running: bool,
}

impl DhcpServer {
    pub fn new(range_start: Ipv4Addr, range_end: Ipv4Addr) -> Self {
        Self {
            range_start,
            range_end,
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(DlsError::Network("DHCP server already running".to_string()));
        }

        info!("Starting DHCP server on range {}-{}", self.range_start, self.range_end);
        
        let bind_addr: SocketAddr = "0.0.0.0:67".parse().unwrap();
        
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| DlsError::Network(format!("Failed to bind DHCP socket: {}", e)))?;

        socket.set_broadcast(true)
            .map_err(|e| DlsError::Network(format!("Failed to set broadcast: {}", e)))?;

        let socket = tokio::net::UdpSocket::from_std(socket)
            .map_err(|e| DlsError::Network(format!("Failed to convert socket: {}", e)))?;

        self.running = true;
        
        tokio::spawn(async move {
            Self::handle_dhcp_requests(socket).await;
        });

        info!("DHCP server started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        self.running = false;
        info!("DHCP server stopped");
        Ok(())
    }

    async fn handle_dhcp_requests(socket: tokio::net::UdpSocket) {
        let mut buf = [0u8; 1024];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    debug!("Received DHCP packet from {}: {} bytes", addr, len);
                    
                    if let Err(e) = Self::process_dhcp_packet(&buf[..len], addr, &socket).await {
                        error!("Failed to process DHCP packet: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to receive DHCP packet: {}", e);
                    break;
                }
            }
        }
    }

    async fn process_dhcp_packet(
        data: &[u8],
        client_addr: SocketAddr,
        _socket: &tokio::net::UdpSocket,
    ) -> Result<()> {
        debug!("Processing DHCP packet from {}: {} bytes", client_addr, data.len());
        
        if data.len() >= 4 {
            match data[0] {
                1 => info!("Received DHCP BOOTREQUEST"),
                2 => info!("Received DHCP BOOTREPLY"),
                _ => debug!("Received unknown DHCP message type: {}", data[0]),
            }
        }

        Ok(())
    }

    fn create_dhcp_offer(&self) -> Result<Vec<u8>> {
        let _offered_ip = self.get_next_available_ip()?;
        
        warn!("DHCP offer creation not fully implemented in development mode");
        Ok(vec![2, 1, 6, 0])
    }

    fn get_next_available_ip(&self) -> Result<Ipv4Addr> {
        let start_octets = self.range_start.octets();
        let end_octets = self.range_end.octets();
        
        if start_octets[3] < end_octets[3] {
            return Ok(Ipv4Addr::new(
                start_octets[0],
                start_octets[1],
                start_octets[2],
                start_octets[3] + 1,
            ));
        }
        
        Err(DlsError::Network("No available IP addresses".to_string()))
    }
}