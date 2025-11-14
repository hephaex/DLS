use crate::error::{DlsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub mac_address: [u8; 6],
    pub hostname: Option<String>,
    pub lease_time: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOptions {
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub lease_time: u32,
    pub tftp_server: Option<Ipv4Addr>,
    pub boot_filename: Option<String>,
    pub vendor_class_identifier: Option<String>,
}

#[derive(Debug)]
pub struct DhcpServer {
    range_start: Ipv4Addr,
    range_end: Ipv4Addr,
    options: DhcpOptions,
    leases: Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
    reservations: Arc<RwLock<HashMap<[u8; 6], Ipv4Addr>>>,
    running: bool,
}

// DHCP packet structure
#[derive(Debug)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: [u8; 4],
    secs: [u8; 2],
    flags: [u8; 2],
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    giaddr: [u8; 4],
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    options: Vec<u8>,
}

impl DhcpServer {
    pub fn new(range_start: Ipv4Addr, range_end: Ipv4Addr, options: DhcpOptions) -> Self {
        Self {
            range_start,
            range_end,
            options,
            leases: Arc::new(RwLock::new(HashMap::new())),
            reservations: Arc::new(RwLock::new(HashMap::new())),
            running: false,
        }
    }

    pub async fn add_reservation(&self, mac_address: [u8; 6], ip: Ipv4Addr) -> Result<()> {
        let mut reservations = self.reservations.write().await;
        reservations.insert(mac_address, ip);
        info!(
            "Added DHCP reservation: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {}",
            mac_address[0],
            mac_address[1],
            mac_address[2],
            mac_address[3],
            mac_address[4],
            mac_address[5],
            ip
        );
        Ok(())
    }

    pub async fn remove_reservation(&self, mac_address: [u8; 6]) -> Result<()> {
        let mut reservations = self.reservations.write().await;
        if reservations.remove(&mac_address).is_some() {
            info!(
                "Removed DHCP reservation for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac_address[0],
                mac_address[1],
                mac_address[2],
                mac_address[3],
                mac_address[4],
                mac_address[5]
            );
        }
        Ok(())
    }

    pub async fn get_leases(&self) -> HashMap<[u8; 6], DhcpLease> {
        self.leases.read().await.clone()
    }

    pub async fn cleanup_expired_leases(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut leases = self.leases.write().await;
        let initial_count = leases.len();

        leases.retain(|_, lease| lease.expires_at > now);

        let cleaned = initial_count - leases.len();
        if cleaned > 0 {
            info!("Cleaned up {} expired DHCP leases", cleaned);
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(DlsError::Network("DHCP server already running".to_string()));
        }

        info!(
            "Starting DHCP server on range {}-{}",
            self.range_start, self.range_end
        );
        info!(
            "DHCP options: server={}, subnet={}, gateway={:?}, DNS={:?}",
            self.options.server_ip,
            self.options.subnet_mask,
            self.options.gateway,
            self.options.dns_servers
        );

        if let Some(tftp_server) = self.options.tftp_server {
            info!(
                "PXE boot enabled: TFTP server={}, boot file={:?}",
                tftp_server, self.options.boot_filename
            );
        }

        let bind_addr: SocketAddr = "0.0.0.0:67".parse().unwrap();

        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| DlsError::Network(format!("Failed to bind DHCP socket: {e}")))?;

        socket
            .set_broadcast(true)
            .map_err(|e| DlsError::Network(format!("Failed to set broadcast: {e}")))?;

        let socket = tokio::net::UdpSocket::from_std(socket)
            .map_err(|e| DlsError::Network(format!("Failed to convert socket: {e}")))?;

        self.running = true;

        let server_arc = Arc::new(RwLock::new(DhcpServer {
            range_start: self.range_start,
            range_end: self.range_end,
            options: self.options.clone(),
            leases: self.leases.clone(),
            reservations: self.reservations.clone(),
            running: true,
        }));

        tokio::spawn(async move {
            Self::handle_dhcp_requests(Arc::new(socket), server_arc).await;
        });

        info!("DHCP server started successfully on port 67");
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

    async fn handle_dhcp_requests(
        socket: Arc<tokio::net::UdpSocket>,
        server: Arc<RwLock<DhcpServer>>,
    ) {
        let mut buf = [0u8; 1024];

        // Start cleanup task
        let cleanup_server = server.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                cleanup_server.read().await.cleanup_expired_leases().await;
            }
        });

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    debug!("Received DHCP packet from {}: {} bytes", addr, len);

                    let server_clone = server.clone();
                    let data = buf[..len].to_vec();

                    let socket_clone = socket.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::process_dhcp_packet(&data, addr, &socket_clone, server_clone)
                                .await
                        {
                            error!("Failed to process DHCP packet: {}", e);
                        }
                    });
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
        _client_addr: SocketAddr,
        socket: &tokio::net::UdpSocket,
        server: Arc<RwLock<DhcpServer>>,
    ) -> Result<()> {
        if data.len() < 240 {
            debug!("DHCP packet too small: {} bytes", data.len());
            return Ok(());
        }

        // Parse DHCP packet
        let dhcp_packet = Self::parse_dhcp_packet(data)?;

        // Extract client MAC address from hardware address field
        let client_mac = [
            dhcp_packet.chaddr[0],
            dhcp_packet.chaddr[1],
            dhcp_packet.chaddr[2],
            dhcp_packet.chaddr[3],
            dhcp_packet.chaddr[4],
            dhcp_packet.chaddr[5],
        ];

        debug!(
            "DHCP request from MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            client_mac[0],
            client_mac[1],
            client_mac[2],
            client_mac[3],
            client_mac[4],
            client_mac[5]
        );

        // Process based on message type
        let message_type = Self::get_dhcp_message_type(&dhcp_packet.options)?;

        match message_type {
            1 => {
                // DHCP DISCOVER
                info!(
                    "Processing DHCP DISCOVER from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    client_mac[0],
                    client_mac[1],
                    client_mac[2],
                    client_mac[3],
                    client_mac[4],
                    client_mac[5]
                );
                Self::handle_dhcp_discover(&dhcp_packet, client_mac, socket, server).await?
            }
            3 => {
                // DHCP REQUEST
                info!(
                    "Processing DHCP REQUEST from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    client_mac[0],
                    client_mac[1],
                    client_mac[2],
                    client_mac[3],
                    client_mac[4],
                    client_mac[5]
                );
                Self::handle_dhcp_request(&dhcp_packet, client_mac, socket, server).await?
            }
            7 => {
                // DHCP RELEASE
                info!(
                    "Processing DHCP RELEASE from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    client_mac[0],
                    client_mac[1],
                    client_mac[2],
                    client_mac[3],
                    client_mac[4],
                    client_mac[5]
                );
                Self::handle_dhcp_release(&dhcp_packet, client_mac, server).await?
            }
            _ => {
                debug!("Unhandled DHCP message type: {}", message_type);
            }
        }

        Ok(())
    }

    async fn handle_dhcp_discover(
        request: &DhcpPacket,
        client_mac: [u8; 6],
        socket: &tokio::net::UdpSocket,
        server: Arc<RwLock<DhcpServer>>,
    ) -> Result<()> {
        let server_guard = server.read().await;

        // Check for existing lease or reservation
        let offered_ip =
            if let Some(reserved_ip) = server_guard.reservations.read().await.get(&client_mac) {
                *reserved_ip
            } else if let Some(existing_lease) = server_guard.leases.read().await.get(&client_mac) {
                existing_lease.ip
            } else {
                server_guard.get_next_available_ip().await?
            };

        // Create DHCP OFFER response
        let offer = Self::create_dhcp_offer(request, offered_ip, &server_guard.options)?;

        // Send broadcast response
        let broadcast_addr: SocketAddr = "255.255.255.255:68".parse().unwrap();
        socket
            .send_to(&offer, broadcast_addr)
            .await
            .map_err(|e| DlsError::Network(format!("Failed to send DHCP OFFER: {e}")))?;

        info!(
            "Sent DHCP OFFER: {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            offered_ip,
            client_mac[0],
            client_mac[1],
            client_mac[2],
            client_mac[3],
            client_mac[4],
            client_mac[5]
        );

        Ok(())
    }

    async fn handle_dhcp_request(
        request: &DhcpPacket,
        client_mac: [u8; 6],
        socket: &tokio::net::UdpSocket,
        server: Arc<RwLock<DhcpServer>>,
    ) -> Result<()> {
        let server_guard = server.read().await;

        // Extract requested IP from options
        let requested_ip = Self::get_requested_ip(&request.options).unwrap_or_else(|| {
            Ipv4Addr::new(
                request.ciaddr[0],
                request.ciaddr[1],
                request.ciaddr[2],
                request.ciaddr[3],
            )
        });

        // Validate the request
        if !server_guard.is_ip_available(requested_ip, client_mac).await {
            // Send DHCP NAK
            let nak = Self::create_dhcp_nak(request)?;
            let broadcast_addr: SocketAddr = "255.255.255.255:68".parse().unwrap();
            socket
                .send_to(&nak, broadcast_addr)
                .await
                .map_err(|e| DlsError::Network(format!("Failed to send DHCP NAK: {e}")))?;

            warn!(
                "Sent DHCP NAK to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} for IP {}",
                client_mac[0],
                client_mac[1],
                client_mac[2],
                client_mac[3],
                client_mac[4],
                client_mac[5],
                requested_ip
            );
            return Ok(());
        }

        // Create lease
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let lease = DhcpLease {
            ip: requested_ip,
            mac_address: client_mac,
            hostname: Self::get_hostname(&request.options),
            lease_time: server_guard.options.lease_time,
            issued_at: now,
            expires_at: now + server_guard.options.lease_time as u64,
        };

        // Store lease
        drop(server_guard); // Release read lock
        let server_write = server.write().await;
        server_write.leases.write().await.insert(client_mac, lease);
        drop(server_write);
        let server_guard = server.read().await;

        // Send DHCP ACK
        let ack = Self::create_dhcp_ack(request, requested_ip, &server_guard.options)?;
        let broadcast_addr: SocketAddr = "255.255.255.255:68".parse().unwrap();
        socket
            .send_to(&ack, broadcast_addr)
            .await
            .map_err(|e| DlsError::Network(format!("Failed to send DHCP ACK: {e}")))?;

        info!(
            "Sent DHCP ACK: {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (lease: {} seconds)",
            requested_ip,
            client_mac[0],
            client_mac[1],
            client_mac[2],
            client_mac[3],
            client_mac[4],
            client_mac[5],
            server_guard.options.lease_time
        );

        Ok(())
    }

    async fn handle_dhcp_release(
        _request: &DhcpPacket,
        client_mac: [u8; 6],
        server: Arc<RwLock<DhcpServer>>,
    ) -> Result<()> {
        let server_guard = server.read().await;
        let mut leases = server_guard.leases.write().await;

        if let Some(lease) = leases.remove(&client_mac) {
            info!(
                "Released DHCP lease: {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                lease.ip,
                client_mac[0],
                client_mac[1],
                client_mac[2],
                client_mac[3],
                client_mac[4],
                client_mac[5]
            );
        }

        Ok(())
    }

    async fn get_next_available_ip(&self) -> Result<Ipv4Addr> {
        let leases = self.leases.read().await;
        let reservations = self.reservations.read().await;

        let start = u32::from(self.range_start);
        let end = u32::from(self.range_end);

        for ip_u32 in start..=end {
            let ip = Ipv4Addr::from(ip_u32);

            // Skip if IP is already leased (not expired)
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let is_leased = leases
                .values()
                .any(|lease| lease.ip == ip && lease.expires_at > now);

            // Skip if IP is reserved for a different MAC
            let is_reserved = reservations.values().any(|&reserved_ip| reserved_ip == ip);

            if !is_leased && !is_reserved {
                return Ok(ip);
            }
        }

        Err(DlsError::Network(
            "No available IP addresses in range".to_string(),
        ))
    }

    async fn is_ip_available(&self, ip: Ipv4Addr, client_mac: [u8; 6]) -> bool {
        // Check if IP is in our range
        let ip_u32 = u32::from(ip);
        let start = u32::from(self.range_start);
        let end = u32::from(self.range_end);

        if ip_u32 < start || ip_u32 > end {
            return false;
        }

        let reservations = self.reservations.read().await;
        let leases = self.leases.read().await;

        // Check if IP is reserved for this MAC
        if let Some(&reserved_ip) = reservations.get(&client_mac) {
            if reserved_ip == ip {
                return true; // IP is reserved for this MAC
            }
        }

        // Check if IP is reserved for another MAC
        for (&other_mac, &reserved_ip) in reservations.iter() {
            if reserved_ip == ip && other_mac != client_mac {
                return false; // IP is reserved for another MAC
            }
        }

        // Check if IP is already leased to someone else
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for lease in leases.values() {
            if lease.ip == ip && lease.expires_at > now && lease.mac_address != client_mac {
                return false; // IP is leased to another MAC
            }
        }

        true // IP is available
    }

    // DHCP packet parsing and creation methods
    fn parse_dhcp_packet(data: &[u8]) -> Result<DhcpPacket> {
        if data.len() < 240 {
            return Err(DlsError::Network("DHCP packet too short".to_string()));
        }

        let mut packet = DhcpPacket {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid: [data[4], data[5], data[6], data[7]],
            secs: [data[8], data[9]],
            flags: [data[10], data[11]],
            ciaddr: [data[12], data[13], data[14], data[15]],
            yiaddr: [data[16], data[17], data[18], data[19]],
            siaddr: [data[20], data[21], data[22], data[23]],
            giaddr: [data[24], data[25], data[26], data[27]],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            options: Vec::new(),
        };

        packet.chaddr.copy_from_slice(&data[28..44]);
        packet.sname.copy_from_slice(&data[44..108]);
        packet.file.copy_from_slice(&data[108..236]);

        if data.len() > 240 && data[236..240] == [99, 130, 83, 99] {
            packet.options = data[240..].to_vec();
        }

        Ok(packet)
    }

    fn get_dhcp_message_type(options: &[u8]) -> Result<u8> {
        let mut i = 0;
        while i < options.len() {
            if options[i] == 255 {
                break;
            }
            if options[i] == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= options.len() {
                break;
            }

            let option_type = options[i];
            let option_len = options[i + 1] as usize;

            if option_type == 53 && option_len == 1 && i + 2 < options.len() {
                return Ok(options[i + 2]);
            }

            i += 2 + option_len;
        }

        Err(DlsError::Network("DHCP message type not found".to_string()))
    }

    fn get_requested_ip(options: &[u8]) -> Option<Ipv4Addr> {
        let mut i = 0;
        while i < options.len() {
            if options[i] == 255 {
                break;
            }
            if options[i] == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= options.len() {
                break;
            }

            let option_type = options[i];
            let option_len = options[i + 1] as usize;

            if option_type == 50 && option_len == 4 && i + 5 < options.len() {
                return Some(Ipv4Addr::new(
                    options[i + 2],
                    options[i + 3],
                    options[i + 4],
                    options[i + 5],
                ));
            }

            i += 2 + option_len;
        }
        None
    }

    fn get_hostname(options: &[u8]) -> Option<String> {
        let mut i = 0;
        while i < options.len() {
            if options[i] == 255 {
                break;
            }
            if options[i] == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= options.len() {
                break;
            }

            let option_type = options[i];
            let option_len = options[i + 1] as usize;

            if option_type == 12 && option_len > 0 && i + 2 + option_len <= options.len() {
                let hostname_bytes = &options[i + 2..i + 2 + option_len];
                return String::from_utf8(hostname_bytes.to_vec()).ok();
            }

            i += 2 + option_len;
        }
        None
    }

    fn create_dhcp_offer(
        request: &DhcpPacket,
        offered_ip: Ipv4Addr,
        options: &DhcpOptions,
    ) -> Result<Vec<u8>> {
        let mut response = vec![0u8; 576];

        // Basic DHCP header
        response[0] = 2; // BOOTREPLY
        response[1] = request.htype;
        response[2] = request.hlen;
        response[3] = 0;
        response[4..8].copy_from_slice(&request.xid);
        response[8..10].copy_from_slice(&[0, 0]);
        response[10..12].copy_from_slice(&request.flags);
        response[12..16].copy_from_slice(&[0, 0, 0, 0]);

        let ip_octets = offered_ip.octets();
        response[16..20].copy_from_slice(&ip_octets);

        let server_octets = options.server_ip.octets();
        response[20..24].copy_from_slice(&server_octets);

        response[24..28].copy_from_slice(&request.giaddr);
        response[28..44].copy_from_slice(&request.chaddr);

        // DHCP magic cookie
        response[236..240].copy_from_slice(&[99, 130, 83, 99]);

        let mut option_offset = 240;

        // DHCP Message Type = OFFER (2)
        response[option_offset] = 53;
        response[option_offset + 1] = 1;
        response[option_offset + 2] = 2;
        option_offset += 3;

        // Subnet Mask
        response[option_offset] = 1;
        response[option_offset + 1] = 4;
        response[option_offset + 2..option_offset + 6]
            .copy_from_slice(&options.subnet_mask.octets());
        option_offset += 6;

        // Lease Time
        response[option_offset] = 51;
        response[option_offset + 1] = 4;
        let lease_bytes = options.lease_time.to_be_bytes();
        response[option_offset + 2..option_offset + 6].copy_from_slice(&lease_bytes);
        option_offset += 6;

        // Server Identifier
        response[option_offset] = 54;
        response[option_offset + 1] = 4;
        response[option_offset + 2..option_offset + 6].copy_from_slice(&server_octets);
        option_offset += 6;

        // Gateway/Router
        if let Some(gateway) = options.gateway {
            response[option_offset] = 3;
            response[option_offset + 1] = 4;
            response[option_offset + 2..option_offset + 6].copy_from_slice(&gateway.octets());
            option_offset += 6;
        }

        // DNS Servers
        if !options.dns_servers.is_empty() {
            response[option_offset] = 6;
            response[option_offset + 1] = (options.dns_servers.len() * 4) as u8;
            option_offset += 2;
            for dns in &options.dns_servers {
                response[option_offset..option_offset + 4].copy_from_slice(&dns.octets());
                option_offset += 4;
            }
        }

        // PXE Options for network boot
        if let Some(tftp_server) = options.tftp_server {
            response[20..24].copy_from_slice(&tftp_server.octets());

            if let Some(ref boot_filename) = options.boot_filename {
                let filename_bytes = boot_filename.as_bytes();
                let copy_len = std::cmp::min(filename_bytes.len(), 127);
                response[108..108 + copy_len].copy_from_slice(&filename_bytes[..copy_len]);
            }

            response[option_offset] = 66;
            let tftp_str = tftp_server.to_string();
            let tftp_bytes = tftp_str.as_bytes();
            response[option_offset + 1] = tftp_bytes.len() as u8;
            response[option_offset + 2..option_offset + 2 + tftp_bytes.len()]
                .copy_from_slice(tftp_bytes);
            option_offset += 2 + tftp_bytes.len();
        }

        // Domain name
        if let Some(ref domain) = options.domain_name {
            response[option_offset] = 15;
            let domain_bytes = domain.as_bytes();
            response[option_offset + 1] = domain_bytes.len() as u8;
            response[option_offset + 2..option_offset + 2 + domain_bytes.len()]
                .copy_from_slice(domain_bytes);
            option_offset += 2 + domain_bytes.len();
        }

        // End option
        response[option_offset] = 255;

        Ok(response[..option_offset + 1].to_vec())
    }

    fn create_dhcp_ack(
        request: &DhcpPacket,
        client_ip: Ipv4Addr,
        options: &DhcpOptions,
    ) -> Result<Vec<u8>> {
        let mut ack = Self::create_dhcp_offer(request, client_ip, options)?;

        // Change message type from OFFER (2) to ACK (5)
        for i in 240..ack.len() - 2 {
            if ack[i] == 53 && ack[i + 1] == 1 {
                ack[i + 2] = 5;
                break;
            }
        }

        Ok(ack)
    }

    fn create_dhcp_nak(request: &DhcpPacket) -> Result<Vec<u8>> {
        let mut response = vec![0u8; 300];

        response[0] = 2; // BOOTREPLY
        response[1] = request.htype;
        response[2] = request.hlen;
        response[3] = 0;
        response[4..8].copy_from_slice(&request.xid);
        response[28..44].copy_from_slice(&request.chaddr);

        // DHCP magic cookie
        response[236..240].copy_from_slice(&[99, 130, 83, 99]);

        // DHCP Message Type = NAK (6)
        response[240] = 53;
        response[241] = 1;
        response[242] = 6;

        // End option
        response[243] = 255;

        Ok(response[..244].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_dhcp_options() -> DhcpOptions {
        DhcpOptions {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            domain_name: Some("test.local".to_string()),
            lease_time: 3600,
            tftp_server: Some(Ipv4Addr::new(192, 168, 1, 1)),
            boot_filename: Some("pxelinux.0".to_string()),
            vendor_class_identifier: None,
        }
    }

    #[test]
    fn test_dhcp_lease_creation() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let lease_time = 3600;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lease = DhcpLease {
            ip,
            mac_address: mac,
            hostname: Some("test-host".to_string()),
            lease_time,
            issued_at: now,
            expires_at: now + lease_time as u64,
        };

        assert_eq!(lease.ip, ip);
        assert_eq!(lease.mac_address, mac);
        assert_eq!(lease.hostname, Some("test-host".to_string()));
        assert_eq!(lease.lease_time, lease_time);
        assert!(lease.expires_at > now); // Should not be expired immediately
    }

    #[test]
    fn test_dhcp_server_creation() {
        let range_start = Ipv4Addr::new(192, 168, 1, 100);
        let range_end = Ipv4Addr::new(192, 168, 1, 200);
        let options = create_test_dhcp_options();

        let server = DhcpServer::new(range_start, range_end, options.clone());

        assert_eq!(server.range_start, range_start);
        assert_eq!(server.range_end, range_end);
        assert_eq!(server.options.server_ip, options.server_ip);
        assert!(!server.running);
    }

    #[tokio::test]
    async fn test_dhcp_reservation_management() {
        let range_start = Ipv4Addr::new(192, 168, 1, 100);
        let range_end = Ipv4Addr::new(192, 168, 1, 200);
        let options = create_test_dhcp_options();
        let server = DhcpServer::new(range_start, range_end, options);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let reserved_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Add reservation
        server.add_reservation(mac, reserved_ip).await.unwrap();

        // Check reservation exists
        let reservations = server.reservations.read().await;
        assert_eq!(reservations.get(&mac), Some(&reserved_ip));
        drop(reservations);

        // Remove reservation
        server.remove_reservation(mac).await.unwrap();

        // Check reservation removed
        let reservations = server.reservations.read().await;
        assert_eq!(reservations.get(&mac), None);
    }

    #[tokio::test]
    async fn test_ip_allocation() {
        let range_start = Ipv4Addr::new(192, 168, 1, 100);
        let range_end = Ipv4Addr::new(192, 168, 1, 102);
        let options = create_test_dhcp_options();
        let server = DhcpServer::new(range_start, range_end, options);

        // Should be able to allocate first IP
        let ip1 = server.get_next_available_ip().await.unwrap();
        assert!(ip1 >= range_start && ip1 <= range_end);

        // Create a lease for first IP
        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lease1 = DhcpLease {
            ip: ip1,
            mac_address: mac1,
            hostname: None,
            lease_time: 3600,
            issued_at: now,
            expires_at: now + 3600,
        };
        server.leases.write().await.insert(mac1, lease1);

        // Should be able to allocate second IP
        let ip2 = server.get_next_available_ip().await.unwrap();
        assert_ne!(ip1, ip2);
        assert!(ip2 >= range_start && ip2 <= range_end);
    }

    #[tokio::test]
    async fn test_lease_cleanup() {
        let range_start = Ipv4Addr::new(192, 168, 1, 100);
        let range_end = Ipv4Addr::new(192, 168, 1, 200);
        let options = create_test_dhcp_options();
        let server = DhcpServer::new(range_start, range_end, options);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create expired lease
        let expired_lease = DhcpLease {
            ip,
            mac_address: mac,
            hostname: None,
            lease_time: 1,
            issued_at: now - 10,
            expires_at: now - 5, // Expired 5 seconds ago
        };

        server.leases.write().await.insert(mac, expired_lease);
        assert_eq!(server.leases.read().await.len(), 1);

        // Clean up expired leases
        server.cleanup_expired_leases().await;
        assert_eq!(server.leases.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_ip_availability_check() {
        let range_start = Ipv4Addr::new(192, 168, 1, 100);
        let range_end = Ipv4Addr::new(192, 168, 1, 200);
        let options = create_test_dhcp_options();
        let server = DhcpServer::new(range_start, range_end, options);

        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x56];
        let ip = Ipv4Addr::new(192, 168, 1, 150);

        // IP should be available initially
        assert!(server.is_ip_available(ip, mac1).await);

        // Add reservation for mac1
        server.reservations.write().await.insert(mac1, ip);

        // IP should be available for mac1 (reserved) but not mac2
        assert!(server.is_ip_available(ip, mac1).await);
        assert!(!server.is_ip_available(ip, mac2).await);

        // IP outside range should not be available
        let out_of_range_ip = Ipv4Addr::new(192, 168, 2, 1);
        assert!(!server.is_ip_available(out_of_range_ip, mac1).await);
    }

    #[test]
    fn test_dhcp_packet_parsing() {
        let mut packet_data = vec![0u8; 300];

        // Fill basic DHCP header
        packet_data[0] = 1; // BOOTREQUEST
        packet_data[1] = 1; // Ethernet
        packet_data[2] = 6; // Hardware address length
        packet_data[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]); // XID

        // Client hardware address (MAC)
        packet_data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // DHCP magic cookie
        packet_data[236..240].copy_from_slice(&[99, 130, 83, 99]);

        // DHCP Message Type option (Discover = 1)
        packet_data[240] = 53; // Option 53 (Message Type)
        packet_data[241] = 1; // Length
        packet_data[242] = 1; // DHCP Discover

        // End option
        packet_data[243] = 255;

        let parsed = DhcpServer::parse_dhcp_packet(&packet_data).unwrap();

        assert_eq!(parsed.op, 1);
        assert_eq!(parsed.htype, 1);
        assert_eq!(parsed.hlen, 6);
        assert_eq!(parsed.xid, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&parsed.chaddr[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let message_type = DhcpServer::get_dhcp_message_type(&parsed.options).unwrap();
        assert_eq!(message_type, 1); // DHCP Discover
    }

    #[test]
    fn test_dhcp_offer_creation() {
        let mut request_packet = DhcpPacket {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: [0x12, 0x34, 0x56, 0x78],
            secs: [0, 0],
            flags: [0, 0],
            ciaddr: [0, 0, 0, 0],
            yiaddr: [0, 0, 0, 0],
            siaddr: [0, 0, 0, 0],
            giaddr: [0, 0, 0, 0],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            options: vec![53, 1, 1, 255], // DHCP Discover + End
        };
        request_packet.chaddr[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let offered_ip = Ipv4Addr::new(192, 168, 1, 100);
        let options = create_test_dhcp_options();

        let offer = DhcpServer::create_dhcp_offer(&request_packet, offered_ip, &options).unwrap();

        // Check basic structure
        assert!(offer.len() > 240);
        assert_eq!(offer[0], 2); // BOOTREPLY
        assert_eq!(offer[16..20], offered_ip.octets()); // yiaddr
        assert_eq!(offer[236..240], [99, 130, 83, 99]); // Magic cookie

        // Check for DHCP Offer message type
        let mut found_offer_type = false;
        let mut i = 240;
        while i < offer.len() - 2 {
            if offer[i] == 53 && offer[i + 1] == 1 && offer[i + 2] == 2 {
                found_offer_type = true;
                break;
            }
            if offer[i] == 255 {
                break;
            }
            if offer[i] == 0 {
                i += 1;
                continue;
            }
            if i + 1 < offer.len() {
                i += 2 + offer[i + 1] as usize;
            } else {
                break;
            }
        }
        assert!(found_offer_type, "DHCP Offer message type not found");
    }

    #[test]
    fn test_requested_ip_parsing() {
        let options = vec![
            50, 4, 192, 168, 1, 100, // Requested IP Address option
            255, // End option
        ];

        let requested_ip = DhcpServer::get_requested_ip(&options);
        assert_eq!(requested_ip, Some(Ipv4Addr::new(192, 168, 1, 100)));

        // Test with no requested IP option
        let empty_options = vec![255];
        let no_ip = DhcpServer::get_requested_ip(&empty_options);
        assert_eq!(no_ip, None);
    }

    #[test]
    fn test_hostname_parsing() {
        let hostname = "test-client";
        let mut options = vec![
            12,
            hostname.len() as u8, // Hostname option
        ];
        options.extend_from_slice(hostname.as_bytes());
        options.push(255); // End option

        let parsed_hostname = DhcpServer::get_hostname(&options);
        assert_eq!(parsed_hostname, Some("test-client".to_string()));

        // Test with no hostname option
        let empty_options = vec![255];
        let no_hostname = DhcpServer::get_hostname(&empty_options);
        assert_eq!(no_hostname, None);
    }

    #[test]
    fn test_dhcp_nak_creation() {
        let request_packet = DhcpPacket {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: [0x12, 0x34, 0x56, 0x78],
            secs: [0, 0],
            flags: [0, 0],
            ciaddr: [192, 168, 1, 50],
            yiaddr: [0, 0, 0, 0],
            siaddr: [0, 0, 0, 0],
            giaddr: [0, 0, 0, 0],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            options: vec![53, 1, 3, 255], // DHCP Request + End
        };

        let nak = DhcpServer::create_dhcp_nak(&request_packet).unwrap();

        assert_eq!(nak[0], 2); // BOOTREPLY
        assert_eq!(nak[4..8], [0x12, 0x34, 0x56, 0x78]); // Same XID
        assert_eq!(nak[236..240], [99, 130, 83, 99]); // Magic cookie
        assert_eq!(nak[240], 53); // Message Type option
        assert_eq!(nak[241], 1); // Length
        assert_eq!(nak[242], 6); // DHCP NAK
        assert_eq!(nak[243], 255); // End option
    }

    #[test]
    fn test_dhcp_options_default() {
        let options = DhcpOptions {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            domain_name: Some("dls.local".to_string()),
            lease_time: 3600,
            tftp_server: Some(Ipv4Addr::new(192, 168, 1, 1)),
            boot_filename: Some("pxelinux.0".to_string()),
            vendor_class_identifier: None,
        };

        assert_eq!(options.server_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(options.lease_time, 3600);
        assert!(options.tftp_server.is_some());
        assert!(options.boot_filename.is_some());
    }
}
