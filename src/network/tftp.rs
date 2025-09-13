use crate::error::{DlsError, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

/// TFTP opcodes as defined in RFC 1350
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpOpcode {
    ReadRequest = 1,   // RRQ
    WriteRequest = 2,  // WRQ  
    Data = 3,          // DATA
    Ack = 4,           // ACK
    Error = 5,         // ERROR
    OptionAck = 6,     // OACK (RFC 2347)
}

impl TryFrom<u16> for TftpOpcode {
    type Error = DlsError;
    
    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(TftpOpcode::ReadRequest),
            2 => Ok(TftpOpcode::WriteRequest),
            3 => Ok(TftpOpcode::Data),
            4 => Ok(TftpOpcode::Ack),
            5 => Ok(TftpOpcode::Error),
            6 => Ok(TftpOpcode::OptionAck),
            _ => Err(DlsError::Network(format!("Invalid TFTP opcode: {}", value))),
        }
    }
}

/// TFTP error codes as defined in RFC 1350
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpErrorCode {
    NotDefined = 0,
    FileNotFound = 1,
    AccessViolation = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTransferId = 5,
    FileAlreadyExists = 6,
    NoSuchUser = 7,
    OptionNegotiation = 8,
}

/// TFTP transfer modes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftpMode {
    Netascii,
    Octet,
    Mail, // Obsolete but part of RFC
}

impl TftpMode {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "netascii" => Ok(TftpMode::Netascii),
            "octet" | "binary" => Ok(TftpMode::Octet),
            "mail" => Ok(TftpMode::Mail),
            _ => Err(DlsError::Network(format!("Invalid TFTP mode: {}", s))),
        }
    }
}

/// TFTP packet structure
#[derive(Debug, Clone)]
pub struct TftpPacket {
    pub opcode: TftpOpcode,
    pub data: Vec<u8>,
}

impl TftpPacket {
    /// Parse a TFTP packet from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(DlsError::Network("TFTP packet too short".to_string()));
        }
        
        let opcode = u16::from_be_bytes([data[0], data[1]]);
        let opcode = TftpOpcode::try_from(opcode)?;
        
        Ok(TftpPacket {
            opcode,
            data: data[2..].to_vec(),
        })
    }
    
    /// Convert packet to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.opcode as u16).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
    
    /// Create a read request packet
    pub fn read_request(filename: &str, mode: TftpMode, options: &HashMap<String, String>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(filename.as_bytes());
        data.push(0); // Null terminator
        
        let mode_str = match mode {
            TftpMode::Netascii => "netascii",
            TftpMode::Octet => "octet",
            TftpMode::Mail => "mail",
        };
        data.extend_from_slice(mode_str.as_bytes());
        data.push(0); // Null terminator
        
        // Add options
        for (key, value) in options {
            data.extend_from_slice(key.as_bytes());
            data.push(0);
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        
        TftpPacket {
            opcode: TftpOpcode::ReadRequest,
            data,
        }
    }
    
    /// Create a data packet
    pub fn data(block_number: u16, data: &[u8]) -> Self {
        let mut packet_data = Vec::new();
        packet_data.extend_from_slice(&block_number.to_be_bytes());
        packet_data.extend_from_slice(data);
        
        TftpPacket {
            opcode: TftpOpcode::Data,
            data: packet_data,
        }
    }
    
    /// Create an ACK packet
    pub fn ack(block_number: u16) -> Self {
        TftpPacket {
            opcode: TftpOpcode::Ack,
            data: block_number.to_be_bytes().to_vec(),
        }
    }
    
    /// Create an error packet
    pub fn error(error_code: TftpErrorCode, message: &str) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&(error_code as u16).to_be_bytes());
        data.extend_from_slice(message.as_bytes());
        data.push(0); // Null terminator
        
        TftpPacket {
            opcode: TftpOpcode::Error,
            data,
        }
    }
    
    /// Create an Option ACK packet
    pub fn option_ack(options: &HashMap<String, String>) -> Self {
        let mut data = Vec::new();
        
        for (key, value) in options {
            data.extend_from_slice(key.as_bytes());
            data.push(0);
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        
        TftpPacket {
            opcode: TftpOpcode::OptionAck,
            data,
        }
    }
}

/// Active TFTP transfer session
#[derive(Debug, Clone)]
pub struct TftpSession {
    pub client_addr: SocketAddr,
    pub filename: String,
    pub mode: TftpMode,
    pub block_size: usize,
    pub timeout: Duration,
    pub transfer_size: Option<u64>,
    pub current_block: u16,
    pub file_size: u64,
    pub bytes_transferred: u64,
    pub created_at: u64,
    pub last_activity: u64,
}

impl TftpSession {
    pub fn new(client_addr: SocketAddr, filename: String, mode: TftpMode) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        Self {
            client_addr,
            filename,
            mode,
            block_size: 512, // Default TFTP block size
            timeout: Duration::from_secs(5),
            transfer_size: None,
            current_block: 0,
            file_size: 0,
            bytes_transferred: 0,
            created_at: now,
            last_activity: now,
        }
    }
    
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    }
    
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now - self.last_activity > 300 // 5 minutes timeout
    }
}

/// TFTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TftpConfig {
    pub bind_addr: SocketAddr,
    pub root_path: PathBuf,
    pub allow_read: bool,
    pub allow_write: bool,
    pub max_block_size: usize,
    pub timeout_seconds: u64,
    pub max_sessions: usize,
    pub allowed_extensions: Vec<String>,
    pub security_mode: TftpSecurityMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TftpSecurityMode {
    Permissive,  // Allow all requests
    Whitelist,   // Only allowed extensions
    Secure,      // Strict security checks
}

impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:69".parse().unwrap(),
            root_path: PathBuf::from("/var/lib/claude_dls/tftp"),
            allow_read: true,
            allow_write: false, // Disabled by default for security
            max_block_size: 65464, // RFC 2348 maximum
            timeout_seconds: 5,
            max_sessions: 100,
            allowed_extensions: vec![
                "pxe".to_string(),
                "0".to_string(), // pxelinux.0
                "efi".to_string(),
                "img".to_string(),
                "iso".to_string(),
                "kernel".to_string(),
                "initrd".to_string(),
            ],
            security_mode: TftpSecurityMode::Whitelist,
        }
    }
}

/// Main TFTP server structure
#[derive(Debug)]
pub struct TftpServer {
    config: TftpConfig,
    sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    running: bool,
}

impl TftpServer {
    pub fn new(root_path: String) -> Self {
        let mut config = TftpConfig::default();
        config.root_path = PathBuf::from(root_path);
        
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            running: false,
        }
    }
    
    pub fn with_config(config: TftpConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            running: false,
        }
    }
    
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(DlsError::Network("TFTP server already running".to_string()));
        }

        if !self.config.root_path.exists() {
            tokio::fs::create_dir_all(&self.config.root_path).await?;
        }

        info!("Starting TFTP server with root: {:?}", self.config.root_path);
        info!("TFTP security mode: {:?}", self.config.security_mode);
        info!("TFTP allowed extensions: {:?}", self.config.allowed_extensions);
        
        let config = self.config.clone();
        let sessions = self.sessions.clone();
        
        tokio::spawn(async move {
            if let Err(e) = Self::run_tftp_server(config, sessions).await {
                error!("TFTP server error: {}", e);
            }
        });

        self.running = true;
        info!("TFTP server started successfully on {}", self.config.bind_addr);
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

    async fn run_tftp_server(
        config: TftpConfig, 
        sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>
    ) -> Result<()> {
        let socket = UdpSocket::bind(config.bind_addr).await
            .map_err(|e| DlsError::Network(format!("Failed to bind TFTP socket: {}", e)))?;

        let socket = Arc::new(socket);
        info!("TFTP server listening on {}", config.bind_addr);
        
        // Start session cleanup task
        let cleanup_sessions = sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Cleanup every minute
            loop {
                interval.tick().await;
                let mut sessions_guard = cleanup_sessions.write().await;
                let initial_count = sessions_guard.len();
                sessions_guard.retain(|_, session| !session.is_expired());
                let cleaned = initial_count - sessions_guard.len();
                if cleaned > 0 {
                    info!("Cleaned up {} expired TFTP sessions", cleaned);
                }
            }
        });

        let mut buf = [0u8; 1024];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    debug!("TFTP request from {}: {} bytes", addr, len);
                    
                    let config_clone = config.clone();
                    let sessions_clone = sessions.clone();
                    let socket_clone = socket.clone();
                    let data = buf[..len].to_vec();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tftp_request(
                            &data, addr, &socket_clone, config_clone, sessions_clone
                        ).await {
                            error!("Failed to handle TFTP request from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to receive TFTP request: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_tftp_request(
        data: &[u8],
        client_addr: SocketAddr,
        socket: &UdpSocket,
        config: TftpConfig,
        sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    ) -> Result<()> {
        let packet = TftpPacket::parse(data)?;
        
        match packet.opcode {
            TftpOpcode::ReadRequest => {
                Self::handle_read_request(packet, client_addr, socket, config, sessions).await
            }
            TftpOpcode::WriteRequest => {
                Self::handle_write_request(packet, client_addr, socket, config, sessions).await
            }
            TftpOpcode::Ack => {
                Self::handle_ack(packet, client_addr, socket, config, sessions).await
            }
            TftpOpcode::Data => {
                Self::handle_data(packet, client_addr, socket, config, sessions).await
            }
            TftpOpcode::Error => {
                Self::handle_error(packet, client_addr, sessions).await
            }
            _ => {
                warn!("Unsupported TFTP opcode: {:?} from {}", packet.opcode, client_addr);
                Ok(())
            }
        }
    }
    
    async fn handle_read_request(
        packet: TftpPacket,
        client_addr: SocketAddr,
        socket: &UdpSocket,
        config: TftpConfig,
        sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    ) -> Result<()> {
        // Check if too many sessions
        {
            let sessions_guard = sessions.read().await;
            if sessions_guard.len() >= config.max_sessions {
                let error_packet = TftpPacket::error(TftpErrorCode::NotDefined, "Server too busy");
                socket.send_to(&error_packet.to_bytes(), client_addr).await?;
                return Ok(());
            }
        }
        
        // Parse filename and mode from packet data
        let data = &packet.data;
        let parts: Vec<&[u8]> = data.split(|&b| b == 0).collect();
        
        if parts.len() < 2 {
            let error_packet = TftpPacket::error(TftpErrorCode::IllegalOperation, "Invalid request format");
            socket.send_to(&error_packet.to_bytes(), client_addr).await?;
            return Ok(());
        }
        
        let filename = String::from_utf8_lossy(parts[0]).to_string();
        let mode_str = String::from_utf8_lossy(parts[1]).to_string();
        
        info!("TFTP read request from {}: {} (mode: {})", client_addr, filename, mode_str);
        
        // Security check: validate filename
        if !Self::is_filename_allowed(&filename, &config) {
            warn!("TFTP access denied for file '{}' from {}", filename, client_addr);
            let error_packet = TftpPacket::error(TftpErrorCode::AccessViolation, "Access denied");
            socket.send_to(&error_packet.to_bytes(), client_addr).await?;
            return Ok(());
        }
        
        let mode = TftpMode::from_str(&mode_str)?;
        
        // Parse options if present
        let mut options = HashMap::new();
        if parts.len() > 2 {
            for chunk in parts[2..].chunks(2) {
                if chunk.len() == 2 && !chunk[0].is_empty() && !chunk[1].is_empty() {
                    let key = String::from_utf8_lossy(chunk[0]).to_lowercase();
                    let value = String::from_utf8_lossy(chunk[1]).to_string();
                    options.insert(key, value);
                }
            }
        }
        
        // Construct full file path
        let file_path = config.root_path.join(&filename);
        
        // Security check: prevent directory traversal
        if !file_path.starts_with(&config.root_path) {
            warn!("Directory traversal attempt for '{}' from {}", filename, client_addr);
            let error_packet = TftpPacket::error(TftpErrorCode::AccessViolation, "Access denied");
            socket.send_to(&error_packet.to_bytes(), client_addr).await?;
            return Ok(());
        }
        
        // Check if file exists
        let metadata = match tokio::fs::metadata(&file_path).await {
            Ok(metadata) => metadata,
            Err(_) => {
                let error_packet = TftpPacket::error(TftpErrorCode::FileNotFound, "File not found");
                socket.send_to(&error_packet.to_bytes(), client_addr).await?;
                return Ok(());
            }
        };
        
        if !metadata.is_file() {
            let error_packet = TftpPacket::error(TftpErrorCode::AccessViolation, "Not a file");
            socket.send_to(&error_packet.to_bytes(), client_addr).await?;
            return Ok(());
        }
        
        // Create session
        let mut session = TftpSession::new(client_addr, filename.clone(), mode);
        session.file_size = metadata.len();
        
        // Handle options negotiation
        let mut response_options = HashMap::new();
        
        if let Some(blksize) = options.get("blksize") {
            if let Ok(size) = blksize.parse::<usize>() {
                if size >= 8 && size <= config.max_block_size {
                    session.block_size = size;
                    response_options.insert("blksize".to_string(), size.to_string());
                }
            }
        }
        
        if let Some(timeout) = options.get("timeout") {
            if let Ok(secs) = timeout.parse::<u64>() {
                if secs >= 1 && secs <= 60 {
                    session.timeout = Duration::from_secs(secs);
                    response_options.insert("timeout".to_string(), secs.to_string());
                }
            }
        }
        
        if options.contains_key("tsize") {
            response_options.insert("tsize".to_string(), session.file_size.to_string());
        }
        
        // Send OACK if options were negotiated
        if !response_options.is_empty() {
            let oack_packet = TftpPacket::option_ack(&response_options);
            socket.send_to(&oack_packet.to_bytes(), client_addr).await?;
            debug!("Sent OACK to {} with options: {:?}", client_addr, response_options);
        } else {
            // Send first data block
            Self::send_next_data_block(&file_path, &mut session, socket).await?;
        }
        
        // Store session
        {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.insert(client_addr, session);
        }
        
        Ok(())
    }
    
    async fn handle_write_request(
        _packet: TftpPacket,
        client_addr: SocketAddr,
        socket: &UdpSocket,
        config: TftpConfig,
        _sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    ) -> Result<()> {
        if !config.allow_write {
            warn!("TFTP write request denied from {}", client_addr);
            let error_packet = TftpPacket::error(TftpErrorCode::AccessViolation, "Write not allowed");
            socket.send_to(&error_packet.to_bytes(), client_addr).await?;
        } else {
            // For now, reject all write requests - would need additional security measures
            let error_packet = TftpPacket::error(TftpErrorCode::AccessViolation, "Write not implemented");
            socket.send_to(&error_packet.to_bytes(), client_addr).await?;
        }
        Ok(())
    }
    
    async fn handle_ack(
        packet: TftpPacket,
        client_addr: SocketAddr,
        socket: &UdpSocket,
        config: TftpConfig,
        sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    ) -> Result<()> {
        if packet.data.len() < 2 {
            return Ok(());
        }
        
        let block_number = u16::from_be_bytes([packet.data[0], packet.data[1]]);
        debug!("Received ACK for block {} from {}", block_number, client_addr);
        
        let mut sessions_guard = sessions.write().await;
        if let Some(session) = sessions_guard.get_mut(&client_addr) {
            session.update_activity();
            
            if block_number == session.current_block {
                // Send next data block - construct full path
                let file_path = config.root_path.join(&session.filename);
                if let Err(e) = Self::send_next_data_block(
                    &file_path, session, socket
                ).await {
                    error!("Failed to send next data block: {}", e);
                    sessions_guard.remove(&client_addr);
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_data(
        _packet: TftpPacket,
        client_addr: SocketAddr,
        socket: &UdpSocket,
        _config: TftpConfig,
        _sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    ) -> Result<()> {
        // Write requests not fully implemented for security reasons
        let error_packet = TftpPacket::error(TftpErrorCode::IllegalOperation, "Write not supported");
        socket.send_to(&error_packet.to_bytes(), client_addr).await?;
        Ok(())
    }
    
    async fn handle_error(
        packet: TftpPacket,
        client_addr: SocketAddr,
        sessions: Arc<RwLock<HashMap<SocketAddr, TftpSession>>>,
    ) -> Result<()> {
        if packet.data.len() >= 2 {
            let error_code = u16::from_be_bytes([packet.data[0], packet.data[1]]);
            let message = if packet.data.len() > 2 {
                String::from_utf8_lossy(&packet.data[2..]).to_string()
            } else {
                "Unknown error".to_string()
            };
            
            warn!("TFTP error from {}: code={}, message='{}'", client_addr, error_code, message);
        }
        
        // Remove session on error
        let mut sessions_guard = sessions.write().await;
        sessions_guard.remove(&client_addr);
        
        Ok(())
    }
    
    async fn send_next_data_block(
        file_path: &Path,
        session: &mut TftpSession,
        socket: &UdpSocket,
    ) -> Result<()> {
        session.current_block = session.current_block.wrapping_add(1);
        
        let mut file = File::open(file_path).await?;
        let seek_pos = (session.current_block as u64 - 1) * session.block_size as u64;
        file.seek(SeekFrom::Start(seek_pos)).await?;
        
        let mut buffer = vec![0u8; session.block_size];
        let bytes_read = file.read(&mut buffer).await?;
        buffer.truncate(bytes_read);
        
        let data_packet = TftpPacket::data(session.current_block, &buffer);
        socket.send_to(&data_packet.to_bytes(), session.client_addr).await?;
        
        session.bytes_transferred += bytes_read as u64;
        session.update_activity();
        
        debug!("Sent data block {} ({} bytes) to {}", 
               session.current_block, bytes_read, session.client_addr);
        
        // If this was the last block (less than block_size bytes), transfer is complete
        if bytes_read < session.block_size {
            info!("TFTP transfer completed: {} ({} bytes) to {}", 
                  session.filename, session.bytes_transferred, session.client_addr);
        }
        
        Ok(())
    }
    
    fn is_filename_allowed(filename: &str, config: &TftpConfig) -> bool {
        match config.security_mode {
            TftpSecurityMode::Permissive => true,
            TftpSecurityMode::Whitelist => {
                // Check file extension against whitelist
                if let Some(extension) = Path::new(filename).extension() {
                    let ext_str = extension.to_string_lossy().to_lowercase();
                    config.allowed_extensions.contains(&ext_str)
                } else {
                    // Allow files without extension if "0" is in whitelist (for pxelinux.0)
                    config.allowed_extensions.contains(&"0".to_string()) ||
                    filename.ends_with(".0") || filename.ends_with("pxelinux")
                }
            },
            TftpSecurityMode::Secure => {
                // Strict security: only specific known boot files
                let allowed_files = [
                    "pxelinux.0", "lpxelinux.0", "bootx64.efi", "grubx64.efi",
                    "kernel", "initrd.gz", "vmlinuz", "initrd.img"
                ];
                
                let basename = Path::new(filename).file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                    
                allowed_files.iter().any(|&f| basename.starts_with(f)) ||
                config.allowed_extensions.iter().any(|ext| basename.ends_with(ext))
            }
        }
    }
    
    pub async fn get_active_sessions(&self) -> usize {
        self.sessions.read().await.len()
    }
    
    pub async fn get_session_info(&self, client_addr: SocketAddr) -> Option<TftpSession> {
        self.sessions.read().await.get(&client_addr).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    
    #[test]
    fn test_tftp_opcode_conversion() {
        assert_eq!(TftpOpcode::try_from(1).unwrap(), TftpOpcode::ReadRequest);
        assert_eq!(TftpOpcode::try_from(2).unwrap(), TftpOpcode::WriteRequest);
        assert_eq!(TftpOpcode::try_from(3).unwrap(), TftpOpcode::Data);
        assert_eq!(TftpOpcode::try_from(4).unwrap(), TftpOpcode::Ack);
        assert_eq!(TftpOpcode::try_from(5).unwrap(), TftpOpcode::Error);
        assert_eq!(TftpOpcode::try_from(6).unwrap(), TftpOpcode::OptionAck);
        
        assert!(TftpOpcode::try_from(99).is_err());
    }
    
    #[test]
    fn test_tftp_mode_parsing() {
        assert_eq!(TftpMode::from_str("netascii").unwrap(), TftpMode::Netascii);
        assert_eq!(TftpMode::from_str("octet").unwrap(), TftpMode::Octet);
        assert_eq!(TftpMode::from_str("binary").unwrap(), TftpMode::Octet);
        assert_eq!(TftpMode::from_str("mail").unwrap(), TftpMode::Mail);
        
        assert!(TftpMode::from_str("invalid").is_err());
    }
    
    #[test]
    fn test_tftp_packet_parsing() {
        // Test RRQ packet
        let mut data = vec![0, 1]; // Opcode: RRQ
        data.extend_from_slice(b"filename.txt");
        data.push(0);
        data.extend_from_slice(b"octet");
        data.push(0);
        
        let packet = TftpPacket::parse(&data).unwrap();
        assert_eq!(packet.opcode, TftpOpcode::ReadRequest);
        assert_eq!(packet.data, b"filename.txt\0octet\0");
    }
    
    #[test]
    fn test_tftp_data_packet_creation() {
        let data_payload = b"Hello, TFTP!";
        let packet = TftpPacket::data(1, data_payload);
        
        assert_eq!(packet.opcode, TftpOpcode::Data);
        let bytes = packet.to_bytes();
        assert_eq!(&bytes[0..2], &[0, 3]); // DATA opcode
        assert_eq!(&bytes[2..4], &[0, 1]); // Block number
        assert_eq!(&bytes[4..], data_payload);
    }
    
    #[test]
    fn test_tftp_ack_packet_creation() {
        let packet = TftpPacket::ack(42);
        
        assert_eq!(packet.opcode, TftpOpcode::Ack);
        let bytes = packet.to_bytes();
        assert_eq!(&bytes[0..2], &[0, 4]); // ACK opcode
        assert_eq!(&bytes[2..4], &[0, 42]); // Block number
    }
    
    #[test]
    fn test_tftp_error_packet_creation() {
        let packet = TftpPacket::error(TftpErrorCode::FileNotFound, "File not found");
        
        assert_eq!(packet.opcode, TftpOpcode::Error);
        let bytes = packet.to_bytes();
        assert_eq!(&bytes[0..2], &[0, 5]); // ERROR opcode
        assert_eq!(&bytes[2..4], &[0, 1]); // Error code: File not found
        assert_eq!(&bytes[4..bytes.len()-1], b"File not found");
        assert_eq!(bytes[bytes.len()-1], 0); // Null terminator
    }
    
    #[test]
    fn test_tftp_session_creation() {
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let session = TftpSession::new(addr, "test.txt".to_string(), TftpMode::Octet);
        
        assert_eq!(session.client_addr, addr);
        assert_eq!(session.filename, "test.txt");
        assert_eq!(session.mode, TftpMode::Octet);
        assert_eq!(session.block_size, 512);
        assert_eq!(session.current_block, 0);
        assert!(!session.is_expired());
    }
    
    #[test]
    fn test_filename_security_permissive() {
        let mut config = TftpConfig::default();
        config.security_mode = TftpSecurityMode::Permissive;
        
        assert!(TftpServer::is_filename_allowed("any-file.txt", &config));
        assert!(TftpServer::is_filename_allowed("../etc/passwd", &config));
    }
    
    #[test]
    fn test_filename_security_whitelist() {
        let mut config = TftpConfig::default();
        config.security_mode = TftpSecurityMode::Whitelist;
        config.allowed_extensions = vec!["efi".to_string(), "0".to_string()];
        
        assert!(TftpServer::is_filename_allowed("bootx64.efi", &config));
        assert!(TftpServer::is_filename_allowed("pxelinux.0", &config));
        assert!(!TftpServer::is_filename_allowed("malicious.exe", &config));
    }
    
    #[test]
    fn test_filename_security_secure() {
        let mut config = TftpConfig::default();
        config.security_mode = TftpSecurityMode::Secure;
        
        assert!(TftpServer::is_filename_allowed("pxelinux.0", &config));
        assert!(TftpServer::is_filename_allowed("bootx64.efi", &config));
        assert!(TftpServer::is_filename_allowed("vmlinuz-5.4.0", &config));
        assert!(!TftpServer::is_filename_allowed("malicious.exe", &config));
        assert!(!TftpServer::is_filename_allowed("../etc/passwd", &config));
    }
    
    #[test]
    fn test_tftp_config_default() {
        let config = TftpConfig::default();
        
        assert_eq!(config.bind_addr.port(), 69);
        assert!(config.allow_read);
        assert!(!config.allow_write); // Security: write disabled by default
        assert_eq!(config.max_block_size, 65464);
        assert_eq!(config.security_mode, TftpSecurityMode::Whitelist);
        assert!(config.allowed_extensions.contains(&"efi".to_string()));
    }
    
    #[tokio::test]
    async fn test_tftp_server_creation() {
        let server = TftpServer::new("/tmp/tftp".to_string());
        
        assert!(!server.running);
        assert_eq!(server.get_active_sessions().await, 0);
    }
}