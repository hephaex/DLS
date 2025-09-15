use crate::error::{DlsError, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;

/// iSCSI protocol constants
const ISCSI_DEFAULT_PORT: u16 = 3260;
const ISCSI_HEADER_SIZE: usize = 48;
const ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH: u32 = 262144; // 256KB
const ISCSI_MAX_FIRST_BURST_LENGTH: u32 = 65536; // 64KB
const ISCSI_MAX_BURST_LENGTH: u32 = 262144; // 256KB

/// iSCSI PDU opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IscsiOpcode {
    NoOp = 0x00,
    ScsiCommand = 0x01,
    ScsiTaskManagement = 0x02,
    LoginRequest = 0x03,
    TextRequest = 0x04,
    ScsiDataOut = 0x05,
    LogoutRequest = 0x06,
    SnackRequest = 0x10,
    
    // Response opcodes
    NoOpIn = 0x20,
    ScsiResponse = 0x21,
    ScsiTaskManagementResponse = 0x22,
    LoginResponse = 0x23,
    TextResponse = 0x24,
    ScsiDataIn = 0x25,
    LogoutResponse = 0x26,
    R2T = 0x31,
    AsyncMessage = 0x32,
    Reject = 0x3f,
}

impl TryFrom<u8> for IscsiOpcode {
    type Error = DlsError;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(IscsiOpcode::NoOp),
            0x01 => Ok(IscsiOpcode::ScsiCommand),
            0x02 => Ok(IscsiOpcode::ScsiTaskManagement),
            0x03 => Ok(IscsiOpcode::LoginRequest),
            0x04 => Ok(IscsiOpcode::TextRequest),
            0x05 => Ok(IscsiOpcode::ScsiDataOut),
            0x06 => Ok(IscsiOpcode::LogoutRequest),
            0x10 => Ok(IscsiOpcode::SnackRequest),
            0x20 => Ok(IscsiOpcode::NoOpIn),
            0x21 => Ok(IscsiOpcode::ScsiResponse),
            0x22 => Ok(IscsiOpcode::ScsiTaskManagementResponse),
            0x23 => Ok(IscsiOpcode::LoginResponse),
            0x24 => Ok(IscsiOpcode::TextResponse),
            0x25 => Ok(IscsiOpcode::ScsiDataIn),
            0x26 => Ok(IscsiOpcode::LogoutResponse),
            0x31 => Ok(IscsiOpcode::R2T),
            0x32 => Ok(IscsiOpcode::AsyncMessage),
            0x3f => Ok(IscsiOpcode::Reject),
            _ => Err(DlsError::Network(format!("Invalid iSCSI opcode: {:#04x}", value))),
        }
    }
}

/// iSCSI login phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LoginPhase {
    SecurityNegotiation = 0,
    LoginOperationalNegotiation = 1,
    FullFeaturePhase = 3,
}

/// SCSI command status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScsiStatus {
    Good = 0x00,
    CheckCondition = 0x02,
    ConditionMet = 0x04,
    Busy = 0x08,
    IntermediateGood = 0x10,
    ReservationConflict = 0x18,
    TaskSetFull = 0x28,
    AcaActive = 0x30,
    TaskAborted = 0x40,
}

/// iSCSI Basic Header Segment (BHS)
#[derive(Debug, Clone)]
pub struct IscsiHeader {
    pub opcode: IscsiOpcode,
    pub immediate: bool,
    pub final_bit: bool,
    pub total_ahs_length: u8,
    pub data_segment_length: u32,
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub max_cmd_sn: u32,
    pub data: Vec<u8>,
}

impl IscsiHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < ISCSI_HEADER_SIZE {
            return Err(DlsError::Network("iSCSI header too short".to_string()));
        }
        
        let opcode = IscsiOpcode::try_from(data[0] & 0x3f)?;
        let immediate = (data[0] & 0x40) != 0;
        let final_bit = (data[0] & 0x80) != 0;
        let total_ahs_length = data[4];
        
        let data_segment_length = u32::from_be_bytes([0, data[5], data[6], data[7]]);
        
        let lun = u64::from_be_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15]
        ]);
        
        let initiator_task_tag = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let target_transfer_tag = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let cmd_sn = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        let exp_stat_sn = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        let max_cmd_sn = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        
        let payload = if data.len() > ISCSI_HEADER_SIZE {
            data[ISCSI_HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };
        
        Ok(IscsiHeader {
            opcode,
            immediate,
            final_bit,
            total_ahs_length,
            data_segment_length,
            lun,
            initiator_task_tag,
            target_transfer_tag,
            cmd_sn,
            exp_stat_sn,
            max_cmd_sn,
            data: payload,
        })
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = vec![0u8; ISCSI_HEADER_SIZE];
        
        header[0] = self.opcode as u8;
        if self.immediate { header[0] |= 0x40; }
        if self.final_bit { header[0] |= 0x80; }
        
        header[4] = self.total_ahs_length;
        
        let data_len_bytes = self.data_segment_length.to_be_bytes();
        header[5] = data_len_bytes[1];
        header[6] = data_len_bytes[2];
        header[7] = data_len_bytes[3];
        
        let lun_bytes = self.lun.to_be_bytes();
        header[8..16].copy_from_slice(&lun_bytes);
        
        header[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        header[20..24].copy_from_slice(&self.target_transfer_tag.to_be_bytes());
        header[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        header[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        header[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        
        header.extend_from_slice(&self.data);
        header
    }
}

/// iSCSI Logical Unit Number (LUN)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IscsiLun {
    pub lun_id: u32,
    pub target_name: String,
    pub image_path: PathBuf,
    pub size: u64,
    pub block_size: u32,
    pub read_only: bool,
    pub online: bool,
    pub created_at: u64,
}

impl IscsiLun {
    pub fn new(lun_id: u32, target_name: String, image_path: PathBuf) -> Result<Self> {
        let metadata = std::fs::metadata(&image_path)
            .map_err(|e| DlsError::Storage(format!("Cannot access image file: {}", e)))?;
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        Ok(Self {
            lun_id,
            target_name,
            image_path,
            size: metadata.len(),
            block_size: 512, // Standard block size
            read_only: false,
            online: true,
            created_at: now,
        })
    }
    
    pub fn block_count(&self) -> u64 {
        self.size / self.block_size as u64
    }
}

/// iSCSI session state
#[derive(Debug, Clone)]
pub struct IscsiSession {
    pub initiator_name: String,
    pub target_name: String,
    pub session_id: u64,
    pub client_addr: SocketAddr,
    pub login_phase: LoginPhase,
    pub authenticated: bool,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub max_cmd_sn: u32,
    pub created_at: u64,
    pub last_activity: u64,
}

impl IscsiSession {
    pub fn new(initiator_name: String, target_name: String, client_addr: SocketAddr) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let session_id = now; // Simple session ID generation
        
        Self {
            initiator_name,
            target_name,
            session_id,
            client_addr,
            login_phase: LoginPhase::SecurityNegotiation,
            authenticated: false,
            cmd_sn: 0,
            exp_stat_sn: 0,
            max_cmd_sn: 0,
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

/// iSCSI target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IscsiConfig {
    pub bind_addr: SocketAddr,
    pub target_name: String,
    pub max_sessions: usize,
    pub max_connections_per_session: usize,
    pub authentication_required: bool,
    pub chap_username: Option<String>,
    pub chap_password: Option<String>,
    pub max_recv_data_segment_length: u32,
    pub max_burst_length: u32,
    pub first_burst_length: u32,
    pub immediate_data: bool,
    pub initial_r2t: bool,
}

impl Default for IscsiConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], ISCSI_DEFAULT_PORT)),
            target_name: "iqn.2025-01.local.claude:target1".to_string(),
            max_sessions: 16,
            max_connections_per_session: 1,
            authentication_required: false, // Simplified for development
            chap_username: None,
            chap_password: None,
            max_recv_data_segment_length: ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH,
            max_burst_length: ISCSI_MAX_BURST_LENGTH,
            first_burst_length: ISCSI_MAX_FIRST_BURST_LENGTH,
            immediate_data: true,
            initial_r2t: true,
        }
    }
}

/// Main iSCSI target server
#[derive(Debug)]
pub struct IscsiTarget {
    config: IscsiConfig,
    luns: Arc<RwLock<HashMap<u32, IscsiLun>>>,
    sessions: Arc<RwLock<HashMap<u64, IscsiSession>>>,
    // Performance optimization: File handle cache to avoid repeated open/close
    file_cache: Arc<DashMap<PathBuf, Arc<RwLock<File>>>>,
    running: bool,
}

impl IscsiTarget {
    pub fn new(target_name: String) -> Self {
        let mut config = IscsiConfig::default();
        config.target_name = target_name;
        
        Self {
            config,
            luns: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            file_cache: Arc::new(DashMap::new()),
            running: false,
        }
    }
    
    pub fn with_config(config: IscsiConfig) -> Self {
        Self {
            config,
            luns: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            file_cache: Arc::new(DashMap::new()),
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(DlsError::Network("iSCSI target already running".to_string()));
        }

        info!("Starting iSCSI target: {}", self.config.target_name);
        info!("iSCSI target binding to: {}", self.config.bind_addr);
        
        let config = self.config.clone();
        let luns = self.luns.clone();
        let sessions = self.sessions.clone();
        let file_cache = self.file_cache.clone();
        
        tokio::spawn(async move {
            if let Err(e) = Self::run_iscsi_target(config, luns, sessions, file_cache).await {
                error!("iSCSI target error: {}", e);
            }
        });
        
        self.running = true;
        info!("iSCSI target started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        self.running = false;
        info!("iSCSI target stopped");
        Ok(())
    }

    pub async fn add_lun(&mut self, lun_id: u32, image_path: &str) -> Result<()> {
        let image_path = PathBuf::from(image_path);
        
        if !image_path.exists() {
            return Err(DlsError::Storage(format!("Image file does not exist: {}", image_path.display())));
        }
        
        let lun = IscsiLun::new(lun_id, self.config.target_name.clone(), image_path)?;
        
        info!("Adding LUN {}: {} ({} bytes, {} blocks)", 
              lun.lun_id, lun.image_path.display(), lun.size, lun.block_count());
        
        let mut luns_guard = self.luns.write().await;
        luns_guard.insert(lun_id, lun);
        
        Ok(())
    }

    pub async fn remove_lun(&mut self, lun_id: u32) -> Result<()> {
        let mut luns_guard = self.luns.write().await;
        
        if let Some(lun) = luns_guard.remove(&lun_id) {
            info!("Removed LUN {}: {}", lun_id, lun.image_path.display());
            Ok(())
        } else {
            Err(DlsError::Storage(format!("LUN {} not found", lun_id)))
        }
    }
    
    pub async fn list_luns(&self) -> Vec<IscsiLun> {
        self.luns.read().await.values().cloned().collect()
    }
    
    pub async fn get_active_sessions(&self) -> usize {
        self.sessions.read().await.len()
    }
    
    async fn run_iscsi_target(
        config: IscsiConfig,
        luns: Arc<RwLock<HashMap<u32, IscsiLun>>>,
        sessions: Arc<RwLock<HashMap<u64, IscsiSession>>>,
        file_cache: Arc<DashMap<PathBuf, Arc<RwLock<File>>>>,
    ) -> Result<()> {
        let listener = TcpListener::bind(config.bind_addr).await
            .map_err(|e| DlsError::Network(format!("Failed to bind iSCSI socket: {}", e)))?;
            
        info!("iSCSI target listening on {}", config.bind_addr);
        
        // Start session cleanup task
        let cleanup_sessions = sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut sessions_guard = cleanup_sessions.write().await;
                let initial_count = sessions_guard.len();
                sessions_guard.retain(|_, session| !session.is_expired());
                let cleaned = initial_count - sessions_guard.len();
                if cleaned > 0 {
                    info!("Cleaned up {} expired iSCSI sessions", cleaned);
                }
            }
        });
        
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New iSCSI connection from {}", addr);
                    
                    let config_clone = config.clone();
                    let luns_clone = luns.clone();
                    let sessions_clone = sessions.clone();
                    let file_cache_clone = file_cache.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream, addr, config_clone, luns_clone, sessions_clone, file_cache_clone
                        ).await {
                            error!("iSCSI connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept iSCSI connection: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_connection(
        mut stream: TcpStream,
        client_addr: SocketAddr,
        config: IscsiConfig,
        luns: Arc<RwLock<HashMap<u32, IscsiLun>>>,
        sessions: Arc<RwLock<HashMap<u64, IscsiSession>>>,
        file_cache: Arc<DashMap<PathBuf, Arc<RwLock<File>>>>,
    ) -> Result<()> {
        info!("Handling iSCSI connection from {}", client_addr);
        
        let mut buffer = vec![0u8; 8192];
        let mut session: Option<IscsiSession> = None;
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("iSCSI connection closed by client: {}", client_addr);
                    break;
                }
                Ok(len) => {
                    debug!("Received iSCSI PDU from {}: {} bytes", client_addr, len);
                    
                    if let Err(e) = Self::process_pdu(
                        &buffer[..len], &mut stream, client_addr, &config,
                        &luns, &sessions, &file_cache, &mut session
                    ).await {
                        error!("Error processing iSCSI PDU from {}: {}", client_addr, e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Error reading from iSCSI connection {}: {}", client_addr, e);
                    break;
                }
            }
        }
        
        // Clean up session on disconnect
        if let Some(session) = session {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&session.session_id);
            info!("iSCSI session {} terminated for {}", session.session_id, client_addr);
        }
        
        Ok(())
    }
    
    async fn process_pdu(
        data: &[u8],
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        config: &IscsiConfig,
        luns: &Arc<RwLock<HashMap<u32, IscsiLun>>>,
        sessions: &Arc<RwLock<HashMap<u64, IscsiSession>>>,
        file_cache: &Arc<DashMap<PathBuf, Arc<RwLock<File>>>>,
        session: &mut Option<IscsiSession>,
    ) -> Result<()> {
        let header = IscsiHeader::parse(data)?;
        
        match header.opcode {
            IscsiOpcode::LoginRequest => {
                Self::handle_login_request(header, stream, client_addr, config, sessions, session).await
            }
            IscsiOpcode::LogoutRequest => {
                Self::handle_logout_request(header, stream, sessions, session).await
            }
            IscsiOpcode::ScsiCommand => {
                Self::handle_scsi_command(header, stream, luns, file_cache, session).await
            }
            IscsiOpcode::NoOp => {
                Self::handle_noop(header, stream, session).await
            }
            _ => {
                warn!("Unhandled iSCSI opcode: {:?} from {}", header.opcode, client_addr);
                Ok(())
            }
        }
    }
    
    async fn handle_login_request(
        request: IscsiHeader,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        config: &IscsiConfig,
        sessions: &Arc<RwLock<HashMap<u64, IscsiSession>>>,
        session: &mut Option<IscsiSession>,
    ) -> Result<()> {
        info!("Processing iSCSI login request from {}", client_addr);
        
        // Parse login parameters (simplified)
        let login_data = String::from_utf8_lossy(&request.data);
        debug!("Login data: {}", login_data);
        
        // Extract initiator name and target name from login data
        let mut initiator_name = "unknown".to_string();
        let mut target_name = config.target_name.clone();
        
        for line in login_data.lines() {
            if line.starts_with("InitiatorName=") {
                initiator_name = line.strip_prefix("InitiatorName=").unwrap_or("unknown").to_string();
            } else if line.starts_with("TargetName=") {
                target_name = line.strip_prefix("TargetName=").unwrap_or(&config.target_name).to_string();
            }
        }
        
        // Create session
        let mut new_session = IscsiSession::new(initiator_name.clone(), target_name.clone(), client_addr);
        new_session.login_phase = LoginPhase::FullFeaturePhase; // Skip authentication for simplicity
        new_session.authenticated = true;
        
        info!("Creating iSCSI session {} for initiator {} -> target {}", 
              new_session.session_id, initiator_name, target_name);
        
        // Store session
        {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.insert(new_session.session_id, new_session.clone());
        }
        *session = Some(new_session);
        
        // Send login response
        let response_data = format!(
            "TargetName={}\r\nTargetPortalGroupTag=1\r\nMaxRecvDataSegmentLength={}\r\nMaxBurstLength={}\r\nFirstBurstLength={}\r\n",
            config.target_name,
            config.max_recv_data_segment_length,
            config.max_burst_length,
            config.first_burst_length
        );
        
        let response = IscsiHeader {
            opcode: IscsiOpcode::LoginResponse,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: response_data.len() as u32,
            lun: 0,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: response_data.into_bytes(),
        };
        
        stream.write_all(&response.to_bytes()).await?;
        debug!("Sent login response to {}", client_addr);
        
        Ok(())
    }
    
    async fn handle_logout_request(
        request: IscsiHeader,
        stream: &mut TcpStream,
        sessions: &Arc<RwLock<HashMap<u64, IscsiSession>>>,
        session: &mut Option<IscsiSession>,
    ) -> Result<()> {
        info!("Processing iSCSI logout request");
        
        // Remove session
        if let Some(ref s) = session {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&s.session_id);
        }
        
        let response = IscsiHeader {
            opcode: IscsiOpcode::LogoutResponse,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: 0,
            lun: 0,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: Vec::new(),
        };
        
        stream.write_all(&response.to_bytes()).await?;
        *session = None;
        
        info!("iSCSI logout completed");
        Ok(())
    }
    
    async fn handle_scsi_command(
        request: IscsiHeader,
        stream: &mut TcpStream,
        luns: &Arc<RwLock<HashMap<u32, IscsiLun>>>,
        file_cache: &Arc<DashMap<PathBuf, Arc<RwLock<File>>>>,
        session: &mut Option<IscsiSession>,
    ) -> Result<()> {
        debug!("Processing SCSI command for LUN {}", request.lun);
        
        if session.is_none() {
            return Err(DlsError::Network("No active iSCSI session".to_string()));
        }
        
        // Extract SCSI CDB (Command Descriptor Block) - first 16 bytes of data
        if request.data.len() < 16 {
            return Err(DlsError::Network("Invalid SCSI command length".to_string()));
        }
        
        let cdb = &request.data[0..16];
        let scsi_opcode = cdb[0];
        
        debug!("SCSI command opcode: {:#04x}", scsi_opcode);
        
        match scsi_opcode {
            0x12 => Self::handle_inquiry(request, stream, luns).await,
            0x25 => Self::handle_read_capacity(request, stream, luns).await,
            0x28 => Self::handle_read_10(request, stream, luns, file_cache).await,
            0x2A => Self::handle_write_10(request, stream, luns).await,
            0x00 => Self::handle_test_unit_ready(request, stream).await,
            _ => {
                warn!("Unhandled SCSI command: {:#04x}", scsi_opcode);
                Self::send_scsi_error(request, stream, ScsiStatus::CheckCondition).await
            }
        }
    }
    
    async fn handle_inquiry(
        request: IscsiHeader,
        stream: &mut TcpStream,
        luns: &Arc<RwLock<HashMap<u32, IscsiLun>>>,
    ) -> Result<()> {
        debug!("Handling INQUIRY command");
        
        let luns_guard = luns.read().await;
        let lun_exists = luns_guard.contains_key(&(request.lun as u32));
        drop(luns_guard);
        
        let inquiry_data = if lun_exists {
            // Standard INQUIRY response for direct-access device
            vec![
                0x00, // Device type: direct-access device
                0x00, // RMB=0, device type qualifier=0
                0x05, // Version: SPC-3
                0x12, // Response data format
                0x5b, // Additional length
                0x00, 0x00, 0x00, // Reserved
                // Vendor ID (8 bytes)
                b'C', b'L', b'A', b'U', b'D', b'E', b' ', b' ',
                // Product ID (16 bytes)
                b'D', b'L', b'S', b' ', b'T', b'a', b'r', b'g',
                b'e', b't', b' ', b' ', b' ', b' ', b' ', b' ',
                // Product revision (4 bytes)
                b'1', b'.', b'0', b'0',
            ]
        } else {
            // LUN not found
            vec![0x7f] // Invalid device type
        };
        
        // Send SCSI Data-In PDU
        let data_in = IscsiHeader {
            opcode: IscsiOpcode::ScsiDataIn,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: inquiry_data.len() as u32,
            lun: request.lun,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: inquiry_data,
        };
        
        stream.write_all(&data_in.to_bytes()).await?;
        
        // Send SCSI Response
        Self::send_scsi_response(request, stream, ScsiStatus::Good, 0).await
    }
    
    async fn handle_read_capacity(
        request: IscsiHeader,
        stream: &mut TcpStream,
        luns: &Arc<RwLock<HashMap<u32, IscsiLun>>>,
    ) -> Result<()> {
        debug!("Handling READ CAPACITY command");
        
        let luns_guard = luns.read().await;
        let lun = luns_guard.get(&(request.lun as u32));
        
        let capacity_data = if let Some(lun) = lun {
            let last_block = lun.block_count() - 1;
            let mut data = Vec::new();
            data.extend_from_slice(&(last_block as u32).to_be_bytes());
            data.extend_from_slice(&lun.block_size.to_be_bytes());
            data
        } else {
            return Self::send_scsi_error(request, stream, ScsiStatus::CheckCondition).await;
        };
        drop(luns_guard);
        
        // Send SCSI Data-In PDU
        let data_in = IscsiHeader {
            opcode: IscsiOpcode::ScsiDataIn,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: capacity_data.len() as u32,
            lun: request.lun,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: capacity_data,
        };
        
        stream.write_all(&data_in.to_bytes()).await?;
        
        // Send SCSI Response
        Self::send_scsi_response(request, stream, ScsiStatus::Good, 8).await
    }
    
    async fn handle_read_10(
        request: IscsiHeader,
        stream: &mut TcpStream,
        luns: &Arc<RwLock<HashMap<u32, IscsiLun>>>,
        file_cache: &Arc<DashMap<PathBuf, Arc<RwLock<File>>>>,
    ) -> Result<()> {
        debug!("Handling READ(10) command");
        
        // Parse READ(10) CDB
        let cdb = &request.data[0..16];
        let lba = u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]);
        let transfer_length = u16::from_be_bytes([cdb[7], cdb[8]]) as u32;
        
        debug!("READ(10): LBA={}, blocks={}", lba, transfer_length);
        
        let luns_guard = luns.read().await;
        let lun = luns_guard.get(&(request.lun as u32)).cloned();
        drop(luns_guard);
        
        let lun = match lun {
            Some(lun) => lun,
            None => return Self::send_scsi_error(request, stream, ScsiStatus::CheckCondition).await,
        };
        
        // Performance optimization: Use cached file handle
        let cached_file = if let Some(cached) = file_cache.get(&lun.image_path) {
            Arc::clone(&*cached)
        } else {
            let new_file = Arc::new(RwLock::new(File::open(&lun.image_path).await?));
            file_cache.insert(lun.image_path.clone(), Arc::clone(&new_file));
            new_file
        };
        
        let offset = lba as u64 * lun.block_size as u64;
        let read_size = transfer_length * lun.block_size;
        
        // Use cached file handle for reading
        let mut file = cached_file.write().await;
        file.seek(SeekFrom::Start(offset)).await?;
        let mut buffer = vec![0u8; read_size as usize];
        let bytes_read = file.read(&mut buffer).await?;
        buffer.truncate(bytes_read);
        
        debug!("Read {} bytes from offset {}", bytes_read, offset);
        
        // Send SCSI Data-In PDU
        let data_in = IscsiHeader {
            opcode: IscsiOpcode::ScsiDataIn,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: buffer.len() as u32,
            lun: request.lun,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: buffer,
        };
        
        stream.write_all(&data_in.to_bytes()).await?;
        
        // Send SCSI Response
        Self::send_scsi_response(request, stream, ScsiStatus::Good, bytes_read as u32).await
    }
    
    async fn handle_write_10(
        request: IscsiHeader,
        stream: &mut TcpStream,
        luns: &Arc<RwLock<HashMap<u32, IscsiLun>>>,
    ) -> Result<()> {
        debug!("Handling WRITE(10) command");
        
        let luns_guard = luns.read().await;
        let lun = luns_guard.get(&(request.lun as u32)).cloned();
        drop(luns_guard);
        
        let lun = match lun {
            Some(lun) => lun,
            None => return Self::send_scsi_error(request, stream, ScsiStatus::CheckCondition).await,
        };
        
        if lun.read_only {
            return Self::send_scsi_error(request, stream, ScsiStatus::CheckCondition).await;
        }
        
        // For simplicity, just acknowledge the write without actually writing
        warn!("WRITE(10) command acknowledged but not implemented for safety");
        
        // Send SCSI Response
        Self::send_scsi_response(request, stream, ScsiStatus::Good, 0).await
    }
    
    async fn handle_test_unit_ready(
        request: IscsiHeader,
        stream: &mut TcpStream,
    ) -> Result<()> {
        debug!("Handling TEST UNIT READY command");
        
        // Simply return success
        Self::send_scsi_response(request, stream, ScsiStatus::Good, 0).await
    }
    
    async fn handle_noop(
        request: IscsiHeader,
        stream: &mut TcpStream,
        session: &mut Option<IscsiSession>,
    ) -> Result<()> {
        debug!("Handling NOP-Out");
        
        if let Some(ref mut s) = session {
            s.update_activity();
        }
        
        // Send NOP-In response
        let response = IscsiHeader {
            opcode: IscsiOpcode::NoOpIn,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: 0,
            lun: 0,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: Vec::new(),
        };
        
        stream.write_all(&response.to_bytes()).await?;
        Ok(())
    }
    
    async fn send_scsi_response(
        request: IscsiHeader,
        stream: &mut TcpStream,
        status: ScsiStatus,
        _residual_count: u32,
    ) -> Result<()> {
        let mut response_data = vec![0u8; 48]; // SCSI response data
        
        // Set status
        response_data[0] = status as u8;
        
        let response = IscsiHeader {
            opcode: IscsiOpcode::ScsiResponse,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: response_data.len() as u32,
            lun: request.lun,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag: 0xffffffff,
            cmd_sn: request.cmd_sn,
            exp_stat_sn: request.exp_stat_sn,
            max_cmd_sn: request.cmd_sn + 64,
            data: response_data,
        };
        
        stream.write_all(&response.to_bytes()).await?;
        debug!("Sent SCSI response with status: {:?}", status);
        Ok(())
    }
    
    async fn send_scsi_error(
        request: IscsiHeader,
        stream: &mut TcpStream,
        status: ScsiStatus,
    ) -> Result<()> {
        warn!("Sending SCSI error response: {:?}", status);
        Self::send_scsi_response(request, stream, status, 0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    
    #[test]
    fn test_iscsi_opcode_conversion() {
        assert_eq!(IscsiOpcode::try_from(0x01).unwrap(), IscsiOpcode::ScsiCommand);
        assert_eq!(IscsiOpcode::try_from(0x03).unwrap(), IscsiOpcode::LoginRequest);
        assert_eq!(IscsiOpcode::try_from(0x23).unwrap(), IscsiOpcode::LoginResponse);
        assert_eq!(IscsiOpcode::try_from(0x21).unwrap(), IscsiOpcode::ScsiResponse);
        
        assert!(IscsiOpcode::try_from(0xFF).is_err());
    }
    
    #[test]
    fn test_iscsi_session_creation() {
        let addr: SocketAddr = "127.0.0.1:3260".parse().unwrap();
        let session = IscsiSession::new(
            "iqn.1993-08.org.debian:01:test".to_string(),
            "iqn.2025-01.local.claude:target1".to_string(),
            addr
        );
        
        assert_eq!(session.initiator_name, "iqn.1993-08.org.debian:01:test");
        assert_eq!(session.target_name, "iqn.2025-01.local.claude:target1");
        assert_eq!(session.client_addr, addr);
        assert_eq!(session.login_phase, LoginPhase::SecurityNegotiation);
        assert!(!session.authenticated);
        assert!(!session.is_expired());
    }
    
    #[tokio::test]
    async fn test_iscsi_lun_creation() {
        let temp_file = "/tmp/test_lun.img";
        
        // Create a test file
        if let Ok(mut file) = std::fs::File::create(temp_file) {
            use std::io::Write;
            file.write_all(&vec![0u8; 1024]).unwrap();
        }
        
        let lun = IscsiLun::new(0, "test-target".to_string(), PathBuf::from(temp_file));
        
        if let Ok(lun) = lun {
            assert_eq!(lun.lun_id, 0);
            assert_eq!(lun.target_name, "test-target");
            assert_eq!(lun.size, 1024);
            assert_eq!(lun.block_size, 512);
            assert_eq!(lun.block_count(), 2);
            assert!(!lun.read_only);
            assert!(lun.online);
        }
        
        // Clean up
        let _ = std::fs::remove_file(temp_file);
    }
    
    #[test]
    fn test_iscsi_header_parsing() {
        let mut header_data = vec![0u8; 48];
        header_data[0] = 0x01; // SCSI Command
        header_data[16..20].copy_from_slice(&0x12345678u32.to_be_bytes()); // ITT
        
        let header = IscsiHeader::parse(&header_data).unwrap();
        
        assert_eq!(header.opcode, IscsiOpcode::ScsiCommand);
        assert_eq!(header.initiator_task_tag, 0x12345678);
        assert!(!header.immediate);
        assert!(!header.final_bit);
    }
    
    #[test]
    fn test_iscsi_header_serialization() {
        let header = IscsiHeader {
            opcode: IscsiOpcode::LoginResponse,
            immediate: false,
            final_bit: true,
            total_ahs_length: 0,
            data_segment_length: 0,
            lun: 0,
            initiator_task_tag: 0x12345678,
            target_transfer_tag: 0xffffffff,
            cmd_sn: 1,
            exp_stat_sn: 1,
            max_cmd_sn: 64,
            data: Vec::new(),
        };
        
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 48);
        assert_eq!(bytes[0], 0x23 | 0x80); // LoginResponse + Final bit
        assert_eq!(&bytes[16..20], &0x12345678u32.to_be_bytes());
    }
    
    #[tokio::test]
    async fn test_iscsi_target_creation() {
        let target = IscsiTarget::new("iqn.2025-01.local.test:target1".to_string());
        
        assert!(!target.running);
        assert_eq!(target.config.target_name, "iqn.2025-01.local.test:target1");
        assert_eq!(target.get_active_sessions().await, 0);
    }
    
    #[test]
    fn test_iscsi_config_default() {
        let config = IscsiConfig::default();
        
        assert_eq!(config.bind_addr.port(), ISCSI_DEFAULT_PORT);
        assert!(config.target_name.starts_with("iqn."));
        assert_eq!(config.max_sessions, 16);
        assert!(!config.authentication_required); // Simplified for development
        assert_eq!(config.max_recv_data_segment_length, ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH);
    }
}