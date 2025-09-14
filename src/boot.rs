use crate::error::{Result, DlsError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn, debug};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootType {
    LegacyBios,
    Uefi,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchitectureType {
    X86,
    X64,
    Arm64,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatingSystem {
    Linux(LinuxDistribution),
    Windows(WindowsVersion),
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxDistribution {
    Ubuntu,
    CentOS,
    Debian,
    RHEL,
    Fedora,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsVersion {
    Windows10,
    Windows11,
    WindowsServer2019,
    WindowsServer2022,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootProfile {
    pub profile_id: String,
    pub name: String,
    pub description: String,
    pub boot_type: BootType,
    pub architecture: ArchitectureType,
    pub operating_system: OperatingSystem,
    pub boot_files: BootFiles,
    pub kernel_parameters: Vec<String>,
    pub iscsi_target: Option<IscsiBootTarget>,
    pub network_config: NetworkBootConfig,
    pub enabled: bool,
    pub default_for_architecture: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootFiles {
    pub pxe_loader: Option<String>,
    pub uefi_loader: Option<String>,
    pub kernel: Option<String>,
    pub initrd: Option<String>,
    pub boot_config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IscsiBootTarget {
    pub target_name: String,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub lun: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBootConfig {
    pub dhcp_options: HashMap<u8, String>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub ntp_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub search_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientBootRequest {
    pub client_mac: [u8; 6],
    pub client_ip: Ipv4Addr,
    pub client_arch: Option<u16>, // PXE client architecture from DHCP Option 93
    pub vendor_class: Option<String>,
    pub user_class: Option<String>,
    pub requested_profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BootSession {
    pub session_id: String,
    pub client_mac: [u8; 6],
    pub client_ip: Ipv4Addr,
    pub assigned_profile: BootProfile,
    pub boot_stage: BootStage,
    pub created_at: u64,
    pub last_activity: u64,
    pub boot_attempts: u32,
    pub error_count: u32,
    pub status: BootStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootStage {
    Initial,           // Boot request received
    ProfileAssigned,   // Boot profile selected
    PxeLoaderSent,     // Initial bootloader transferred
    KernelLoading,     // Kernel/OS loading in progress
    IscsiConnecting,   // Connecting to iSCSI storage
    BootComplete,      // Boot process completed
    Failed,            // Boot process failed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootStatus {
    Active,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug)]
pub struct PxeOrchestrator {
    config: BootOrchestratorConfig,
    profiles: Arc<RwLock<HashMap<String, BootProfile>>>,
    sessions: Arc<RwLock<HashMap<String, BootSession>>>,
    client_mappings: Arc<RwLock<HashMap<[u8; 6], String>>>, // MAC -> Profile ID mapping
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootOrchestratorConfig {
    pub enabled: bool,
    pub auto_assignment: bool,
    pub session_timeout: u64, // seconds
    pub max_boot_attempts: u32,
    pub tftp_root: PathBuf,
    pub default_profiles: DefaultProfiles,
    pub client_detection: ClientDetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultProfiles {
    pub legacy_bios: String,
    pub uefi_x64: String,
    pub uefi_ia32: String,
    pub uefi_arm64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDetectionConfig {
    pub detect_by_dhcp_options: bool,
    pub detect_by_vendor_class: bool,
    pub detect_by_user_class: bool,
    pub detect_by_mac_prefix: bool,
    pub mac_vendor_database: Option<PathBuf>,
}

impl PxeOrchestrator {
    pub fn new(config: BootOrchestratorConfig) -> Self {
        Self {
            config,
            profiles: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            client_mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if !self.config.enabled {
            info!("PXE orchestrator is disabled");
            return Ok(());
        }

        info!("Starting PXE boot orchestrator");
        
        // Load default boot profiles
        self.load_default_profiles().await?;
        
        // Start session cleanup task
        self.start_session_cleanup().await;
        
        info!("PXE boot orchestrator started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping PXE boot orchestrator");
        
        // Clear active sessions
        let mut sessions = self.sessions.write().await;
        sessions.clear();
        
        info!("PXE boot orchestrator stopped");
        Ok(())
    }

    async fn load_default_profiles(&mut self) -> Result<()> {
        let mut profiles = self.profiles.write().await;
        
        // Legacy BIOS Profile for Linux
        let legacy_linux = BootProfile {
            profile_id: "legacy-linux-ubuntu".to_string(),
            name: "Ubuntu Linux (Legacy BIOS)".to_string(),
            description: "Ubuntu diskless boot for Legacy BIOS systems".to_string(),
            boot_type: BootType::LegacyBios,
            architecture: ArchitectureType::X86,
            operating_system: OperatingSystem::Linux(LinuxDistribution::Ubuntu),
            boot_files: BootFiles {
                pxe_loader: Some("pxelinux.0".to_string()),
                uefi_loader: None,
                kernel: Some("ubuntu/vmlinuz".to_string()),
                initrd: Some("ubuntu/initrd.img".to_string()),
                boot_config: Some("pxelinux.cfg/default".to_string()),
            },
            kernel_parameters: vec![
                "boot=live".to_string(),
                "netboot=nfs".to_string(),
                "splash".to_string(),
                "quiet".to_string(),
            ],
            iscsi_target: Some(IscsiBootTarget {
                target_name: "iqn.2025-01.com.claude.dls:ubuntu".to_string(),
                target_ip: Ipv4Addr::new(192, 168, 1, 1),
                target_port: 3260,
                lun: 0,
                username: None,
                password: None,
            }),
            network_config: NetworkBootConfig {
                dhcp_options: HashMap::new(),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                ntp_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                domain_name: Some("dls.local".to_string()),
                search_domains: vec!["dls.local".to_string()],
            },
            enabled: true,
            default_for_architecture: true,
        };

        // UEFI x64 Profile for Linux
        let uefi_linux = BootProfile {
            profile_id: "uefi-linux-ubuntu".to_string(),
            name: "Ubuntu Linux (UEFI x64)".to_string(),
            description: "Ubuntu diskless boot for UEFI x64 systems".to_string(),
            boot_type: BootType::Uefi,
            architecture: ArchitectureType::X64,
            operating_system: OperatingSystem::Linux(LinuxDistribution::Ubuntu),
            boot_files: BootFiles {
                pxe_loader: None,
                uefi_loader: Some("bootx64.efi".to_string()),
                kernel: Some("ubuntu/vmlinuz".to_string()),
                initrd: Some("ubuntu/initrd.img".to_string()),
                boot_config: Some("grub/grub.cfg".to_string()),
            },
            kernel_parameters: vec![
                "boot=live".to_string(),
                "netboot=iscsi".to_string(),
                "splash".to_string(),
                "quiet".to_string(),
            ],
            iscsi_target: Some(IscsiBootTarget {
                target_name: "iqn.2025-01.com.claude.dls:ubuntu".to_string(),
                target_ip: Ipv4Addr::new(192, 168, 1, 1),
                target_port: 3260,
                lun: 0,
                username: None,
                password: None,
            }),
            network_config: NetworkBootConfig {
                dhcp_options: HashMap::new(),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                ntp_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                domain_name: Some("dls.local".to_string()),
                search_domains: vec!["dls.local".to_string()],
            },
            enabled: true,
            default_for_architecture: true,
        };

        // UEFI Windows Profile
        let uefi_windows = BootProfile {
            profile_id: "uefi-windows11".to_string(),
            name: "Windows 11 (UEFI x64)".to_string(),
            description: "Windows 11 diskless boot for UEFI x64 systems".to_string(),
            boot_type: BootType::Uefi,
            architecture: ArchitectureType::X64,
            operating_system: OperatingSystem::Windows(WindowsVersion::Windows11),
            boot_files: BootFiles {
                pxe_loader: None,
                uefi_loader: Some("bootx64.efi".to_string()),
                kernel: Some("windows/boot.wim".to_string()),
                initrd: None,
                boot_config: Some("BCD".to_string()),
            },
            kernel_parameters: vec![],
            iscsi_target: Some(IscsiBootTarget {
                target_name: "iqn.2025-01.com.claude.dls:windows11".to_string(),
                target_ip: Ipv4Addr::new(192, 168, 1, 1),
                target_port: 3260,
                lun: 1,
                username: None,
                password: None,
            }),
            network_config: NetworkBootConfig {
                dhcp_options: HashMap::new(),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                ntp_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                domain_name: Some("dls.local".to_string()),
                search_domains: vec!["dls.local".to_string()],
            },
            enabled: false, // Disabled by default
            default_for_architecture: false,
        };

        profiles.insert(legacy_linux.profile_id.clone(), legacy_linux);
        profiles.insert(uefi_linux.profile_id.clone(), uefi_linux);
        profiles.insert(uefi_windows.profile_id.clone(), uefi_windows);

        info!("Loaded {} default boot profiles", profiles.len());
        Ok(())
    }

    pub async fn handle_boot_request(&self, request: ClientBootRequest) -> Result<BootSession> {
        info!("Processing boot request from client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
              request.client_mac[0], request.client_mac[1], request.client_mac[2],
              request.client_mac[3], request.client_mac[4], request.client_mac[5]);

        // Check for existing session
        if let Some(existing_session) = self.get_active_session(request.client_mac).await? {
            debug!("Found existing boot session for client: {}", existing_session.session_id);
            return Ok(existing_session);
        }

        // Select appropriate boot profile
        let profile = self.select_boot_profile(&request).await?;
        
        // Create new boot session
        let session_id = self.generate_session_id();
        let boot_session = BootSession {
            session_id: session_id.clone(),
            client_mac: request.client_mac,
            client_ip: request.client_ip,
            assigned_profile: profile,
            boot_stage: BootStage::Initial,
            created_at: chrono::Utc::now().timestamp() as u64,
            last_activity: chrono::Utc::now().timestamp() as u64,
            boot_attempts: 1,
            error_count: 0,
            status: BootStatus::Active,
        };

        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, boot_session.clone());
        
        info!("Created boot session {} for client using profile '{}'", 
              boot_session.session_id, boot_session.assigned_profile.name);

        Ok(boot_session)
    }

    async fn select_boot_profile(&self, request: &ClientBootRequest) -> Result<BootProfile> {
        let profiles = self.profiles.read().await;
        let client_mappings = self.client_mappings.read().await;

        // Check for explicit client mapping
        if let Some(profile_id) = client_mappings.get(&request.client_mac) {
            if let Some(profile) = profiles.get(profile_id) {
                if profile.enabled {
                    return Ok(profile.clone());
                }
            }
        }

        // Check for requested profile
        if let Some(requested_profile) = &request.requested_profile {
            if let Some(profile) = profiles.get(requested_profile) {
                if profile.enabled {
                    return Ok(profile.clone());
                }
            }
        }

        // Auto-detect based on client architecture
        if let Some(client_arch) = request.client_arch {
            let boot_type = self.detect_boot_type_from_arch(client_arch)?;
            let architecture = self.detect_architecture_from_arch(client_arch)?;

            for profile in profiles.values() {
                if profile.enabled 
                   && profile.default_for_architecture 
                   && profile.boot_type == boot_type 
                   && profile.architecture == architecture {
                    return Ok(profile.clone());
                }
            }
        }

        // Fallback to first enabled profile
        for profile in profiles.values() {
            if profile.enabled {
                warn!("Using fallback boot profile '{}' for client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                      profile.name,
                      request.client_mac[0], request.client_mac[1], request.client_mac[2],
                      request.client_mac[3], request.client_mac[4], request.client_mac[5]);
                return Ok(profile.clone());
            }
        }

        Err(DlsError::NotFound("No suitable boot profile found for client".to_string()))
    }

    fn detect_boot_type_from_arch(&self, client_arch: u16) -> Result<BootType> {
        match client_arch {
            0x0000 => Ok(BootType::LegacyBios),      // Intel x86PC
            0x0001 => Ok(BootType::LegacyBios),      // NEC/PC98
            0x0002 => Ok(BootType::LegacyBios),      // EFI Itanium
            0x0006 => Ok(BootType::Uefi),            // EFI IA32
            0x0007 => Ok(BootType::Uefi),            // EFI BC (Byte Code)
            0x0009 => Ok(BootType::Uefi),            // EFI x86-64
            0x000B => Ok(BootType::Uefi),            // EFI ARM32
            0x000C => Ok(BootType::Uefi),            // EFI ARM64
            _ => Ok(BootType::Auto),
        }
    }

    fn detect_architecture_from_arch(&self, client_arch: u16) -> Result<ArchitectureType> {
        match client_arch {
            0x0000 => Ok(ArchitectureType::X86),     // Intel x86PC
            0x0001 => Ok(ArchitectureType::X86),     // NEC/PC98
            0x0002 => Ok(ArchitectureType::X64),     // EFI Itanium
            0x0006 => Ok(ArchitectureType::X86),     // EFI IA32
            0x0007 => Ok(ArchitectureType::Auto),    // EFI BC (Byte Code)
            0x0009 => Ok(ArchitectureType::X64),     // EFI x86-64
            0x000B => Ok(ArchitectureType::Arm64),   // EFI ARM32
            0x000C => Ok(ArchitectureType::Arm64),   // EFI ARM64
            _ => Ok(ArchitectureType::Auto),
        }
    }

    async fn get_active_session(&self, client_mac: [u8; 6]) -> Result<Option<BootSession>> {
        let sessions = self.sessions.read().await;
        
        for session in sessions.values() {
            if session.client_mac == client_mac && session.status == BootStatus::Active {
                return Ok(Some(session.clone()));
            }
        }
        
        Ok(None)
    }

    pub async fn update_boot_stage(&self, session_id: &str, stage: BootStage) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            session.boot_stage = stage;
            session.last_activity = chrono::Utc::now().timestamp() as u64;
            
            info!("Boot session {} updated to stage: {:?}", session_id, stage);
            
            // Update status based on stage
            match stage {
                BootStage::BootComplete => {
                    session.status = BootStatus::Completed;
                }
                BootStage::Failed => {
                    session.status = BootStatus::Failed;
                    session.error_count += 1;
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    pub async fn get_boot_files_for_session(&self, session_id: &str) -> Result<BootFiles> {
        let sessions = self.sessions.read().await;
        
        if let Some(session) = sessions.get(session_id) {
            Ok(session.assigned_profile.boot_files.clone())
        } else {
            Err(DlsError::NotFound(format!("Boot session not found: {}", session_id)))
        }
    }

    pub async fn add_boot_profile(&self, profile: BootProfile) -> Result<()> {
        let mut profiles = self.profiles.write().await;
        
        info!("Adding boot profile: {} ({})", profile.name, profile.profile_id);
        profiles.insert(profile.profile_id.clone(), profile);
        
        Ok(())
    }

    pub async fn remove_boot_profile(&self, profile_id: &str) -> Result<()> {
        let mut profiles = self.profiles.write().await;
        
        if profiles.remove(profile_id).is_some() {
            info!("Removed boot profile: {}", profile_id);
            Ok(())
        } else {
            Err(DlsError::NotFound(format!("Boot profile not found: {}", profile_id)))
        }
    }

    pub async fn assign_profile_to_client(&self, client_mac: [u8; 6], profile_id: String) -> Result<()> {
        let mut client_mappings = self.client_mappings.write().await;
        
        client_mappings.insert(client_mac, profile_id.clone());
        
        info!("Assigned profile '{}' to client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
              profile_id,
              client_mac[0], client_mac[1], client_mac[2],
              client_mac[3], client_mac[4], client_mac[5]);
        
        Ok(())
    }

    pub async fn get_session_stats(&self) -> Result<(usize, usize, usize, usize)> {
        let sessions = self.sessions.read().await;
        
        let mut active = 0;
        let mut completed = 0;
        let mut failed = 0;
        let mut expired = 0;
        
        for session in sessions.values() {
            match session.status {
                BootStatus::Active => active += 1,
                BootStatus::Completed => completed += 1,
                BootStatus::Failed => failed += 1,
                BootStatus::Expired => expired += 1,
            }
        }
        
        Ok((active, completed, failed, expired))
    }

    fn generate_session_id(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
            
        let mut hasher = DefaultHasher::new();
        timestamp.hash(&mut hasher);
        rand::random::<u32>().hash(&mut hasher);
        
        format!("boot-{:016x}", hasher.finish())
    }

    async fn start_session_cleanup(&self) {
        let sessions_clone = Arc::clone(&self.sessions);
        let timeout = self.config.session_timeout;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
            
            loop {
                interval.tick().await;
                
                let mut sessions_guard = sessions_clone.write().await;
                let current_time = chrono::Utc::now().timestamp() as u64;
                let initial_count = sessions_guard.len();
                
                sessions_guard.retain(|_, session| {
                    let expired = current_time - session.last_activity > timeout;
                    if expired && session.status == BootStatus::Active {
                        info!("Marking boot session {} as expired", session.session_id);
                    }
                    !expired || session.status == BootStatus::Completed
                });
                
                let cleaned = initial_count - sessions_guard.len();
                if cleaned > 0 {
                    info!("Cleaned up {} expired boot sessions", cleaned);
                }
            }
        });
    }
}

impl Default for BootOrchestratorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_assignment: true,
            session_timeout: 3600, // 1 hour
            max_boot_attempts: 3,
            tftp_root: PathBuf::from("/var/lib/dls_server/tftp"),
            default_profiles: DefaultProfiles {
                legacy_bios: "legacy-linux-ubuntu".to_string(),
                uefi_x64: "uefi-linux-ubuntu".to_string(),
                uefi_ia32: "uefi-linux-ubuntu".to_string(),
                uefi_arm64: "uefi-linux-ubuntu".to_string(),
            },
            client_detection: ClientDetectionConfig {
                detect_by_dhcp_options: true,
                detect_by_vendor_class: true,
                detect_by_user_class: false,
                detect_by_mac_prefix: false,
                mac_vendor_database: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_profile_creation() {
        let profile = BootProfile {
            profile_id: "test-profile".to_string(),
            name: "Test Profile".to_string(),
            description: "Test boot profile".to_string(),
            boot_type: BootType::LegacyBios,
            architecture: ArchitectureType::X86,
            operating_system: OperatingSystem::Linux(LinuxDistribution::Ubuntu),
            boot_files: BootFiles {
                pxe_loader: Some("pxelinux.0".to_string()),
                uefi_loader: None,
                kernel: Some("vmlinuz".to_string()),
                initrd: Some("initrd.img".to_string()),
                boot_config: Some("pxelinux.cfg/default".to_string()),
            },
            kernel_parameters: vec!["quiet".to_string()],
            iscsi_target: None,
            network_config: NetworkBootConfig {
                dhcp_options: HashMap::new(),
                dns_servers: vec![],
                ntp_servers: vec![],
                domain_name: None,
                search_domains: vec![],
            },
            enabled: true,
            default_for_architecture: false,
        };
        
        assert_eq!(profile.profile_id, "test-profile");
        assert_eq!(profile.boot_type, BootType::LegacyBios);
        assert!(profile.enabled);
    }

    #[tokio::test]
    async fn test_pxe_orchestrator_creation() {
        let config = BootOrchestratorConfig::default();
        let orchestrator = PxeOrchestrator::new(config);
        
        // Test initial state
        let profiles = orchestrator.profiles.read().await;
        let sessions = orchestrator.sessions.read().await;
        
        assert!(profiles.is_empty());
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_boot_type_detection() {
        let config = BootOrchestratorConfig::default();
        let orchestrator = PxeOrchestrator::new(config);
        
        // Test Legacy BIOS detection
        assert_eq!(orchestrator.detect_boot_type_from_arch(0x0000).unwrap(), BootType::LegacyBios);
        
        // Test UEFI detection
        assert_eq!(orchestrator.detect_boot_type_from_arch(0x0009).unwrap(), BootType::Uefi);
        assert_eq!(orchestrator.detect_boot_type_from_arch(0x0006).unwrap(), BootType::Uefi);
    }

    #[test]
    fn test_architecture_detection() {
        let config = BootOrchestratorConfig::default();
        let orchestrator = PxeOrchestrator::new(config);
        
        // Test x86 detection
        assert_eq!(orchestrator.detect_architecture_from_arch(0x0000).unwrap(), ArchitectureType::X86);
        
        // Test x64 detection
        assert_eq!(orchestrator.detect_architecture_from_arch(0x0009).unwrap(), ArchitectureType::X64);
        
        // Test ARM64 detection
        assert_eq!(orchestrator.detect_architecture_from_arch(0x000C).unwrap(), ArchitectureType::Arm64);
    }

    #[test]
    fn test_client_boot_request() {
        let request = ClientBootRequest {
            client_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            client_ip: Ipv4Addr::new(192, 168, 1, 100),
            client_arch: Some(0x0009), // EFI x86-64
            vendor_class: Some("PXEClient".to_string()),
            user_class: None,
            requested_profile: None,
        };
        
        assert_eq!(request.client_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(request.client_arch, Some(0x0009));
    }

    #[test]
    fn test_boot_session_creation() {
        let session = BootSession {
            session_id: "test-session".to_string(),
            client_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            client_ip: Ipv4Addr::new(192, 168, 1, 100),
            assigned_profile: BootProfile {
                profile_id: "test".to_string(),
                name: "Test".to_string(),
                description: "Test".to_string(),
                boot_type: BootType::LegacyBios,
                architecture: ArchitectureType::X86,
                operating_system: OperatingSystem::Linux(LinuxDistribution::Ubuntu),
                boot_files: BootFiles {
                    pxe_loader: None,
                    uefi_loader: None,
                    kernel: None,
                    initrd: None,
                    boot_config: None,
                },
                kernel_parameters: vec![],
                iscsi_target: None,
                network_config: NetworkBootConfig {
                    dhcp_options: HashMap::new(),
                    dns_servers: vec![],
                    ntp_servers: vec![],
                    domain_name: None,
                    search_domains: vec![],
                },
                enabled: true,
                default_for_architecture: false,
            },
            boot_stage: BootStage::Initial,
            created_at: 1640000000,
            last_activity: 1640000000,
            boot_attempts: 1,
            error_count: 0,
            status: BootStatus::Active,
        };
        
        assert_eq!(session.boot_stage, BootStage::Initial);
        assert_eq!(session.status, BootStatus::Active);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let config = BootOrchestratorConfig::default();
        let orchestrator = PxeOrchestrator::new(config);
        
        let (active, completed, failed, expired) = orchestrator.get_session_stats().await.unwrap();
        assert_eq!(active, 0);
        assert_eq!(completed, 0);
        assert_eq!(failed, 0);
        assert_eq!(expired, 0);
    }

    #[test]
    fn test_iscsi_boot_target() {
        let target = IscsiBootTarget {
            target_name: "iqn.2025-01.com.claude.dls:test".to_string(),
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            target_port: 3260,
            lun: 0,
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
        };
        
        assert_eq!(target.target_port, 3260);
        assert_eq!(target.lun, 0);
        assert!(target.username.is_some());
    }

    #[test]
    fn test_boot_orchestrator_config_default() {
        let config = BootOrchestratorConfig::default();
        
        assert!(config.enabled);
        assert!(config.auto_assignment);
        assert_eq!(config.session_timeout, 3600);
        assert_eq!(config.max_boot_attempts, 3);
    }
}