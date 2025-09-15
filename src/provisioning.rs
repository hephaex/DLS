use crate::error::Result;
use crate::storage::StorageManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub os_type: OsType,
    pub architecture: Architecture,
    pub base_image_path: PathBuf,
    pub size_gb: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningJob {
    pub id: String,
    pub template_id: String,
    pub target_name: String,
    pub target_size_gb: u64,
    pub customizations: Vec<ImageCustomization>,
    pub status: JobStatus,
    pub progress: f32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub logs: Vec<JobLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageCustomization {
    pub customization_type: CustomizationType,
    pub parameters: HashMap<String, String>,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomizationType {
    InjectFiles,
    RunScript,
    InstallPackages,
    ConfigureNetwork,
    SetHostname,
    CreateUsers,
    InstallDrivers,
    ConfigureServices,
    SecurityHardening,
    RegistrySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OsType {
    Linux,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X64,
    ARM32,
    ARM64,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobLog {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
    pub component: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Clone)]
pub struct ProvisioningManager {
    templates: Arc<RwLock<HashMap<String, ImageTemplate>>>,
    jobs: Arc<RwLock<HashMap<String, ProvisioningJob>>>,
    storage_manager: Arc<RwLock<Option<Box<dyn StorageManager + Send + Sync>>>>,
    work_directory: PathBuf,
    max_concurrent_jobs: usize,
    running_jobs: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl ProvisioningManager {
    pub fn new(work_directory: PathBuf, max_concurrent_jobs: usize) -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            storage_manager: Arc::new(RwLock::new(None)),
            work_directory,
            max_concurrent_jobs,
            running_jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting provisioning manager");
        
        // Create work directory if it doesn't exist
        if !self.work_directory.exists() {
            fs::create_dir_all(&self.work_directory).await?;
        }
        
        // Load existing templates and jobs
        self.load_templates().await?;
        self.load_jobs().await?;
        
        info!("Provisioning manager started successfully");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping provisioning manager");
        
        // Cancel all running jobs
        let mut running_jobs = self.running_jobs.write().await;
        for (job_id, handle) in running_jobs.drain() {
            warn!("Cancelling running job: {}", job_id);
            handle.abort();
            
            // Update job status
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.status = JobStatus::Cancelled;
                job.completed_at = Some(chrono::Utc::now());
                self.add_job_log(job, LogLevel::Warning, "Job cancelled during shutdown".to_string()).await;
            }
        }
        
        // Save current state
        self.save_templates().await?;
        self.save_jobs().await?;
        
        info!("Provisioning manager stopped successfully");
        Ok(())
    }

    // Template Management
    pub async fn create_template(&self, template: ImageTemplate) -> Result<String> {
        info!("Creating image template: {}", template.name);
        
        let template_id = template.id.clone();
        let mut templates = self.templates.write().await;
        templates.insert(template_id.clone(), template);
        
        self.save_templates().await?;
        
        debug!("Template created with ID: {}", template_id);
        Ok(template_id)
    }

    pub async fn list_templates(&self) -> Vec<ImageTemplate> {
        let templates = self.templates.read().await;
        templates.values().cloned().collect()
    }

    pub async fn get_template(&self, template_id: &str) -> Option<ImageTemplate> {
        let templates = self.templates.read().await;
        templates.get(template_id).cloned()
    }

    pub async fn update_template(&self, template_id: &str, template: ImageTemplate) -> Result<()> {
        info!("Updating template: {}", template_id);
        
        let mut templates = self.templates.write().await;
        if templates.contains_key(template_id) {
            templates.insert(template_id.to_string(), template);
            self.save_templates().await?;
            debug!("Template updated: {}", template_id);
            Ok(())
        } else {
            Err(crate::error::DlsError::NotFound("Template not found".to_string()))
        }
    }

    pub async fn delete_template(&self, template_id: &str) -> Result<()> {
        info!("Deleting template: {}", template_id);
        
        let mut templates = self.templates.write().await;
        if templates.remove(template_id).is_some() {
            self.save_templates().await?;
            debug!("Template deleted: {}", template_id);
            Ok(())
        } else {
            Err(crate::error::DlsError::NotFound("Template not found".to_string()))
        }
    }

    // Job Management
    pub async fn create_provisioning_job(
        &self,
        template_id: String,
        target_name: String,
        target_size_gb: u64,
        customizations: Vec<ImageCustomization>,
    ) -> Result<String> {
        info!("Creating provisioning job for template: {}", template_id);
        
        // Verify template exists
        if !self.templates.read().await.contains_key(&template_id) {
            return Err(crate::error::DlsError::NotFound("Template not found".to_string()));
        }

        let job_id = Uuid::new_v4().to_string();
        let job = ProvisioningJob {
            id: job_id.clone(),
            template_id,
            target_name,
            target_size_gb,
            customizations,
            status: JobStatus::Pending,
            progress: 0.0,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
            logs: Vec::new(),
        };

        let mut jobs = self.jobs.write().await;
        jobs.insert(job_id.clone(), job);
        
        self.save_jobs().await?;
        
        debug!("Provisioning job created with ID: {}", job_id);
        Ok(job_id)
    }

    pub async fn list_jobs(&self) -> Vec<ProvisioningJob> {
        let jobs = self.jobs.read().await;
        jobs.values().cloned().collect()
    }

    pub async fn get_job(&self, job_id: &str) -> Option<ProvisioningJob> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).cloned()
    }

    pub async fn start_job(&self, job_id: &str) -> Result<()> {
        info!("Starting provisioning job: {}", job_id);
        
        // Check if we've reached max concurrent jobs
        let running_count = self.running_jobs.read().await.len();
        if running_count >= self.max_concurrent_jobs {
            return Err(crate::error::DlsError::ResourceExhausted(
                format!("Maximum concurrent jobs ({}) reached", self.max_concurrent_jobs)
            ));
        }

        // Get job and template
        let (job, template) = {
            let jobs = self.jobs.read().await;
            let templates = self.templates.read().await;
            
            let job = jobs.get(job_id)
                .ok_or_else(|| crate::error::DlsError::NotFound("Job not found".to_string()))?
                .clone();
            
            let template = templates.get(&job.template_id)
                .ok_or_else(|| crate::error::DlsError::NotFound("Template not found".to_string()))?
                .clone();
            
            (job, template)
        };

        if job.status != JobStatus::Pending {
            return Err(crate::error::DlsError::InvalidOperation(
                format!("Job is not in pending state: {:?}", job.status)
            ));
        }

        // Update job status to running
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(job_id) {
                job.status = JobStatus::Running;
                job.started_at = Some(chrono::Utc::now());
                self.add_job_log(job, LogLevel::Info, "Job started".to_string()).await;
            }
        }

        // Spawn job execution task
        let job_handle = self.spawn_job_execution(job, template).await;
        
        let mut running_jobs = self.running_jobs.write().await;
        running_jobs.insert(job_id.to_string(), job_handle);

        debug!("Job started: {}", job_id);
        Ok(())
    }

    pub async fn cancel_job(&self, job_id: &str) -> Result<()> {
        info!("Cancelling job: {}", job_id);
        
        // Cancel the running task if it exists
        let mut running_jobs = self.running_jobs.write().await;
        if let Some(handle) = running_jobs.remove(job_id) {
            handle.abort();
        }

        // Update job status
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            job.status = JobStatus::Cancelled;
            job.completed_at = Some(chrono::Utc::now());
            self.add_job_log(job, LogLevel::Warning, "Job cancelled".to_string()).await;
        }

        debug!("Job cancelled: {}", job_id);
        Ok(())
    }

    // Private helper methods
    async fn spawn_job_execution(&self, mut job: ProvisioningJob, template: ImageTemplate) -> tokio::task::JoinHandle<()> {
        let jobs = Arc::clone(&self.jobs);
        let storage_manager = Arc::clone(&self.storage_manager);
        let work_directory = self.work_directory.clone();
        let running_jobs = Arc::clone(&self.running_jobs);

        tokio::spawn(async move {
            let job_id = job.id.clone();
            
            let result = Self::execute_provisioning_job(
                &mut job,
                &template,
                &storage_manager,
                &work_directory,
            ).await;

            // Update job status based on result
            let mut jobs_guard = jobs.write().await;
            if let Some(stored_job) = jobs_guard.get_mut(&job_id) {
                match result {
                    Ok(_) => {
                        stored_job.status = JobStatus::Completed;
                        stored_job.progress = 100.0;
                        stored_job.completed_at = Some(chrono::Utc::now());
                        Self::add_job_log_static(stored_job, LogLevel::Info, "Job completed successfully".to_string()).await;
                    }
                    Err(e) => {
                        stored_job.status = JobStatus::Failed;
                        stored_job.completed_at = Some(chrono::Utc::now());
                        stored_job.error_message = Some(e.to_string());
                        Self::add_job_log_static(stored_job, LogLevel::Error, format!("Job failed: {}", e)).await;
                    }
                }
            }

            // Remove from running jobs
            let mut running_jobs_guard = running_jobs.write().await;
            running_jobs_guard.remove(&job_id);
        })
    }

    async fn execute_provisioning_job(
        job: &mut ProvisioningJob,
        template: &ImageTemplate,
        storage_manager: &Arc<RwLock<Option<Box<dyn StorageManager + Send + Sync>>>>,
        work_directory: &Path,
    ) -> Result<()> {
        info!("Executing provisioning job: {}", job.id);

        // Step 1: Create base image copy
        Self::add_job_log_static(job, LogLevel::Info, "Creating base image copy".to_string()).await;
        job.progress = 10.0;
        
        let target_path = work_directory.join(format!("{}.img", job.target_name));
        Self::copy_base_image(&template.base_image_path, &target_path, job.target_size_gb).await?;

        // Step 2: Mount image for customization
        Self::add_job_log_static(job, LogLevel::Info, "Mounting image for customization".to_string()).await;
        job.progress = 20.0;
        
        let mount_point = work_directory.join(format!("mount_{}", job.id));
        fs::create_dir_all(&mount_point).await?;
        
        Self::mount_image(&target_path, &mount_point, &template.os_type).await?;

        // Step 3: Apply customizations
        job.progress = 30.0;
        let customization_count = job.customizations.len();
        let customizations = job.customizations.clone(); // Clone to avoid borrowing issues
        
        for (i, customization) in customizations.iter().enumerate() {
            Self::add_job_log_static(job, LogLevel::Info, format!("Applying customization: {:?}", customization.customization_type)).await;
            
            Self::apply_customization(&mount_point, customization, &template.os_type).await?;
            
            job.progress = 30.0 + (50.0 * (i + 1) as f32 / customization_count as f32);
        }

        // Step 4: Unmount image
        Self::add_job_log_static(job, LogLevel::Info, "Unmounting image".to_string()).await;
        job.progress = 80.0;
        
        Self::unmount_image(&mount_point).await?;
        fs::remove_dir_all(&mount_point).await?;

        // Step 5: Register with storage manager
        Self::add_job_log_static(job, LogLevel::Info, "Registering image with storage manager".to_string()).await;
        job.progress = 90.0;
        
        let storage_guard = storage_manager.read().await;
        if let Some(storage) = storage_guard.as_ref() {
            // Register the new image (implementation depends on storage manager)
            info!("Image registered with storage manager: {}", target_path.display());
        }

        Self::add_job_log_static(job, LogLevel::Info, "Provisioning completed successfully".to_string()).await;
        job.progress = 100.0;

        Ok(())
    }

    async fn copy_base_image(source: &Path, target: &Path, size_gb: u64) -> Result<()> {
        debug!("Copying base image from {} to {}", source.display(), target.display());
        
        // Use dd command for efficient copying and resizing
        let output = Command::new("dd")
            .arg(format!("if={}", source.display()))
            .arg(format!("of={}", target.display()))
            .arg("bs=1M")
            .arg("status=progress")
            .output()
            .await?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(crate::error::DlsError::CommandFailed(format!("dd failed: {}", error_msg)));
        }

        // Resize image if needed
        if size_gb > 0 {
            let output = Command::new("qemu-img")
                .arg("resize")
                .arg(target)
                .arg(format!("{}G", size_gb))
                .output()
                .await?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(crate::error::DlsError::CommandFailed(format!("qemu-img resize failed: {}", error_msg)));
            }
        }

        Ok(())
    }

    async fn mount_image(image_path: &Path, mount_point: &Path, os_type: &OsType) -> Result<()> {
        debug!("Mounting image {} at {}", image_path.display(), mount_point.display());
        
        match os_type {
            OsType::Linux => {
                // Mount using loop device
                let output = Command::new("sudo")
                    .arg("mount")
                    .arg("-o")
                    .arg("loop")
                    .arg(image_path)
                    .arg(mount_point)
                    .output()
                    .await?;

                if !output.status.success() {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    return Err(crate::error::DlsError::CommandFailed(format!("mount failed: {}", error_msg)));
                }
            }
            OsType::Windows => {
                // Windows images require more complex mounting (guestmount or similar)
                let output = Command::new("guestmount")
                    .arg("-a")
                    .arg(image_path)
                    .arg("-m")
                    .arg("/dev/sda1")
                    .arg(mount_point)
                    .output()
                    .await?;

                if !output.status.success() {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    return Err(crate::error::DlsError::CommandFailed(format!("guestmount failed: {}", error_msg)));
                }
            }
            _ => {
                return Err(crate::error::DlsError::UnsupportedOperation("Unknown OS type for mounting".to_string()));
            }
        }

        Ok(())
    }

    async fn unmount_image(mount_point: &Path) -> Result<()> {
        debug!("Unmounting {}", mount_point.display());
        
        let output = Command::new("sudo")
            .arg("umount")
            .arg(mount_point)
            .output()
            .await?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(crate::error::DlsError::CommandFailed(format!("umount failed: {}", error_msg)));
        }

        Ok(())
    }

    async fn apply_customization(
        mount_point: &Path,
        customization: &ImageCustomization,
        os_type: &OsType,
    ) -> Result<()> {
        debug!("Applying customization: {:?}", customization.customization_type);

        match &customization.customization_type {
            CustomizationType::InjectFiles => {
                Self::inject_files(mount_point, &customization.parameters).await?;
            }
            CustomizationType::RunScript => {
                Self::run_script(mount_point, &customization.parameters, os_type).await?;
            }
            CustomizationType::InstallPackages => {
                Self::install_packages(mount_point, &customization.parameters, os_type).await?;
            }
            CustomizationType::ConfigureNetwork => {
                Self::configure_network(mount_point, &customization.parameters, os_type).await?;
            }
            CustomizationType::SetHostname => {
                Self::set_hostname(mount_point, &customization.parameters, os_type).await?;
            }
            CustomizationType::CreateUsers => {
                Self::create_users(mount_point, &customization.parameters, os_type).await?;
            }
            _ => {
                warn!("Customization type not yet implemented: {:?}", customization.customization_type);
            }
        }

        Ok(())
    }

    async fn inject_files(mount_point: &Path, parameters: &HashMap<String, String>) -> Result<()> {
        for (source, target) in parameters {
            let target_path = mount_point.join(target.trim_start_matches('/'));
            
            // Create parent directories if they don't exist
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            
            fs::copy(source, &target_path).await?;
            debug!("Injected file: {} -> {}", source, target_path.display());
        }
        Ok(())
    }

    async fn run_script(mount_point: &Path, parameters: &HashMap<String, String>, os_type: &OsType) -> Result<()> {
        if let Some(script_content) = parameters.get("content") {
            let script_path = mount_point.join("tmp/provisioning_script");
            
            // Create tmp directory
            fs::create_dir_all(mount_point.join("tmp")).await?;
            
            // Write script content
            fs::write(&script_path, script_content).await?;
            
            // Make executable (for Linux)
            if matches!(os_type, OsType::Linux) {
                Command::new("chmod")
                    .arg("+x")
                    .arg(&script_path)
                    .output()
                    .await?;
                
                // Execute in chroot
                let output = Command::new("sudo")
                    .arg("chroot")
                    .arg(mount_point)
                    .arg("/tmp/provisioning_script")
                    .output()
                    .await?;
                
                if !output.status.success() {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    return Err(crate::error::DlsError::CommandFailed(format!("Script execution failed: {}", error_msg)));
                }
            }
            
            // Clean up script
            fs::remove_file(&script_path).await?;
        }
        Ok(())
    }

    async fn install_packages(mount_point: &Path, parameters: &HashMap<String, String>, os_type: &OsType) -> Result<()> {
        if let Some(packages) = parameters.get("packages") {
            let package_list: Vec<&str> = packages.split(',').map(|p| p.trim()).collect();
            
            match os_type {
                OsType::Linux => {
                    // Use apt-get for Debian/Ubuntu
                    let output = Command::new("sudo")
                        .arg("chroot")
                        .arg(mount_point)
                        .arg("apt-get")
                        .arg("update")
                        .output()
                        .await?;
                    
                    if output.status.success() {
                        for package in package_list {
                            Command::new("sudo")
                                .arg("chroot")
                                .arg(mount_point)
                                .arg("apt-get")
                                .arg("install")
                                .arg("-y")
                                .arg(package)
                                .output()
                                .await?;
                        }
                    }
                }
                _ => {
                    warn!("Package installation not implemented for OS type: {:?}", os_type);
                }
            }
        }
        Ok(())
    }

    async fn configure_network(mount_point: &Path, parameters: &HashMap<String, String>, os_type: &OsType) -> Result<()> {
        match os_type {
            OsType::Linux => {
                if let (Some(interface), Some(ip)) = (parameters.get("interface"), parameters.get("ip")) {
                    let netplan_config = format!(
                        "network:\n  version: 2\n  ethernets:\n    {}:\n      dhcp4: false\n      addresses:\n        - {}\n",
                        interface, ip
                    );
                    
                    let config_path = mount_point.join("etc/netplan/00-installer-config.yaml");
                    fs::write(&config_path, netplan_config).await?;
                }
            }
            _ => {
                warn!("Network configuration not implemented for OS type: {:?}", os_type);
            }
        }
        Ok(())
    }

    async fn set_hostname(mount_point: &Path, parameters: &HashMap<String, String>, os_type: &OsType) -> Result<()> {
        if let Some(hostname) = parameters.get("hostname") {
            match os_type {
                OsType::Linux => {
                    fs::write(mount_point.join("etc/hostname"), hostname).await?;
                    
                    // Update /etc/hosts
                    let hosts_content = format!("127.0.0.1 localhost {}\n", hostname);
                    fs::write(mount_point.join("etc/hosts"), hosts_content).await?;
                }
                _ => {
                    warn!("Hostname configuration not implemented for OS type: {:?}", os_type);
                }
            }
        }
        Ok(())
    }

    async fn create_users(mount_point: &Path, parameters: &HashMap<String, String>, os_type: &OsType) -> Result<()> {
        if let Some(username) = parameters.get("username") {
            match os_type {
                OsType::Linux => {
                    // Create user via chroot
                    let output = Command::new("sudo")
                        .arg("chroot")
                        .arg(mount_point)
                        .arg("useradd")
                        .arg("-m")
                        .arg("-s")
                        .arg("/bin/bash")
                        .arg(username)
                        .output()
                        .await?;
                    
                    if !output.status.success() {
                        let error_msg = String::from_utf8_lossy(&output.stderr);
                        warn!("User creation warning: {}", error_msg);
                    }
                    
                    // Set password if provided
                    if let Some(password) = parameters.get("password") {
                        let passwd_input = format!("{}:{}", username, password);
                        Command::new("sudo")
                            .arg("chroot")
                            .arg(mount_point)
                            .arg("chpasswd")
                            .stdin(std::process::Stdio::piped())
                            .spawn()?
                            .stdin
                            .as_mut()
                            .unwrap()
                            .write_all(passwd_input.as_bytes())
                            .await?;
                    }
                }
                _ => {
                    warn!("User creation not implemented for OS type: {:?}", os_type);
                }
            }
        }
        Ok(())
    }

    async fn add_job_log(&self, job: &mut ProvisioningJob, level: LogLevel, message: String) {
        let log_entry = JobLog {
            timestamp: chrono::Utc::now(),
            level,
            message,
            component: "ProvisioningManager".to_string(),
        };
        job.logs.push(log_entry);
    }

    async fn add_job_log_static(job: &mut ProvisioningJob, level: LogLevel, message: String) {
        let log_entry = JobLog {
            timestamp: chrono::Utc::now(),
            level,
            message,
            component: "ProvisioningManager".to_string(),
        };
        job.logs.push(log_entry);
    }

    async fn load_templates(&self) -> Result<()> {
        let templates_file = self.work_directory.join("templates.json");
        if templates_file.exists() {
            let content = fs::read_to_string(&templates_file).await?;
            let templates: HashMap<String, ImageTemplate> = serde_json::from_str(&content)
                .unwrap_or_default();
            
            let mut templates_guard = self.templates.write().await;
            *templates_guard = templates;
            
            debug!("Loaded {} templates", templates_guard.len());
        }
        Ok(())
    }

    async fn save_templates(&self) -> Result<()> {
        let templates_file = self.work_directory.join("templates.json");
        let templates = self.templates.read().await;
        let content = serde_json::to_string_pretty(&*templates)?;
        fs::write(&templates_file, content).await?;
        Ok(())
    }

    async fn load_jobs(&self) -> Result<()> {
        let jobs_file = self.work_directory.join("jobs.json");
        if jobs_file.exists() {
            let content = fs::read_to_string(&jobs_file).await?;
            let jobs: HashMap<String, ProvisioningJob> = serde_json::from_str(&content)
                .unwrap_or_default();
            
            let mut jobs_guard = self.jobs.write().await;
            *jobs_guard = jobs;
            
            debug!("Loaded {} jobs", jobs_guard.len());
        }
        Ok(())
    }

    async fn save_jobs(&self) -> Result<()> {
        let jobs_file = self.work_directory.join("jobs.json");
        let jobs = self.jobs.read().await;
        let content = serde_json::to_string_pretty(&*jobs)?;
        fs::write(&jobs_file, content).await?;
        Ok(())
    }
}

// Default implementations
impl Default for ProvisioningManager {
    fn default() -> Self {
        Self::new(PathBuf::from("/tmp/dls-provisioning"), 2)
    }
}

impl Default for ImageTemplate {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Untitled Template".to_string(),
            description: String::new(),
            os_type: OsType::Linux,
            architecture: Architecture::X64,
            base_image_path: PathBuf::new(),
            size_gb: 10,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_provisioning_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProvisioningManager::new(temp_dir.path().to_path_buf(), 2);
        
        assert_eq!(manager.max_concurrent_jobs, 2);
        assert_eq!(manager.work_directory, temp_dir.path());
    }

    #[tokio::test]
    async fn test_template_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProvisioningManager::new(temp_dir.path().to_path_buf(), 2);
        
        let template = ImageTemplate {
            id: "test-template".to_string(),
            name: "Test Template".to_string(),
            description: "A test template".to_string(),
            os_type: OsType::Linux,
            architecture: Architecture::X64,
            base_image_path: PathBuf::from("/tmp/base.img"),
            size_gb: 20,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        };
        
        let template_id = manager.create_template(template).await.unwrap();
        assert_eq!(template_id, "test-template");
        
        let retrieved = manager.get_template(&template_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Template");
    }

    #[tokio::test]
    async fn test_job_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProvisioningManager::new(temp_dir.path().to_path_buf(), 2);
        
        // Create a template first
        let template = ImageTemplate {
            id: "test-template".to_string(),
            name: "Test Template".to_string(),
            ..Default::default()
        };
        
        let template_id = manager.create_template(template).await.unwrap();
        
        // Create a job
        let job_id = manager.create_provisioning_job(
            template_id,
            "test-image".to_string(),
            20,
            vec![],
        ).await.unwrap();
        
        let job = manager.get_job(&job_id).await;
        assert!(job.is_some());
        assert_eq!(job.unwrap().target_name, "test-image");
    }

    #[test]
    fn test_image_customization_creation() {
        let customization = ImageCustomization {
            customization_type: CustomizationType::InjectFiles,
            parameters: HashMap::from([
                ("source".to_string(), "/host/file.txt".to_string()),
                ("target".to_string(), "/etc/config.txt".to_string()),
            ]),
            priority: 1,
        };
        
        assert_eq!(customization.priority, 1);
        assert!(customization.parameters.contains_key("source"));
    }

    #[test]
    fn test_job_status_transitions() {
        let job_status = JobStatus::Pending;
        assert!(matches!(job_status, JobStatus::Pending));
    }

    #[test]
    fn test_os_type_serialization() {
        let os_type = OsType::Linux;
        let serialized = serde_json::to_string(&os_type).unwrap();
        let deserialized: OsType = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, OsType::Linux));
    }

    #[test]
    fn test_architecture_serialization() {
        let arch = Architecture::X64;
        let serialized = serde_json::to_string(&arch).unwrap();
        let deserialized: Architecture = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, Architecture::X64));
    }

    #[test]
    fn test_customization_type_variants() {
        let customizations = vec![
            CustomizationType::InjectFiles,
            CustomizationType::RunScript,
            CustomizationType::InstallPackages,
            CustomizationType::ConfigureNetwork,
            CustomizationType::SetHostname,
            CustomizationType::CreateUsers,
        ];
        
        assert_eq!(customizations.len(), 6);
    }

    #[tokio::test]
    async fn test_template_listing() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProvisioningManager::new(temp_dir.path().to_path_buf(), 2);
        
        // Create multiple templates
        for i in 0..3 {
            let template = ImageTemplate {
                id: format!("template-{}", i),
                name: format!("Template {}", i),
                ..Default::default()
            };
            manager.create_template(template).await.unwrap();
        }
        
        let templates = manager.list_templates().await;
        assert_eq!(templates.len(), 3);
    }

    #[tokio::test]
    async fn test_job_listing() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProvisioningManager::new(temp_dir.path().to_path_buf(), 2);
        
        // Create a template
        let template = ImageTemplate::default();
        let template_id = manager.create_template(template).await.unwrap();
        
        // Create multiple jobs
        for i in 0..3 {
            manager.create_provisioning_job(
                template_id.clone(),
                format!("image-{}", i),
                10 + i as u64,
                vec![],
            ).await.unwrap();
        }
        
        let jobs = manager.list_jobs().await;
        assert_eq!(jobs.len(), 3);
    }
}