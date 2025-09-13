pub mod zfs;

use crate::error::{DlsError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use zfs::{ZfsManager, FreeBsdZfsManager, ZfsDataset, ZfsSnapshot, CompressionType};

#[cfg(not(target_os = "freebsd"))]
pub use zfs::MockZfsManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskImage {
    pub id: Uuid,
    pub name: String,
    pub size_bytes: u64,
    pub format: ImageFormat,
    pub path: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub description: Option<String>,
    pub os_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImageFormat {
    Raw,
    Vhdx,
    Qcow2,
}

#[async_trait]
pub trait StorageManager: Send + Sync {
    async fn create_image(&self, name: &str, size_bytes: u64, format: ImageFormat) -> Result<DiskImage>;
    async fn delete_image(&self, id: Uuid) -> Result<()>;
    async fn get_image(&self, id: Uuid) -> Result<Option<DiskImage>>;
    async fn list_images(&self) -> Result<Vec<DiskImage>>;
    async fn resize_image(&self, id: Uuid, new_size_bytes: u64) -> Result<()>;
    async fn clone_image(&self, id: Uuid, new_name: &str) -> Result<DiskImage>;
    async fn create_snapshot(&self, id: Uuid, snapshot_name: &str) -> Result<String>;
    async fn restore_snapshot(&self, id: Uuid, snapshot_name: &str) -> Result<()>;
    async fn export_image(&self, id: Uuid, export_path: &str) -> Result<()>;
    async fn import_image(&self, name: &str, import_path: &str) -> Result<DiskImage>;
}

pub struct ZfsStorageManager {
    pool_name: String,
    base_path: String,
    zfs_manager: Box<dyn ZfsManager>,
    images_metadata: tokio::sync::RwLock<HashMap<Uuid, DiskImage>>,
}

impl std::fmt::Debug for ZfsStorageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZfsStorageManager")
            .field("pool_name", &self.pool_name)
            .field("base_path", &self.base_path)
            .field("images_metadata", &self.images_metadata)
            .finish()
    }
}

impl ZfsStorageManager {
    pub fn new(pool_name: String, base_path: String) -> Self {
        #[cfg(target_os = "freebsd")]
        let zfs_manager: Box<dyn ZfsManager> = Box::new(FreeBsdZfsManager::new(pool_name.clone()));
        
        #[cfg(not(target_os = "freebsd"))]
        let zfs_manager: Box<dyn ZfsManager> = Box::new(zfs::MockZfsManager::new(pool_name.clone()));
        
        Self { 
            pool_name, 
            base_path,
            zfs_manager,
            images_metadata: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn with_zfs_manager(zfs_manager: Box<dyn ZfsManager>, pool_name: String, base_path: String) -> Self {
        Self {
            pool_name,
            base_path,
            zfs_manager,
            images_metadata: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    async fn ensure_dataset_exists(&self, dataset: &str) -> Result<()> {
        let _dataset_path = format!("{}/{}", self.pool_name, dataset);
        
        #[cfg(target_os = "freebsd")]
        {
            use crate::storage::zfs::FreeBsdZfsManager;
            let zfs_manager = FreeBsdZfsManager::new(self.pool_name.clone());
            
            if zfs_manager.get_dataset(dataset).await?.is_none() {
                let mut properties = std::collections::HashMap::new();
                properties.insert("mountpoint".to_string(), format!("{}/{}", self.base_path, dataset));
                properties.insert("compression".to_string(), "lz4".to_string());
                
                zfs_manager.create_dataset(dataset, properties).await?;
            }
        }
        
        #[cfg(not(target_os = "freebsd"))]
        {
            tokio::fs::create_dir_all(&self.base_path).await
                .map_err(|e| DlsError::Storage(format!("Failed to create directory: {}", e)))?;
        }
        
        Ok(())
    }

    fn image_path(&self, id: Uuid, format: &ImageFormat) -> String {
        let extension = match format {
            ImageFormat::Raw => "img",
            ImageFormat::Vhdx => "vhdx",
            ImageFormat::Qcow2 => "qcow2",
        };
        format!("{}/{}.{}", self.base_path, id, extension)
    }
    
    fn dataset_name_for_image(&self, id: Uuid) -> String {
        format!("images/{}", id)
    }
    
    async fn load_image_metadata(&self) -> Result<()> {
        debug!("Loading image metadata from ZFS datasets");
        
        let datasets = self.zfs_manager.list_datasets(Some("images")).await?;
        let mut metadata = self.images_metadata.write().await;
        
        for dataset in datasets {
            if let Some(image_name) = dataset.name.strip_prefix(&format!("{}/images/", self.pool_name)) {
                if let Ok(id) = Uuid::parse_str(image_name) {
                    let image_path = self.image_path(id, &ImageFormat::Raw);
                    
                    if let Ok(file_metadata) = tokio::fs::metadata(&image_path).await {
                        let disk_image = DiskImage {
                            id,
                            name: format!("disk-image-{}", id),
                            size_bytes: file_metadata.len(),
                            format: ImageFormat::Raw,
                            path: image_path,
                            created_at: dataset.created,
                            updated_at: chrono::Utc::now(),
                            description: None,
                            os_type: None,
                        };
                        
                        metadata.insert(id, disk_image);
                    }
                }
            }
        }
        
        info!("Loaded {} image metadata records", metadata.len());
        Ok(())
    }
    
    async fn save_image_metadata(&self, image: &DiskImage) -> Result<()> {
        let mut metadata = self.images_metadata.write().await;
        metadata.insert(image.id, image.clone());
        debug!("Saved metadata for image: {}", image.id);
        Ok(())
    }
    
    async fn remove_image_metadata(&self, id: Uuid) -> Result<()> {
        let mut metadata = self.images_metadata.write().await;
        metadata.remove(&id);
        debug!("Removed metadata for image: {}", id);
        Ok(())
    }
    
    async fn create_image_file(&self, path: &str, size_bytes: u64, format: &ImageFormat) -> Result<()> {
        match format {
            ImageFormat::Raw => {
                debug!("Creating raw image file: {} ({} bytes)", path, size_bytes);
                let file = fs::File::create(path).await
                    .map_err(|e| DlsError::Storage(format!("Failed to create image file: {}", e)))?;
                file.set_len(size_bytes).await
                    .map_err(|e| DlsError::Storage(format!("Failed to set file size: {}", e)))?;
            },
            ImageFormat::Qcow2 => {
                debug!("Creating qcow2 image file: {} ({} bytes)", path, size_bytes);
                let output = Command::new("qemu-img")
                    .args(&["create", "-f", "qcow2", path, &format!("{}B", size_bytes)])
                    .output()
                    .await
                    .map_err(|e| DlsError::Storage(format!("Failed to execute qemu-img: {}", e)))?;
                
                if !output.status.success() {
                    return Err(DlsError::Storage(format!(
                        "qemu-img failed: {}", 
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
            },
            ImageFormat::Vhdx => {
                debug!("Creating VHDX image file: {} ({} bytes)", path, size_bytes);
                let output = Command::new("qemu-img")
                    .args(&["create", "-f", "vhdx", path, &format!("{}B", size_bytes)])
                    .output()
                    .await
                    .map_err(|e| DlsError::Storage(format!("Failed to execute qemu-img: {}", e)))?;
                
                if !output.status.success() {
                    return Err(DlsError::Storage(format!(
                        "qemu-img failed: {}", 
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
            }
        }
        
        info!("Successfully created image file: {}", path);
        Ok(())
    }

    pub async fn create_image_dataset(&self, image_id: Uuid) -> Result<ZfsDataset> {
        #[cfg(target_os = "freebsd")]
        {
            let zfs_manager = FreeBsdZfsManager::new(self.pool_name.clone());
            let dataset_name = format!("images/{}", image_id);
            
            let mut properties = std::collections::HashMap::new();
            properties.insert("mountpoint".to_string(), format!("{}/{}", self.base_path, image_id));
            properties.insert("compression".to_string(), "lz4".to_string());
            properties.insert("dedup".to_string(), "off".to_string());
            properties.insert("quota".to_string(), "100G".to_string());
            
            zfs_manager.create_dataset(&dataset_name, properties).await
        }
        
        #[cfg(not(target_os = "freebsd"))]
        {
            use crate::storage::zfs::MockZfsManager;
            let zfs_manager = MockZfsManager::new(self.pool_name.clone());
            let dataset_name = format!("images/{}", image_id);
            
            let mut properties = std::collections::HashMap::new();
            properties.insert("compression".to_string(), "lz4".to_string());
            
            zfs_manager.create_dataset(&dataset_name, properties).await
        }
    }

    pub async fn create_image_snapshot(&self, image_id: Uuid, snapshot_name: &str) -> Result<ZfsSnapshot> {
        #[cfg(target_os = "freebsd")]
        {
            let zfs_manager = FreeBsdZfsManager::new(self.pool_name.clone());
            let dataset_name = format!("images/{}", image_id);
            zfs_manager.create_snapshot(&dataset_name, snapshot_name).await
        }
        
        #[cfg(not(target_os = "freebsd"))]
        {
            use crate::storage::zfs::MockZfsManager;
            let zfs_manager = MockZfsManager::new(self.pool_name.clone());
            let dataset_name = format!("images/{}", image_id);
            zfs_manager.create_snapshot(&dataset_name, snapshot_name).await
        }
    }
}

#[async_trait]
impl StorageManager for ZfsStorageManager {
    async fn create_image(&self, name: &str, size_bytes: u64, format: ImageFormat) -> Result<DiskImage> {
        let id = Uuid::new_v4();
        let image_path = self.image_path(id, &format);
        let dataset_name = self.dataset_name_for_image(id);
        
        info!("Creating image: {} ({}GB, format: {:?})", name, size_bytes / (1024 * 1024 * 1024), format);
        
        self.ensure_dataset_exists("images").await?;
        
        let mut properties = HashMap::new();
        properties.insert("mountpoint".to_string(), format!("{}/{}", self.base_path, id));
        properties.insert("compression".to_string(), "lz4".to_string());
        properties.insert("dedup".to_string(), "off".to_string());
        
        let _dataset = self.zfs_manager.create_dataset(&dataset_name, properties).await?;
        
        self.create_image_file(&image_path, size_bytes, &format).await?;

        let now = chrono::Utc::now();
        let image = DiskImage {
            id,
            name: name.to_string(),
            size_bytes,
            format,
            path: image_path,
            created_at: now,
            updated_at: now,
            description: None,
            os_type: None,
        };
        
        self.save_image_metadata(&image).await?;
        info!("Successfully created image: {} with ID: {}", name, id);

        Ok(image)
    }

    async fn delete_image(&self, id: Uuid) -> Result<()> {
        info!("Deleting image with ID: {}", id);
        
        let dataset_name = self.dataset_name_for_image(id);
        
        if let Ok(Some(_)) = self.zfs_manager.get_dataset(&dataset_name).await {
            self.zfs_manager.destroy_dataset(&dataset_name, true).await?;
        }
        
        let metadata = self.images_metadata.read().await;
        if let Some(image) = metadata.get(&id) {
            if Path::new(&image.path).exists() {
                fs::remove_file(&image.path).await
                    .map_err(|e| DlsError::Storage(format!("Failed to remove image file: {}", e)))?;
            }
        }
        drop(metadata);
        
        self.remove_image_metadata(id).await?;
        info!("Successfully deleted image: {}", id);
        Ok(())
    }

    async fn get_image(&self, id: Uuid) -> Result<Option<DiskImage>> {
        let metadata = self.images_metadata.read().await;
        Ok(metadata.get(&id).cloned())
    }

    async fn list_images(&self) -> Result<Vec<DiskImage>> {
        if self.images_metadata.read().await.is_empty() {
            self.load_image_metadata().await?;
        }
        
        let metadata = self.images_metadata.read().await;
        Ok(metadata.values().cloned().collect())
    }

    async fn resize_image(&self, id: Uuid, new_size_bytes: u64) -> Result<()> {
        info!("Resizing image {} to {} bytes", id, new_size_bytes);
        
        let mut metadata = self.images_metadata.write().await;
        if let Some(image) = metadata.get_mut(&id) {
            match image.format {
                ImageFormat::Raw => {
                    let file = fs::OpenOptions::new()
                        .write(true)
                        .open(&image.path)
                        .await
                        .map_err(|e| DlsError::Storage(format!("Failed to open image file: {}", e)))?;
                    
                    file.set_len(new_size_bytes).await
                        .map_err(|e| DlsError::Storage(format!("Failed to resize image file: {}", e)))?;
                },
                _ => {
                    let output = Command::new("qemu-img")
                        .args(&["resize", &image.path, &format!("{}B", new_size_bytes)])
                        .output()
                        .await
                        .map_err(|e| DlsError::Storage(format!("Failed to execute qemu-img resize: {}", e)))?;
                    
                    if !output.status.success() {
                        return Err(DlsError::Storage(format!(
                            "qemu-img resize failed: {}", 
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                }
            }
            
            image.size_bytes = new_size_bytes;
            image.updated_at = chrono::Utc::now();
            info!("Successfully resized image: {}", id);
            Ok(())
        } else {
            Err(DlsError::Storage(format!("Image not found: {}", id)))
        }
    }

    async fn clone_image(&self, id: Uuid, new_name: &str) -> Result<DiskImage> {
        info!("Cloning image {} with new name: {}", id, new_name);
        
        let metadata = self.images_metadata.read().await;
        let source_image = metadata.get(&id)
            .ok_or_else(|| DlsError::Storage(format!("Source image not found: {}", id)))?
            .clone();
        drop(metadata);
        
        let source_dataset = self.dataset_name_for_image(id);
        let snapshot_name = format!("clone-{}", chrono::Utc::now().timestamp());
        
        self.zfs_manager.create_snapshot(&source_dataset, &snapshot_name).await?;
        
        let new_id = Uuid::new_v4();
        let clone_dataset = self.dataset_name_for_image(new_id);
        let snapshot_full_name = format!("{}/{}@{}", self.pool_name, source_dataset, snapshot_name);
        
        let _clone_dataset = self.zfs_manager.clone_snapshot(&snapshot_full_name, &clone_dataset).await?;
        
        let new_image_path = self.image_path(new_id, &source_image.format);
        let now = chrono::Utc::now();
        
        let cloned_image = DiskImage {
            id: new_id,
            name: new_name.to_string(),
            size_bytes: source_image.size_bytes,
            format: source_image.format.clone(),
            path: new_image_path,
            created_at: now,
            updated_at: now,
            description: Some(format!("Clone of {}", source_image.name)),
            os_type: source_image.os_type.clone(),
        };
        
        self.save_image_metadata(&cloned_image).await?;
        info!("Successfully cloned image {} to {}", id, new_id);
        
        Ok(cloned_image)
    }

    async fn create_snapshot(&self, id: Uuid, snapshot_name: &str) -> Result<String> {
        info!("Creating snapshot '{}' for image {}", snapshot_name, id);
        
        let dataset_name = self.dataset_name_for_image(id);
        let snapshot = self.zfs_manager.create_snapshot(&dataset_name, snapshot_name).await?;
        
        info!("Successfully created snapshot: {}", snapshot.name);
        Ok(snapshot.name)
    }

    async fn restore_snapshot(&self, id: Uuid, snapshot_name: &str) -> Result<()> {
        info!("Restoring snapshot '{}' for image {}", snapshot_name, id);
        
        let dataset_name = self.dataset_name_for_image(id);
        self.zfs_manager.rollback_snapshot(&dataset_name, snapshot_name).await?;
        
        let mut metadata = self.images_metadata.write().await;
        if let Some(image) = metadata.get_mut(&id) {
            image.updated_at = chrono::Utc::now();
        }
        
        info!("Successfully restored snapshot '{}' for image {}", snapshot_name, id);
        Ok(())
    }

    async fn export_image(&self, id: Uuid, export_path: &str) -> Result<()> {
        info!("Exporting image {} to {}", id, export_path);
        
        let metadata = self.images_metadata.read().await;
        let image = metadata.get(&id)
            .ok_or_else(|| DlsError::Storage(format!("Image not found: {}", id)))?;
        
        fs::copy(&image.path, export_path).await
            .map_err(|e| DlsError::Storage(format!("Failed to export image: {}", e)))?;
        
        info!("Successfully exported image {} to {}", id, export_path);
        Ok(())
    }

    async fn import_image(&self, name: &str, import_path: &str) -> Result<DiskImage> {
        info!("Importing image from {} with name: {}", import_path, name);
        
        if !Path::new(import_path).exists() {
            return Err(DlsError::Storage(format!("Import file not found: {}", import_path)));
        }
        
        let file_metadata = fs::metadata(import_path).await
            .map_err(|e| DlsError::Storage(format!("Failed to read import file metadata: {}", e)))?;
        
        let format = if import_path.ends_with(".qcow2") {
            ImageFormat::Qcow2
        } else if import_path.ends_with(".vhdx") {
            ImageFormat::Vhdx
        } else {
            ImageFormat::Raw
        };
        
        let id = Uuid::new_v4();
        let image_path = self.image_path(id, &format);
        let dataset_name = self.dataset_name_for_image(id);
        
        self.ensure_dataset_exists("images").await?;
        
        let mut properties = HashMap::new();
        properties.insert("mountpoint".to_string(), format!("{}/{}", self.base_path, id));
        properties.insert("compression".to_string(), "lz4".to_string());
        
        let _dataset = self.zfs_manager.create_dataset(&dataset_name, properties).await?;
        
        fs::copy(import_path, &image_path).await
            .map_err(|e| DlsError::Storage(format!("Failed to copy import file: {}", e)))?;
        
        let now = chrono::Utc::now();
        let image = DiskImage {
            id,
            name: name.to_string(),
            size_bytes: file_metadata.len(),
            format,
            path: image_path,
            created_at: now,
            updated_at: now,
            description: Some(format!("Imported from {}", import_path)),
            os_type: None,
        };
        
        self.save_image_metadata(&image).await?;
        info!("Successfully imported image: {} with ID: {}", name, id);
        
        Ok(image)
    }
}