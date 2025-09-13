use crate::error::{DlsError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug)]
pub struct ZfsStorageManager {
    pool_name: String,
    base_path: String,
}

impl ZfsStorageManager {
    pub fn new(pool_name: String, base_path: String) -> Self {
        Self { pool_name, base_path }
    }

    async fn ensure_dataset_exists(&self, dataset: &str) -> Result<()> {
        let dataset_path = format!("{}/{}", self.pool_name, dataset);
        
        #[cfg(target_os = "freebsd")]
        {
            use libzetta::zfs::{CreateDatasetBuilder, Zfs};
            
            let zfs = Zfs::new();
            if let Err(_) = zfs.get_dataset(&dataset_path) {
                CreateDatasetBuilder::new(&dataset_path)
                    .create()
                    .map_err(|e| DlsError::Storage(format!("Failed to create ZFS dataset: {}", e)))?;
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
}

#[async_trait]
impl StorageManager for ZfsStorageManager {
    async fn create_image(&self, name: &str, size_bytes: u64, format: ImageFormat) -> Result<DiskImage> {
        let id = Uuid::new_v4();
        let image_path = self.image_path(id, &format);
        
        self.ensure_dataset_exists("images").await?;
        
        match format {
            ImageFormat::Raw => {
                let file = fs::File::create(&image_path).await?;
                file.set_len(size_bytes).await?;
            },
            _ => {
                return Err(DlsError::Storage("Only raw format supported in development".to_string()));
            }
        }

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

        Ok(image)
    }

    async fn delete_image(&self, id: Uuid) -> Result<()> {
        let path = format!("{}/{}.img", self.base_path, id);
        if Path::new(&path).exists() {
            fs::remove_file(&path).await?;
        }
        Ok(())
    }

    async fn get_image(&self, _id: Uuid) -> Result<Option<DiskImage>> {
        Ok(None)
    }

    async fn list_images(&self) -> Result<Vec<DiskImage>> {
        Ok(vec![])
    }

    async fn resize_image(&self, _id: Uuid, _new_size_bytes: u64) -> Result<()> {
        Err(DlsError::Storage("Resize not implemented".to_string()))
    }

    async fn clone_image(&self, _id: Uuid, _new_name: &str) -> Result<DiskImage> {
        Err(DlsError::Storage("Clone not implemented".to_string()))
    }

    async fn create_snapshot(&self, _id: Uuid, _snapshot_name: &str) -> Result<String> {
        Err(DlsError::Storage("Snapshot not implemented".to_string()))
    }

    async fn restore_snapshot(&self, _id: Uuid, _snapshot_name: &str) -> Result<()> {
        Err(DlsError::Storage("Restore snapshot not implemented".to_string()))
    }

    async fn export_image(&self, _id: Uuid, _export_path: &str) -> Result<()> {
        Err(DlsError::Storage("Export not implemented".to_string()))
    }

    async fn import_image(&self, _name: &str, _import_path: &str) -> Result<DiskImage> {
        Err(DlsError::Storage("Import not implemented".to_string()))
    }
}