use crate::error::{DlsError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZfsDataset {
    pub name: String,
    pub mountpoint: Option<PathBuf>,
    pub used: u64,
    pub available: u64,
    pub compression: CompressionType,
    pub dedup: bool,
    pub properties: HashMap<String, String>,
    pub created: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionType {
    Off,
    Lz4,
    Gzip,
    Zstd,
    Lzjb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZfsSnapshot {
    pub name: String,
    pub dataset: String,
    pub used: u64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub properties: HashMap<String, String>,
}

#[async_trait]
pub trait ZfsManager: Send + Sync {
    async fn create_dataset(
        &self,
        name: &str,
        properties: HashMap<String, String>,
    ) -> Result<ZfsDataset>;
    async fn destroy_dataset(&self, name: &str, recursive: bool) -> Result<()>;
    async fn list_datasets(&self, parent: Option<&str>) -> Result<Vec<ZfsDataset>>;
    async fn get_dataset(&self, name: &str) -> Result<Option<ZfsDataset>>;
    async fn set_property(&self, dataset: &str, property: &str, value: &str) -> Result<()>;
    async fn get_property(&self, dataset: &str, property: &str) -> Result<Option<String>>;

    async fn create_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<ZfsSnapshot>;
    async fn destroy_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<()>;
    async fn list_snapshots(&self, dataset: Option<&str>) -> Result<Vec<ZfsSnapshot>>;
    async fn rollback_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<()>;
    async fn clone_snapshot(&self, snapshot: &str, clone_name: &str) -> Result<ZfsDataset>;

    async fn send_snapshot(&self, snapshot: &str, destination: &str) -> Result<()>;
    async fn receive_snapshot(&self, source: &str, destination: &str) -> Result<()>;
}

#[derive(Debug)]
pub struct FreeBsdZfsManager {
    pool_name: String,
    zfs_command: String,
    zpool_command: String,
}

impl FreeBsdZfsManager {
    pub fn new(pool_name: String) -> Self {
        Self {
            pool_name,
            zfs_command: "zfs".to_string(),
            zpool_command: "zpool".to_string(),
        }
    }

    pub fn with_commands(pool_name: String, zfs_cmd: String, zpool_cmd: String) -> Self {
        Self {
            pool_name,
            zfs_command: zfs_cmd,
            zpool_command: zpool_cmd,
        }
    }

    async fn run_zfs_command(&self, args: &[&str]) -> Result<String> {
        debug!(
            "Running ZFS command: {} {}",
            self.zfs_command,
            args.join(" ")
        );

        let output = Command::new(&self.zfs_command)
            .args(args)
            .output()
            .await
            .map_err(|e| DlsError::Storage(format!("Failed to execute ZFS command: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DlsError::Storage(format!("ZFS command failed: {stderr}")));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    }

    async fn run_zpool_command(&self, args: &[&str]) -> Result<String> {
        debug!(
            "Running ZPool command: {} {}",
            self.zpool_command,
            args.join(" ")
        );

        let output = Command::new(&self.zpool_command)
            .args(args)
            .output()
            .await
            .map_err(|e| DlsError::Storage(format!("Failed to execute ZPool command: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DlsError::Storage(format!("ZPool command failed: {stderr}")));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    }

    fn parse_dataset_info(&self, line: &str) -> Result<ZfsDataset> {
        let parts: Vec<&str> = line.trim().split('\t').collect();
        if parts.len() < 7 {
            return Err(DlsError::Storage("Invalid ZFS dataset format".to_string()));
        }

        let name = parts[0].to_string();
        let mountpoint = if parts[1] == "-" || parts[1] == "none" {
            None
        } else {
            Some(PathBuf::from(parts[1]))
        };

        let used = parts[2]
            .parse::<u64>()
            .map_err(|_| DlsError::Storage("Invalid used size".to_string()))?;
        let available = parts[3]
            .parse::<u64>()
            .map_err(|_| DlsError::Storage("Invalid available size".to_string()))?;

        let compression = match parts[4] {
            "off" => CompressionType::Off,
            "lz4" => CompressionType::Lz4,
            "gzip" | "gzip-1" | "gzip-9" => CompressionType::Gzip,
            "zstd" => CompressionType::Zstd,
            "lzjb" => CompressionType::Lzjb,
            _ => CompressionType::Off,
        };

        let dedup = parts[5] == "on";

        let created = chrono::DateTime::parse_from_rfc3339(parts[6])
            .map_err(|_| DlsError::Storage("Invalid creation date".to_string()))?
            .with_timezone(&chrono::Utc);

        Ok(ZfsDataset {
            name,
            mountpoint,
            used,
            available,
            compression,
            dedup,
            properties: HashMap::new(),
            created,
        })
    }

    fn build_dataset_name(&self, name: &str) -> String {
        if name.contains('/') {
            name.to_string()
        } else {
            format!("{}/{}", self.pool_name, name)
        }
    }
}

#[async_trait]
impl ZfsManager for FreeBsdZfsManager {
    async fn create_dataset(
        &self,
        name: &str,
        properties: HashMap<String, String>,
    ) -> Result<ZfsDataset> {
        let full_name = self.build_dataset_name(name);

        let mut args = vec!["create"];
        let property_strings: Vec<String> = properties
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();

        for property_string in &property_strings {
            args.push("-o");
            args.push(property_string);
        }

        args.push(&full_name);

        self.run_zfs_command(&args).await?;

        info!("Created ZFS dataset: {}", full_name);

        self.get_dataset(&full_name)
            .await?
            .ok_or_else(|| DlsError::Storage("Dataset created but not found".to_string()))
    }

    async fn destroy_dataset(&self, name: &str, recursive: bool) -> Result<()> {
        let full_name = self.build_dataset_name(name);

        let mut args = vec!["destroy"];
        if recursive {
            args.push("-r");
        }
        args.push(&full_name);

        self.run_zfs_command(&args).await?;

        info!("Destroyed ZFS dataset: {}", full_name);
        Ok(())
    }

    async fn list_datasets(&self, parent: Option<&str>) -> Result<Vec<ZfsDataset>> {
        let target = parent.unwrap_or(&self.pool_name);

        let args = [
            "list",
            "-H",
            "-o",
            "name,mountpoint,used,available,compression,dedup,creation",
            "-r",
            target,
        ];

        let output = self.run_zfs_command(&args).await?;

        let mut datasets = Vec::new();
        for line in output.lines() {
            if !line.trim().is_empty() {
                match self.parse_dataset_info(line) {
                    Ok(dataset) => datasets.push(dataset),
                    Err(e) => warn!("Failed to parse dataset info: {}", e),
                }
            }
        }

        Ok(datasets)
    }

    async fn get_dataset(&self, name: &str) -> Result<Option<ZfsDataset>> {
        let full_name = self.build_dataset_name(name);

        let args = [
            "list",
            "-H",
            "-o",
            "name,mountpoint,used,available,compression,dedup,creation",
            &full_name,
        ];

        match self.run_zfs_command(&args).await {
            Ok(output) => {
                if let Some(line) = output.lines().next() {
                    if !line.trim().is_empty() {
                        return Ok(Some(self.parse_dataset_info(line)?));
                    }
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    async fn set_property(&self, dataset: &str, property: &str, value: &str) -> Result<()> {
        let full_name = self.build_dataset_name(dataset);
        let prop_value = format!("{property}={value}");

        let args = ["set", &prop_value, &full_name];
        self.run_zfs_command(&args).await?;

        debug!("Set property {} on dataset {}", prop_value, full_name);
        Ok(())
    }

    async fn get_property(&self, dataset: &str, property: &str) -> Result<Option<String>> {
        let full_name = self.build_dataset_name(dataset);

        let args = ["get", "-H", "-o", "value", property, &full_name];

        match self.run_zfs_command(&args).await {
            Ok(output) => {
                let value = output.trim();
                if value.is_empty() || value == "-" {
                    Ok(None)
                } else {
                    Ok(Some(value.to_string()))
                }
            }
            Err(_) => Ok(None),
        }
    }

    async fn create_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<ZfsSnapshot> {
        let full_name = self.build_dataset_name(dataset);
        let snap_name = format!("{full_name}@{snapshot_name}");

        let args = ["snapshot", &snap_name];
        self.run_zfs_command(&args).await?;

        info!("Created ZFS snapshot: {}", snap_name);

        Ok(ZfsSnapshot {
            name: snap_name,
            dataset: full_name,
            used: 0,
            created: chrono::Utc::now(),
            properties: HashMap::new(),
        })
    }

    async fn destroy_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<()> {
        let full_name = self.build_dataset_name(dataset);
        let snap_name = format!("{full_name}@{snapshot_name}");

        let args = ["destroy", &snap_name];
        self.run_zfs_command(&args).await?;

        info!("Destroyed ZFS snapshot: {}", snap_name);
        Ok(())
    }

    async fn list_snapshots(&self, dataset: Option<&str>) -> Result<Vec<ZfsSnapshot>> {
        let target = if let Some(ds) = dataset {
            self.build_dataset_name(ds)
        } else {
            self.pool_name.clone()
        };

        let args = [
            "list",
            "-H",
            "-t",
            "snapshot",
            "-o",
            "name,used,creation",
            "-r",
            &target,
        ];

        let output = self.run_zfs_command(&args).await?;

        let mut snapshots = Vec::new();
        for line in output.lines() {
            if !line.trim().is_empty() {
                let parts: Vec<&str> = line.trim().split('\t').collect();
                if parts.len() >= 3 {
                    let name = parts[0].to_string();
                    let dataset_name = name.split('@').next().unwrap_or("").to_string();
                    let used = parts[1].parse::<u64>().unwrap_or(0);
                    let created = chrono::DateTime::parse_from_rfc3339(parts[2])
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc);

                    snapshots.push(ZfsSnapshot {
                        name,
                        dataset: dataset_name,
                        used,
                        created,
                        properties: HashMap::new(),
                    });
                }
            }
        }

        Ok(snapshots)
    }

    async fn rollback_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<()> {
        let full_name = self.build_dataset_name(dataset);
        let snap_name = format!("{full_name}@{snapshot_name}");

        let args = ["rollback", &snap_name];
        self.run_zfs_command(&args).await?;

        info!(
            "Rolled back ZFS dataset {} to snapshot {}",
            full_name, snapshot_name
        );
        Ok(())
    }

    async fn clone_snapshot(&self, snapshot: &str, clone_name: &str) -> Result<ZfsDataset> {
        let clone_full_name = self.build_dataset_name(clone_name);

        let args = ["clone", snapshot, &clone_full_name];
        self.run_zfs_command(&args).await?;

        info!("Cloned ZFS snapshot {} to {}", snapshot, clone_full_name);

        self.get_dataset(&clone_full_name)
            .await?
            .ok_or_else(|| DlsError::Storage("Clone created but not found".to_string()))
    }

    async fn send_snapshot(&self, snapshot: &str, destination: &str) -> Result<()> {
        // This is a simplified implementation - real implementation would use pipes
        warn!("ZFS send/receive not fully implemented in development mode");

        let args = ["send", snapshot];
        let _output = self.run_zfs_command(&args).await?;

        // In a real implementation, this would pipe to the destination
        info!(
            "ZFS send initiated for snapshot {} to {}",
            snapshot, destination
        );
        Ok(())
    }

    async fn receive_snapshot(&self, source: &str, destination: &str) -> Result<()> {
        warn!("ZFS send/receive not fully implemented in development mode");

        // In a real implementation, this would receive from a pipe
        info!("ZFS receive initiated from {} to {}", source, destination);
        Ok(())
    }
}

#[cfg(not(target_os = "freebsd"))]
#[derive(Debug)]
pub struct MockZfsManager {
    pool_name: String,
    datasets: tokio::sync::RwLock<HashMap<String, ZfsDataset>>,
    snapshots: tokio::sync::RwLock<HashMap<String, ZfsSnapshot>>,
}

#[cfg(not(target_os = "freebsd"))]
impl MockZfsManager {
    pub fn new(pool_name: String) -> Self {
        Self {
            pool_name,
            datasets: tokio::sync::RwLock::new(HashMap::new()),
            snapshots: tokio::sync::RwLock::new(HashMap::new()),
        }
    }
}

#[cfg(not(target_os = "freebsd"))]
#[async_trait]
impl ZfsManager for MockZfsManager {
    async fn create_dataset(
        &self,
        name: &str,
        properties: HashMap<String, String>,
    ) -> Result<ZfsDataset> {
        let full_name = format!("{}/{}", self.pool_name, name);

        let dataset = ZfsDataset {
            name: full_name.clone(),
            mountpoint: Some(PathBuf::from(format!("/{full_name}"))),
            used: 0,
            available: 1024 * 1024 * 1024, // 1GB
            compression: CompressionType::Lz4,
            dedup: false,
            properties,
            created: chrono::Utc::now(),
        };

        let mut datasets = self.datasets.write().await;
        datasets.insert(full_name.clone(), dataset.clone());

        info!("Created mock ZFS dataset: {}", full_name);
        Ok(dataset)
    }

    async fn destroy_dataset(&self, name: &str, _recursive: bool) -> Result<()> {
        let full_name = format!("{}/{}", self.pool_name, name);

        let mut datasets = self.datasets.write().await;
        datasets.remove(&full_name);

        info!("Destroyed mock ZFS dataset: {}", full_name);
        Ok(())
    }

    async fn list_datasets(&self, _parent: Option<&str>) -> Result<Vec<ZfsDataset>> {
        let datasets = self.datasets.read().await;
        Ok(datasets.values().cloned().collect())
    }

    async fn get_dataset(&self, name: &str) -> Result<Option<ZfsDataset>> {
        let full_name = format!("{}/{}", self.pool_name, name);
        let datasets = self.datasets.read().await;
        Ok(datasets.get(&full_name).cloned())
    }

    async fn set_property(&self, dataset: &str, property: &str, value: &str) -> Result<()> {
        let full_name = format!("{}/{}", self.pool_name, dataset);
        let mut datasets = self.datasets.write().await;

        if let Some(ds) = datasets.get_mut(&full_name) {
            ds.properties
                .insert(property.to_string(), value.to_string());
        }

        Ok(())
    }

    async fn get_property(&self, dataset: &str, property: &str) -> Result<Option<String>> {
        let full_name = format!("{}/{}", self.pool_name, dataset);
        let datasets = self.datasets.read().await;

        if let Some(ds) = datasets.get(&full_name) {
            Ok(ds.properties.get(property).cloned())
        } else {
            Ok(None)
        }
    }

    async fn create_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<ZfsSnapshot> {
        let full_name = format!("{}/{}", self.pool_name, dataset);
        let snap_name = format!("{full_name}@{snapshot_name}");

        let snapshot = ZfsSnapshot {
            name: snap_name.clone(),
            dataset: full_name,
            used: 0,
            created: chrono::Utc::now(),
            properties: HashMap::new(),
        };

        let mut snapshots = self.snapshots.write().await;
        snapshots.insert(snap_name.clone(), snapshot.clone());

        info!("Created mock ZFS snapshot: {}", snap_name);
        Ok(snapshot)
    }

    async fn destroy_snapshot(&self, dataset: &str, snapshot_name: &str) -> Result<()> {
        let full_name = format!("{}/{}", self.pool_name, dataset);
        let snap_name = format!("{full_name}@{snapshot_name}");

        let mut snapshots = self.snapshots.write().await;
        snapshots.remove(&snap_name);

        info!("Destroyed mock ZFS snapshot: {}", snap_name);
        Ok(())
    }

    async fn list_snapshots(&self, _dataset: Option<&str>) -> Result<Vec<ZfsSnapshot>> {
        let snapshots = self.snapshots.read().await;
        Ok(snapshots.values().cloned().collect())
    }

    async fn rollback_snapshot(&self, _dataset: &str, _snapshot_name: &str) -> Result<()> {
        info!("Mock ZFS rollback executed");
        Ok(())
    }

    async fn clone_snapshot(&self, _snapshot: &str, clone_name: &str) -> Result<ZfsDataset> {
        let properties = HashMap::new();
        self.create_dataset(clone_name, properties).await
    }

    async fn send_snapshot(&self, _snapshot: &str, _destination: &str) -> Result<()> {
        info!("Mock ZFS send executed");
        Ok(())
    }

    async fn receive_snapshot(&self, _source: &str, _destination: &str) -> Result<()> {
        info!("Mock ZFS receive executed");
        Ok(())
    }
}
