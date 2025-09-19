use crate::error::{DlsError, Result};
use crate::storage::StorageManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeStorageNode {
    pub node_id: String,
    pub storage_capacity_gb: u64,
    pub used_capacity_gb: u64,
    pub available_capacity_gb: u64,
    pub storage_type: StorageType,
    pub performance_tier: PerformanceTier,
    pub replication_factor: u8,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub data_chunks: Vec<DataChunk>,
    pub sync_status: SyncStatus,
    pub last_sync: DateTime<Utc>,
    pub health_metrics: StorageHealthMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageType {
    NVMe,
    SSD,
    HDD,
    Hybrid,
    InMemory,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PerformanceTier {
    Hot,      // Frequently accessed data
    Warm,     // Occasionally accessed data
    Cold,     // Rarely accessed data
    Archive,  // Long-term storage
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    Synced,
    Syncing,
    OutOfSync,
    Failed,
    Paused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataChunk {
    pub chunk_id: String,
    pub object_id: String,
    pub chunk_index: u32,
    pub size_bytes: u64,
    pub checksum: String,
    pub chunk_type: ChunkType,
    pub compression_ratio: f64,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u64,
    pub replicas: Vec<ChunkReplica>,
    pub tier: PerformanceTier,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChunkType {
    Data,
    Metadata,
    Index,
    Parity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkReplica {
    pub replica_id: String,
    pub node_id: String,
    pub is_primary: bool,
    pub sync_status: SyncStatus,
    pub last_verified: DateTime<Utc>,
    pub checksum_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHealthMetrics {
    pub read_iops: u64,
    pub write_iops: u64,
    pub read_bandwidth_mbps: f64,
    pub write_bandwidth_mbps: f64,
    pub average_latency_ms: f64,
    pub error_rate: f64,
    pub temperature_celsius: Option<f64>,
    pub wear_level_percentage: Option<f64>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedObject {
    pub object_id: String,
    pub object_name: String,
    pub object_type: ObjectType,
    pub total_size_bytes: u64,
    pub chunk_count: u32,
    pub replication_factor: u8,
    pub consistency_level: ConsistencyLevel,
    pub storage_policy: StoragePolicy,
    pub chunks: Vec<String>, // chunk_ids
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub access_pattern: AccessPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ObjectType {
    DiskImage,
    BootFile,
    Configuration,
    Application,
    Dataset,
    Backup,
    Temporary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsistencyLevel {
    Strong,    // All replicas must be consistent
    Eventual,  // Replicas will eventually be consistent
    Weak,      // No consistency guarantees
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePolicy {
    pub policy_id: String,
    pub min_replicas: u8,
    pub max_replicas: u8,
    pub preferred_tiers: Vec<PerformanceTier>,
    pub geo_distribution: GeoDistributionPolicy,
    pub retention_days: Option<u32>,
    pub auto_tiering: bool,
    pub compression_algorithm: Option<String>,
    pub encryption_algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GeoDistributionPolicy {
    Any,
    SameRegion,
    MultiRegion,
    SpecificNodes(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    pub access_frequency: AccessFrequency,
    pub read_write_ratio: f64,
    pub sequential_access_percentage: f64,
    pub peak_access_hours: Vec<u8>,
    pub seasonal_patterns: Vec<SeasonalPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessFrequency {
    VeryHigh,  // Multiple times per minute
    High,      // Multiple times per hour
    Medium,    // Multiple times per day
    Low,       // Once per day or less
    Archive,   // Very rarely accessed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPattern {
    pub pattern_type: PatternType,
    pub peak_periods: Vec<TimePeriod>,
    pub multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternType {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePeriod {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days_of_week: Option<Vec<u8>>,
    pub months: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOperation {
    pub operation_id: String,
    pub operation_type: SyncOperationType,
    pub source_node: String,
    pub target_nodes: Vec<String>,
    pub affected_chunks: Vec<String>,
    pub status: SyncOperationStatus,
    pub progress_percentage: f64,
    pub bytes_transferred: u64,
    pub estimated_completion: Option<DateTime<Utc>>,
    pub started_at: DateTime<Utc>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncOperationType {
    FullSync,
    IncrementalSync,
    RepairSync,
    RebalanceSync,
    MigrationSync,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncOperationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

pub struct StorageSyncEngine {
    sync_operations: Arc<DashMap<String, SyncOperation>>,
    sync_schedules: Arc<RwLock<HashMap<String, SyncSchedule>>>,
    bandwidth_limits: Arc<RwLock<HashMap<String, BandwidthLimit>>>,
    conflict_resolution: Arc<RwLock<ConflictResolutionPolicy>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSchedule {
    pub schedule_id: String,
    pub cron_expression: String,
    pub sync_type: SyncOperationType,
    pub target_nodes: Vec<String>,
    pub enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthLimit {
    pub max_bandwidth_mbps: f64,
    pub priority_levels: HashMap<String, f64>,
    pub time_based_limits: Vec<TimedBandwidthLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedBandwidthLimit {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days_of_week: Vec<u8>,
    pub limit_mbps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolutionPolicy {
    LastWriteWins,
    FirstWriteWins,
    MergeConflicts,
    ManualResolution,
    VersionBased,
}

pub struct DistributedStorageManager {
    storage_nodes: Arc<DashMap<String, EdgeStorageNode>>,
    distributed_objects: Arc<DashMap<String, DistributedObject>>,
    storage_policies: Arc<DashMap<String, StoragePolicy>>,
    sync_engine: Arc<StorageSyncEngine>,
    local_storage: Arc<dyn std::any::Any + Send + Sync>, // Placeholder for storage manager
    chunk_map: Arc<DashMap<String, Vec<String>>>, // object_id -> chunk_ids
    node_selector: Arc<RwLock<Box<dyn NodeSelector + Send + Sync>>>,
    tiering_scheduler: Arc<TieringScheduler>,
}

pub trait NodeSelector {
    fn select_nodes_for_replication(
        &self,
        chunk: &DataChunk,
        available_nodes: &[EdgeStorageNode],
        replication_factor: u8,
    ) -> Result<Vec<String>>;

    fn select_node_for_read(&self, chunk: &DataChunk, available_replicas: &[ChunkReplica]) -> Result<String>;
}

pub struct GeographicNodeSelector;

impl NodeSelector for GeographicNodeSelector {
    fn select_nodes_for_replication(
        &self,
        _chunk: &DataChunk,
        available_nodes: &[EdgeStorageNode],
        replication_factor: u8,
    ) -> Result<Vec<String>> {
        if available_nodes.len() < replication_factor as usize {
            return Err(DlsError::ResourceExhausted("Not enough nodes for replication".to_string()));
        }

        // Simple round-robin selection for now
        // In production, this would consider geographic distribution, performance, etc.
        let selected: Vec<String> = available_nodes
            .iter()
            .take(replication_factor as usize)
            .map(|node| node.node_id.clone())
            .collect();

        Ok(selected)
    }

    fn select_node_for_read(&self, _chunk: &DataChunk, available_replicas: &[ChunkReplica]) -> Result<String> {
        // Select the primary replica or the one with best sync status
        let best_replica = available_replicas
            .iter()
            .filter(|r| r.sync_status == SyncStatus::Synced)
            .find(|r| r.is_primary)
            .or_else(|| available_replicas.iter().find(|r| r.sync_status == SyncStatus::Synced))
            .ok_or_else(|| DlsError::NotFound("No available synced replica".to_string()))?;

        Ok(best_replica.node_id.clone())
    }
}

pub struct TieringScheduler {
    tiering_rules: Arc<RwLock<Vec<TieringRule>>>,
    scheduled_migrations: Arc<DashMap<String, TieringMigration>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieringRule {
    pub rule_id: String,
    pub name: String,
    pub source_tier: PerformanceTier,
    pub target_tier: PerformanceTier,
    pub conditions: Vec<TieringCondition>,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieringCondition {
    pub condition_type: TieringConditionType,
    pub operator: ComparisonOperator,
    pub threshold: f64,
    pub evaluation_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TieringConditionType {
    LastAccessTime,
    AccessFrequency,
    DataAge,
    StorageCost,
    Performance,
    Capacity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComparisonOperator {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Equal,
    NotEqual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieringMigration {
    pub migration_id: String,
    pub chunk_id: String,
    pub source_tier: PerformanceTier,
    pub target_tier: PerformanceTier,
    pub scheduled_time: DateTime<Utc>,
    pub status: MigrationStatus,
    pub progress_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MigrationStatus {
    Scheduled,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

impl StorageSyncEngine {
    pub fn new() -> Self {
        Self {
            sync_operations: Arc::new(DashMap::new()),
            sync_schedules: Arc::new(RwLock::new(HashMap::new())),
            bandwidth_limits: Arc::new(RwLock::new(HashMap::new())),
            conflict_resolution: Arc::new(RwLock::new(ConflictResolutionPolicy::LastWriteWins)),
        }
    }

    pub async fn initiate_sync(&self, operation: SyncOperation) -> Result<String> {
        let operation_id = operation.operation_id.clone();
        self.sync_operations.insert(operation_id.clone(), operation);

        // In a real implementation, this would start the actual sync process
        tracing::info!("Sync operation {} initiated", operation_id);
        Ok(operation_id)
    }

    pub async fn get_sync_status(&self, operation_id: &str) -> Result<SyncOperation> {
        self.sync_operations
            .get(operation_id)
            .map(|op| op.clone())
            .ok_or_else(|| DlsError::NotFound(format!("Sync operation {} not found", operation_id)))
    }

    pub async fn cancel_sync(&self, operation_id: &str) -> Result<()> {
        if let Some(mut operation) = self.sync_operations.get_mut(operation_id) {
            operation.status = SyncOperationStatus::Cancelled;
            tracing::info!("Sync operation {} cancelled", operation_id);
            Ok(())
        } else {
            Err(DlsError::NotFound(format!("Sync operation {} not found", operation_id)))
        }
    }

    pub async fn schedule_periodic_sync(&self, schedule: SyncSchedule) -> Result<()> {
        let schedule_id = schedule.schedule_id.clone();
        self.sync_schedules.write().insert(schedule_id.clone(), schedule);
        tracing::info!("Periodic sync scheduled: {}", schedule_id);
        Ok(())
    }
}

impl TieringScheduler {
    pub fn new() -> Self {
        Self {
            tiering_rules: Arc::new(RwLock::new(Vec::new())),
            scheduled_migrations: Arc::new(DashMap::new()),
        }
    }

    pub async fn add_tiering_rule(&self, rule: TieringRule) -> Result<()> {
        let rule_id = rule.rule_id.clone();
        self.tiering_rules.write().push(rule);
        tracing::info!("Tiering rule {} added", rule_id);
        Ok(())
    }

    pub async fn evaluate_tiering(&self, chunk: &DataChunk) -> Result<Option<PerformanceTier>> {
        let rules = self.tiering_rules.read();

        for rule in rules.iter().filter(|r| r.enabled && r.source_tier == chunk.tier) {
            if self.evaluate_rule_conditions(chunk, &rule.conditions).await? {
                return Ok(Some(rule.target_tier.clone()));
            }
        }

        Ok(None)
    }

    async fn evaluate_rule_conditions(&self, chunk: &DataChunk, conditions: &[TieringCondition]) -> Result<bool> {
        for condition in conditions {
            if !self.evaluate_condition(chunk, condition).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn evaluate_condition(&self, chunk: &DataChunk, condition: &TieringCondition) -> Result<bool> {
        let value = match condition.condition_type {
            TieringConditionType::LastAccessTime => {
                (Utc::now() - chunk.last_accessed).num_days() as f64
            }
            TieringConditionType::AccessFrequency => {
                // Calculate access frequency based on access count and age
                let age_days = (Utc::now() - chunk.last_accessed).num_days().max(1) as f64;
                chunk.access_count as f64 / age_days
            }
            TieringConditionType::DataAge => {
                (Utc::now() - chunk.last_accessed).num_hours() as f64
            }
            _ => 0.0, // Other conditions would be implemented based on available metrics
        };

        let result = match condition.operator {
            ComparisonOperator::LessThan => value < condition.threshold,
            ComparisonOperator::LessThanOrEqual => value <= condition.threshold,
            ComparisonOperator::GreaterThan => value > condition.threshold,
            ComparisonOperator::GreaterThanOrEqual => value >= condition.threshold,
            ComparisonOperator::Equal => (value - condition.threshold).abs() < f64::EPSILON,
            ComparisonOperator::NotEqual => (value - condition.threshold).abs() >= f64::EPSILON,
        };

        Ok(result)
    }

    pub async fn schedule_migration(&self, migration: TieringMigration) -> Result<()> {
        let migration_id = migration.migration_id.clone();
        self.scheduled_migrations.insert(migration_id.clone(), migration);
        tracing::info!("Tiering migration {} scheduled", migration_id);
        Ok(())
    }
}

impl DistributedStorageManager {
    pub async fn new() -> Result<Self> {
        let sync_engine = Arc::new(StorageSyncEngine::new());
        let tiering_scheduler = Arc::new(TieringScheduler::new());
        let node_selector: Arc<RwLock<Box<dyn NodeSelector + Send + Sync>>> =
            Arc::new(RwLock::new(Box::new(GeographicNodeSelector)));

        Ok(Self {
            storage_nodes: Arc::new(DashMap::new()),
            distributed_objects: Arc::new(DashMap::new()),
            storage_policies: Arc::new(DashMap::new()),
            sync_engine,
            local_storage: Arc::new(()),
            chunk_map: Arc::new(DashMap::new()),
            node_selector,
            tiering_scheduler,
        })
    }

    pub async fn register_storage_node(&self, node: EdgeStorageNode) -> Result<()> {
        let node_id = node.node_id.clone();
        self.storage_nodes.insert(node_id.clone(), node);
        tracing::info!("Storage node {} registered", node_id);
        Ok(())
    }

    pub async fn store_object(&self, object_data: Vec<u8>, object_name: String, policy_id: String) -> Result<String> {
        let object_id = Uuid::new_v4().to_string();
        let policy = self.storage_policies
            .get(&policy_id)
            .ok_or_else(|| DlsError::NotFound(format!("Storage policy {} not found", policy_id)))?
            .clone();

        // Split object into chunks
        let chunks = self.create_chunks(&object_data, &object_id).await?;

        // Store chunks across nodes according to policy
        for chunk in &chunks {
            self.replicate_chunk(chunk, &policy).await?;
        }

        // Create distributed object metadata
        let distributed_object = DistributedObject {
            object_id: object_id.clone(),
            object_name,
            object_type: ObjectType::DiskImage, // Default type
            total_size_bytes: object_data.len() as u64,
            chunk_count: chunks.len() as u32,
            replication_factor: policy.min_replicas,
            consistency_level: ConsistencyLevel::Strong,
            storage_policy: policy,
            chunks: chunks.iter().map(|c| c.chunk_id.clone()).collect(),
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_modified: Utc::now(),
            last_accessed: Utc::now(),
            access_pattern: AccessPattern {
                access_frequency: AccessFrequency::Medium,
                read_write_ratio: 1.0,
                sequential_access_percentage: 80.0,
                peak_access_hours: vec![9, 10, 11, 14, 15, 16],
                seasonal_patterns: Vec::new(),
            },
        };

        self.distributed_objects.insert(object_id.clone(), distributed_object);
        self.chunk_map.insert(object_id.clone(), chunks.iter().map(|c| c.chunk_id.clone()).collect());

        tracing::info!("Object {} stored with {} chunks", object_id, chunks.len());
        Ok(object_id)
    }

    async fn create_chunks(&self, data: &[u8], object_id: &str) -> Result<Vec<DataChunk>> {
        const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB chunks
        let mut chunks = Vec::new();

        for (index, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
            let chunk_id = format!("{}-chunk-{}", object_id, index);
            let checksum = self.calculate_checksum(chunk_data);

            let chunk = DataChunk {
                chunk_id,
                object_id: object_id.to_string(),
                chunk_index: index as u32,
                size_bytes: chunk_data.len() as u64,
                checksum,
                chunk_type: ChunkType::Data,
                compression_ratio: 1.0, // No compression by default
                last_accessed: Utc::now(),
                access_count: 0,
                replicas: Vec::new(),
                tier: PerformanceTier::Hot,
            };

            chunks.push(chunk);
        }

        Ok(chunks)
    }

    fn calculate_checksum(&self, data: &[u8]) -> String {
        // Simple checksum calculation - in production would use SHA-256 or similar
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    async fn replicate_chunk(&self, chunk: &DataChunk, policy: &StoragePolicy) -> Result<()> {
        let available_nodes: Vec<EdgeStorageNode> = self.storage_nodes
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        let node_selector = self.node_selector.read();
        let selected_nodes = node_selector.select_nodes_for_replication(
            chunk,
            &available_nodes,
            policy.min_replicas,
        )?;

        // Create replicas
        for (index, node_id) in selected_nodes.iter().enumerate() {
            let replica = ChunkReplica {
                replica_id: format!("{}-replica-{}", chunk.chunk_id, index),
                node_id: node_id.clone(),
                is_primary: index == 0,
                sync_status: SyncStatus::Synced,
                last_verified: Utc::now(),
                checksum_verified: true,
            };

            // In a real implementation, this would actually transfer the chunk data
            tracing::debug!("Chunk {} replicated to node {}", chunk.chunk_id, node_id);
        }

        Ok(())
    }

    pub async fn retrieve_object(&self, object_id: &str) -> Result<Vec<u8>> {
        let object = self.distributed_objects
            .get(object_id)
            .ok_or_else(|| DlsError::NotFound(format!("Object {} not found", object_id)))?;

        let mut object_data = Vec::with_capacity(object.total_size_bytes as usize);

        // Retrieve chunks in order
        for chunk_id in &object.chunks {
            let chunk_data = self.retrieve_chunk(chunk_id).await?;
            object_data.extend(chunk_data);
        }

        // Update access patterns
        self.update_access_pattern(object_id).await?;

        Ok(object_data)
    }

    async fn retrieve_chunk(&self, chunk_id: &str) -> Result<Vec<u8>> {
        // In a real implementation, this would:
        // 1. Find the best replica to read from
        // 2. Retrieve the chunk data from the selected node
        // 3. Verify checksum
        // 4. Return the data

        // For now, return placeholder data
        tracing::debug!("Retrieving chunk {}", chunk_id);
        Ok(vec![0u8; 1024]) // Placeholder
    }

    async fn update_access_pattern(&self, object_id: &str) -> Result<()> {
        if let Some(mut object) = self.distributed_objects.get_mut(object_id) {
            object.last_accessed = Utc::now();

            // Update access frequency based on recent access
            // This would be more sophisticated in a real implementation
        }

        Ok(())
    }

    pub async fn delete_object(&self, object_id: &str) -> Result<()> {
        let object = self.distributed_objects
            .remove(object_id)
            .ok_or_else(|| DlsError::NotFound(format!("Object {} not found", object_id)))?;

        // Delete all chunks
        for chunk_id in &object.1.chunks {
            self.delete_chunk(chunk_id).await?;
        }

        self.chunk_map.remove(object_id);
        tracing::info!("Object {} deleted", object_id);
        Ok(())
    }

    async fn delete_chunk(&self, chunk_id: &str) -> Result<()> {
        // In a real implementation, this would delete the chunk from all replica nodes
        tracing::debug!("Deleting chunk {}", chunk_id);
        Ok(())
    }

    pub async fn create_storage_policy(&self, policy: StoragePolicy) -> Result<()> {
        let policy_id = policy.policy_id.clone();
        self.storage_policies.insert(policy_id.clone(), policy);
        tracing::info!("Storage policy {} created", policy_id);
        Ok(())
    }

    pub async fn sync_with_nodes(&self, node_ids: Vec<String>) -> Result<String> {
        let operation = SyncOperation {
            operation_id: Uuid::new_v4().to_string(),
            operation_type: SyncOperationType::IncrementalSync,
            source_node: "local".to_string(),
            target_nodes: node_ids,
            affected_chunks: Vec::new(),
            status: SyncOperationStatus::Pending,
            progress_percentage: 0.0,
            bytes_transferred: 0,
            estimated_completion: Some(Utc::now() + Duration::minutes(30)),
            started_at: Utc::now(),
            error_message: None,
        };

        let operation_id = self.sync_engine.initiate_sync(operation).await?;
        Ok(operation_id)
    }

    pub async fn get_storage_stats(&self) -> StorageStats {
        let nodes: Vec<EdgeStorageNode> = self.storage_nodes.iter().map(|entry| entry.value().clone()).collect();
        let objects: Vec<DistributedObject> = self.distributed_objects.iter().map(|entry| entry.value().clone()).collect();

        let total_capacity: u64 = nodes.iter().map(|n| n.storage_capacity_gb).sum();
        let used_capacity: u64 = nodes.iter().map(|n| n.used_capacity_gb).sum();
        let total_objects = objects.len();
        let total_chunks: u32 = objects.iter().map(|o| o.chunk_count).sum();

        StorageStats {
            total_nodes: nodes.len(),
            active_nodes: nodes.iter().filter(|n| n.sync_status == SyncStatus::Synced).count(),
            total_capacity_gb: total_capacity,
            used_capacity_gb: used_capacity,
            available_capacity_gb: total_capacity.saturating_sub(used_capacity),
            utilization_percentage: if total_capacity > 0 { (used_capacity as f64 / total_capacity as f64) * 100.0 } else { 0.0 },
            total_objects,
            total_chunks,
            replication_health: self.calculate_replication_health(&objects),
            last_updated: Utc::now(),
        }
    }

    fn calculate_replication_health(&self, objects: &[DistributedObject]) -> f64 {
        if objects.is_empty() {
            return 100.0;
        }

        let healthy_objects = objects.iter().filter(|obj| {
            // Check if object has sufficient replicas
            obj.chunks.len() > 0 // Simplified check
        }).count();

        (healthy_objects as f64 / objects.len() as f64) * 100.0
    }

    pub async fn run_tiering_evaluation(&self) -> Result<Vec<String>> {
        let mut migration_ids = Vec::new();

        // Evaluate all chunks for tiering opportunities
        for object_entry in self.distributed_objects.iter() {
            let object = object_entry.value();

            for chunk_id in &object.chunks {
                // Get chunk data (simplified - would need actual chunk lookup)
                let dummy_chunk = DataChunk {
                    chunk_id: chunk_id.clone(),
                    object_id: object.object_id.clone(),
                    chunk_index: 0,
                    size_bytes: 1024,
                    checksum: "dummy".to_string(),
                    chunk_type: ChunkType::Data,
                    compression_ratio: 1.0,
                    last_accessed: object.last_accessed,
                    access_count: 10,
                    replicas: Vec::new(),
                    tier: PerformanceTier::Hot,
                };

                if let Some(target_tier) = self.tiering_scheduler.evaluate_tiering(&dummy_chunk).await? {
                    let migration = TieringMigration {
                        migration_id: Uuid::new_v4().to_string(),
                        chunk_id: chunk_id.clone(),
                        source_tier: dummy_chunk.tier,
                        target_tier,
                        scheduled_time: Utc::now() + Duration::hours(1),
                        status: MigrationStatus::Scheduled,
                        progress_percentage: 0.0,
                    };

                    migration_ids.push(migration.migration_id.clone());
                    self.tiering_scheduler.schedule_migration(migration).await?;
                }
            }
        }

        Ok(migration_ids)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub total_capacity_gb: u64,
    pub used_capacity_gb: u64,
    pub available_capacity_gb: u64,
    pub utilization_percentage: f64,
    pub total_objects: usize,
    pub total_chunks: u32,
    pub replication_health: f64,
    pub last_updated: DateTime<Utc>,
}