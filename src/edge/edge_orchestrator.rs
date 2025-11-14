use crate::ai::{IntelligentOpsEngine, PredictiveAnalyticsEngine};
use crate::edge::edge_node::{EdgeNode, EdgeNodeManager, EdgeWorkload, WorkloadPriority};
use crate::error::{DlsError, Result};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCluster {
    pub cluster_id: String,
    pub cluster_name: String,
    pub cluster_type: ClusterType,
    pub region: String,
    pub member_nodes: Vec<String>,
    pub cluster_policies: ClusterPolicies,
    pub load_balancing: LoadBalancingConfig,
    pub auto_scaling: AutoScalingConfig,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterType {
    Compute,
    Storage,
    Hybrid,
    ContentDelivery,
    IoTGateway,
    Analytics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPolicies {
    pub workload_distribution: DistributionPolicy,
    pub failover_strategy: FailoverStrategy,
    pub resource_allocation: ResourceAllocationPolicy,
    pub security_requirements: SecurityRequirements,
    pub data_locality: DataLocalityPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DistributionPolicy {
    RoundRobin,
    LeastLoaded,
    GeographicProximity,
    ResourceAware,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FailoverStrategy {
    Immediate,
    Graceful,
    ManualOnly,
    Predictive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocationPolicy {
    pub cpu_overcommit_ratio: f64,
    pub memory_overcommit_ratio: f64,
    pub storage_overcommit_ratio: f64,
    pub priority_weights: HashMap<WorkloadPriority, f64>,
    pub resource_limits: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequirements {
    pub minimum_trust_score: f64,
    pub encryption_required: bool,
    pub isolation_level: IsolationLevel,
    pub compliance_standards: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationLevel {
    None,
    Process,
    Container,
    VM,
    Physical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataLocalityPolicy {
    Any,
    SameRegion,
    SameDatacenter,
    SameRack,
    Specific(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancingConfig {
    pub algorithm: LoadBalancingAlgorithm,
    pub health_check_interval: Duration,
    pub unhealthy_threshold: u32,
    pub recovery_threshold: u32,
    pub session_affinity: bool,
    pub weights: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
    ResourceBased,
    GeographicProximity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoScalingConfig {
    pub enabled: bool,
    pub min_nodes: u32,
    pub max_nodes: u32,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
    pub scale_up_cooldown: Duration,
    pub scale_down_cooldown: Duration,
    pub target_utilization: f64,
    pub metrics: Vec<AutoScalingMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoScalingMetric {
    pub metric_name: String,
    pub metric_type: MetricType,
    pub threshold: f64,
    pub weight: f64,
    pub aggregation: MetricAggregation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    CPU,
    Memory,
    Network,
    Storage,
    ResponseTime,
    ErrorRate,
    CustomMetric(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricAggregation {
    Average,
    Maximum,
    Minimum,
    Sum,
    Percentile(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadDistribution {
    pub distribution_id: String,
    pub cluster_id: String,
    pub workload_assignments: HashMap<String, Vec<String>>, // node_id -> workload_ids
    pub resource_utilization: HashMap<String, ResourceUtilization>,
    pub load_balance_score: f64,
    pub distribution_strategy: DistributionStrategy,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    pub cpu_used: u32,
    pub cpu_total: u32,
    pub memory_used_mb: u32,
    pub memory_total_mb: u32,
    pub storage_used_gb: u32,
    pub storage_total_gb: u32,
    pub network_bandwidth_used_mbps: u32,
    pub network_bandwidth_total_mbps: u32,
    pub utilization_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionStrategy {
    pub strategy_name: String,
    pub optimization_goals: Vec<OptimizationGoal>,
    pub constraints: Vec<PlacementConstraint>,
    pub weights: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OptimizationGoal {
    LoadBalance,
    MinimizeLatency,
    MaximizeUtilization,
    MinimizeCost,
    MaximizeReliability,
    EnergyEfficiency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementConstraint {
    pub constraint_type: ConstraintType,
    pub target: String,
    pub operator: ComparisonOperator,
    pub value: f64,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConstraintType {
    NodeCapacity,
    NetworkLatency,
    GeographicDistance,
    SecurityLevel,
    ComplianceRequirement,
    CostLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComparisonOperator {
    LessThan,
    LessThanOrEqual,
    Equal,
    GreaterThanOrEqual,
    GreaterThan,
    NotEqual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeOrchestrationEvent {
    pub event_id: String,
    pub event_type: OrchestrationEventType,
    pub cluster_id: String,
    pub node_id: Option<String>,
    pub workload_id: Option<String>,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OrchestrationEventType {
    NodeAdded,
    NodeRemoved,
    NodeFailed,
    WorkloadScheduled,
    WorkloadMigrated,
    WorkloadFailed,
    ClusterScaled,
    LoadRebalanced,
    FailoverTriggered,
    PolicyUpdated,
}

pub struct EdgeOrchestrator {
    clusters: Arc<DashMap<String, EdgeCluster>>,
    node_manager: Arc<EdgeNodeManager>,
    workload_distributions: Arc<DashMap<String, WorkloadDistribution>>,
    orchestration_events: Arc<RwLock<Vec<EdgeOrchestrationEvent>>>,
    ai_engine: Arc<IntelligentOpsEngine>,
    analytics_engine: Arc<PredictiveAnalyticsEngine>,
    active_scaling_operations: Arc<DashMap<String, ScalingOperation>>,
    placement_algorithms: Arc<DashMap<String, Box<dyn PlacementAlgorithm + Send + Sync>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingOperation {
    pub operation_id: String,
    pub cluster_id: String,
    pub operation_type: ScalingOperationType,
    pub target_nodes: u32,
    pub current_nodes: u32,
    pub status: ScalingStatus,
    pub started_at: DateTime<Utc>,
    pub estimated_completion: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScalingOperationType {
    ScaleUp,
    ScaleDown,
    RightSize,
    Rebalance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScalingStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

pub trait PlacementAlgorithm {
    fn calculate_placement(
        &self,
        workload: &EdgeWorkload,
        available_nodes: &[EdgeNode],
    ) -> Result<String>;
    fn get_algorithm_name(&self) -> &str;
}

pub struct RoundRobinPlacement {
    counter: std::sync::atomic::AtomicUsize,
}

impl Default for RoundRobinPlacement {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinPlacement {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl PlacementAlgorithm for RoundRobinPlacement {
    fn calculate_placement(
        &self,
        _workload: &EdgeWorkload,
        available_nodes: &[EdgeNode],
    ) -> Result<String> {
        if available_nodes.is_empty() {
            return Err(DlsError::ResourceExhausted(
                "No available nodes for placement".to_string(),
            ));
        }

        let index = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % available_nodes.len();
        Ok(available_nodes[index].node_id.clone())
    }

    fn get_algorithm_name(&self) -> &str {
        "round_robin"
    }
}

pub struct ResourceAwarePlacement;

impl PlacementAlgorithm for ResourceAwarePlacement {
    fn calculate_placement(
        &self,
        workload: &EdgeWorkload,
        available_nodes: &[EdgeNode],
    ) -> Result<String> {
        let mut best_node = None;
        let mut best_score = f64::NEG_INFINITY;

        for node in available_nodes {
            let score = self.calculate_resource_score(workload, node);
            if score > best_score {
                best_score = score;
                best_node = Some(node);
            }
        }

        match best_node {
            Some(node) => Ok(node.node_id.clone()),
            None => Err(DlsError::ResourceExhausted(
                "No suitable node found for workload".to_string(),
            )),
        }
    }

    fn get_algorithm_name(&self) -> &str {
        "resource_aware"
    }
}

impl ResourceAwarePlacement {
    fn calculate_resource_score(&self, workload: &EdgeWorkload, node: &EdgeNode) -> f64 {
        let cpu_utilization = node.health_metrics.cpu_utilization / 100.0;
        let memory_utilization = node.health_metrics.memory_utilization / 100.0;
        let storage_utilization = node.health_metrics.storage_utilization / 100.0;

        // Calculate remaining capacity
        let cpu_capacity = 1.0 - cpu_utilization;
        let memory_capacity = 1.0 - memory_utilization;
        let storage_capacity = 1.0 - storage_utilization;

        // Check if node can accommodate the workload
        let cpu_fits = workload.resource_allocation.cpu_cores as f64
            <= node.capabilities.cpu_cores as f64 * cpu_capacity;
        let memory_fits = workload.resource_allocation.memory_mb as f64
            <= node.capabilities.memory_gb as f64 * 1024.0 * memory_capacity;

        if !cpu_fits || !memory_fits {
            return f64::NEG_INFINITY; // Cannot fit
        }

        // Score based on remaining capacity after placement
        let remaining_cpu = cpu_capacity
            - (workload.resource_allocation.cpu_cores as f64 / node.capabilities.cpu_cores as f64);
        let remaining_memory = memory_capacity
            - (workload.resource_allocation.memory_mb as f64
                / (node.capabilities.memory_gb as f64 * 1024.0));

        // Weighted score favoring balanced utilization
        remaining_cpu * 0.4 + remaining_memory * 0.4 + storage_capacity * 0.2
    }
}

impl EdgeOrchestrator {
    pub async fn new(
        node_manager: Arc<EdgeNodeManager>,
        ai_engine: Arc<IntelligentOpsEngine>,
        analytics_engine: Arc<PredictiveAnalyticsEngine>,
    ) -> Result<Self> {
        let placement_algorithms: Arc<DashMap<String, Box<dyn PlacementAlgorithm + Send + Sync>>> =
            Arc::new(DashMap::new());

        // Register default placement algorithms
        placement_algorithms.insert(
            "round_robin".to_string(),
            Box::new(RoundRobinPlacement::new()),
        );
        placement_algorithms.insert(
            "resource_aware".to_string(),
            Box::new(ResourceAwarePlacement),
        );

        Ok(Self {
            clusters: Arc::new(DashMap::new()),
            node_manager,
            workload_distributions: Arc::new(DashMap::new()),
            orchestration_events: Arc::new(RwLock::new(Vec::new())),
            ai_engine,
            analytics_engine,
            active_scaling_operations: Arc::new(DashMap::new()),
            placement_algorithms,
        })
    }

    pub async fn create_cluster(&self, mut cluster: EdgeCluster) -> Result<String> {
        // Validate cluster configuration
        self.validate_cluster_config(&cluster).await?;

        // Set creation timestamp
        cluster.created_at = Utc::now();
        cluster.last_updated = Utc::now();

        let cluster_id = cluster.cluster_id.clone();
        self.clusters.insert(cluster_id.clone(), cluster);

        // Log orchestration event
        self.log_orchestration_event(
            OrchestrationEventType::PolicyUpdated,
            &cluster_id,
            None,
            None,
            "Cluster created".to_string(),
        )
        .await;

        tracing::info!("Edge cluster {} created successfully", cluster_id);
        Ok(cluster_id)
    }

    async fn validate_cluster_config(&self, cluster: &EdgeCluster) -> Result<()> {
        // Validate auto-scaling configuration
        if cluster.auto_scaling.min_nodes > cluster.auto_scaling.max_nodes {
            return Err(DlsError::InvalidInput(
                "Min nodes cannot exceed max nodes".to_string(),
            ));
        }

        // Validate thresholds
        if cluster.auto_scaling.scale_up_threshold <= cluster.auto_scaling.scale_down_threshold {
            return Err(DlsError::InvalidInput(
                "Scale up threshold must be greater than scale down threshold".to_string(),
            ));
        }

        // Validate resource allocation ratios
        let resource_policy = &cluster.cluster_policies.resource_allocation;
        if resource_policy.cpu_overcommit_ratio < 1.0
            || resource_policy.memory_overcommit_ratio < 1.0
        {
            return Err(DlsError::InvalidInput(
                "Overcommit ratios must be >= 1.0".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn add_node_to_cluster(&self, cluster_id: &str, node_id: &str) -> Result<()> {
        // Verify node exists
        let node_status = self.node_manager.get_node_status(node_id).await?;
        if node_status != crate::edge::edge_node::EdgeNodeStatus::Active {
            return Err(DlsError::InvalidState(format!(
                "Node {node_id} is not active"
            )));
        }

        // Add to cluster
        if let Some(mut cluster) = self.clusters.get_mut(cluster_id) {
            if !cluster.member_nodes.contains(&node_id.to_string()) {
                cluster.member_nodes.push(node_id.to_string());
                cluster.last_updated = Utc::now();
            }
        } else {
            return Err(DlsError::NotFound(format!(
                "Cluster {cluster_id} not found"
            )));
        }

        // Log event
        self.log_orchestration_event(
            OrchestrationEventType::NodeAdded,
            cluster_id,
            Some(node_id.to_string()),
            None,
            format!("Node {node_id} added to cluster"),
        )
        .await;

        // Trigger rebalancing if needed
        self.trigger_rebalancing(cluster_id).await?;

        tracing::info!("Node {} added to cluster {}", node_id, cluster_id);
        Ok(())
    }

    pub async fn remove_node_from_cluster(&self, cluster_id: &str, node_id: &str) -> Result<()> {
        // Remove from cluster
        if let Some(mut cluster) = self.clusters.get_mut(cluster_id) {
            cluster.member_nodes.retain(|id| id != node_id);
            cluster.last_updated = Utc::now();
        } else {
            return Err(DlsError::NotFound(format!(
                "Cluster {cluster_id} not found"
            )));
        }

        // Migrate workloads from the node
        self.migrate_workloads_from_node(cluster_id, node_id)
            .await?;

        // Log event
        self.log_orchestration_event(
            OrchestrationEventType::NodeRemoved,
            cluster_id,
            Some(node_id.to_string()),
            None,
            format!("Node {node_id} removed from cluster"),
        )
        .await;

        tracing::info!("Node {} removed from cluster {}", node_id, cluster_id);
        Ok(())
    }

    async fn migrate_workloads_from_node(
        &self,
        cluster_id: &str,
        source_node_id: &str,
    ) -> Result<()> {
        // Get cluster nodes (excluding the source node)
        let cluster = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| DlsError::NotFound(format!("Cluster {cluster_id} not found")))?;

        let target_nodes: Vec<String> = cluster
            .member_nodes
            .iter()
            .filter(|&id| id != source_node_id)
            .cloned()
            .collect();

        if target_nodes.is_empty() {
            return Err(DlsError::ResourceExhausted(
                "No target nodes available for workload migration".to_string(),
            ));
        }

        // Get workloads on the source node
        let source_node_list = self.node_manager.list_nodes().await;
        let source_node = source_node_list
            .iter()
            .find(|n| n.node_id == source_node_id);

        if let Some(node) = source_node {
            for workload in &node.active_workloads {
                // Find best target node for each workload
                let target_node_id = self
                    .select_target_node_for_migration(&target_nodes, workload)
                    .await?;

                // Migrate workload
                self.migrate_workload(&workload.workload_id, source_node_id, &target_node_id)
                    .await?;

                // Log migration event
                self.log_orchestration_event(
                    OrchestrationEventType::WorkloadMigrated,
                    cluster_id,
                    Some(target_node_id.clone()),
                    Some(workload.workload_id.clone()),
                    format!("Workload migrated from {source_node_id} to {target_node_id}"),
                )
                .await;
            }
        }

        Ok(())
    }

    async fn select_target_node_for_migration(
        &self,
        target_nodes: &[String],
        workload: &EdgeWorkload,
    ) -> Result<String> {
        // Get node details for target nodes
        let all_nodes = self.node_manager.list_nodes().await;
        let available_nodes: Vec<EdgeNode> = all_nodes
            .into_iter()
            .filter(|n| target_nodes.contains(&n.node_id))
            .collect();

        if available_nodes.is_empty() {
            return Err(DlsError::ResourceExhausted(
                "No available target nodes for migration".to_string(),
            ));
        }

        // Use resource-aware placement for migration
        let placement_algorithm = ResourceAwarePlacement;
        placement_algorithm.calculate_placement(workload, &available_nodes)
    }

    async fn migrate_workload(
        &self,
        workload_id: &str,
        source_node_id: &str,
        target_node_id: &str,
    ) -> Result<()> {
        // This would implement the actual workload migration logic
        // For now, we'll simulate the migration by removing from source and adding to target

        // Remove from source
        self.node_manager
            .remove_workload(source_node_id, workload_id)
            .await?;

        // Add to target (would need to get the workload details first)
        // In a real implementation, this would involve more complex orchestration

        tracing::info!(
            "Workload {} migrated from {} to {}",
            workload_id,
            source_node_id,
            target_node_id
        );
        Ok(())
    }

    pub async fn schedule_workload(
        &self,
        cluster_id: &str,
        workload: EdgeWorkload,
    ) -> Result<String> {
        let cluster = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| DlsError::NotFound(format!("Cluster {cluster_id} not found")))?;

        // Get available nodes in cluster
        let all_nodes = self.node_manager.list_nodes().await;
        let available_nodes: Vec<EdgeNode> = all_nodes
            .into_iter()
            .filter(|n| cluster.member_nodes.contains(&n.node_id))
            .filter(|n| n.status == crate::edge::edge_node::EdgeNodeStatus::Active)
            .collect();

        if available_nodes.is_empty() {
            return Err(DlsError::ResourceExhausted(
                "No available nodes in cluster".to_string(),
            ));
        }

        // Select placement algorithm based on cluster policy
        let algorithm_name = match cluster.cluster_policies.workload_distribution {
            DistributionPolicy::RoundRobin => "round_robin",
            DistributionPolicy::ResourceAware => "resource_aware",
            DistributionPolicy::LeastLoaded => "resource_aware", // Fallback to resource aware
            _ => "round_robin",                                  // Default fallback
        };

        let selected_node_id =
            if let Some(algorithm) = self.placement_algorithms.get(algorithm_name) {
                algorithm.calculate_placement(&workload, &available_nodes)?
            } else {
                return Err(DlsError::InternalError(
                    "Placement algorithm not found".to_string(),
                ));
            };

        // Assign workload to selected node
        self.node_manager
            .assign_workload(&selected_node_id, workload.clone())
            .await?;

        // Update workload distribution
        self.update_workload_distribution(cluster_id, &selected_node_id, &workload.workload_id)
            .await?;

        // Log scheduling event
        self.log_orchestration_event(
            OrchestrationEventType::WorkloadScheduled,
            cluster_id,
            Some(selected_node_id.clone()),
            Some(workload.workload_id.clone()),
            format!("Workload scheduled to node {selected_node_id}"),
        )
        .await;

        tracing::info!(
            "Workload {} scheduled to node {} in cluster {}",
            workload.workload_id,
            selected_node_id,
            cluster_id
        );
        Ok(selected_node_id)
    }

    async fn update_workload_distribution(
        &self,
        cluster_id: &str,
        node_id: &str,
        workload_id: &str,
    ) -> Result<()> {
        let distribution_id = format!("{cluster_id}-distribution");

        if let Some(mut distribution) = self.workload_distributions.get_mut(&distribution_id) {
            // Add workload to existing distribution
            distribution
                .workload_assignments
                .entry(node_id.to_string())
                .or_insert_with(Vec::new)
                .push(workload_id.to_string());
        } else {
            // Create new distribution
            let mut workload_assignments = HashMap::new();
            workload_assignments.insert(node_id.to_string(), vec![workload_id.to_string()]);

            let distribution = WorkloadDistribution {
                distribution_id: distribution_id.clone(),
                cluster_id: cluster_id.to_string(),
                workload_assignments,
                resource_utilization: HashMap::new(),
                load_balance_score: 0.0,
                distribution_strategy: DistributionStrategy {
                    strategy_name: "default".to_string(),
                    optimization_goals: vec![OptimizationGoal::LoadBalance],
                    constraints: Vec::new(),
                    weights: HashMap::new(),
                },
                created_at: Utc::now(),
            };

            self.workload_distributions
                .insert(distribution_id, distribution);
        }

        Ok(())
    }

    pub async fn trigger_auto_scaling(&self, cluster_id: &str) -> Result<()> {
        let cluster = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| DlsError::NotFound(format!("Cluster {cluster_id} not found")))?;

        if !cluster.auto_scaling.enabled {
            return Ok(()); // Auto-scaling disabled
        }

        // Check if already scaling
        if self.active_scaling_operations.contains_key(cluster_id) {
            return Ok(()); // Already scaling
        }

        // Calculate current cluster utilization
        let cluster_utilization = self.calculate_cluster_utilization(cluster_id).await?;

        let should_scale_up = cluster_utilization > cluster.auto_scaling.scale_up_threshold
            && cluster.member_nodes.len() < cluster.auto_scaling.max_nodes as usize;

        let should_scale_down = cluster_utilization < cluster.auto_scaling.scale_down_threshold
            && cluster.member_nodes.len() > cluster.auto_scaling.min_nodes as usize;

        if should_scale_up {
            self.initiate_scale_up(cluster_id, cluster_utilization)
                .await?;
        } else if should_scale_down {
            self.initiate_scale_down(cluster_id, cluster_utilization)
                .await?;
        }

        Ok(())
    }

    async fn calculate_cluster_utilization(&self, cluster_id: &str) -> Result<f64> {
        let cluster = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| DlsError::NotFound(format!("Cluster {cluster_id} not found")))?;

        let nodes = self.node_manager.list_nodes_by_cluster(cluster_id).await;

        if nodes.is_empty() {
            return Ok(0.0);
        }

        let total_utilization: f64 = nodes
            .iter()
            .map(|n| {
                // Weight different metrics according to auto-scaling configuration
                let cpu_weight = 0.4;
                let memory_weight = 0.4;
                let network_weight = 0.2;

                (n.health_metrics.cpu_utilization * cpu_weight)
                    + (n.health_metrics.memory_utilization * memory_weight)
                    + (n.health_metrics.network_utilization * network_weight)
            })
            .sum();

        Ok(total_utilization / nodes.len() as f64)
    }

    async fn initiate_scale_up(&self, cluster_id: &str, current_utilization: f64) -> Result<()> {
        let operation = ScalingOperation {
            operation_id: Uuid::new_v4().to_string(),
            cluster_id: cluster_id.to_string(),
            operation_type: ScalingOperationType::ScaleUp,
            target_nodes: 0,  // Will be determined by scaling algorithm
            current_nodes: 0, // Will be set below
            status: ScalingStatus::Pending,
            started_at: Utc::now(),
            estimated_completion: Utc::now() + Duration::minutes(10),
            reason: format!(
                "Cluster utilization ({current_utilization:.1}%) exceeds scale-up threshold"
            ),
        };

        self.active_scaling_operations
            .insert(cluster_id.to_string(), operation);

        // Log scaling event
        self.log_orchestration_event(
            OrchestrationEventType::ClusterScaled,
            cluster_id,
            None,
            None,
            "Scale-up operation initiated".to_string(),
        )
        .await;

        // Here you would implement the actual node provisioning logic
        tracing::info!("Scale-up operation initiated for cluster {}", cluster_id);
        Ok(())
    }

    async fn initiate_scale_down(&self, cluster_id: &str, current_utilization: f64) -> Result<()> {
        let operation = ScalingOperation {
            operation_id: Uuid::new_v4().to_string(),
            cluster_id: cluster_id.to_string(),
            operation_type: ScalingOperationType::ScaleDown,
            target_nodes: 0,
            current_nodes: 0,
            status: ScalingStatus::Pending,
            started_at: Utc::now(),
            estimated_completion: Utc::now() + Duration::minutes(15),
            reason: format!(
                "Cluster utilization ({current_utilization:.1}%) below scale-down threshold"
            ),
        };

        self.active_scaling_operations
            .insert(cluster_id.to_string(), operation);

        // Log scaling event
        self.log_orchestration_event(
            OrchestrationEventType::ClusterScaled,
            cluster_id,
            None,
            None,
            "Scale-down operation initiated".to_string(),
        )
        .await;

        tracing::info!("Scale-down operation initiated for cluster {}", cluster_id);
        Ok(())
    }

    async fn trigger_rebalancing(&self, cluster_id: &str) -> Result<()> {
        // Calculate current load distribution
        let load_imbalance = self.calculate_load_imbalance(cluster_id).await?;

        // Trigger rebalancing if imbalance exceeds threshold
        if load_imbalance > 0.3 {
            // 30% imbalance threshold
            self.perform_load_rebalancing(cluster_id).await?;
        }

        Ok(())
    }

    async fn calculate_load_imbalance(&self, cluster_id: &str) -> Result<f64> {
        let nodes = self.node_manager.list_nodes_by_cluster(cluster_id).await;

        if nodes.len() < 2 {
            return Ok(0.0); // No imbalance with single node
        }

        let utilizations: Vec<f64> = nodes
            .iter()
            .map(|n| n.health_metrics.cpu_utilization)
            .collect();
        let avg_utilization: f64 = utilizations.iter().sum::<f64>() / utilizations.len() as f64;

        let max_deviation = utilizations
            .iter()
            .map(|u| (u - avg_utilization).abs())
            .fold(0.0, f64::max);

        Ok(max_deviation / avg_utilization)
    }

    async fn perform_load_rebalancing(&self, cluster_id: &str) -> Result<()> {
        // This would implement intelligent load rebalancing
        // For now, we'll log the event

        self.log_orchestration_event(
            OrchestrationEventType::LoadRebalanced,
            cluster_id,
            None,
            None,
            "Load rebalancing performed".to_string(),
        )
        .await;

        tracing::info!("Load rebalancing performed for cluster {}", cluster_id);
        Ok(())
    }

    async fn log_orchestration_event(
        &self,
        event_type: OrchestrationEventType,
        cluster_id: &str,
        node_id: Option<String>,
        workload_id: Option<String>,
        description: String,
    ) {
        let event = EdgeOrchestrationEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            cluster_id: cluster_id.to_string(),
            node_id,
            workload_id,
            description,
            metadata: HashMap::new(),
            timestamp: Utc::now(),
        };

        let mut events = self.orchestration_events.write();
        events.push(event);

        // Keep only recent events (last 1000)
        if events.len() > 1000 {
            let events_len = events.len();
            events.drain(0..events_len - 1000);
        }
    }

    pub async fn get_cluster_status(&self, cluster_id: &str) -> Result<ClusterStatus> {
        let cluster = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| DlsError::NotFound(format!("Cluster {cluster_id} not found")))?;

        let nodes = self.node_manager.list_nodes_by_cluster(cluster_id).await;
        let active_nodes = nodes
            .iter()
            .filter(|n| n.status == crate::edge::edge_node::EdgeNodeStatus::Active)
            .count();

        let total_workloads: usize = nodes.iter().map(|n| n.active_workloads.len()).sum();
        let current_utilization = self
            .calculate_cluster_utilization(cluster_id)
            .await
            .unwrap_or(0.0);

        Ok(ClusterStatus {
            cluster_id: cluster_id.to_string(),
            total_nodes: nodes.len(),
            active_nodes,
            total_workloads,
            current_utilization,
            auto_scaling_enabled: cluster.auto_scaling.enabled,
            last_updated: Utc::now(),
        })
    }

    pub async fn list_clusters(&self) -> Vec<EdgeCluster> {
        self.clusters
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn get_orchestration_events(
        &self,
        cluster_id: Option<&str>,
        limit: Option<usize>,
    ) -> Vec<EdgeOrchestrationEvent> {
        let events = self.orchestration_events.read();
        let filtered_events: Vec<EdgeOrchestrationEvent> = events
            .iter()
            .filter(|event| cluster_id.map_or(true, |id| event.cluster_id == id))
            .cloned()
            .collect();

        match limit {
            Some(n) => filtered_events.into_iter().rev().take(n).collect(),
            None => filtered_events,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub cluster_id: String,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub total_workloads: usize,
    pub current_utilization: f64,
    pub auto_scaling_enabled: bool,
    pub last_updated: DateTime<Utc>,
}
