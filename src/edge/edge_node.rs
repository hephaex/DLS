use crate::ai::{AnomalyDetectionEngine, PredictiveAnalyticsEngine};
use crate::error::{DlsError, Result};
use crate::security::zero_trust::{DeviceIdentity, TrustScore, ZeroTrustManager};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EdgeNodeStatus {
    Initializing,
    Active,
    Degraded,
    Offline,
    Maintenance,
    Decommissioned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EdgeNodeType {
    Compute,
    Storage,
    Gateway,
    Hybrid,
    IoTAggregator,
    CDNEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCapabilities {
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub storage_gb: u32,
    pub network_bandwidth_mbps: u32,
    pub gpu_available: bool,
    pub ai_acceleration: bool,
    pub storage_tier: StorageTier,
    pub supported_protocols: Vec<String>,
    pub max_concurrent_clients: u32,
    pub geolocation: GeographicLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageTier {
    NVMe,
    SSD,
    HDD,
    Hybrid,
    InMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub city: String,
    pub country: String,
    pub region: String,
    pub datacenter_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNodeMetrics {
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
    pub storage_utilization: f64,
    pub network_utilization: f64,
    pub active_connections: u32,
    pub boot_sessions: u32,
    pub data_transfer_gb: f64,
    pub response_time_ms: f64,
    pub error_rate: f64,
    pub uptime_percentage: f64,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNode {
    pub node_id: String,
    pub node_type: EdgeNodeType,
    pub status: EdgeNodeStatus,
    pub capabilities: EdgeCapabilities,
    pub network_address: SocketAddr,
    pub management_endpoint: String,
    pub cluster_id: Option<String>,
    pub parent_datacenter: Option<String>,
    pub deployed_images: Vec<String>,
    pub active_workloads: Vec<EdgeWorkload>,
    pub security_profile: EdgeSecurityProfile,
    pub health_metrics: EdgeNodeMetrics,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeWorkload {
    pub workload_id: String,
    pub workload_type: WorkloadType,
    pub resource_allocation: ResourceAllocation,
    pub priority: WorkloadPriority,
    pub startup_time: DateTime<Utc>,
    pub expected_duration: Option<Duration>,
    pub dependencies: Vec<String>,
    pub status: WorkloadStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkloadType {
    DisklessClient,
    AIInference,
    DataProcessing,
    ContentCaching,
    NetworkRelay,
    SecurityScanning,
    BackupReplication,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WorkloadPriority {
    Critical,
    High,
    Normal,
    Low,
    Background,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkloadStatus {
    Pending,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Migrating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub cpu_cores: u32,
    pub memory_mb: u32,
    pub storage_mb: u32,
    pub network_bandwidth_mbps: u32,
    pub gpu_units: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeSecurityProfile {
    pub device_identity: DeviceIdentity,
    pub trust_score: TrustScore,
    pub security_policies: Vec<String>,
    pub encryption_enabled: bool,
    pub firewall_rules: Vec<FirewallRule>,
    pub access_control_list: Vec<AccessRule>,
    pub certificate_fingerprint: String,
    pub last_security_scan: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub rule_id: String,
    pub direction: TrafficDirection,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub action: FirewallAction,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallAction {
    Allow,
    Deny,
    Drop,
    Log,
    RateLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub rule_id: String,
    pub user_groups: Vec<String>,
    pub resource_patterns: Vec<String>,
    pub permissions: Vec<String>,
    pub time_restrictions: Option<TimeRestriction>,
    pub ip_restrictions: Option<Vec<IpAddr>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    pub allowed_hours: Vec<u8>, // 0-23
    pub allowed_days: Vec<u8>,  // 0-6 (Sunday-Saturday)
    pub timezone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNodeHealth {
    pub node_id: String,
    pub health_score: f64,
    pub component_health: HashMap<String, ComponentHealth>,
    pub alerts: Vec<HealthAlert>,
    pub performance_trends: Vec<PerformanceTrend>,
    pub predictive_maintenance: MaintenanceRecommendation,
    pub last_assessment: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component_name: String,
    pub health_percentage: f64,
    pub status: ComponentStatus,
    pub metrics: HashMap<String, f64>,
    pub issues: Vec<String>,
    pub last_check: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComponentStatus {
    Healthy,
    Warning,
    Critical,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthAlert {
    pub alert_id: String,
    pub severity: AlertSeverity,
    pub component: String,
    pub message: String,
    pub threshold_exceeded: Option<f64>,
    pub recommended_action: String,
    pub triggered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTrend {
    pub metric_name: String,
    pub trend_direction: TrendDirection,
    pub rate_of_change: f64,
    pub prediction_horizon: Duration,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceRecommendation {
    pub recommended_maintenance: Vec<MaintenanceTask>,
    pub urgency_level: UrgencyLevel,
    pub estimated_downtime: Duration,
    pub optimal_maintenance_window: Option<DateTime<Utc>>,
    pub cost_estimate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceTask {
    pub task_id: String,
    pub task_type: MaintenanceType,
    pub description: String,
    pub estimated_duration: Duration,
    pub required_skills: Vec<String>,
    pub parts_needed: Vec<String>,
    pub downtime_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MaintenanceType {
    Preventive,
    Corrective,
    Predictive,
    Emergency,
    Upgrade,
    SecurityPatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UrgencyLevel {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

pub struct EdgeNodeManager {
    nodes: Arc<DashMap<String, EdgeNode>>,
    node_health: Arc<DashMap<String, EdgeNodeHealth>>,
    zero_trust_manager: Arc<ZeroTrustManager>,
    analytics_engine: Arc<PredictiveAnalyticsEngine>,
    anomaly_detector: Arc<AnomalyDetectionEngine>,
    cluster_memberships: Arc<DashMap<String, Vec<String>>>,
    heartbeat_intervals: Arc<RwLock<HashMap<String, Duration>>>,
    performance_thresholds: Arc<RwLock<HashMap<String, f64>>>,
    auto_scaling_enabled: Arc<RwLock<bool>>,
}

impl EdgeNodeManager {
    pub async fn new(
        zero_trust_manager: Arc<ZeroTrustManager>,
        analytics_engine: Arc<PredictiveAnalyticsEngine>,
        anomaly_detector: Arc<AnomalyDetectionEngine>,
    ) -> Result<Self> {
        Ok(Self {
            nodes: Arc::new(DashMap::new()),
            node_health: Arc::new(DashMap::new()),
            zero_trust_manager,
            analytics_engine,
            anomaly_detector,
            cluster_memberships: Arc::new(DashMap::new()),
            heartbeat_intervals: Arc::new(RwLock::new(HashMap::new())),
            performance_thresholds: Arc::new(RwLock::new(Self::default_thresholds())),
            auto_scaling_enabled: Arc::new(RwLock::new(true)),
        })
    }

    pub async fn register_edge_node(&self, mut node: EdgeNode) -> Result<String> {
        // Validate and set up security profile
        self.validate_node_security(&mut node).await?;

        // Initialize health monitoring
        let health = self.initialize_node_health(&node).await?;

        // Register with zero-trust framework
        self.zero_trust_manager
            .register_device(node.security_profile.device_identity.clone())
            .await?;

        // Store node and health information
        let node_id = node.node_id.clone();
        self.nodes.insert(node_id.clone(), node);
        self.node_health.insert(node_id.clone(), health);

        // Set default heartbeat interval
        self.heartbeat_intervals
            .write()
            .insert(node_id.clone(), Duration::minutes(1));

        tracing::info!("Edge node {} registered successfully", node_id);
        Ok(node_id)
    }

    async fn validate_node_security(&self, node: &mut EdgeNode) -> Result<()> {
        // Verify device identity and certificates
        if node.security_profile.certificate_fingerprint.is_empty() {
            return Err(DlsError::Security(
                "Node certificate fingerprint required".to_string(),
            ));
        }

        // Validate trust score
        // Calculate basic trust score (simplified implementation)
        let trust_score = TrustScore {
            device_trust: 0.8,
            user_trust: 0.8,
            behavioral_trust: 0.8,
            environmental_trust: 0.8,
            overall_trust: 0.8,
            last_calculated: Utc::now(),
            factors: Vec::new(),
        };

        node.security_profile.trust_score = trust_score;

        // Ensure minimum security requirements
        if !node.security_profile.encryption_enabled {
            return Err(DlsError::Security(
                "Encryption must be enabled for edge nodes".to_string(),
            ));
        }

        Ok(())
    }

    async fn initialize_node_health(&self, node: &EdgeNode) -> Result<EdgeNodeHealth> {
        let mut component_health = HashMap::new();

        // Initialize component health tracking
        component_health.insert(
            "cpu".to_string(),
            ComponentHealth {
                component_name: "CPU".to_string(),
                health_percentage: 100.0,
                status: ComponentStatus::Healthy,
                metrics: HashMap::new(),
                issues: Vec::new(),
                last_check: Utc::now(),
            },
        );

        component_health.insert(
            "memory".to_string(),
            ComponentHealth {
                component_name: "Memory".to_string(),
                health_percentage: 100.0,
                status: ComponentStatus::Healthy,
                metrics: HashMap::new(),
                issues: Vec::new(),
                last_check: Utc::now(),
            },
        );

        component_health.insert(
            "storage".to_string(),
            ComponentHealth {
                component_name: "Storage".to_string(),
                health_percentage: 100.0,
                status: ComponentStatus::Healthy,
                metrics: HashMap::new(),
                issues: Vec::new(),
                last_check: Utc::now(),
            },
        );

        component_health.insert(
            "network".to_string(),
            ComponentHealth {
                component_name: "Network".to_string(),
                health_percentage: 100.0,
                status: ComponentStatus::Healthy,
                metrics: HashMap::new(),
                issues: Vec::new(),
                last_check: Utc::now(),
            },
        );

        Ok(EdgeNodeHealth {
            node_id: node.node_id.clone(),
            health_score: 100.0,
            component_health,
            alerts: Vec::new(),
            performance_trends: Vec::new(),
            predictive_maintenance: MaintenanceRecommendation {
                recommended_maintenance: Vec::new(),
                urgency_level: UrgencyLevel::Low,
                estimated_downtime: Duration::zero(),
                optimal_maintenance_window: None,
                cost_estimate: None,
            },
            last_assessment: Utc::now(),
        })
    }

    pub async fn update_node_metrics(&self, node_id: &str, metrics: EdgeNodeMetrics) -> Result<()> {
        if let Some(mut node) = self.nodes.get_mut(node_id) {
            node.health_metrics = metrics.clone();
            node.last_heartbeat = Utc::now();

            // Update health assessment
            self.assess_node_health(node_id, &metrics).await?;

            // Check for anomalies
            self.detect_performance_anomalies(node_id, &metrics).await?;

            // Update predictive models
            self.update_predictive_models(node_id, &metrics).await?;
        } else {
            return Err(DlsError::NotFound(format!(
                "Edge node {} not found",
                node_id
            )));
        }

        Ok(())
    }

    async fn assess_node_health(&self, node_id: &str, metrics: &EdgeNodeMetrics) -> Result<()> {
        let thresholds = self.performance_thresholds.read();

        if let Some(mut health) = self.node_health.get_mut(node_id) {
            // Update component health based on metrics
            self.update_component_health(
                &mut health,
                "cpu",
                metrics.cpu_utilization,
                thresholds.get("cpu_threshold").copied().unwrap_or(80.0),
            );
            self.update_component_health(
                &mut health,
                "memory",
                metrics.memory_utilization,
                thresholds.get("memory_threshold").copied().unwrap_or(85.0),
            );
            self.update_component_health(
                &mut health,
                "storage",
                metrics.storage_utilization,
                thresholds.get("storage_threshold").copied().unwrap_or(90.0),
            );
            self.update_component_health(
                &mut health,
                "network",
                metrics.network_utilization,
                thresholds.get("network_threshold").copied().unwrap_or(75.0),
            );

            // Calculate overall health score
            health.health_score = self.calculate_health_score(&health.component_health);
            health.last_assessment = Utc::now();

            // Generate alerts if necessary
            self.generate_health_alerts(&mut health, metrics).await?;
        }

        Ok(())
    }

    fn update_component_health(
        &self,
        health: &mut EdgeNodeHealth,
        component: &str,
        utilization: f64,
        threshold: f64,
    ) {
        if let Some(comp_health) = health.component_health.get_mut(component) {
            comp_health
                .metrics
                .insert("utilization".to_string(), utilization);

            comp_health.status = if utilization > threshold * 1.1 {
                ComponentStatus::Critical
            } else if utilization > threshold {
                ComponentStatus::Warning
            } else {
                ComponentStatus::Healthy
            };

            comp_health.health_percentage = if utilization > threshold {
                100.0 - ((utilization - threshold) / threshold * 100.0).min(100.0)
            } else {
                100.0
            };

            comp_health.last_check = Utc::now();
        }
    }

    fn calculate_health_score(&self, component_health: &HashMap<String, ComponentHealth>) -> f64 {
        if component_health.is_empty() {
            return 0.0;
        }

        let total: f64 = component_health.values().map(|c| c.health_percentage).sum();
        total / component_health.len() as f64
    }

    async fn generate_health_alerts(
        &self,
        health: &mut EdgeNodeHealth,
        metrics: &EdgeNodeMetrics,
    ) -> Result<()> {
        let mut new_alerts = Vec::new();

        // Check response time
        if metrics.response_time_ms > 1000.0 {
            new_alerts.push(HealthAlert {
                alert_id: Uuid::new_v4().to_string(),
                severity: AlertSeverity::Warning,
                component: "network".to_string(),
                message: format!("High response time: {:.2}ms", metrics.response_time_ms),
                threshold_exceeded: Some(1000.0),
                recommended_action: "Check network connectivity and load balancing".to_string(),
                triggered_at: Utc::now(),
            });
        }

        // Check error rate
        if metrics.error_rate > 0.05 {
            new_alerts.push(HealthAlert {
                alert_id: Uuid::new_v4().to_string(),
                severity: AlertSeverity::Error,
                component: "system".to_string(),
                message: format!("High error rate: {:.2}%", metrics.error_rate * 100.0),
                threshold_exceeded: Some(0.05),
                recommended_action: "Investigate system logs for error patterns".to_string(),
                triggered_at: Utc::now(),
            });
        }

        // Check uptime
        if metrics.uptime_percentage < 99.0 {
            new_alerts.push(HealthAlert {
                alert_id: Uuid::new_v4().to_string(),
                severity: AlertSeverity::Critical,
                component: "system".to_string(),
                message: format!("Low uptime: {:.2}%", metrics.uptime_percentage),
                threshold_exceeded: Some(99.0),
                recommended_action: "Schedule maintenance to address reliability issues"
                    .to_string(),
                triggered_at: Utc::now(),
            });
        }

        health.alerts.extend(new_alerts);

        // Keep only recent alerts (last 24 hours)
        let cutoff = Utc::now() - Duration::hours(24);
        health.alerts.retain(|alert| alert.triggered_at > cutoff);

        Ok(())
    }

    async fn detect_performance_anomalies(
        &self,
        node_id: &str,
        metrics: &EdgeNodeMetrics,
    ) -> Result<()> {
        // Use anomaly detection engine to identify unusual patterns
        let mut metric_values = std::collections::HashMap::new();
        metric_values.insert("cpu_utilization".to_string(), metrics.cpu_utilization);
        metric_values.insert("memory_utilization".to_string(), metrics.memory_utilization);
        metric_values.insert("response_time".to_string(), metrics.response_time_ms);
        metric_values.insert("error_rate".to_string(), metrics.error_rate);

        // This would integrate with the anomaly detection engine
        // For now, we'll implement basic threshold-based detection
        self.check_anomaly_thresholds(node_id, &metric_values)
            .await?;

        Ok(())
    }

    async fn check_anomaly_thresholds(
        &self,
        node_id: &str,
        metrics: &HashMap<String, f64>,
    ) -> Result<()> {
        for (metric_name, value) in metrics {
            let anomaly_detected = match metric_name.as_str() {
                "cpu_utilization" => *value > 95.0 || *value < 1.0,
                "memory_utilization" => *value > 98.0,
                "response_time" => *value > 5000.0,
                "error_rate" => *value > 0.1,
                _ => false,
            };

            if anomaly_detected {
                tracing::warn!(
                    "Anomaly detected in node {} for metric {}: {}",
                    node_id,
                    metric_name,
                    value
                );

                // Generate anomaly alert
                if let Some(mut health) = self.node_health.get_mut(node_id) {
                    health.alerts.push(HealthAlert {
                        alert_id: Uuid::new_v4().to_string(),
                        severity: AlertSeverity::Warning,
                        component: "anomaly_detection".to_string(),
                        message: format!("Anomaly detected: {} = {}", metric_name, value),
                        threshold_exceeded: Some(*value),
                        recommended_action: "Investigate unusual system behavior".to_string(),
                        triggered_at: Utc::now(),
                    });
                }
            }
        }

        Ok(())
    }

    async fn update_predictive_models(
        &self,
        node_id: &str,
        metrics: &EdgeNodeMetrics,
    ) -> Result<()> {
        // Update predictive analytics with new data point
        // This would integrate with the predictive analytics engine

        // For now, implement basic trend analysis
        if let Some(mut health) = self.node_health.get_mut(node_id) {
            // Update performance trends
            self.update_performance_trends(&mut health, metrics).await?;

            // Generate predictive maintenance recommendations
            self.generate_maintenance_recommendations(&mut health, metrics)
                .await?;
        }

        Ok(())
    }

    async fn update_performance_trends(
        &self,
        health: &mut EdgeNodeHealth,
        metrics: &EdgeNodeMetrics,
    ) -> Result<()> {
        // Simple trend analysis - in production this would use the predictive analytics engine
        let trends = vec![
            ("cpu_utilization", metrics.cpu_utilization),
            ("memory_utilization", metrics.memory_utilization),
            ("response_time", metrics.response_time_ms),
            ("error_rate", metrics.error_rate),
        ];

        health.performance_trends.clear();
        for (metric_name, current_value) in trends {
            // Simple trend detection based on current value
            let trend_direction = if current_value > 80.0 {
                TrendDirection::Degrading
            } else if current_value < 20.0 {
                TrendDirection::Improving
            } else {
                TrendDirection::Stable
            };

            health.performance_trends.push(PerformanceTrend {
                metric_name: metric_name.to_string(),
                trend_direction,
                rate_of_change: 0.0, // Would be calculated from historical data
                prediction_horizon: Duration::hours(24),
                confidence: 0.8,
            });
        }

        Ok(())
    }

    async fn generate_maintenance_recommendations(
        &self,
        health: &mut EdgeNodeHealth,
        metrics: &EdgeNodeMetrics,
    ) -> Result<()> {
        let mut recommendations = Vec::new();
        let mut urgency = UrgencyLevel::Low;

        // Check if preventive maintenance is needed
        if metrics.uptime_percentage < 99.5 {
            recommendations.push(MaintenanceTask {
                task_id: Uuid::new_v4().to_string(),
                task_type: MaintenanceType::Preventive,
                description: "System reliability maintenance".to_string(),
                estimated_duration: Duration::hours(2),
                required_skills: vec!["system_admin".to_string()],
                parts_needed: Vec::new(),
                downtime_required: true,
            });
            urgency = UrgencyLevel::Medium;
        }

        // Check for high resource utilization
        if metrics.cpu_utilization > 90.0 || metrics.memory_utilization > 95.0 {
            recommendations.push(MaintenanceTask {
                task_id: Uuid::new_v4().to_string(),
                task_type: MaintenanceType::Corrective,
                description: "Resource optimization and cleanup".to_string(),
                estimated_duration: Duration::hours(1),
                required_skills: vec!["performance_tuning".to_string()],
                parts_needed: Vec::new(),
                downtime_required: false,
            });
            urgency = UrgencyLevel::High;
        }

        health.predictive_maintenance = MaintenanceRecommendation {
            recommended_maintenance: recommendations,
            urgency_level: urgency,
            estimated_downtime: Duration::hours(1),
            optimal_maintenance_window: Some(Utc::now() + Duration::hours(24)),
            cost_estimate: Some(500.0),
        };

        Ok(())
    }

    pub async fn get_node_status(&self, node_id: &str) -> Result<EdgeNodeStatus> {
        if let Some(node) = self.nodes.get(node_id) {
            Ok(node.status.clone())
        } else {
            Err(DlsError::NotFound(format!(
                "Edge node {} not found",
                node_id
            )))
        }
    }

    pub async fn get_node_health(&self, node_id: &str) -> Result<EdgeNodeHealth> {
        if let Some(health) = self.node_health.get(node_id) {
            Ok(health.clone())
        } else {
            Err(DlsError::NotFound(format!(
                "Health data for node {} not found",
                node_id
            )))
        }
    }

    pub async fn list_nodes(&self) -> Vec<EdgeNode> {
        self.nodes
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn list_nodes_by_cluster(&self, cluster_id: &str) -> Vec<EdgeNode> {
        self.nodes
            .iter()
            .filter(|entry| entry.value().cluster_id.as_deref() == Some(cluster_id))
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn update_node_status(&self, node_id: &str, status: EdgeNodeStatus) -> Result<()> {
        if let Some(mut node) = self.nodes.get_mut(node_id) {
            node.status = status;
            tracing::info!("Node {} status updated to {:?}", node_id, node.status);
            Ok(())
        } else {
            Err(DlsError::NotFound(format!(
                "Edge node {} not found",
                node_id
            )))
        }
    }

    pub async fn assign_workload(&self, node_id: &str, workload: EdgeWorkload) -> Result<()> {
        if let Some(mut node) = self.nodes.get_mut(node_id) {
            // Check if node has capacity for the workload
            if self.check_workload_capacity(&node, &workload).await? {
                node.active_workloads.push(workload);
                tracing::info!("Workload assigned to node {}", node_id);
                Ok(())
            } else {
                Err(DlsError::ResourceExhausted(
                    "Node does not have capacity for workload".to_string(),
                ))
            }
        } else {
            Err(DlsError::NotFound(format!(
                "Edge node {} not found",
                node_id
            )))
        }
    }

    async fn check_workload_capacity(
        &self,
        node: &EdgeNode,
        workload: &EdgeWorkload,
    ) -> Result<bool> {
        let current_cpu: u32 = node
            .active_workloads
            .iter()
            .map(|w| w.resource_allocation.cpu_cores)
            .sum();
        let current_memory: u32 = node
            .active_workloads
            .iter()
            .map(|w| w.resource_allocation.memory_mb)
            .sum();

        let available_cpu = node.capabilities.cpu_cores.saturating_sub(current_cpu);
        let available_memory = (node.capabilities.memory_gb * 1024).saturating_sub(current_memory);

        Ok(workload.resource_allocation.cpu_cores <= available_cpu
            && workload.resource_allocation.memory_mb <= available_memory)
    }

    pub async fn remove_workload(&self, node_id: &str, workload_id: &str) -> Result<()> {
        if let Some(mut node) = self.nodes.get_mut(node_id) {
            node.active_workloads
                .retain(|w| w.workload_id != workload_id);
            tracing::info!("Workload {} removed from node {}", workload_id, node_id);
            Ok(())
        } else {
            Err(DlsError::NotFound(format!(
                "Edge node {} not found",
                node_id
            )))
        }
    }

    pub async fn decommission_node(&self, node_id: &str) -> Result<()> {
        // Update node status
        self.update_node_status(node_id, EdgeNodeStatus::Decommissioned)
            .await?;

        // Remove from clusters
        for mut cluster_entry in self.cluster_memberships.iter_mut() {
            cluster_entry.value_mut().retain(|id| id != node_id);
        }

        // Unregister from zero-trust (simplified)
        if let Some(_node) = self.nodes.get(node_id) {
            // Device access revocation would be implemented here
            tracing::info!("Device access revoked for node {}", node_id);
        }

        tracing::info!("Node {} decommissioned", node_id);
        Ok(())
    }

    fn default_thresholds() -> HashMap<String, f64> {
        let mut thresholds = HashMap::new();
        thresholds.insert("cpu_threshold".to_string(), 80.0);
        thresholds.insert("memory_threshold".to_string(), 85.0);
        thresholds.insert("storage_threshold".to_string(), 90.0);
        thresholds.insert("network_threshold".to_string(), 75.0);
        thresholds
    }

    pub async fn get_cluster_health(&self, cluster_id: &str) -> Result<ClusterHealthSummary> {
        let nodes = self.list_nodes_by_cluster(cluster_id).await;

        if nodes.is_empty() {
            return Err(DlsError::NotFound(format!(
                "No nodes found in cluster {}",
                cluster_id
            )));
        }

        let mut total_health = 0.0;
        let mut total_nodes = 0;
        let mut critical_alerts = 0;
        let mut warning_alerts = 0;

        for node in &nodes {
            if let Ok(health) = self.get_node_health(&node.node_id).await {
                total_health += health.health_score;
                total_nodes += 1;

                for alert in &health.alerts {
                    match alert.severity {
                        AlertSeverity::Critical | AlertSeverity::Emergency => critical_alerts += 1,
                        AlertSeverity::Warning => warning_alerts += 1,
                        _ => {}
                    }
                }
            }
        }

        let average_health = if total_nodes > 0 {
            total_health / total_nodes as f64
        } else {
            0.0
        };

        Ok(ClusterHealthSummary {
            cluster_id: cluster_id.to_string(),
            total_nodes: nodes.len(),
            healthy_nodes: nodes
                .iter()
                .filter(|n| n.status == EdgeNodeStatus::Active)
                .count(),
            average_health_score: average_health,
            critical_alerts,
            warning_alerts,
            last_updated: Utc::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealthSummary {
    pub cluster_id: String,
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub average_health_score: f64,
    pub critical_alerts: usize,
    pub warning_alerts: usize,
    pub last_updated: DateTime<Utc>,
}
