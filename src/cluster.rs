use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub node_id: String,
    pub node_name: String,
    pub listen_addr: SocketAddr,
    pub cluster_secret: String,
    pub heartbeat_interval_ms: u64,
    pub election_timeout_ms: u64,
    pub max_log_entries: usize,
    pub sync_interval_ms: u64,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub node_id: String,
    pub addr: SocketAddr,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub node_id: String,
    pub node_name: String,
    pub addr: SocketAddr,
    pub role: NodeRole,
    pub status: NodeStatus,
    pub last_seen: SystemTime,
    pub health_score: f64,
    pub load_metrics: LoadMetrics,
    pub services_status: HashMap<String, ServiceHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Leader,
    Follower,
    Candidate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Online,
    Offline,
    Suspected,
    Failed,
    Joining,
    Leaving,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub network_load: f64,
    pub active_connections: u32,
    pub requests_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub service_name: String,
    pub status: ServiceStatus,
    pub response_time_ms: f64,
    pub error_rate: f64,
    pub last_check: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMessage {
    pub message_id: String,
    pub from_node: String,
    pub to_node: Option<String>,
    pub message_type: MessageType,
    pub payload: MessagePayload,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Heartbeat,
    ElectionRequest,
    ElectionResponse,
    LeaderAnnouncement,
    ServiceSync,
    HealthCheck,
    LoadBalanceRequest,
    FailoverInitiate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    Heartbeat(HeartbeatData),
    Election(ElectionData),
    ServiceSync(ServiceSyncData),
    HealthCheck(HealthCheckData),
    LoadBalance(LoadBalanceData),
    Failover(FailoverData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatData {
    pub node_status: NodeStatus,
    pub load_metrics: LoadMetrics,
    pub services_status: HashMap<String, ServiceHealth>,
    pub term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionData {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
    pub vote_granted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSyncData {
    pub service_configurations: HashMap<String, serde_json::Value>,
    pub state_snapshots: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckData {
    pub service_name: String,
    pub status: ServiceStatus,
    pub metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalanceData {
    pub service_name: String,
    pub preferred_nodes: Vec<String>,
    pub load_distribution: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverData {
    pub failed_node: String,
    pub services_to_migrate: Vec<String>,
    pub target_nodes: Vec<String>,
}

#[derive(Clone)]
pub struct ClusterManager {
    config: ClusterConfig,
    local_node: Arc<RwLock<ClusterNode>>,
    cluster_nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
    current_term: Arc<RwLock<u64>>,
    voted_for: Arc<RwLock<Option<String>>>,
    election_timer: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    heartbeat_timer: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    message_handlers: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
    is_running: Arc<RwLock<bool>>,
}

impl ClusterManager {
    pub fn new(config: ClusterConfig) -> Self {
        let local_node = ClusterNode {
            node_id: config.node_id.clone(),
            node_name: config.node_name.clone(),
            addr: config.listen_addr,
            role: NodeRole::Follower,
            status: NodeStatus::Joining,
            last_seen: SystemTime::now(),
            health_score: 100.0,
            load_metrics: LoadMetrics {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                network_load: 0.0,
                active_connections: 0,
                requests_per_second: 0.0,
            },
            services_status: HashMap::new(),
        };

        Self {
            config,
            local_node: Arc::new(RwLock::new(local_node)),
            cluster_nodes: Arc::new(RwLock::new(HashMap::new())),
            current_term: Arc::new(RwLock::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
            election_timer: Arc::new(RwLock::new(None)),
            heartbeat_timer: Arc::new(RwLock::new(None)),
            message_handlers: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting cluster manager for node: {}", self.config.node_id);
        
        *self.is_running.write().await = true;
        
        // Update local node status
        {
            let mut local_node = self.local_node.write().await;
            local_node.status = NodeStatus::Online;
        }

        // Start TCP listener for cluster communication
        self.start_cluster_listener().await?;
        
        // Start periodic tasks
        self.start_heartbeat_sender().await;
        self.start_health_monitor().await;
        self.start_election_timer().await;
        self.start_cluster_sync().await;
        
        // Join cluster
        self.join_cluster().await?;
        
        info!("Cluster manager started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping cluster manager");
        
        *self.is_running.write().await = false;
        
        // Update local node status
        {
            let mut local_node = self.local_node.write().await;
            local_node.status = NodeStatus::Leaving;
        }
        
        // Send leave notification
        self.send_leave_notification().await;
        
        // Cancel all running tasks
        let mut handlers = self.message_handlers.write().await;
        for (_, handle) in handlers.drain() {
            handle.abort();
        }
        
        if let Some(timer) = self.heartbeat_timer.write().await.take() {
            timer.abort();
        }
        
        if let Some(timer) = self.election_timer.write().await.take() {
            timer.abort();
        }
        
        info!("Cluster manager stopped successfully");
        Ok(())
    }

    pub async fn get_cluster_status(&self) -> ClusterStatus {
        let local_node = self.local_node.read().await;
        let cluster_nodes = self.cluster_nodes.read().await;
        let current_term = *self.current_term.read().await;
        
        let leader_node = cluster_nodes.values()
            .find(|node| node.role == NodeRole::Leader)
            .cloned();
        
        let online_nodes = cluster_nodes.values()
            .filter(|node| node.status == NodeStatus::Online)
            .count() + if local_node.status == NodeStatus::Online { 1 } else { 0 };
        
        let total_nodes = cluster_nodes.len() + 1;
        
        ClusterStatus {
            cluster_healthy: online_nodes > total_nodes / 2,
            current_leader: leader_node.map(|n| n.node_id),
            current_term,
            total_nodes,
            online_nodes,
            local_node_role: local_node.role.clone(),
            local_node_status: local_node.status.clone(),
            nodes: {
                let mut nodes = cluster_nodes.clone();
                nodes.insert(local_node.node_id.clone(), local_node.clone());
                nodes
            },
        }
    }

    pub async fn initiate_failover(&self, failed_node_id: &str) -> Result<()> {
        info!("Initiating failover for failed node: {}", failed_node_id);
        
        let local_node = self.local_node.read().await;
        if local_node.role != NodeRole::Leader {
            return Err(crate::error::DlsError::InvalidOperation(
                "Only leader can initiate failover".to_string()
            ));
        }
        
        // Get services running on failed node
        let services_to_migrate = self.get_services_on_node(failed_node_id).await;
        
        // Find target nodes for service migration
        let target_nodes = self.select_failover_targets(&services_to_migrate).await;
        
        // Create failover plan
        let failover_data = FailoverData {
            failed_node: failed_node_id.to_string(),
            services_to_migrate,
            target_nodes,
        };
        
        // Execute failover
        self.execute_failover_plan(&failover_data).await?;
        
        // Notify cluster about failover
        self.broadcast_failover_notification(failover_data).await;
        
        info!("Failover completed for node: {}", failed_node_id);
        Ok(())
    }

    pub async fn request_leadership(&self) -> Result<()> {
        info!("Requesting leadership");
        
        let current_term = {
            let mut term = self.current_term.write().await;
            *term += 1;
            *term
        };
        
        // Update local node role
        {
            let mut local_node = self.local_node.write().await;
            local_node.role = NodeRole::Candidate;
        }
        
        // Vote for self
        *self.voted_for.write().await = Some(self.config.node_id.clone());
        
        // Request votes from peers
        self.request_votes(current_term).await;
        
        Ok(())
    }

    async fn start_cluster_listener(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!("Cluster listener started on: {}", self.config.listen_addr);
        
        let cluster_manager = self.clone();
        let handle = tokio::spawn(async move {
            while *cluster_manager.is_running.read().await {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Accepted cluster connection from: {}", addr);
                        let manager = cluster_manager.clone();
                        tokio::spawn(async move {
                            if let Err(e) = manager.handle_cluster_connection(stream).await {
                                warn!("Error handling cluster connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Error accepting cluster connection: {}", e);
                    }
                }
            }
        });
        
        let mut handlers = self.message_handlers.write().await;
        handlers.insert("cluster_listener".to_string(), handle);
        
        Ok(())
    }

    async fn handle_cluster_connection(&self, mut stream: TcpStream) -> Result<()> {
        let mut buffer = vec![0; 4096];
        
        loop {
            match timeout(Duration::from_secs(30), stream.readable()).await {
                Ok(_) => {
                    match stream.try_read(&mut buffer) {
                        Ok(0) => break, // Connection closed
                        Ok(n) => {
                            let data = &buffer[..n];
                            if let Ok(message) = serde_json::from_slice::<ClusterMessage>(data) {
                                self.process_cluster_message(message).await;
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(e) => {
                            warn!("Error reading from cluster connection: {}", e);
                            break;
                        }
                    }
                }
                Err(_) => {
                    debug!("Cluster connection timeout");
                    break;
                }
            }
        }
        
        Ok(())
    }

    async fn process_cluster_message(&self, message: ClusterMessage) {
        debug!("Processing cluster message: {:?}", message.message_type);
        
        match message.payload {
            MessagePayload::Heartbeat(data) => {
                self.handle_heartbeat(message.from_node, data).await;
            }
            MessagePayload::Election(data) => {
                self.handle_election_message(message.from_node, data).await;
            }
            MessagePayload::ServiceSync(data) => {
                self.handle_service_sync(message.from_node, data).await;
            }
            MessagePayload::HealthCheck(data) => {
                self.handle_health_check(message.from_node, data).await;
            }
            MessagePayload::LoadBalance(data) => {
                self.handle_load_balance(message.from_node, data).await;
            }
            MessagePayload::Failover(data) => {
                self.handle_failover(message.from_node, data).await;
            }
        }
    }

    async fn handle_heartbeat(&self, from_node: String, data: HeartbeatData) {
        let mut cluster_nodes = self.cluster_nodes.write().await;
        
        if let Some(node) = cluster_nodes.get_mut(&from_node) {
            node.last_seen = SystemTime::now();
            node.status = data.node_status;
            node.load_metrics = data.load_metrics;
            node.services_status = data.services_status;
        } else {
            // New node discovered
            let new_node = ClusterNode {
                node_id: from_node.clone(),
                node_name: format!("node-{}", from_node),
                addr: "0.0.0.0:0".parse().unwrap(), // Will be updated
                role: NodeRole::Follower,
                status: data.node_status,
                last_seen: SystemTime::now(),
                health_score: 100.0,
                load_metrics: data.load_metrics,
                services_status: data.services_status,
            };
            
            cluster_nodes.insert(from_node, new_node);
        }
        
        // Update term if necessary
        if data.term > *self.current_term.read().await {
            *self.current_term.write().await = data.term;
            *self.voted_for.write().await = None;
        }
    }

    async fn handle_election_message(&self, from_node: String, data: ElectionData) {
        if let Some(vote_granted) = data.vote_granted {
            if vote_granted {
                info!("Received vote from node: {}", from_node);
                // Count votes and become leader if majority
                let cluster_nodes = self.cluster_nodes.read().await;
                let total_nodes = cluster_nodes.len() + 1;
                let required_votes = (total_nodes / 2) + 1;
                
                // This is simplified - in practice, you'd track votes properly
                if self.count_votes().await >= required_votes {
                    self.become_leader().await;
                }
            }
        } else {
            // Vote request
            self.handle_vote_request(from_node, data).await;
        }
    }

    async fn handle_vote_request(&self, from_node: String, mut data: ElectionData) {
        let current_term = *self.current_term.read().await;
        let voted_for = self.voted_for.read().await.clone();
        
        let should_grant_vote = data.term >= current_term 
            && (voted_for.is_none() || voted_for == Some(from_node.clone()));
        
        if should_grant_vote {
            *self.voted_for.write().await = Some(from_node.clone());
        }
        
        data.vote_granted = Some(should_grant_vote);
        
        // Send vote response
        let response = ClusterMessage {
            message_id: Uuid::new_v4().to_string(),
            from_node: self.config.node_id.clone(),
            to_node: Some(from_node.clone()),
            message_type: MessageType::ElectionResponse,
            payload: MessagePayload::Election(data),
            timestamp: SystemTime::now(),
        };
        
        self.send_message_to_node(&from_node, response).await;
    }

    async fn become_leader(&self) {
        info!("Becoming cluster leader");
        
        {
            let mut local_node = self.local_node.write().await;
            local_node.role = NodeRole::Leader;
        }
        
        // Send leadership announcement
        self.announce_leadership().await;
        
        // Start leader-specific tasks
        self.start_leader_tasks().await;
    }

    async fn announce_leadership(&self) {
        let announcement = ClusterMessage {
            message_id: Uuid::new_v4().to_string(),
            from_node: self.config.node_id.clone(),
            to_node: None,
            message_type: MessageType::LeaderAnnouncement,
            payload: MessagePayload::Heartbeat(HeartbeatData {
                node_status: NodeStatus::Online,
                load_metrics: self.get_current_load_metrics().await,
                services_status: HashMap::new(),
                term: *self.current_term.read().await,
            }),
            timestamp: SystemTime::now(),
        };
        
        self.broadcast_message(announcement).await;
    }

    async fn start_heartbeat_sender(&self) {
        let cluster_manager = self.clone();
        let interval_ms = self.config.heartbeat_interval_ms;
        
        let handle = tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(interval_ms));
            
            while *cluster_manager.is_running.read().await {
                interval.tick().await;
                cluster_manager.send_heartbeat().await;
            }
        });
        
        *self.heartbeat_timer.write().await = Some(handle);
    }

    async fn send_heartbeat(&self) {
        let local_node = self.local_node.read().await;
        let current_term = *self.current_term.read().await;
        
        let heartbeat = ClusterMessage {
            message_id: Uuid::new_v4().to_string(),
            from_node: self.config.node_id.clone(),
            to_node: None,
            message_type: MessageType::Heartbeat,
            payload: MessagePayload::Heartbeat(HeartbeatData {
                node_status: local_node.status.clone(),
                load_metrics: local_node.load_metrics.clone(),
                services_status: local_node.services_status.clone(),
                term: current_term,
            }),
            timestamp: SystemTime::now(),
        };
        
        self.broadcast_message(heartbeat).await;
    }

    async fn broadcast_message(&self, message: ClusterMessage) {
        for peer in &self.config.peers {
            self.send_message_to_node(&peer.node_id, message.clone()).await;
        }
    }

    async fn send_message_to_node(&self, _node_id: &str, _message: ClusterMessage) {
        // Implementation would send message via TCP connection
        // Simplified for this example
    }

    // Additional helper methods
    async fn join_cluster(&self) -> Result<()> {
        info!("Joining cluster");
        // Implementation would announce presence to existing nodes
        Ok(())
    }

    async fn send_leave_notification(&self) {
        info!("Sending leave notification to cluster");
        // Implementation would notify other nodes of departure
    }

    async fn start_health_monitor(&self) {
        // Implementation would start background health monitoring
    }

    async fn start_election_timer(&self) {
        // Implementation would start election timeout timer
    }

    async fn start_cluster_sync(&self) {
        // Implementation would start periodic cluster state synchronization
    }

    async fn start_leader_tasks(&self) {
        // Implementation would start leader-specific background tasks
    }

    async fn get_current_load_metrics(&self) -> LoadMetrics {
        // Implementation would collect current system metrics
        LoadMetrics {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            network_load: 0.0,
            active_connections: 0,
            requests_per_second: 0.0,
        }
    }

    async fn count_votes(&self) -> usize {
        // Implementation would count received votes
        1
    }

    async fn request_votes(&self, _term: u64) {
        // Implementation would send vote requests to peers
    }

    async fn get_services_on_node(&self, _node_id: &str) -> Vec<String> {
        // Implementation would return services running on specific node
        vec![]
    }

    async fn select_failover_targets(&self, _services: &[String]) -> Vec<String> {
        // Implementation would select optimal target nodes for failover
        vec![]
    }

    async fn execute_failover_plan(&self, _plan: &FailoverData) -> Result<()> {
        // Implementation would execute the failover plan
        Ok(())
    }

    async fn broadcast_failover_notification(&self, _data: FailoverData) {
        // Implementation would notify cluster about failover completion
    }

    async fn handle_service_sync(&self, _from_node: String, _data: ServiceSyncData) {
        // Implementation would handle service state synchronization
    }

    async fn handle_health_check(&self, _from_node: String, _data: HealthCheckData) {
        // Implementation would handle health check updates
    }

    async fn handle_load_balance(&self, _from_node: String, _data: LoadBalanceData) {
        // Implementation would handle load balancing requests
    }

    async fn handle_failover(&self, _from_node: String, _data: FailoverData) {
        // Implementation would handle failover notifications
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub cluster_healthy: bool,
    pub current_leader: Option<String>,
    pub current_term: u64,
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub local_node_role: NodeRole,
    pub local_node_status: NodeStatus,
    pub nodes: HashMap<String, ClusterNode>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: Uuid::new_v4().to_string(),
            node_name: "dls-node".to_string(),
            listen_addr: "0.0.0.0:7777".parse().unwrap(),
            cluster_secret: "default-cluster-secret".to_string(),
            heartbeat_interval_ms: 5000,
            election_timeout_ms: 15000,
            max_log_entries: 1000,
            sync_interval_ms: 30000,
            peers: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_cluster_manager_creation() {
        let config = ClusterConfig::default();
        let manager = ClusterManager::new(config);
        
        let local_node = manager.local_node.read().await;
        assert_eq!(local_node.role, NodeRole::Follower);
        assert_eq!(local_node.status, NodeStatus::Joining);
    }

    #[tokio::test]
    async fn test_cluster_config_default() {
        let config = ClusterConfig::default();
        assert!(!config.node_id.is_empty());
        assert_eq!(config.node_name, "dls-node");
        assert_eq!(config.listen_addr.port(), 7777);
        assert_eq!(config.heartbeat_interval_ms, 5000);
    }

    #[test]
    fn test_node_role_serialization() {
        let role = NodeRole::Leader;
        let serialized = serde_json::to_string(&role).unwrap();
        let deserialized: NodeRole = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, NodeRole::Leader);
    }

    #[test]
    fn test_node_status_transitions() {
        let status = NodeStatus::Joining;
        assert_eq!(status, NodeStatus::Joining);
        
        let status = NodeStatus::Online;
        assert_eq!(status, NodeStatus::Online);
    }

    #[test]
    fn test_cluster_message_creation() {
        let message = ClusterMessage {
            message_id: "test-123".to_string(),
            from_node: "node-1".to_string(),
            to_node: Some("node-2".to_string()),
            message_type: MessageType::Heartbeat,
            payload: MessagePayload::Heartbeat(HeartbeatData {
                node_status: NodeStatus::Online,
                load_metrics: LoadMetrics {
                    cpu_usage: 50.0,
                    memory_usage: 60.0,
                    network_load: 30.0,
                    active_connections: 100,
                    requests_per_second: 50.0,
                },
                services_status: HashMap::new(),
                term: 1,
            }),
            timestamp: SystemTime::now(),
        };
        
        assert_eq!(message.from_node, "node-1");
        assert_eq!(message.to_node, Some("node-2".to_string()));
    }

    #[tokio::test]
    async fn test_cluster_status() {
        let config = ClusterConfig::default();
        let manager = ClusterManager::new(config);
        
        let status = manager.get_cluster_status().await;
        assert_eq!(status.total_nodes, 1);
        assert_eq!(status.local_node_role, NodeRole::Follower);
    }

    #[test]
    fn test_load_metrics() {
        let metrics = LoadMetrics {
            cpu_usage: 75.5,
            memory_usage: 80.2,
            network_load: 45.3,
            active_connections: 150,
            requests_per_second: 100.5,
        };
        
        assert_eq!(metrics.cpu_usage, 75.5);
        assert_eq!(metrics.active_connections, 150);
    }

    #[test]
    fn test_service_health() {
        let health = ServiceHealth {
            service_name: "dhcp".to_string(),
            status: ServiceStatus::Healthy,
            response_time_ms: 25.0,
            error_rate: 0.1,
            last_check: SystemTime::now(),
        };
        
        assert_eq!(health.service_name, "dhcp");
        assert_eq!(health.status, ServiceStatus::Healthy);
    }

    #[test]
    fn test_peer_config() {
        let peer = PeerConfig {
            node_id: "peer-1".to_string(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 7777),
            priority: 100,
        };
        
        assert_eq!(peer.node_id, "peer-1");
        assert_eq!(peer.priority, 100);
    }

    #[tokio::test]
    async fn test_election_data() {
        let election_data = ElectionData {
            term: 5,
            candidate_id: "candidate-1".to_string(),
            last_log_index: 100,
            last_log_term: 4,
            vote_granted: Some(true),
        };
        
        assert_eq!(election_data.term, 5);
        assert_eq!(election_data.vote_granted, Some(true));
    }

    #[test]
    fn test_failover_data() {
        let failover_data = FailoverData {
            failed_node: "node-3".to_string(),
            services_to_migrate: vec!["dhcp".to_string(), "tftp".to_string()],
            target_nodes: vec!["node-1".to_string(), "node-2".to_string()],
        };
        
        assert_eq!(failover_data.services_to_migrate.len(), 2);
        assert_eq!(failover_data.target_nodes.len(), 2);
    }
}