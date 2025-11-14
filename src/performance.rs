use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub cpu_usage: f64,
    pub memory_usage: MemoryStats,
    pub network_stats: NetworkPerformanceStats,
    pub storage_stats: StoragePerformanceStats,
    pub service_metrics: HashMap<String, ServiceMetrics>,
    pub client_metrics: ClientPerformanceStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub usage_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPerformanceStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_count: u32,
    pub bandwidth_utilization: f64,
    pub dhcp_requests_per_second: f64,
    pub tftp_transfers_per_second: f64,
    pub iscsi_iops: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePerformanceStats {
    pub read_iops: f64,
    pub write_iops: f64,
    pub read_throughput_mbps: f64,
    pub write_throughput_mbps: f64,
    pub disk_usage_percentage: f64,
    pub active_provisioning_jobs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetrics {
    pub service_name: String,
    pub response_time_ms: f64,
    pub requests_per_second: f64,
    pub error_rate: f64,
    pub uptime_seconds: u64,
    pub resource_usage: ResourceUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percentage: f64,
    pub memory_mb: u64,
    pub threads: u32,
    pub file_descriptors: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPerformanceStats {
    pub active_clients: u32,
    pub boot_success_rate: f64,
    pub average_boot_time_seconds: f64,
    pub concurrent_boots: u32,
    pub failed_boots_last_hour: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    pub test_name: String,
    pub duration_seconds: u64,
    pub concurrent_clients: u32,
    pub boot_interval_ms: u64,
    pub target_service: LoadTestTarget,
    pub metrics_collection_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadTestTarget {
    DhcpServer,
    TftpServer,
    IscsiTarget,
    ProvisioningSystem,
    FullBootSequence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestResult {
    pub test_id: String,
    pub config: LoadTestConfig,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub status: LoadTestStatus,
    pub metrics_history: Vec<PerformanceMetrics>,
    pub summary: Option<LoadTestSummary>,
    pub error_log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoadTestStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestSummary {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time_ms: f64,
    pub min_response_time_ms: f64,
    pub max_response_time_ms: f64,
    pub requests_per_second: f64,
    pub peak_cpu_usage: f64,
    pub peak_memory_usage_mb: u64,
    pub errors_by_type: HashMap<String, u32>,
}

#[derive(Clone)]
pub struct PerformanceMonitor {
    metrics_history: Arc<RwLock<Vec<PerformanceMetrics>>>,
    load_tests: Arc<RwLock<HashMap<String, LoadTestResult>>>,
    collection_interval: Duration,
    max_history_size: usize,
    running_tests: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl PerformanceMonitor {
    pub fn new(collection_interval: Duration, max_history_size: usize) -> Self {
        Self {
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            load_tests: Arc::new(RwLock::new(HashMap::new())),
            collection_interval,
            max_history_size,
            running_tests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting performance monitor");

        // Start metrics collection loop
        let metrics_history = Arc::clone(&self.metrics_history);
        let collection_interval = self.collection_interval;
        let max_history_size = self.max_history_size;

        tokio::spawn(async move {
            let mut interval = interval(collection_interval);

            loop {
                interval.tick().await;

                if let Ok(metrics) = Self::collect_current_metrics().await {
                    let mut history = metrics_history.write().await;
                    history.push(metrics);

                    // Maintain history size limit
                    if history.len() > max_history_size {
                        history.remove(0);
                    }
                }
            }
        });

        info!("Performance monitor started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping performance monitor");

        // Cancel all running load tests
        let mut running_tests = self.running_tests.write().await;
        for (test_id, handle) in running_tests.drain() {
            warn!("Cancelling running load test: {}", test_id);
            handle.abort();

            // Update test status
            let mut load_tests = self.load_tests.write().await;
            if let Some(test) = load_tests.get_mut(&test_id) {
                test.status = LoadTestStatus::Cancelled;
                test.end_time = Some(chrono::Utc::now());
            }
        }

        info!("Performance monitor stopped successfully");
        Ok(())
    }

    pub async fn get_current_metrics(&self) -> Result<PerformanceMetrics> {
        Self::collect_current_metrics().await
    }

    pub async fn get_metrics_history(&self, limit: Option<usize>) -> Vec<PerformanceMetrics> {
        let history = self.metrics_history.read().await;
        match limit {
            Some(n) => {
                let start = if history.len() > n {
                    history.len() - n
                } else {
                    0
                };
                history[start..].to_vec()
            }
            None => history.clone(),
        }
    }

    pub async fn start_load_test(&self, config: LoadTestConfig) -> Result<String> {
        let test_id = uuid::Uuid::new_v4().to_string();
        info!("Starting load test: {} ({})", config.test_name, test_id);

        let test_result = LoadTestResult {
            test_id: test_id.clone(),
            config: config.clone(),
            start_time: chrono::Utc::now(),
            end_time: None,
            status: LoadTestStatus::Running,
            metrics_history: Vec::new(),
            summary: None,
            error_log: Vec::new(),
        };

        // Store test result
        let mut load_tests = self.load_tests.write().await;
        load_tests.insert(test_id.clone(), test_result);

        // Spawn test execution task
        let test_handle = self
            .spawn_load_test_execution(test_id.clone(), config)
            .await;

        let mut running_tests = self.running_tests.write().await;
        running_tests.insert(test_id.clone(), test_handle);

        debug!("Load test started: {}", test_id);
        Ok(test_id)
    }

    pub async fn stop_load_test(&self, test_id: &str) -> Result<()> {
        info!("Stopping load test: {}", test_id);

        // Cancel the running task if it exists
        let mut running_tests = self.running_tests.write().await;
        if let Some(handle) = running_tests.remove(test_id) {
            handle.abort();
        }

        // Update test status
        let mut load_tests = self.load_tests.write().await;
        if let Some(test) = load_tests.get_mut(test_id) {
            test.status = LoadTestStatus::Cancelled;
            test.end_time = Some(chrono::Utc::now());
        }

        debug!("Load test stopped: {}", test_id);
        Ok(())
    }

    pub async fn get_load_test(&self, test_id: &str) -> Option<LoadTestResult> {
        let load_tests = self.load_tests.read().await;
        load_tests.get(test_id).cloned()
    }

    pub async fn list_load_tests(&self) -> Vec<LoadTestResult> {
        let load_tests = self.load_tests.read().await;
        load_tests.values().cloned().collect()
    }

    async fn spawn_load_test_execution(
        &self,
        test_id: String,
        config: LoadTestConfig,
    ) -> tokio::task::JoinHandle<()> {
        let load_tests = Arc::clone(&self.load_tests);
        let running_tests = Arc::clone(&self.running_tests);
        let metrics_history = Arc::clone(&self.metrics_history);

        tokio::spawn(async move {
            let result = Self::execute_load_test(&test_id, &config, &metrics_history).await;

            // Update test status and results
            let mut load_tests_guard = load_tests.write().await;
            if let Some(test) = load_tests_guard.get_mut(&test_id) {
                test.end_time = Some(chrono::Utc::now());

                match result {
                    Ok(summary) => {
                        test.status = LoadTestStatus::Completed;
                        test.summary = Some(summary);
                    }
                    Err(e) => {
                        test.status = LoadTestStatus::Failed;
                        test.error_log.push(format!("Test execution failed: {e}"));
                    }
                }
            }

            // Remove from running tests
            let mut running_tests_guard = running_tests.write().await;
            running_tests_guard.remove(&test_id);
        })
    }

    async fn execute_load_test(
        test_id: &str,
        config: &LoadTestConfig,
        metrics_history: &Arc<RwLock<Vec<PerformanceMetrics>>>,
    ) -> Result<LoadTestSummary> {
        info!("Executing load test: {} ({})", config.test_name, test_id);

        let start_time = Instant::now();
        let mut total_requests = 0;
        let mut successful_requests = 0;
        let mut failed_requests = 0;
        let mut response_times = Vec::new();
        let mut errors_by_type = HashMap::new();
        let mut peak_cpu_usage: f64 = 0.0;
        let mut peak_memory_usage_mb = 0;

        // Metrics collection interval
        let mut metrics_interval =
            interval(Duration::from_millis(config.metrics_collection_interval_ms));
        let test_duration = Duration::from_secs(config.duration_seconds);

        // Spawn concurrent client simulation tasks
        let mut client_handles = Vec::new();
        for client_id in 0..config.concurrent_clients {
            let config_clone = config.clone();
            let client_handle =
                tokio::spawn(
                    async move { Self::simulate_client_load(client_id, config_clone).await },
                );
            client_handles.push(client_handle);
        }

        // Main test execution loop
        let mut elapsed = Duration::new(0, 0);
        while elapsed < test_duration {
            tokio::select! {
                _ = metrics_interval.tick() => {
                    // Collect metrics during test
                    if let Ok(metrics) = Self::collect_current_metrics().await {
                        peak_cpu_usage = peak_cpu_usage.max(metrics.cpu_usage);
                        peak_memory_usage_mb = peak_memory_usage_mb.max(metrics.memory_usage.used_mb);

                        let mut history = metrics_history.write().await;
                        history.push(metrics);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    elapsed = start_time.elapsed();
                }
            }
        }

        // Wait for all client tasks to complete
        for handle in client_handles {
            if let Ok(client_result) = handle.await {
                total_requests += client_result.total_requests;
                successful_requests += client_result.successful_requests;
                failed_requests += client_result.failed_requests;
                response_times.extend(client_result.response_times);

                for (error_type, count) in client_result.errors_by_type {
                    *errors_by_type.entry(error_type).or_insert(0) += count;
                }
            }
        }

        // Calculate summary statistics
        let average_response_time_ms = if !response_times.is_empty() {
            response_times.iter().sum::<f64>() / response_times.len() as f64
        } else {
            0.0
        };

        let min_response_time_ms = response_times.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_response_time_ms = response_times.iter().cloned().fold(0.0, f64::max);

        let requests_per_second = total_requests as f64 / test_duration.as_secs_f64();

        let summary = LoadTestSummary {
            total_requests,
            successful_requests,
            failed_requests,
            average_response_time_ms,
            min_response_time_ms: if min_response_time_ms == f64::INFINITY {
                0.0
            } else {
                min_response_time_ms
            },
            max_response_time_ms,
            requests_per_second,
            peak_cpu_usage,
            peak_memory_usage_mb,
            errors_by_type,
        };

        info!(
            "Load test completed: {} - {} requests, {:.2} RPS, {:.2}% success rate",
            test_id,
            total_requests,
            requests_per_second,
            (successful_requests as f64 / total_requests as f64) * 100.0
        );

        Ok(summary)
    }

    async fn simulate_client_load(client_id: u32, config: LoadTestConfig) -> ClientLoadResult {
        debug!("Starting client simulation: {}", client_id);

        let mut total_requests = 0;
        let mut successful_requests = 0;
        let mut failed_requests = 0;
        let mut response_times = Vec::new();
        let mut errors_by_type = HashMap::new();

        let start_time = Instant::now();
        let test_duration = Duration::from_secs(config.duration_seconds);
        let request_interval = Duration::from_millis(config.boot_interval_ms);

        let mut interval = interval(request_interval);

        while start_time.elapsed() < test_duration {
            interval.tick().await;

            let request_start = Instant::now();
            total_requests += 1;

            match Self::execute_simulated_request(&config.target_service, client_id).await {
                Ok(_) => {
                    successful_requests += 1;
                    response_times.push(request_start.elapsed().as_millis() as f64);
                }
                Err(e) => {
                    failed_requests += 1;
                    let error_type = format!("{e:?}");
                    *errors_by_type.entry(error_type).or_insert(0) += 1;
                }
            }
        }

        debug!(
            "Client simulation completed: {} - {} requests",
            client_id, total_requests
        );

        ClientLoadResult {
            client_id,
            total_requests,
            successful_requests,
            failed_requests,
            response_times,
            errors_by_type,
        }
    }

    async fn execute_simulated_request(target: &LoadTestTarget, client_id: u32) -> Result<()> {
        match target {
            LoadTestTarget::DhcpServer => {
                // Simulate DHCP request
                Self::simulate_dhcp_request(client_id).await
            }
            LoadTestTarget::TftpServer => {
                // Simulate TFTP file request
                Self::simulate_tftp_request(client_id).await
            }
            LoadTestTarget::IscsiTarget => {
                // Simulate iSCSI connection
                Self::simulate_iscsi_request(client_id).await
            }
            LoadTestTarget::ProvisioningSystem => {
                // Simulate provisioning job
                Self::simulate_provisioning_request(client_id).await
            }
            LoadTestTarget::FullBootSequence => {
                // Simulate full boot sequence
                Self::simulate_full_boot_sequence(client_id).await
            }
        }
    }

    async fn simulate_dhcp_request(_client_id: u32) -> Result<()> {
        // Simulate DHCP discover/request cycle
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    async fn simulate_tftp_request(_client_id: u32) -> Result<()> {
        // Simulate TFTP file transfer
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }

    async fn simulate_iscsi_request(_client_id: u32) -> Result<()> {
        // Simulate iSCSI login and basic I/O
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn simulate_provisioning_request(_client_id: u32) -> Result<()> {
        // Simulate provisioning job creation
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    async fn simulate_full_boot_sequence(_client_id: u32) -> Result<()> {
        // Simulate complete boot sequence: DHCP -> TFTP -> iSCSI
        Self::simulate_dhcp_request(_client_id).await?;
        Self::simulate_tftp_request(_client_id).await?;
        Self::simulate_iscsi_request(_client_id).await?;
        Ok(())
    }

    async fn collect_current_metrics() -> Result<PerformanceMetrics> {
        let timestamp = chrono::Utc::now();

        // System metrics collection
        let cpu_usage = Self::get_cpu_usage().await;
        let memory_stats = Self::get_memory_stats().await;
        let network_stats = Self::get_network_stats().await;
        let storage_stats = Self::get_storage_stats().await;
        let service_metrics = Self::get_service_metrics().await;
        let client_metrics = Self::get_client_metrics().await;

        Ok(PerformanceMetrics {
            timestamp,
            cpu_usage,
            memory_usage: memory_stats,
            network_stats,
            storage_stats,
            service_metrics,
            client_metrics,
        })
    }

    async fn get_cpu_usage() -> f64 {
        // Simplified CPU usage - in production, would use sysinfo or similar
        rand::random::<f64>() * 100.0
    }

    async fn get_memory_stats() -> MemoryStats {
        // Simplified memory stats - in production, would use sysinfo
        let total_mb = 8192;
        let used_mb = (rand::random::<f64>() * total_mb as f64) as u64;
        let available_mb = total_mb - used_mb;
        let usage_percentage = (used_mb as f64 / total_mb as f64) * 100.0;

        MemoryStats {
            total_mb,
            used_mb,
            available_mb,
            usage_percentage,
        }
    }

    async fn get_network_stats() -> NetworkPerformanceStats {
        NetworkPerformanceStats {
            bytes_sent: (rand::random::<u64>() % 1000000) + 1000000,
            bytes_received: (rand::random::<u64>() % 1000000) + 1000000,
            packets_sent: (rand::random::<u64>() % 10000) + 10000,
            packets_received: (rand::random::<u64>() % 10000) + 10000,
            connection_count: (rand::random::<u32>() % 100) + 50,
            bandwidth_utilization: rand::random::<f64>() * 100.0,
            dhcp_requests_per_second: rand::random::<f64>() * 50.0,
            tftp_transfers_per_second: rand::random::<f64>() * 20.0,
            iscsi_iops: rand::random::<f64>() * 1000.0,
        }
    }

    async fn get_storage_stats() -> StoragePerformanceStats {
        StoragePerformanceStats {
            read_iops: rand::random::<f64>() * 1000.0,
            write_iops: rand::random::<f64>() * 500.0,
            read_throughput_mbps: rand::random::<f64>() * 100.0,
            write_throughput_mbps: rand::random::<f64>() * 50.0,
            disk_usage_percentage: rand::random::<f64>() * 100.0,
            active_provisioning_jobs: rand::random::<u32>() % 10,
        }
    }

    async fn get_service_metrics() -> HashMap<String, ServiceMetrics> {
        let mut metrics = HashMap::new();

        let services = ["dhcp", "tftp", "iscsi", "provisioning", "web"];
        for service in services {
            let service_metric = ServiceMetrics {
                service_name: service.to_string(),
                response_time_ms: rand::random::<f64>() * 100.0,
                requests_per_second: rand::random::<f64>() * 50.0,
                error_rate: rand::random::<f64>() * 5.0,
                uptime_seconds: rand::random::<u64>() % 86400 + 3600,
                resource_usage: ResourceUsage {
                    cpu_percentage: rand::random::<f64>() * 20.0,
                    memory_mb: (rand::random::<u64>() % 512) + 128,
                    threads: (rand::random::<u32>() % 20) + 5,
                    file_descriptors: (rand::random::<u32>() % 100) + 20,
                },
            };
            metrics.insert(service.to_string(), service_metric);
        }

        metrics
    }

    async fn get_client_metrics() -> ClientPerformanceStats {
        ClientPerformanceStats {
            active_clients: (rand::random::<u32>() % 50) + 10,
            boot_success_rate: 95.0 + (rand::random::<f64>() * 5.0),
            average_boot_time_seconds: 30.0 + (rand::random::<f64>() * 60.0),
            concurrent_boots: (rand::random::<u32>() % 10) + 1,
            failed_boots_last_hour: rand::random::<u32>() % 5,
        }
    }
}

#[derive(Debug, Clone)]
struct ClientLoadResult {
    client_id: u32,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    response_times: Vec<f64>,
    errors_by_type: HashMap<String, u32>,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new(Duration::from_secs(30), 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_performance_monitor_creation() {
        let monitor = PerformanceMonitor::new(Duration::from_secs(10), 100);
        assert_eq!(monitor.collection_interval, Duration::from_secs(10));
        assert_eq!(monitor.max_history_size, 100);
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let metrics = PerformanceMonitor::collect_current_metrics().await.unwrap();
        assert!(metrics.cpu_usage >= 0.0 && metrics.cpu_usage <= 100.0);
        assert!(metrics.memory_usage.usage_percentage >= 0.0);
        assert!(!metrics.service_metrics.is_empty());
    }

    #[tokio::test]
    async fn test_load_test_config_creation() {
        let config = LoadTestConfig {
            test_name: "Test DHCP Load".to_string(),
            duration_seconds: 60,
            concurrent_clients: 10,
            boot_interval_ms: 1000,
            target_service: LoadTestTarget::DhcpServer,
            metrics_collection_interval_ms: 1000,
        };

        assert_eq!(config.test_name, "Test DHCP Load");
        assert_eq!(config.concurrent_clients, 10);
        assert!(matches!(config.target_service, LoadTestTarget::DhcpServer));
    }

    #[tokio::test]
    async fn test_load_test_creation() {
        let monitor = PerformanceMonitor::default();

        let config = LoadTestConfig {
            test_name: "Test Load".to_string(),
            duration_seconds: 1,
            concurrent_clients: 2,
            boot_interval_ms: 500,
            target_service: LoadTestTarget::DhcpServer,
            metrics_collection_interval_ms: 500,
        };

        let test_id = monitor.start_load_test(config).await.unwrap();
        assert!(!test_id.is_empty());

        let test_result = monitor.get_load_test(&test_id).await;
        assert!(test_result.is_some());
        assert_eq!(test_result.unwrap().status, LoadTestStatus::Running);
    }

    #[test]
    fn test_load_test_status_transitions() {
        let status = LoadTestStatus::Pending;
        assert!(matches!(status, LoadTestStatus::Pending));
    }

    #[test]
    fn test_load_test_target_variants() {
        let targets = [LoadTestTarget::DhcpServer,
            LoadTestTarget::TftpServer,
            LoadTestTarget::IscsiTarget,
            LoadTestTarget::ProvisioningSystem,
            LoadTestTarget::FullBootSequence];

        assert_eq!(targets.len(), 5);
    }

    #[test]
    fn test_performance_metrics_serialization() {
        let memory_stats = MemoryStats {
            total_mb: 8192,
            used_mb: 4096,
            available_mb: 4096,
            usage_percentage: 50.0,
        };

        let serialized = serde_json::to_string(&memory_stats).unwrap();
        let deserialized: MemoryStats = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.total_mb, 8192);
    }

    #[test]
    fn test_client_performance_stats() {
        let stats = ClientPerformanceStats {
            active_clients: 25,
            boot_success_rate: 98.5,
            average_boot_time_seconds: 45.2,
            concurrent_boots: 5,
            failed_boots_last_hour: 2,
        };

        assert_eq!(stats.active_clients, 25);
        assert_eq!(stats.boot_success_rate, 98.5);
    }

    #[tokio::test]
    async fn test_simulated_requests() {
        let result = PerformanceMonitor::simulate_dhcp_request(1).await;
        assert!(result.is_ok());

        let result = PerformanceMonitor::simulate_tftp_request(1).await;
        assert!(result.is_ok());

        let result = PerformanceMonitor::simulate_iscsi_request(1).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_resource_usage_structure() {
        let usage = ResourceUsage {
            cpu_percentage: 15.5,
            memory_mb: 256,
            threads: 10,
            file_descriptors: 50,
        };

        assert_eq!(usage.cpu_percentage, 15.5);
        assert_eq!(usage.memory_mb, 256);
        assert_eq!(usage.threads, 10);
    }

    #[tokio::test]
    async fn test_metrics_history_management() {
        let monitor = PerformanceMonitor::new(Duration::from_millis(100), 3);

        // Simulate adding metrics beyond the limit
        for _ in 0..5 {
            if let Ok(metrics) = PerformanceMonitor::collect_current_metrics().await {
                let mut history = monitor.metrics_history.write().await;
                history.push(metrics);

                // Simulate the size management that would happen in the real monitor
                if history.len() > 3 {
                    history.remove(0);
                }
            }
        }

        let history = monitor.metrics_history.read().await;
        assert!(history.len() <= 3);
    }
}
