// Optimized health monitoring with reduced memory footprint and improved performance
use crate::error::Result;
use crate::optimization::{LightweightStore, BatchProcessor, AsyncDataStore, CircularEventBuffer, PerformanceProfiler};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::interval;

/// Optimized health monitor with reduced memory usage
#[derive(Debug)]
pub struct OptimizedHealthMonitor {
    pub monitor_id: String,
    // Use lightweight store instead of heavy Arc<DashMap>
    pub health_checks: LightweightStore<String, HealthCheck>,
    // Use async-friendly data structures
    pub system_health: AsyncDataStore<String, HealthStatus>,
    // Use circular buffer for events to prevent unbounded growth
    pub health_events: CircularEventBuffer<HealthEvent>,
    // Batch processor for reducing I/O overhead
    pub alert_processor: BatchProcessor<AlertMessage>,
    // Performance profiler for monitoring
    pub profiler: PerformanceProfiler,
    // Configuration
    pub config: HealthMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMonitorConfig {
    pub check_interval: Duration,
    pub alert_batch_size: usize,
    pub alert_flush_interval: Duration,
    pub event_buffer_size: usize,
    pub enable_profiling: bool,
    pub max_concurrent_checks: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub check_id: String,
    pub check_name: String,
    pub check_type: HealthCheckType,
    pub interval: Duration,
    pub timeout: Duration,
    pub enabled: bool,
    pub last_run: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub threshold_config: ThresholdConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HealthCheckType {
    CPU,
    Memory,
    Disk,
    Network,
    Service,
    Database,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub warning_threshold: f64,
    pub critical_threshold: f64,
    pub recovery_threshold: f64,
    pub failure_count_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthEvent {
    pub event_id: String,
    pub check_id: String,
    pub timestamp: SystemTime,
    pub status: HealthStatus,
    pub value: f64,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertMessage {
    pub alert_id: String,
    pub check_id: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: SystemTime,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub overall_status: HealthStatus,
    pub healthy_checks: u32,
    pub warning_checks: u32,
    pub critical_checks: u32,
    pub total_checks: u32,
    pub last_updated: SystemTime,
}

impl OptimizedHealthMonitor {
    pub fn new(config: HealthMonitorConfig) -> Self {
        let event_buffer_size = config.event_buffer_size;
        let alert_batch_size = config.alert_batch_size;
        let alert_flush_interval = config.alert_flush_interval;

        Self {
            monitor_id: format!("health_monitor_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            health_checks: LightweightStore::new(Some(1000)), // Limit to 1000 health checks
            system_health: AsyncDataStore::new(),
            health_events: CircularEventBuffer::new(event_buffer_size),
            alert_processor: BatchProcessor::new(alert_batch_size, alert_flush_interval),
            profiler: PerformanceProfiler::new(),
            config,
        }
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        // Start health check loop
        let health_checks = self.health_checks.clone();
        let system_health = self.system_health.clone();
        let health_events = self.health_events.clone();
        let profiler = self.profiler.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(config.check_interval);
            loop {
                interval.tick().await;

                // Get all health checks
                let check_count = health_checks.len();
                for i in 0..check_count {
                    let check_id = format!("check_{}", i);
                    if let Some(health_check) = health_checks.get(&check_id) {
                        if health_check.enabled {
                            Self::execute_health_check_optimized(
                                &health_check,
                                &system_health,
                                &health_events,
                                &profiler,
                            ).await;
                        }
                    }
                }
            }
        });

        // Start alert processing loop
        let alert_processor = self.alert_processor.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let alerts = alert_processor.flush();
                if !alerts.is_empty() {
                    Self::process_alerts_batch(alerts).await;
                }
            }
        });

        Ok(())
    }

    async fn execute_health_check_optimized(
        health_check: &HealthCheck,
        system_health: &AsyncDataStore<String, HealthStatus>,
        health_events: &CircularEventBuffer<HealthEvent>,
        profiler: &PerformanceProfiler,
    ) {
        let operation_name = format!("health_check_{}", health_check.check_type);

        let result = profiler.measure(&operation_name, async {
            Self::perform_health_check(health_check).await
        }).await;

        match result {
            Ok((status, value, message)) => {
                // Update system health
                system_health.insert(health_check.check_id.clone(), status.clone()).await;

                // Record health event
                let event = HealthEvent {
                    event_id: format!("event_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()),
                    check_id: health_check.check_id.clone(),
                    timestamp: SystemTime::now(),
                    status,
                    value,
                    message,
                    metadata: HashMap::new(),
                };

                health_events.push(event);
            }
            Err(_e) => {
                // Handle error
                let error_status = HealthStatus::Unknown;
                system_health.insert(health_check.check_id.clone(), error_status.clone()).await;

                let error_event = HealthEvent {
                    event_id: format!("error_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()),
                    check_id: health_check.check_id.clone(),
                    timestamp: SystemTime::now(),
                    status: error_status,
                    value: 0.0,
                    message: "Health check failed".to_string(),
                    metadata: HashMap::new(),
                };

                health_events.push(error_event);
            }
        }
    }

    async fn perform_health_check(health_check: &HealthCheck) -> Result<(HealthStatus, f64, String)> {
        // Simulate health check based on type
        match health_check.check_type {
            HealthCheckType::CPU => {
                // Simulate CPU check
                let cpu_usage = 45.5; // Simulated value
                let status = if cpu_usage > health_check.threshold_config.critical_threshold {
                    HealthStatus::Critical
                } else if cpu_usage > health_check.threshold_config.warning_threshold {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                Ok((status, cpu_usage, format!("CPU usage: {:.1}%", cpu_usage)))
            }
            HealthCheckType::Memory => {
                // Simulate memory check
                let memory_usage = 62.3; // Simulated value
                let status = if memory_usage > health_check.threshold_config.critical_threshold {
                    HealthStatus::Critical
                } else if memory_usage > health_check.threshold_config.warning_threshold {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                Ok((status, memory_usage, format!("Memory usage: {:.1}%", memory_usage)))
            }
            HealthCheckType::Disk => {
                // Simulate disk check
                let disk_usage = 78.9; // Simulated value
                let status = if disk_usage > health_check.threshold_config.critical_threshold {
                    HealthStatus::Critical
                } else if disk_usage > health_check.threshold_config.warning_threshold {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                Ok((status, disk_usage, format!("Disk usage: {:.1}%", disk_usage)))
            }
            HealthCheckType::Network => {
                // Simulate network check
                let latency = 25.5; // Simulated value in ms
                let status = if latency > health_check.threshold_config.critical_threshold {
                    HealthStatus::Critical
                } else if latency > health_check.threshold_config.warning_threshold {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                Ok((status, latency, format!("Network latency: {:.1}ms", latency)))
            }
            HealthCheckType::Service => {
                // Simulate service check
                let response_time = 150.0; // Simulated value in ms
                let status = if response_time > health_check.threshold_config.critical_threshold {
                    HealthStatus::Critical
                } else if response_time > health_check.threshold_config.warning_threshold {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                Ok((status, response_time, format!("Service response time: {:.1}ms", response_time)))
            }
            HealthCheckType::Database => {
                // Simulate database check
                let connection_time = 50.0; // Simulated value in ms
                let status = if connection_time > health_check.threshold_config.critical_threshold {
                    HealthStatus::Critical
                } else if connection_time > health_check.threshold_config.warning_threshold {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                Ok((status, connection_time, format!("DB connection time: {:.1}ms", connection_time)))
            }
            HealthCheckType::Custom(_) => {
                // Simulate custom check
                Ok((HealthStatus::Healthy, 100.0, "Custom check passed".to_string()))
            }
        }
    }

    async fn process_alerts_batch(alerts: Vec<AlertMessage>) {
        // Process batched alerts for efficiency
        for alert in alerts {
            // In a real implementation, this would send notifications
            tracing::info!("Processing alert: {} - {}", alert.alert_id, alert.message);
        }
    }

    pub async fn add_health_check(&self, health_check: HealthCheck) -> Result<()> {
        self.health_checks.insert(health_check.check_id.clone(), health_check);
        Ok(())
    }

    pub async fn remove_health_check(&self, check_id: &str) -> Result<()> {
        self.health_checks.remove(&check_id.to_string());
        Ok(())
    }

    pub async fn get_health_summary(&self) -> Result<HealthSummary> {
        let total_checks = self.health_checks.len() as u32;
        let mut healthy_checks = 0;
        let mut warning_checks = 0;
        let mut critical_checks = 0;

        // Count health status efficiently
        for i in 0..total_checks {
            let check_id = format!("check_{}", i);
            if let Some(status) = self.system_health.get(&check_id).await {
                match status {
                    HealthStatus::Healthy => healthy_checks += 1,
                    HealthStatus::Warning => warning_checks += 1,
                    HealthStatus::Critical => critical_checks += 1,
                    HealthStatus::Unknown => {} // Don't count unknown status
                }
            }
        }

        let overall_status = if critical_checks > 0 {
            HealthStatus::Critical
        } else if warning_checks > 0 {
            HealthStatus::Warning
        } else if healthy_checks > 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        };

        Ok(HealthSummary {
            overall_status,
            healthy_checks,
            warning_checks,
            critical_checks,
            total_checks,
            last_updated: SystemTime::now(),
        })
    }

    pub fn get_recent_events(&self, count: usize) -> Vec<HealthEvent> {
        self.health_events.read_recent(count)
    }

    pub async fn trigger_alert(&self, alert: AlertMessage) -> Result<()> {
        let should_flush = self.alert_processor.add(alert).await;
        if should_flush {
            let alerts = self.alert_processor.flush();
            Self::process_alerts_batch(alerts).await;
        }
        Ok(())
    }

    pub fn get_performance_summary(&self) -> crate::optimization::PerformanceSummary {
        self.profiler.get_summary()
    }

    pub async fn get_health_metrics(&self) -> crate::optimization::StoreMetrics {
        self.system_health.get_metrics().await
    }
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            alert_batch_size: 10,
            alert_flush_interval: Duration::from_secs(60),
            event_buffer_size: 1000,
            enable_profiling: true,
            max_concurrent_checks: 50,
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            warning_threshold: 70.0,
            critical_threshold: 90.0,
            recovery_threshold: 60.0,
            failure_count_threshold: 3,
        }
    }
}

// Helper functions for creating common health checks
impl OptimizedHealthMonitor {
    pub async fn add_cpu_check(&self, check_id: String, interval: Duration) -> Result<()> {
        let health_check = HealthCheck {
            check_id,
            check_name: "CPU Usage".to_string(),
            check_type: HealthCheckType::CPU,
            interval,
            timeout: Duration::from_secs(5),
            enabled: true,
            last_run: None,
            consecutive_failures: 0,
            threshold_config: ThresholdConfig {
                warning_threshold: 70.0,
                critical_threshold: 90.0,
                recovery_threshold: 60.0,
                failure_count_threshold: 3,
            },
        };
        self.add_health_check(health_check).await
    }

    pub async fn add_memory_check(&self, check_id: String, interval: Duration) -> Result<()> {
        let health_check = HealthCheck {
            check_id,
            check_name: "Memory Usage".to_string(),
            check_type: HealthCheckType::Memory,
            interval,
            timeout: Duration::from_secs(5),
            enabled: true,
            last_run: None,
            consecutive_failures: 0,
            threshold_config: ThresholdConfig {
                warning_threshold: 80.0,
                critical_threshold: 95.0,
                recovery_threshold: 70.0,
                failure_count_threshold: 3,
            },
        };
        self.add_health_check(health_check).await
    }

    pub async fn add_disk_check(&self, check_id: String, interval: Duration) -> Result<()> {
        let health_check = HealthCheck {
            check_id,
            check_name: "Disk Usage".to_string(),
            check_type: HealthCheckType::Disk,
            interval,
            timeout: Duration::from_secs(10),
            enabled: true,
            last_run: None,
            consecutive_failures: 0,
            threshold_config: ThresholdConfig {
                warning_threshold: 85.0,
                critical_threshold: 95.0,
                recovery_threshold: 75.0,
                failure_count_threshold: 2,
            },
        };
        self.add_health_check(health_check).await
    }
}