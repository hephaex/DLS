pub mod health_monitor;
pub mod error_recovery;
pub mod performance_optimizer;
pub mod system_observer;
pub mod deployment_manager;

// Export key production types
pub use health_monitor::{SystemHealthMonitor, HealthCheck, SystemHealth, HealthStatus};
pub use error_recovery::{ErrorRecoveryManager, RecoveryStrategy, RecoveryAction};
pub use performance_optimizer::{PerformanceOptimizer, OptimizationEngine, PerformanceTuning};
pub use system_observer::{SystemObserver, TelemetryCollector, MetricsRegistry, AlertingSystem as SystemAlertingSystem};
pub use deployment_manager::{DeploymentManager, DeploymentPipeline, RolloutStrategy, EnvironmentManager, ReleaseOrchestrator};