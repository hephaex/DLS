pub mod edge_node;
pub mod edge_orchestrator;
pub mod distributed_storage;
pub mod edge_ai;

// Export key types
pub use edge_node::{EdgeNode, EdgeNodeManager, EdgeNodeStatus, EdgeCapabilities};
pub use edge_orchestrator::{EdgeOrchestrator, EdgeCluster, WorkloadDistribution};
pub use distributed_storage::{DistributedStorageManager, EdgeStorageNode, StorageSyncEngine};
pub use edge_ai::{EdgeAIEngine, EdgeInference, DistributedMLPipeline};