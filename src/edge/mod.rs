pub mod distributed_storage;
pub mod edge_ai;
pub mod edge_node;
pub mod edge_orchestrator;

// Export key types
pub use distributed_storage::{DistributedStorageManager, EdgeStorageNode, StorageSyncEngine};
pub use edge_ai::{DistributedMLPipeline, EdgeAIEngine, EdgeInference};
pub use edge_node::{EdgeCapabilities, EdgeNode, EdgeNodeManager, EdgeNodeStatus};
pub use edge_orchestrator::{EdgeCluster, EdgeOrchestrator, WorkloadDistribution};
