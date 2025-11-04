// Sprint 5 Phase 1: Advanced Integration & Orchestration
pub mod api_gateway;
pub mod event_streaming;
pub mod service_mesh;
pub mod workflow_engine;

// Export key integration types
pub use api_gateway::{ApiGateway, ApiRoute, AuthenticationProvider, RateLimiter};
pub use event_streaming::{EventProcessor, EventStreamingPlatform, StreamAnalytics};
pub use service_mesh::{ServiceDiscovery, ServiceMesh, ServiceMeshConfig, TrafficManagement};
pub use workflow_engine::{StateManager, WorkflowDefinition, WorkflowEngine, WorkflowExecution};
