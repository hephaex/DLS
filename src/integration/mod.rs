// Sprint 5 Phase 1: Advanced Integration & Orchestration
pub mod service_mesh;
pub mod api_gateway;
pub mod event_streaming;
pub mod workflow_engine;

// Export key integration types
pub use service_mesh::{ServiceMesh, ServiceMeshConfig, ServiceDiscovery, TrafficManagement};
pub use api_gateway::{ApiGateway, ApiRoute, RateLimiter, AuthenticationProvider};
pub use event_streaming::{EventStreamingPlatform, EventProcessor, StreamAnalytics};
pub use workflow_engine::{WorkflowEngine, WorkflowDefinition, WorkflowExecution, StateManager};