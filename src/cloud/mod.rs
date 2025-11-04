// Multi-Cloud & Hybrid Infrastructure Management

// Multi-Cloud components
pub use multi_cloud::{
    CloudProvider, CloudProviderType, ComparisonOperator as MultiCloudComparisonOperator,
    ComplianceCertification as MultiCloudComplianceCertification,
    DeploymentStrategy as MultiCloudDeploymentStrategy, MultiCloudManager, ResourceType,
    ScalingTrigger as MultiCloudScalingTrigger,
};

// Hybrid Orchestrator components
pub use hybrid_orchestrator::{
    CloudEnvironment, EnvironmentManager, HybridOrchestrator,
    ResourceInventory as HybridResourceInventory, WorkloadBalancer,
};

// Cloud Federation components
pub use cloud_federation::{
    CloudFederationManager, ComplianceCertification as FederationComplianceCertification,
    ConfigurationOption as FederationConfigurationOption, FederationMember,
    ScalingTrigger as FederationScalingTrigger, VolumeDiscount as FederationVolumeDiscount,
};

// Cross-Platform Deployment components
pub use cross_platform_deployment::{
    ActiveDeployment as CrossPlatformActiveDeployment,
    ComparisonOperator as CrossPlatformComparisonOperator, CrossPlatformDeploymentEngine,
    DeploymentOrchestrator, DeploymentStatus as CrossPlatformDeploymentStatus,
    DeploymentStrategy as CrossPlatformDeploymentStrategy,
};

pub mod cloud_federation;
pub mod cross_platform_deployment;
pub mod hybrid_orchestrator;
pub mod multi_cloud;
