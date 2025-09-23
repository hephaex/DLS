// Multi-Cloud & Hybrid Infrastructure Management

// Multi-Cloud components
pub use multi_cloud::{MultiCloudManager, CloudProvider, CloudProviderType, ResourceType,
                      DeploymentStrategy as MultiCloudDeploymentStrategy,
                      ComplianceCertification as MultiCloudComplianceCertification,
                      ScalingTrigger as MultiCloudScalingTrigger,
                      ComparisonOperator as MultiCloudComparisonOperator};

// Hybrid Orchestrator components
pub use hybrid_orchestrator::{HybridOrchestrator, EnvironmentManager, WorkloadBalancer,
                             CloudEnvironment, ResourceInventory as HybridResourceInventory};

// Cloud Federation components
pub use cloud_federation::{CloudFederationManager, FederationMember,
                          ComplianceCertification as FederationComplianceCertification,
                          ScalingTrigger as FederationScalingTrigger,
                          ConfigurationOption as FederationConfigurationOption,
                          VolumeDiscount as FederationVolumeDiscount};

// Cross-Platform Deployment components
pub use cross_platform_deployment::{CrossPlatformDeploymentEngine, DeploymentOrchestrator,
                                    ActiveDeployment as CrossPlatformActiveDeployment,
                                    DeploymentStrategy as CrossPlatformDeploymentStrategy,
                                    DeploymentStatus as CrossPlatformDeploymentStatus,
                                    ComparisonOperator as CrossPlatformComparisonOperator};

pub mod multi_cloud;
pub mod hybrid_orchestrator;
pub mod cloud_federation;
pub mod cross_platform_deployment;