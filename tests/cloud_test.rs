mod common;

use chrono::Utc;
use dls_server::cloud::{
    CloudConfig, CloudManager, CloudProvider, DataSyncConfig, DeploymentMode, DnsConfig,
    FailoverConfig, HybridDeployment, HybridNetworkConfig, LoadBalancingConfig, ResourceType,
};
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_cloud_manager_creation() {
    common::setup();

    let config = CloudConfig::default();
    let manager = CloudManager::new(config.clone());

    assert!(!manager.config.enabled);
    assert_eq!(manager.config.deployment_mode, DeploymentMode::OnPremises);
    assert_eq!(manager.config.primary_provider, CloudProvider::OnPremises);
}

#[tokio::test]
async fn test_cloud_config_creation() {
    common::setup();

    let mut config = CloudConfig::default();
    config.enabled = true;
    config.deployment_mode = DeploymentMode::HybridCloud;
    config.primary_provider = CloudProvider::Aws;
    config.failover_providers = vec![CloudProvider::Azure, CloudProvider::GoogleCloud];
    config.auto_scaling_enabled = true;
    config.multi_region_enabled = true;

    assert!(config.enabled);
    assert_eq!(config.deployment_mode, DeploymentMode::HybridCloud);
    assert_eq!(config.primary_provider, CloudProvider::Aws);
    assert_eq!(config.failover_providers.len(), 2);
}

#[tokio::test]
async fn test_hybrid_deployment_creation() {
    common::setup();

    let manager = CloudManager::default();
    let deployment_id = Uuid::new_v4();

    let deployment = HybridDeployment {
        id: deployment_id,
        name: "test-hybrid-deployment".to_string(),
        tenant_id: Some(Uuid::new_v4()),
        on_premises_resources: vec!["server-1".to_string(), "storage-1".to_string()],
        cloud_resources: {
            let mut resources = HashMap::new();
            resources.insert(CloudProvider::Aws, vec!["ec2-instance-1".to_string()]);
            resources.insert(CloudProvider::Azure, vec!["vm-1".to_string()]);
            resources
        },
        network_configuration: HybridNetworkConfig {
            vpn_enabled: true,
            vpn_gateway_ip: Some("10.0.0.1".parse().unwrap()),
            site_to_site_vpn: true,
            private_connectivity: true,
            network_peering: HashMap::new(),
            dns_configuration: DnsConfig {
                primary_dns: "8.8.8.8".parse().unwrap(),
                secondary_dns: Some("8.8.4.4".parse().unwrap()),
                domain_name: "hybrid.local".to_string(),
                cloud_dns_zones: HashMap::new(),
            },
            firewall_rules: Vec::new(),
        },
        load_balancing_config: LoadBalancingConfig {
            enabled: true,
            algorithm: "round-robin".to_string(),
            health_check_enabled: true,
            health_check_interval_seconds: 30,
            failover_threshold: 3,
            sticky_sessions: false,
            ssl_termination: true,
        },
        data_sync_config: DataSyncConfig {
            enabled: true,
            sync_interval_minutes: 60,
            bidirectional_sync: true,
            conflict_resolution: "latest-wins".to_string(),
            encrypted_sync: true,
            compression_enabled: true,
            bandwidth_limit_mbps: Some(100),
        },
        failover_config: FailoverConfig {
            enabled: true,
            automatic_failover: true,
            failover_threshold_seconds: 300,
            health_check_interval_seconds: 60,
            recovery_time_objective_minutes: 15,
            recovery_point_objective_minutes: 5,
            notification_enabled: true,
            notification_endpoints: vec!["admin@company.com".to_string()],
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let created_deployment_id = manager
        .create_hybrid_deployment(deployment.clone())
        .await
        .unwrap();
    assert_eq!(created_deployment_id, deployment_id);

    let retrieved_deployment = manager.get_deployment(&deployment_id).unwrap();
    assert_eq!(retrieved_deployment.name, "test-hybrid-deployment");
    assert_eq!(retrieved_deployment.on_premises_resources.len(), 2);
    assert_eq!(retrieved_deployment.cloud_resources.len(), 2);
    assert!(retrieved_deployment.network_configuration.vpn_enabled);
    assert!(retrieved_deployment.load_balancing_config.enabled);
    assert!(retrieved_deployment.data_sync_config.enabled);
    assert!(retrieved_deployment.failover_config.enabled);
}

#[tokio::test]
async fn test_cloud_resource_provisioning() {
    common::setup();

    let manager = CloudManager::default();

    let config = serde_json::json!({
        "instance_type": "t3.micro",
        "ami_id": "ami-12345678",
        "region": "us-east-1"
    });

    let resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Aws, config)
        .await
        .unwrap();

    assert!(!resource_id.is_empty());

    let resource = manager.get_resource(&resource_id).unwrap();
    assert_eq!(resource.resource_type, ResourceType::Compute);
    assert_eq!(resource.provider, CloudProvider::Aws);
    assert_eq!(resource.region, "us-east-1");
}

#[tokio::test]
async fn test_multi_cloud_deployment() {
    common::setup();

    let manager = CloudManager::default();

    // Provision resources on different cloud providers
    let aws_config = serde_json::json!({
        "instance_type": "t3.small",
        "ami_id": "ami-12345678"
    });
    let aws_resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Aws, aws_config)
        .await
        .unwrap();

    let azure_config = serde_json::json!({
        "vm_size": "Standard_B1s",
        "image": "Ubuntu18.04-LTS"
    });
    let azure_resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Azure, azure_config)
        .await
        .unwrap();

    let gcp_config = serde_json::json!({
        "machine_type": "e2-micro",
        "image_family": "ubuntu-1804-lts"
    });
    let gcp_resource_id = manager
        .provision_cloud_resource(
            ResourceType::Compute,
            CloudProvider::GoogleCloud,
            gcp_config,
        )
        .await
        .unwrap();

    // Verify all resources are created
    assert!(manager.get_resource(&aws_resource_id).is_some());
    assert!(manager.get_resource(&azure_resource_id).is_some());
    assert!(manager.get_resource(&gcp_resource_id).is_some());

    // Test resource listing by provider
    let aws_resources = manager.list_resources_by_provider(CloudProvider::Aws);
    let azure_resources = manager.list_resources_by_provider(CloudProvider::Azure);
    let gcp_resources = manager.list_resources_by_provider(CloudProvider::GoogleCloud);

    assert_eq!(aws_resources.len(), 1);
    assert_eq!(azure_resources.len(), 1);
    assert_eq!(gcp_resources.len(), 1);

    // Test total resource count
    let all_resources = manager.list_resources();
    assert_eq!(all_resources.len(), 3);
}

#[tokio::test]
async fn test_resource_migration() {
    common::setup();

    let manager = CloudManager::default();

    let config = serde_json::json!({
        "instance_type": "t3.micro",
        "ami_id": "ami-12345678"
    });

    let resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Aws, config)
        .await
        .unwrap();

    // Verify initial provider
    let resource = manager.get_resource(&resource_id).unwrap();
    assert_eq!(resource.provider, CloudProvider::Aws);

    // Migrate to Azure
    manager
        .migrate_resource(&resource_id, CloudProvider::Azure)
        .await
        .unwrap();

    // Verify migration
    let migrated_resource = manager.get_resource(&resource_id).unwrap();
    assert_eq!(migrated_resource.provider, CloudProvider::Azure);
}

#[tokio::test]
async fn test_auto_scaling_configuration() {
    common::setup();

    let manager = CloudManager::default();

    let config = serde_json::json!({
        "instance_type": "t3.micro",
        "ami_id": "ami-12345678"
    });

    let resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Aws, config)
        .await
        .unwrap();

    // Setup auto-scaling
    let result = manager.setup_auto_scaling(&resource_id, 2, 10).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_data_synchronization() {
    common::setup();

    let manager = CloudManager::default();

    let source = "on-premises://storage/data";
    let destination = "aws://s3/backup-bucket/data";

    let result = manager.sync_data(source, destination).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_cost_analysis() {
    common::setup();

    let manager = CloudManager::default();

    // Test cost analysis without tenant filter
    let analysis = manager.get_cost_analysis(None).await;
    assert_eq!(analysis.total_cost_per_hour, 0.0);
    assert_eq!(analysis.total_cost_per_month, 0.0);

    // Test cost analysis with tenant filter
    let tenant_id = Uuid::new_v4();
    let tenant_analysis = manager.get_cost_analysis(Some(tenant_id)).await;
    assert_eq!(tenant_analysis.total_cost_per_hour, 0.0);
}

#[tokio::test]
async fn test_cost_optimization() {
    common::setup();

    let manager = CloudManager::default();

    let optimizations = manager.optimize_costs().await.unwrap();
    assert_eq!(optimizations.len(), 0); // No resources yet, so no optimizations
}

#[tokio::test]
async fn test_resource_deletion() {
    common::setup();

    let manager = CloudManager::default();

    let config = serde_json::json!({
        "instance_type": "t3.micro",
        "ami_id": "ami-12345678"
    });

    let resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Aws, config)
        .await
        .unwrap();

    // Verify resource exists
    assert!(manager.get_resource(&resource_id).is_some());

    // Delete resource
    manager.delete_cloud_resource(&resource_id).await.unwrap();

    // Verify resource is deleted
    assert!(manager.get_resource(&resource_id).is_none());
}

#[tokio::test]
async fn test_deployment_listing() {
    common::setup();

    let manager = CloudManager::default();

    // Create multiple deployments
    for i in 1..=3 {
        let deployment = HybridDeployment {
            id: Uuid::new_v4(),
            name: format!("deployment-{}", i),
            tenant_id: None,
            on_premises_resources: vec![format!("server-{}", i)],
            cloud_resources: HashMap::new(),
            network_configuration: HybridNetworkConfig {
                vpn_enabled: false,
                vpn_gateway_ip: None,
                site_to_site_vpn: false,
                private_connectivity: false,
                network_peering: HashMap::new(),
                dns_configuration: DnsConfig {
                    primary_dns: "8.8.8.8".parse().unwrap(),
                    secondary_dns: None,
                    domain_name: "test.local".to_string(),
                    cloud_dns_zones: HashMap::new(),
                },
                firewall_rules: Vec::new(),
            },
            load_balancing_config: LoadBalancingConfig {
                enabled: false,
                algorithm: "round-robin".to_string(),
                health_check_enabled: false,
                health_check_interval_seconds: 30,
                failover_threshold: 3,
                sticky_sessions: false,
                ssl_termination: false,
            },
            data_sync_config: DataSyncConfig {
                enabled: false,
                sync_interval_minutes: 60,
                bidirectional_sync: false,
                conflict_resolution: "latest-wins".to_string(),
                encrypted_sync: true,
                compression_enabled: false,
                bandwidth_limit_mbps: None,
            },
            failover_config: FailoverConfig {
                enabled: false,
                automatic_failover: false,
                failover_threshold_seconds: 300,
                health_check_interval_seconds: 60,
                recovery_time_objective_minutes: 15,
                recovery_point_objective_minutes: 5,
                notification_enabled: false,
                notification_endpoints: Vec::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        manager.create_hybrid_deployment(deployment).await.unwrap();
    }

    let deployments = manager.list_deployments();
    assert_eq!(deployments.len(), 3);
}

#[tokio::test]
async fn test_audit_logging() {
    common::setup();

    let manager = CloudManager::default();

    let config = serde_json::json!({
        "instance_type": "t3.micro",
        "ami_id": "ami-12345678"
    });

    // Create and delete resource to generate audit events
    let resource_id = manager
        .provision_cloud_resource(ResourceType::Compute, CloudProvider::Aws, config)
        .await
        .unwrap();

    manager.delete_cloud_resource(&resource_id).await.unwrap();

    // Check audit logs
    let logs = manager.get_audit_logs(None, Some(10)).await;
    assert!(logs.len() >= 2); // Resource creation + resource deletion

    // Check logs are ordered by timestamp (most recent first)
    for i in 1..logs.len() {
        assert!(logs[i - 1].timestamp >= logs[i].timestamp);
    }
}
