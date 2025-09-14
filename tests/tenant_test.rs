mod common;

use dls_server::tenant::{TenantManager, TenantMetadata, ResourceQuota, TenantStatus};
use std::collections::HashMap;

#[tokio::test]
async fn test_tenant_creation_and_retrieval() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Test Organization".to_string(),
        contact_email: "admin@testorg.com".to_string(),
        contact_phone: Some("+1-555-0123".to_string()),
        description: Some("Test tenant for unit testing".to_string()),
        tags: vec!["test".to_string(), "development".to_string()],
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Test Tenant".to_string(), "test-tenant".to_string(), metadata)
        .await
        .unwrap();

    // Test retrieval by ID
    let tenant = manager.get_tenant(&tenant_id).unwrap();
    assert_eq!(tenant.name, "Test Tenant");
    assert_eq!(tenant.namespace, "test-tenant");
    assert_eq!(tenant.status, TenantStatus::PendingActivation);
    assert_eq!(tenant.metadata.organization_name, "Test Organization");

    // Test retrieval by namespace
    let tenant_by_namespace = manager.get_tenant_by_namespace("test-tenant").unwrap();
    assert_eq!(tenant.id, tenant_by_namespace.id);
}

#[tokio::test]
async fn test_tenant_activation_and_status() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Active Org".to_string(),
        contact_email: "admin@activeorg.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Active Tenant".to_string(), "active-tenant".to_string(), metadata)
        .await
        .unwrap();

    // Initially pending
    let tenant = manager.get_tenant(&tenant_id).unwrap();
    assert!(!tenant.is_active());
    assert_eq!(tenant.status, TenantStatus::PendingActivation);

    // Activate tenant
    manager.activate_tenant(tenant_id).await.unwrap();

    // Should now be active
    let tenant = manager.get_tenant(&tenant_id).unwrap();
    assert!(tenant.is_active());
    assert_eq!(tenant.status, TenantStatus::Active);

    // Test suspension
    manager.suspend_tenant(tenant_id, Some("Testing suspension".to_string())).await.unwrap();

    let tenant = manager.get_tenant(&tenant_id).unwrap();
    assert!(!tenant.is_active());
    assert_eq!(tenant.status, TenantStatus::Suspended);
}

#[tokio::test]
async fn test_namespace_uniqueness() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata1 = TenantMetadata {
        organization_name: "Org 1".to_string(),
        contact_email: "admin1@org.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };
    let metadata2 = TenantMetadata {
        organization_name: "Org 2".to_string(),
        contact_email: "admin2@org.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    // Create first tenant
    manager
        .create_tenant("First Tenant".to_string(), "unique-namespace".to_string(), metadata1)
        .await
        .unwrap();

    // Try to create second tenant with same namespace
    let result = manager
        .create_tenant("Second Tenant".to_string(), "unique-namespace".to_string(), metadata2)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_tenant_listing() {
    common::setup();
    
    let manager = TenantManager::new();
    
    // Create multiple tenants
    for i in 1..=3 {
        let metadata = TenantMetadata {
            organization_name: format!("Organization {}", i),
            contact_email: format!("admin{}@org.com", i),
            contact_phone: None,
            description: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
        };

        let tenant_id = manager
            .create_tenant(format!("Tenant {}", i), format!("tenant-{}", i), metadata)
            .await
            .unwrap();

        if i % 2 == 1 {
            // Activate odd-numbered tenants
            manager.activate_tenant(tenant_id).await.unwrap();
        }
    }

    // Test list all tenants
    let all_tenants = manager.list_tenants();
    assert_eq!(all_tenants.len(), 3);

    // Test list only active tenants
    let active_tenants = manager.list_active_tenants();
    assert_eq!(active_tenants.len(), 2); // Only tenants 1 and 3
}

#[tokio::test]
async fn test_resource_quota_management() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Quota Test Org".to_string(),
        contact_email: "quota@test.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Quota Tenant".to_string(), "quota-tenant".to_string(), metadata)
        .await
        .unwrap();

    // Check default quota
    let tenant = manager.get_tenant(&tenant_id).unwrap();
    assert_eq!(tenant.resource_quota.max_clients, 50);
    assert_eq!(tenant.resource_quota.max_storage_gb, 1000);

    // Update quota
    let new_quota = ResourceQuota {
        max_clients: 100,
        max_storage_gb: 2000,
        max_bandwidth_mbps: 2000,
        max_cpu_cores: 32,
        max_memory_gb: 64,
        max_concurrent_sessions: 200,
        max_boot_images: 20,
    };

    manager.update_tenant_quota(tenant_id, new_quota.clone()).await.unwrap();

    // Verify quota update
    let tenant = manager.get_tenant(&tenant_id).unwrap();
    assert_eq!(tenant.resource_quota.max_clients, 100);
    assert_eq!(tenant.resource_quota.max_storage_gb, 2000);
    assert_eq!(tenant.resource_quota.max_bandwidth_mbps, 2000);
}

#[tokio::test]
async fn test_client_connection_tracking() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Connection Test Org".to_string(),
        contact_email: "connection@test.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Connection Tenant".to_string(), "connection-tenant".to_string(), metadata)
        .await
        .unwrap();

    manager.activate_tenant(tenant_id).await.unwrap();

    // Test client registration
    let client_ip1 = "192.168.1.100".parse().unwrap();
    let client_ip2 = "192.168.1.101".parse().unwrap();

    manager.register_client_connection(client_ip1, tenant_id).await.unwrap();
    manager.register_client_connection(client_ip2, tenant_id).await.unwrap();

    // Verify client-tenant mapping
    assert_eq!(manager.get_tenant_for_client(&client_ip1), Some(tenant_id));
    assert_eq!(manager.get_tenant_for_client(&client_ip2), Some(tenant_id));

    // Check resource usage update
    let usage = manager.get_resource_usage(&tenant_id).unwrap();
    assert_eq!(usage.active_clients, 2);

    // Test client disconnection
    manager.unregister_client_connection(client_ip1).await.unwrap();
    
    assert_eq!(manager.get_tenant_for_client(&client_ip1), None);
    assert_eq!(manager.get_tenant_for_client(&client_ip2), Some(tenant_id));

    let usage = manager.get_resource_usage(&tenant_id).unwrap();
    assert_eq!(usage.active_clients, 1);
}

#[tokio::test]
async fn test_resource_usage_and_quota_violations() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Quota Violation Test".to_string(),
        contact_email: "quota@violation.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Violation Tenant".to_string(), "violation-tenant".to_string(), metadata)
        .await
        .unwrap();

    // Set a low quota for testing
    let low_quota = ResourceQuota {
        max_clients: 2,
        max_storage_gb: 100,
        max_bandwidth_mbps: 500,
        max_cpu_cores: 4,
        max_memory_gb: 8,
        max_concurrent_sessions: 10,
        max_boot_images: 5,
    };
    manager.update_tenant_quota(tenant_id, low_quota).await.unwrap();

    // Update resource usage to exceed quotas
    manager.update_resource_usage(tenant_id, |usage| {
        usage.active_clients = 5; // Exceeds max_clients (2)
        usage.storage_used_gb = 150; // Exceeds max_storage_gb (100)
        usage.bandwidth_used_mbps = 600; // Exceeds max_bandwidth_mbps (500)
    }).await.unwrap();

    // Check for violations
    let usage = manager.get_resource_usage(&tenant_id).unwrap();
    let tenant = manager.get_tenant(&tenant_id).unwrap();
    let violations = usage.is_quota_exceeded(&tenant.resource_quota);
    
    assert_eq!(violations.len(), 3); // Should have 3 violations
    assert!(violations.iter().any(|v| v.contains("Active clients")));
    assert!(violations.iter().any(|v| v.contains("Storage usage")));
    assert!(violations.iter().any(|v| v.contains("Bandwidth usage")));
}

#[tokio::test]
async fn test_hierarchical_tenants() {
    common::setup();
    
    let manager = TenantManager::new();
    
    // Create parent tenant
    let parent_metadata = TenantMetadata {
        organization_name: "Parent Organization".to_string(),
        contact_email: "parent@org.com".to_string(),
        contact_phone: None,
        description: Some("Parent tenant".to_string()),
        tags: vec!["parent".to_string()],
        custom_fields: HashMap::new(),
    };

    let parent_id = manager
        .create_tenant("Parent Tenant".to_string(), "parent-tenant".to_string(), parent_metadata)
        .await
        .unwrap();

    manager.activate_tenant(parent_id).await.unwrap();

    // Create child tenant
    let child_metadata = TenantMetadata {
        organization_name: "Child Organization".to_string(),
        contact_email: "child@org.com".to_string(),
        contact_phone: None,
        description: Some("Child tenant".to_string()),
        tags: vec!["child".to_string()],
        custom_fields: HashMap::new(),
    };

    let child_id = manager
        .create_child_tenant(parent_id, "Child Tenant".to_string(), "child-tenant".to_string(), child_metadata)
        .await
        .unwrap();

    // Verify parent-child relationship
    let parent = manager.get_tenant(&parent_id).unwrap();
    let child = manager.get_tenant(&child_id).unwrap();

    assert!(parent.child_tenant_ids.contains(&child_id));
    assert_eq!(child.parent_tenant_id, Some(parent_id));
}

#[tokio::test]
async fn test_audit_logging() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Audit Test Org".to_string(),
        contact_email: "audit@test.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Audit Tenant".to_string(), "audit-tenant".to_string(), metadata)
        .await
        .unwrap();

    manager.activate_tenant(tenant_id).await.unwrap();
    manager.suspend_tenant(tenant_id, Some("Test suspension".to_string())).await.unwrap();

    // Check audit logs
    let logs = manager.get_audit_logs(Some(tenant_id), Some(10)).await;
    assert!(logs.len() >= 3); // Created, Activated, Suspended

    // Check that logs are ordered by timestamp (most recent first)
    for i in 1..logs.len() {
        assert!(logs[i-1].timestamp >= logs[i].timestamp);
    }

    // Test filtering by tenant
    let all_logs = manager.get_audit_logs(None, None).await;
    let tenant_logs = manager.get_audit_logs(Some(tenant_id), None).await;
    assert!(all_logs.len() >= tenant_logs.len());
}

#[tokio::test]
async fn test_ip_range_validation() {
    common::setup();
    
    let manager = TenantManager::new();
    
    // Test CIDR matching
    let client_ip = "192.168.1.100".parse().unwrap();
    assert!(manager.ip_in_range(&client_ip, "192.168.1.0/24").unwrap());
    assert!(!manager.ip_in_range(&client_ip, "10.0.0.0/8").unwrap());
    
    // Test exact IP matching
    assert!(manager.ip_in_range(&client_ip, "192.168.1.100").unwrap());
    assert!(!manager.ip_in_range(&client_ip, "192.168.1.101").unwrap());
}

#[tokio::test]
async fn test_tenant_deletion_constraints() {
    common::setup();
    
    let manager = TenantManager::new();
    let metadata = TenantMetadata {
        organization_name: "Delete Test Org".to_string(),
        contact_email: "delete@test.com".to_string(),
        contact_phone: None,
        description: None,
        tags: Vec::new(),
        custom_fields: HashMap::new(),
    };

    let tenant_id = manager
        .create_tenant("Delete Tenant".to_string(), "delete-tenant".to_string(), metadata)
        .await
        .unwrap();

    manager.activate_tenant(tenant_id).await.unwrap();

    // Register a client connection
    let client_ip = "192.168.1.200".parse().unwrap();
    manager.register_client_connection(client_ip, tenant_id).await.unwrap();

    // Try to delete tenant with active connections - should fail
    let result = manager.delete_tenant(tenant_id).await;
    assert!(result.is_err());

    // Unregister client and try again - should succeed
    manager.unregister_client_connection(client_ip).await.unwrap();
    let result = manager.delete_tenant(tenant_id).await;
    assert!(result.is_ok());

    // Verify tenant is deleted
    assert!(manager.get_tenant(&tenant_id).is_none());
}