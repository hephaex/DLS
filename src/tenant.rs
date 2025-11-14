use crate::error::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TenantStatus {
    Active,
    Suspended,
    Inactive,
    PendingActivation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_clients: u32,
    pub max_storage_gb: u64,
    pub max_bandwidth_mbps: u64,
    pub max_cpu_cores: u32,
    pub max_memory_gb: u32,
    pub max_concurrent_sessions: u32,
    pub max_boot_images: u32,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            max_clients: 50,
            max_storage_gb: 1000,
            max_bandwidth_mbps: 1000,
            max_cpu_cores: 16,
            max_memory_gb: 32,
            max_concurrent_sessions: 100,
            max_boot_images: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct NetworkConfig {
    pub vlan_id: Option<u16>,
    pub subnet: Option<String>,
    pub allowed_ip_ranges: Vec<String>,
    pub dhcp_pool_start: Option<IpAddr>,
    pub dhcp_pool_end: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub root_path: PathBuf,
    pub encryption_enabled: bool,
    pub compression_enabled: bool,
    pub deduplication_enabled: bool,
    pub backup_enabled: bool,
    pub retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/var/lib/dls/tenants"),
            encryption_enabled: true,
            compression_enabled: true,
            deduplication_enabled: true,
            backup_enabled: true,
            retention_days: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub authentication_required: bool,
    pub mfa_required: bool,
    pub password_complexity_enabled: bool,
    pub session_timeout_minutes: u32,
    pub max_failed_logins: u32,
    pub lockout_duration_minutes: u32,
    pub audit_logging: bool,
    pub network_access_control: bool,
    pub encryption_in_transit: bool,
    pub encryption_at_rest: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            authentication_required: true,
            mfa_required: false,
            password_complexity_enabled: true,
            session_timeout_minutes: 480,
            max_failed_logins: 5,
            lockout_duration_minutes: 30,
            audit_logging: true,
            network_access_control: true,
            encryption_in_transit: true,
            encryption_at_rest: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMetadata {
    pub organization_name: String,
    pub contact_email: String,
    pub contact_phone: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    pub status: TenantStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_activity: Option<DateTime<Utc>>,
    pub resource_quota: ResourceQuota,
    pub network_config: NetworkConfig,
    pub storage_config: StorageConfig,
    pub security_policy: SecurityPolicy,
    pub metadata: TenantMetadata,
    pub parent_tenant_id: Option<Uuid>,
    pub child_tenant_ids: Vec<Uuid>,
}

impl Tenant {
    pub fn new(name: String, namespace: String, metadata: TenantMetadata) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            namespace,
            status: TenantStatus::PendingActivation,
            created_at: now,
            updated_at: now,
            last_activity: None,
            resource_quota: ResourceQuota::default(),
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            security_policy: SecurityPolicy::default(),
            metadata,
            parent_tenant_id: None,
            child_tenant_ids: Vec::new(),
        }
    }

    pub fn activate(&mut self) -> Result<()> {
        self.status = TenantStatus::Active;
        self.updated_at = Utc::now();
        Ok(())
    }

    pub fn suspend(&mut self, reason: Option<String>) -> Result<()> {
        self.status = TenantStatus::Suspended;
        self.updated_at = Utc::now();
        if let Some(reason) = reason {
            self.metadata
                .custom_fields
                .insert("suspension_reason".to_string(), reason);
        }
        Ok(())
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    pub fn add_child_tenant(&mut self, child_id: Uuid) {
        if !self.child_tenant_ids.contains(&child_id) {
            self.child_tenant_ids.push(child_id);
            self.updated_at = Utc::now();
        }
    }

    pub fn remove_child_tenant(&mut self, child_id: &Uuid) {
        self.child_tenant_ids.retain(|id| id != child_id);
        self.updated_at = Utc::now();
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, TenantStatus::Active)
    }

    pub fn get_effective_storage_path(&self) -> PathBuf {
        self.storage_config.root_path.join(&self.namespace)
    }

    pub fn get_vlan_id(&self) -> Option<u16> {
        self.network_config.vlan_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub tenant_id: Uuid,
    pub active_clients: u32,
    pub storage_used_gb: u64,
    pub bandwidth_used_mbps: u64,
    pub cpu_usage_percent: f64,
    pub memory_used_gb: u32,
    pub concurrent_sessions: u32,
    pub boot_images_count: u32,
    pub last_updated: DateTime<Utc>,
}

impl ResourceUsage {
    pub fn new(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            active_clients: 0,
            storage_used_gb: 0,
            bandwidth_used_mbps: 0,
            cpu_usage_percent: 0.0,
            memory_used_gb: 0,
            concurrent_sessions: 0,
            boot_images_count: 0,
            last_updated: Utc::now(),
        }
    }

    pub fn is_quota_exceeded(&self, quota: &ResourceQuota) -> Vec<String> {
        let mut violations = Vec::new();

        if self.active_clients > quota.max_clients {
            violations.push(format!(
                "Active clients ({}) exceeds limit ({})",
                self.active_clients, quota.max_clients
            ));
        }
        if self.storage_used_gb > quota.max_storage_gb {
            violations.push(format!(
                "Storage usage ({} GB) exceeds limit ({} GB)",
                self.storage_used_gb, quota.max_storage_gb
            ));
        }
        if self.bandwidth_used_mbps > quota.max_bandwidth_mbps {
            violations.push(format!(
                "Bandwidth usage ({} Mbps) exceeds limit ({} Mbps)",
                self.bandwidth_used_mbps, quota.max_bandwidth_mbps
            ));
        }
        if self.memory_used_gb > quota.max_memory_gb {
            violations.push(format!(
                "Memory usage ({} GB) exceeds limit ({} GB)",
                self.memory_used_gb, quota.max_memory_gb
            ));
        }
        if self.concurrent_sessions > quota.max_concurrent_sessions {
            violations.push(format!(
                "Concurrent sessions ({}) exceeds limit ({})",
                self.concurrent_sessions, quota.max_concurrent_sessions
            ));
        }
        if self.boot_images_count > quota.max_boot_images {
            violations.push(format!(
                "Boot images ({}) exceeds limit ({})",
                self.boot_images_count, quota.max_boot_images
            ));
        }

        violations
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TenantEvent {
    Created {
        tenant_id: Uuid,
        name: String,
    },
    Activated {
        tenant_id: Uuid,
    },
    Suspended {
        tenant_id: Uuid,
        reason: Option<String>,
    },
    Updated {
        tenant_id: Uuid,
        fields: Vec<String>,
    },
    QuotaExceeded {
        tenant_id: Uuid,
        violations: Vec<String>,
    },
    ClientConnected {
        tenant_id: Uuid,
        client_ip: IpAddr,
    },
    ClientDisconnected {
        tenant_id: Uuid,
        client_ip: IpAddr,
    },
    ResourceLimitReached {
        tenant_id: Uuid,
        resource: String,
    },
    SecurityViolation {
        tenant_id: Uuid,
        violation: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event: TenantEvent,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub ip_address: Option<IpAddr>,
    pub details: HashMap<String, String>,
}

impl AuditLog {
    pub fn new(tenant_id: Uuid, event: TenantEvent) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            event,
            timestamp: Utc::now(),
            user_id: None,
            ip_address: None,
            details: HashMap::new(),
        }
    }

    pub fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_ip(mut self, ip_address: IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    pub fn with_details(mut self, details: HashMap<String, String>) -> Self {
        self.details = details;
        self
    }
}

#[derive(Debug)]
pub struct TenantManager {
    tenants: Arc<DashMap<Uuid, Tenant>>,
    tenant_by_namespace: Arc<DashMap<String, Uuid>>,
    resource_usage: Arc<DashMap<Uuid, ResourceUsage>>,
    audit_logs: Arc<RwLock<Vec<AuditLog>>>,
    active_sessions: Arc<DashMap<Uuid, Vec<String>>>, // tenant_id -> session_ids
    pub client_connections: Arc<DashMap<IpAddr, Uuid>>, // client_ip -> tenant_id
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantManager {
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(DashMap::new()),
            tenant_by_namespace: Arc::new(DashMap::new()),
            resource_usage: Arc::new(DashMap::new()),
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            active_sessions: Arc::new(DashMap::new()),
            client_connections: Arc::new(DashMap::new()),
        }
    }

    pub async fn create_tenant(
        &self,
        name: String,
        namespace: String,
        metadata: TenantMetadata,
    ) -> Result<Uuid> {
        // Validate namespace uniqueness
        if self.tenant_by_namespace.contains_key(&namespace) {
            return Err(crate::error::DlsError::Validation(format!(
                "Namespace '{namespace}' already exists"
            )));
        }

        let tenant = Tenant::new(name.clone(), namespace.clone(), metadata);
        let tenant_id = tenant.id;

        // Initialize resource usage tracking
        let resource_usage = ResourceUsage::new(tenant_id);
        self.resource_usage.insert(tenant_id, resource_usage);

        // Store tenant
        self.tenants.insert(tenant_id, tenant.clone());
        self.tenant_by_namespace.insert(namespace, tenant_id);

        // Log creation
        let event = TenantEvent::Created { tenant_id, name };
        self.log_event(tenant_id, event).await;

        Ok(tenant_id)
    }

    pub async fn activate_tenant(&self, tenant_id: Uuid) -> Result<()> {
        if let Some(mut tenant) = self.tenants.get_mut(&tenant_id) {
            tenant.activate()?;

            let event = TenantEvent::Activated { tenant_id };
            self.log_event(tenant_id, event).await;

            Ok(())
        } else {
            Err(crate::error::Error::NotFound(format!(
                "Tenant {tenant_id} not found"
            )))
        }
    }

    pub async fn suspend_tenant(&self, tenant_id: Uuid, reason: Option<String>) -> Result<()> {
        if let Some(mut tenant) = self.tenants.get_mut(&tenant_id) {
            tenant.suspend(reason.clone())?;

            let event = TenantEvent::Suspended { tenant_id, reason };
            self.log_event(tenant_id, event).await;

            Ok(())
        } else {
            Err(crate::error::Error::NotFound(format!(
                "Tenant {tenant_id} not found"
            )))
        }
    }

    pub fn get_tenant(&self, tenant_id: &Uuid) -> Option<Tenant> {
        self.tenants.get(tenant_id).map(|tenant| tenant.clone())
    }

    pub fn get_tenant_by_namespace(&self, namespace: &str) -> Option<Tenant> {
        self.tenant_by_namespace
            .get(namespace)
            .and_then(|tenant_id| self.tenants.get(&tenant_id))
            .map(|tenant| tenant.clone())
    }

    pub fn list_tenants(&self) -> Vec<Tenant> {
        self.tenants
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn list_active_tenants(&self) -> Vec<Tenant> {
        self.tenants
            .iter()
            .filter_map(|entry| {
                let tenant = entry.value();
                if tenant.is_active() {
                    Some(tenant.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn update_tenant_quota(&self, tenant_id: Uuid, quota: ResourceQuota) -> Result<()> {
        if let Some(mut tenant) = self.tenants.get_mut(&tenant_id) {
            tenant.resource_quota = quota;
            tenant.updated_at = Utc::now();

            let event = TenantEvent::Updated {
                tenant_id,
                fields: vec!["resource_quota".to_string()],
            };
            self.log_event(tenant_id, event).await;

            Ok(())
        } else {
            Err(crate::error::Error::NotFound(format!(
                "Tenant {tenant_id} not found"
            )))
        }
    }

    pub async fn register_client_connection(
        &self,
        client_ip: IpAddr,
        tenant_id: Uuid,
    ) -> Result<()> {
        // Verify tenant exists and is active
        let tenant = self.get_tenant(&tenant_id).ok_or_else(|| {
            crate::error::Error::NotFound(format!("Tenant {tenant_id} not found"))
        })?;

        if !tenant.is_active() {
            return Err(crate::error::DlsError::Validation(format!(
                "Tenant {tenant_id} is not active"
            )));
        }

        // Check if client IP is allowed
        if !self.is_client_ip_allowed(&client_ip, &tenant).await? {
            return Err(crate::error::Error::AccessDenied(format!(
                "Client IP {client_ip} not allowed for tenant {tenant_id}"
            )));
        }

        // Update active client count
        if let Some(mut usage) = self.resource_usage.get_mut(&tenant_id) {
            usage.active_clients += 1;
            usage.last_updated = Utc::now();

            // Check quota limits
            let violations = usage.is_quota_exceeded(&tenant.resource_quota);
            if !violations.is_empty() {
                let event = TenantEvent::QuotaExceeded {
                    tenant_id,
                    violations,
                };
                self.log_event(tenant_id, event).await;
            }
        }

        // Register connection
        self.client_connections.insert(client_ip, tenant_id);

        let event = TenantEvent::ClientConnected {
            tenant_id,
            client_ip,
        };
        self.log_event(tenant_id, event).await;

        Ok(())
    }

    pub async fn unregister_client_connection(&self, client_ip: IpAddr) -> Result<()> {
        if let Some((_, tenant_id)) = self.client_connections.remove(&client_ip) {
            // Update active client count
            if let Some(mut usage) = self.resource_usage.get_mut(&tenant_id) {
                if usage.active_clients > 0 {
                    usage.active_clients -= 1;
                }
                usage.last_updated = Utc::now();
            }

            let event = TenantEvent::ClientDisconnected {
                tenant_id,
                client_ip,
            };
            self.log_event(tenant_id, event).await;
        }

        Ok(())
    }

    pub fn get_tenant_for_client(&self, client_ip: &IpAddr) -> Option<Uuid> {
        self.client_connections
            .get(client_ip)
            .map(|entry| *entry.value())
    }

    pub fn get_resource_usage(&self, tenant_id: &Uuid) -> Option<ResourceUsage> {
        self.resource_usage
            .get(tenant_id)
            .map(|usage| usage.clone())
    }

    pub async fn update_resource_usage(
        &self,
        tenant_id: Uuid,
        usage_update: impl Fn(&mut ResourceUsage),
    ) -> Result<()> {
        if let Some(mut usage) = self.resource_usage.get_mut(&tenant_id) {
            usage_update(&mut usage);
            usage.last_updated = Utc::now();

            // Check for quota violations
            if let Some(tenant) = self.get_tenant(&tenant_id) {
                let violations = usage.is_quota_exceeded(&tenant.resource_quota);
                if !violations.is_empty() {
                    let event = TenantEvent::QuotaExceeded {
                        tenant_id,
                        violations,
                    };
                    self.log_event(tenant_id, event).await;
                }
            }
        }

        Ok(())
    }

    pub async fn create_child_tenant(
        &self,
        parent_id: Uuid,
        name: String,
        namespace: String,
        metadata: TenantMetadata,
    ) -> Result<Uuid> {
        // Verify parent exists and is active
        let parent = self.get_tenant(&parent_id).ok_or_else(|| {
            crate::error::Error::NotFound(format!("Parent tenant {parent_id} not found"))
        })?;

        if !parent.is_active() {
            return Err(crate::error::DlsError::Validation(format!(
                "Parent tenant {parent_id} is not active"
            )));
        }

        // Create child tenant
        let child_id = self.create_tenant(name, namespace, metadata).await?;

        // Establish parent-child relationship
        if let Some(mut child) = self.tenants.get_mut(&child_id) {
            child.parent_tenant_id = Some(parent_id);
        }

        if let Some(mut parent) = self.tenants.get_mut(&parent_id) {
            parent.add_child_tenant(child_id);
        }

        Ok(child_id)
    }

    pub async fn delete_tenant(&self, tenant_id: Uuid) -> Result<()> {
        // Check if tenant has active connections
        let has_connections = self
            .client_connections
            .iter()
            .any(|entry| *entry.value() == tenant_id);

        if has_connections {
            return Err(crate::error::DlsError::Validation(format!(
                "Cannot delete tenant {tenant_id} with active connections"
            )));
        }

        // Remove from parent if this is a child tenant
        if let Some(tenant) = self.get_tenant(&tenant_id) {
            if let Some(parent_id) = tenant.parent_tenant_id {
                if let Some(mut parent) = self.tenants.get_mut(&parent_id) {
                    parent.remove_child_tenant(&tenant_id);
                }
            }

            // Remove from namespace mapping
            self.tenant_by_namespace.remove(&tenant.namespace);
        }

        // Remove tenant and associated data
        self.tenants.remove(&tenant_id);
        self.resource_usage.remove(&tenant_id);
        self.active_sessions.remove(&tenant_id);

        Ok(())
    }

    pub async fn get_audit_logs(
        &self,
        tenant_id: Option<Uuid>,
        limit: Option<usize>,
    ) -> Vec<AuditLog> {
        let logs = self.audit_logs.read();
        let filtered: Vec<AuditLog> = logs
            .iter()
            .filter(|log| tenant_id.map_or(true, |id| log.tenant_id == id))
            .cloned()
            .collect();

        let mut result = filtered;
        result.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Most recent first

        if let Some(limit) = limit {
            result.truncate(limit);
        }

        result
    }

    async fn log_event(&self, tenant_id: Uuid, event: TenantEvent) {
        let log = AuditLog::new(tenant_id, event);
        let mut logs = self.audit_logs.write();
        logs.push(log);

        // Keep only last 10000 logs to prevent unbounded growth
        if logs.len() > 10000 {
            let excess = logs.len() - 10000;
            logs.drain(0..excess);
        }
    }

    async fn is_client_ip_allowed(&self, client_ip: &IpAddr, tenant: &Tenant) -> Result<bool> {
        // If no IP restrictions configured, allow all
        if tenant.network_config.allowed_ip_ranges.is_empty() {
            return Ok(true);
        }

        // Check if client IP is in allowed ranges
        for range in &tenant.network_config.allowed_ip_ranges {
            if self.ip_in_range(client_ip, range)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn ip_in_range(&self, ip: &IpAddr, range: &str) -> Result<bool> {
        // Simple CIDR check - in production, use a proper IP range library
        if range.contains('/') {
            // CIDR notation
            let parts: Vec<&str> = range.split('/').collect();
            if parts.len() != 2 {
                return Ok(false);
            }

            let network_ip: IpAddr = parts[0].parse().map_err(|_| {
                crate::error::DlsError::Validation(format!("Invalid network IP: {}", parts[0]))
            })?;

            let prefix_len: u8 = parts[1].parse().map_err(|_| {
                crate::error::DlsError::Validation(format!("Invalid prefix length: {}", parts[1]))
            })?;

            // Basic CIDR matching (simplified)
            match (ip, network_ip) {
                (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                    let ip_bits = u32::from(*ip4);
                    let net_bits = u32::from(net4);
                    let mask = !0u32 << (32 - prefix_len);
                    Ok((ip_bits & mask) == (net_bits & mask))
                }
                (IpAddr::V6(_), IpAddr::V6(_)) => {
                    // IPv6 CIDR matching would be more complex
                    Ok(false)
                }
                _ => Ok(false),
            }
        } else {
            // Exact IP match
            let allowed_ip: IpAddr = range.parse().map_err(|_| {
                crate::error::DlsError::Validation(format!("Invalid IP address: {range}"))
            })?;
            Ok(*ip == allowed_ip)
        }
    }

    pub async fn cleanup_inactive_sessions(&self) {
        let now = Utc::now();
        let mut expired_sessions = Vec::new();

        for entry in self.tenants.iter() {
            let tenant = entry.value();
            if let Some(last_activity) = tenant.last_activity {
                let inactive_duration = now.signed_duration_since(last_activity);
                if inactive_duration.num_minutes()
                    > tenant.security_policy.session_timeout_minutes as i64
                {
                    expired_sessions.push(tenant.id);
                }
            }
        }

        for tenant_id in expired_sessions {
            self.active_sessions.remove(&tenant_id);
        }
    }

    pub async fn start(&self) -> Result<()> {
        // Start background cleanup task
        let tenant_manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                tenant_manager.cleanup_inactive_sessions().await;
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        // Cleanup would happen here
        Ok(())
    }
}

// Clone implementation for TenantManager
impl Clone for TenantManager {
    fn clone(&self) -> Self {
        Self {
            tenants: Arc::clone(&self.tenants),
            tenant_by_namespace: Arc::clone(&self.tenant_by_namespace),
            resource_usage: Arc::clone(&self.resource_usage),
            audit_logs: Arc::clone(&self.audit_logs),
            active_sessions: Arc::clone(&self.active_sessions),
            client_connections: Arc::clone(&self.client_connections),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tenant_creation() {
        let manager = TenantManager::new();
        let metadata = TenantMetadata {
            organization_name: "Test Org".to_string(),
            contact_email: "test@example.com".to_string(),
            contact_phone: None,
            description: Some("Test tenant".to_string()),
            tags: vec!["test".to_string()],
            custom_fields: HashMap::new(),
        };

        let tenant_id = manager
            .create_tenant(
                "Test Tenant".to_string(),
                "test-tenant".to_string(),
                metadata,
            )
            .await
            .unwrap();

        assert!(manager.get_tenant(&tenant_id).is_some());
        assert!(manager.get_tenant_by_namespace("test-tenant").is_some());
    }

    #[tokio::test]
    async fn test_tenant_activation() {
        let manager = TenantManager::new();
        let metadata = TenantMetadata {
            organization_name: "Test Org".to_string(),
            contact_email: "test@example.com".to_string(),
            contact_phone: None,
            description: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
        };

        let tenant_id = manager
            .create_tenant("Test".to_string(), "test".to_string(), metadata)
            .await
            .unwrap();

        manager.activate_tenant(tenant_id).await.unwrap();

        let tenant = manager.get_tenant(&tenant_id).unwrap();
        assert!(tenant.is_active());
    }

    #[tokio::test]
    async fn test_resource_quota_tracking() {
        let manager = TenantManager::new();
        let metadata = TenantMetadata {
            organization_name: "Test Org".to_string(),
            contact_email: "test@example.com".to_string(),
            contact_phone: None,
            description: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
        };

        let tenant_id = manager
            .create_tenant("Test".to_string(), "test".to_string(), metadata)
            .await
            .unwrap();

        let usage = manager.get_resource_usage(&tenant_id).unwrap();
        assert_eq!(usage.active_clients, 0);
        assert_eq!(usage.storage_used_gb, 0);
    }

    #[tokio::test]
    async fn test_client_connection_tracking() {
        let manager = TenantManager::new();
        let metadata = TenantMetadata {
            organization_name: "Test Org".to_string(),
            contact_email: "test@example.com".to_string(),
            contact_phone: None,
            description: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
        };

        let tenant_id = manager
            .create_tenant("Test".to_string(), "test".to_string(), metadata)
            .await
            .unwrap();

        manager.activate_tenant(tenant_id).await.unwrap();

        let client_ip = "192.168.1.100".parse().unwrap();
        manager
            .register_client_connection(client_ip, tenant_id)
            .await
            .unwrap();

        assert_eq!(manager.get_tenant_for_client(&client_ip), Some(tenant_id));

        let usage = manager.get_resource_usage(&tenant_id).unwrap();
        assert_eq!(usage.active_clients, 1);
    }
}
