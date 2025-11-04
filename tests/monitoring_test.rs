mod common;

use dls_server::monitoring::{ClientStatus, MonitoringManager};

#[tokio::test]
async fn test_monitoring_manager_creation() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();
    let metrics = monitoring_manager.get_metrics();

    // Verify all metrics are initialized
    assert!(metrics.dhcp_requests.get() == 0.0);
    assert!(metrics.tftp_requests.get() == 0.0);
    assert!(metrics.iscsi_connections.get() == 0.0);
    assert!(metrics.active_clients.get() == 0.0);
    assert!(metrics.storage_used_bytes.get() == 0.0);
}

#[tokio::test]
async fn test_network_service_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test DHCP metrics
    monitoring_manager.record_dhcp_request().await;
    monitoring_manager.record_dhcp_request().await;
    monitoring_manager.record_dhcp_error().await;

    // Test TFTP metrics
    monitoring_manager.record_tftp_request().await;
    monitoring_manager.record_tftp_error().await;

    // Test iSCSI metrics
    monitoring_manager.record_iscsi_connection().await;
    monitoring_manager.record_iscsi_error().await;

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.dhcp_requests.get() == 2.0);
    assert!(metrics.dhcp_errors.get() == 1.0);
    assert!(metrics.tftp_requests.get() == 1.0);
    assert!(metrics.tftp_errors.get() == 1.0);
    assert!(metrics.iscsi_connections.get() == 1.0);
    assert!(metrics.iscsi_errors.get() == 1.0);
}

#[tokio::test]
async fn test_system_performance_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test system metrics
    monitoring_manager.update_cpu_usage(75.5).await;
    monitoring_manager.update_memory_usage(8589934592.0).await; // 8GB in bytes
    monitoring_manager
        .update_memory_available(2147483648.0)
        .await; // 2GB in bytes
    monitoring_manager
        .update_network_throughput(1073741824.0)
        .await; // 1GB/sec
    monitoring_manager.record_disk_io(4096.0).await; // 4KB

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.cpu_usage_percent.get() == 75.5);
    assert!(metrics.memory_usage_bytes.get() == 8589934592.0);
    assert!(metrics.memory_available_bytes.get() == 2147483648.0);
    assert!(metrics.network_throughput_bytes.get() == 1073741824.0);
    assert!(metrics.disk_io_bytes.get() == 4096.0);
}

#[tokio::test]
async fn test_authentication_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test authentication metrics
    monitoring_manager.record_auth_request().await;
    monitoring_manager.record_auth_request().await;
    monitoring_manager.record_auth_failure().await;
    monitoring_manager.update_active_sessions(5.0).await;
    monitoring_manager.record_token_refresh().await;

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.auth_requests.get() == 2.0);
    assert!(metrics.auth_failures.get() == 1.0);
    assert!(metrics.active_sessions.get() == 5.0);
    assert!(metrics.token_refreshes.get() == 1.0);
}

#[tokio::test]
async fn test_database_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test database metrics
    monitoring_manager.update_database_connections(10.0).await;
    monitoring_manager.record_database_query(0.025).await; // 25ms query
    monitoring_manager.record_database_query(0.100).await; // 100ms query
    monitoring_manager.record_database_error().await;

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.database_connections.get() == 10.0);
    assert!(metrics.database_queries.get() == 2.0);
    assert!(metrics.database_errors.get() == 1.0);

    // Test histogram buckets (should have recorded the query times)
    let histogram_samples = metrics.database_query_duration.get_sample_count();
    assert!(histogram_samples == 2);
}

#[tokio::test]
async fn test_storage_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test storage metrics
    monitoring_manager.update_disk_images_count(25.0).await;
    monitoring_manager
        .update_storage_used(1099511627776.0)
        .await; // 1TB in bytes
    monitoring_manager
        .update_storage_available(2199023255552.0)
        .await; // 2TB in bytes
    monitoring_manager.update_zfs_snapshots_count(150.0).await;
    monitoring_manager.record_image_operation().await;
    monitoring_manager.record_image_operation().await;

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.disk_images_total.get() == 25.0);
    assert!(metrics.storage_used_bytes.get() == 1099511627776.0);
    assert!(metrics.storage_available_bytes.get() == 2199023255552.0);
    assert!(metrics.zfs_snapshots_total.get() == 150.0);
    assert!(metrics.image_operations.get() == 2.0);
}

#[tokio::test]
async fn test_health_and_uptime_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test health metrics
    monitoring_manager.update_uptime(86400.0).await; // 1 day in seconds
    monitoring_manager.record_health_check().await;
    monitoring_manager.record_health_check().await;
    monitoring_manager.record_service_restart().await;

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.uptime_seconds.get() == 86400.0);
    assert!(metrics.health_checks.get() == 2.0);
    assert!(metrics.service_restarts.get() == 1.0);
}

#[tokio::test]
async fn test_client_session_metrics() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Test boot session metrics
    monitoring_manager.record_boot_session_start().await;
    monitoring_manager.record_boot_session_start().await;
    monitoring_manager.record_boot_failure().await;
    monitoring_manager.record_boot_time(45.5).await; // 45.5 seconds
    monitoring_manager.record_boot_time(32.1).await; // 32.1 seconds

    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.boot_sessions_total.get() == 2.0);
    assert!(metrics.boot_failures.get() == 1.0);

    // Test histogram buckets for boot time
    let histogram_samples = metrics.boot_time_histogram.get_sample_count();
    assert!(histogram_samples == 2);
}

#[tokio::test]
async fn test_metrics_export() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Record some metrics
    monitoring_manager.record_dhcp_request().await;
    monitoring_manager.update_active_clients(3.0).await;
    monitoring_manager.record_auth_request().await;

    // Test metrics export
    let exported_metrics = monitoring_manager.export_metrics().await.unwrap();

    // Verify the export contains Prometheus format
    assert!(exported_metrics.contains("dhcp_requests_total"));
    assert!(exported_metrics.contains("active_clients"));
    assert!(exported_metrics.contains("auth_requests_total"));
    assert!(
        exported_metrics.contains("TYPE")
            && (exported_metrics.contains("counter") || exported_metrics.contains("gauge"))
    );
    assert!(exported_metrics.contains("# HELP"));

    // Should contain the metric values we set
    assert!(exported_metrics.contains("dhcp_requests_total 1"));
    assert!(exported_metrics.contains("active_clients 3"));
    assert!(exported_metrics.contains("auth_requests_total 1"));
}

#[tokio::test]
async fn test_client_session_management() {
    common::setup();

    let monitoring_manager = MonitoringManager::new().unwrap();

    // Start a client session
    let client_id = "client-001".to_string();
    let ip_address = "192.168.1.100".to_string();

    monitoring_manager
        .start_client_session(client_id.clone(), ip_address.clone())
        .await
        .unwrap();

    // Verify active clients count
    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.active_clients.get() == 1.0);

    // Update client status
    monitoring_manager
        .update_client_status(&client_id, ClientStatus::ImageLoading)
        .await
        .unwrap();
    monitoring_manager
        .update_client_status(&client_id, ClientStatus::Ready)
        .await
        .unwrap();

    // End client session
    monitoring_manager
        .end_client_session(&client_id)
        .await
        .unwrap();

    // Verify active clients count decreased
    let metrics = monitoring_manager.get_metrics();
    assert!(metrics.active_clients.get() == 0.0);

    // Verify session exists in history
    let sessions = monitoring_manager.get_client_sessions().await;
    assert!(sessions.is_empty()); // Should be empty after ending session
}
