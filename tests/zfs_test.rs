mod common;

use dls_server::storage::{CompressionType, MockZfsManager, ZfsManager};
use std::collections::HashMap;

#[tokio::test]
async fn test_mock_zfs_dataset_creation() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    let mut properties = HashMap::new();
    properties.insert("compression".to_string(), "lz4".to_string());
    properties.insert("mountpoint".to_string(), "/test/dataset".to_string());

    let dataset = zfs_manager
        .create_dataset("test-dataset", properties)
        .await
        .unwrap();

    assert_eq!(dataset.name, "test-pool/test-dataset");
    assert_eq!(
        dataset.mountpoint,
        Some(std::path::PathBuf::from("/test-pool/test-dataset"))
    );
    assert!(matches!(dataset.compression, CompressionType::Lz4));
    assert!(!dataset.dedup);
}

#[tokio::test]
async fn test_mock_zfs_dataset_list() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    // Create multiple datasets
    for i in 1..=3 {
        let properties = HashMap::new();
        zfs_manager
            .create_dataset(&format!("dataset-{}", i), properties)
            .await
            .unwrap();
    }

    let datasets = zfs_manager.list_datasets(None).await.unwrap();
    assert_eq!(datasets.len(), 3);

    let names: Vec<String> = datasets.iter().map(|d| d.name.clone()).collect();
    assert!(names.contains(&"test-pool/dataset-1".to_string()));
    assert!(names.contains(&"test-pool/dataset-2".to_string()));
    assert!(names.contains(&"test-pool/dataset-3".to_string()));
}

#[tokio::test]
async fn test_mock_zfs_dataset_properties() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    let properties = HashMap::new();
    zfs_manager
        .create_dataset("prop-test", properties)
        .await
        .unwrap();

    // Set a property
    zfs_manager
        .set_property("prop-test", "compression", "gzip")
        .await
        .unwrap();

    // Get the property
    let value = zfs_manager
        .get_property("prop-test", "compression")
        .await
        .unwrap();
    assert_eq!(value, Some("gzip".to_string()));

    // Get non-existent property
    let non_existent = zfs_manager
        .get_property("prop-test", "non-existent")
        .await
        .unwrap();
    assert_eq!(non_existent, None);
}

#[tokio::test]
async fn test_mock_zfs_snapshots() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    // Create a dataset first
    let properties = HashMap::new();
    zfs_manager
        .create_dataset("snap-test", properties)
        .await
        .unwrap();

    // Create snapshots
    let snapshot1 = zfs_manager
        .create_snapshot("snap-test", "snapshot-1")
        .await
        .unwrap();
    let snapshot2 = zfs_manager
        .create_snapshot("snap-test", "snapshot-2")
        .await
        .unwrap();

    assert_eq!(snapshot1.name, "test-pool/snap-test@snapshot-1");
    assert_eq!(snapshot2.name, "test-pool/snap-test@snapshot-2");

    // List snapshots
    let snapshots = zfs_manager.list_snapshots(Some("snap-test")).await.unwrap();
    assert_eq!(snapshots.len(), 2);

    // Destroy a snapshot
    zfs_manager
        .destroy_snapshot("snap-test", "snapshot-1")
        .await
        .unwrap();

    let snapshots_after = zfs_manager.list_snapshots(Some("snap-test")).await.unwrap();
    assert_eq!(snapshots_after.len(), 1);
    assert_eq!(snapshots_after[0].name, "test-pool/snap-test@snapshot-2");
}

#[tokio::test]
async fn test_mock_zfs_clone() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    // Create original dataset and snapshot
    let properties = HashMap::new();
    zfs_manager
        .create_dataset("original", properties)
        .await
        .unwrap();
    zfs_manager
        .create_snapshot("original", "snap1")
        .await
        .unwrap();

    // Clone the snapshot
    let clone = zfs_manager
        .clone_snapshot("test-pool/original@snap1", "cloned")
        .await
        .unwrap();

    assert_eq!(clone.name, "test-pool/cloned");

    // Verify clone exists in dataset list
    let datasets = zfs_manager.list_datasets(None).await.unwrap();
    let clone_exists = datasets.iter().any(|d| d.name == "test-pool/cloned");
    assert!(clone_exists);
}

#[tokio::test]
async fn test_mock_zfs_rollback() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    // Create dataset and snapshot
    let properties = HashMap::new();
    zfs_manager
        .create_dataset("rollback-test", properties)
        .await
        .unwrap();
    zfs_manager
        .create_snapshot("rollback-test", "before-changes")
        .await
        .unwrap();

    // Rollback (this is a mock operation)
    let result = zfs_manager
        .rollback_snapshot("rollback-test", "before-changes")
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_mock_zfs_send_receive() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    // Create dataset and snapshot
    let properties = HashMap::new();
    zfs_manager
        .create_dataset("send-test", properties)
        .await
        .unwrap();
    zfs_manager
        .create_snapshot("send-test", "send-snap")
        .await
        .unwrap();

    // Send snapshot (mock operation)
    let send_result = zfs_manager
        .send_snapshot("test-pool/send-test@send-snap", "remote-host")
        .await;
    assert!(send_result.is_ok());

    // Receive snapshot (mock operation)
    let receive_result = zfs_manager
        .receive_snapshot("remote-host", "test-pool/received")
        .await;
    assert!(receive_result.is_ok());
}

#[tokio::test]
async fn test_mock_zfs_dataset_destroy() {
    common::setup();

    let zfs_manager = MockZfsManager::new("test-pool".to_string());

    // Create dataset
    let properties = HashMap::new();
    zfs_manager
        .create_dataset("destroy-test", properties)
        .await
        .unwrap();

    // Verify it exists
    let dataset = zfs_manager.get_dataset("destroy-test").await.unwrap();
    assert!(dataset.is_some());

    // Destroy it
    zfs_manager
        .destroy_dataset("destroy-test", false)
        .await
        .unwrap();

    // Verify it's gone
    let dataset_after = zfs_manager.get_dataset("destroy-test").await.unwrap();
    assert!(dataset_after.is_none());
}

#[tokio::test]
async fn test_zfs_compression_types() {
    use dls_server::storage::CompressionType;

    let compression_types = vec![
        CompressionType::Off,
        CompressionType::Lz4,
        CompressionType::Gzip,
        CompressionType::Zstd,
        CompressionType::Lzjb,
    ];

    // Test serialization/deserialization
    for comp_type in compression_types {
        let serialized = serde_json::to_string(&comp_type).unwrap();
        let deserialized: CompressionType = serde_json::from_str(&serialized).unwrap();

        // This tests that the types are the same variant
        match (&comp_type, &deserialized) {
            (CompressionType::Off, CompressionType::Off) => {}
            (CompressionType::Lz4, CompressionType::Lz4) => {}
            (CompressionType::Gzip, CompressionType::Gzip) => {}
            (CompressionType::Zstd, CompressionType::Zstd) => {}
            (CompressionType::Lzjb, CompressionType::Lzjb) => {}
            _ => panic!("Compression type serialization/deserialization failed"),
        }
    }
}
