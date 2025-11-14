#![allow(unused_variables)]

mod common;

use dls_server::storage::{ImageFormat, StorageManager, ZfsStorageManager};

#[tokio::test]
async fn test_create_raw_image() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let image = storage_manager
        .create_image(
            "test-ubuntu",
            1024 * 1024 * 1024, // 1GB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    assert_eq!(image.name, "test-ubuntu");
    assert_eq!(image.size_bytes, 1024 * 1024 * 1024);
    assert!(matches!(image.format, ImageFormat::Raw));
    assert!(image.path.contains(&image.id.to_string()));

    let retrieved = storage_manager.get_image(image.id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "test-ubuntu");
}

#[tokio::test]
async fn test_list_images() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let image1 = storage_manager
        .create_image(
            "ubuntu-20.04",
            2 * 1024 * 1024 * 1024, // 2GB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    let image2 = storage_manager
        .create_image(
            "windows-11",
            10 * 1024 * 1024 * 1024, // 10GB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    let images = storage_manager.list_images().await.unwrap();
    assert_eq!(images.len(), 2);

    let names: Vec<String> = images.iter().map(|img| img.name.clone()).collect();
    assert!(names.contains(&"ubuntu-20.04".to_string()));
    assert!(names.contains(&"windows-11".to_string()));
}

#[tokio::test]
async fn test_delete_image() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let image = storage_manager
        .create_image(
            "temp-image",
            512 * 1024 * 1024, // 512MB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    let image_id = image.id;

    // Verify it exists
    let retrieved = storage_manager.get_image(image_id).await.unwrap();
    assert!(retrieved.is_some());

    // Delete it
    storage_manager.delete_image(image_id).await.unwrap();

    // Verify it's gone
    let retrieved_after = storage_manager.get_image(image_id).await.unwrap();
    assert!(retrieved_after.is_none());
}

#[tokio::test]
async fn test_resize_image() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let image = storage_manager
        .create_image(
            "resize-test",
            1024 * 1024 * 1024, // 1GB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    let new_size = 2 * 1024 * 1024 * 1024; // 2GB
    storage_manager
        .resize_image(image.id, new_size)
        .await
        .unwrap();

    let updated_image = storage_manager.get_image(image.id).await.unwrap().unwrap();
    assert_eq!(updated_image.size_bytes, new_size);
}

#[tokio::test]
async fn test_create_snapshot() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let image = storage_manager
        .create_image(
            "snapshot-test",
            1024 * 1024 * 1024, // 1GB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    let snapshot_name = storage_manager
        .create_snapshot(image.id, "test-snapshot")
        .await
        .unwrap();
    assert!(snapshot_name.contains("test-snapshot"));
    assert!(snapshot_name.contains(&image.id.to_string()));
}

#[tokio::test]
async fn test_clone_image() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let original = storage_manager
        .create_image(
            "original-image",
            1024 * 1024 * 1024, // 1GB
            ImageFormat::Raw,
        )
        .await
        .unwrap();

    let cloned = storage_manager
        .clone_image(original.id, "cloned-image")
        .await
        .unwrap();

    assert_eq!(cloned.name, "cloned-image");
    assert_eq!(cloned.size_bytes, original.size_bytes);
    assert_eq!(cloned.format, original.format);
    assert_ne!(cloned.id, original.id);
    assert!(cloned.description.is_some());
    assert!(cloned.description.as_ref().unwrap().contains("Clone"));
}

#[tokio::test]
async fn test_image_formats() {
    common::setup();

    let storage_manager =
        ZfsStorageManager::new("test-pool".to_string(), "/tmp/test-images".to_string());

    let raw_image = storage_manager
        .create_image("raw-image", 512 * 1024 * 1024, ImageFormat::Raw)
        .await
        .unwrap();

    assert!(matches!(raw_image.format, ImageFormat::Raw));
    assert!(raw_image.path.ends_with(".img"));

    // Test that other formats would be handled (if qemu-img is available)
    // Note: These might fail in CI if qemu-img is not installed
    if std::process::Command::new("qemu-img")
        .arg("--version")
        .output()
        .is_ok()
    {
        let qcow2_image = storage_manager
            .create_image("qcow2-image", 512 * 1024 * 1024, ImageFormat::Qcow2)
            .await
            .unwrap();

        assert!(matches!(qcow2_image.format, ImageFormat::Qcow2));
        assert!(qcow2_image.path.ends_with(".qcow2"));
    }
}
