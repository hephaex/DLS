mod common;

use claude_dls::config::Settings;
use claude_dls::storage::{ImageFormat, StorageManager, ZfsStorageManager};
use claude_dls::auth::{AuthManager, User, UserRole};
use tempfile::TempDir;

#[tokio::test]
async fn test_config_loading() {
    common::setup();
    
    let config = Settings::default();
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.server.bind_address, "0.0.0.0");
}

#[tokio::test]
async fn test_storage_manager() {
    common::setup();
    
    let temp_dir = TempDir::new().unwrap();
    let storage = ZfsStorageManager::new(
        "test-pool".to_string(),
        temp_dir.path().to_string_lossy().to_string(),
    );

    let result = storage.create_image("test-image", 1024 * 1024, ImageFormat::Raw).await;
    assert!(result.is_ok());
    
    let image = result.unwrap();
    assert_eq!(image.name, "test-image");
    assert_eq!(image.size_bytes, 1024 * 1024);
    assert!(matches!(image.format, ImageFormat::Raw));
}

#[test]
fn test_auth_manager() {
    let auth = AuthManager::new("test-secret", 24);
    
    let password = "test-password";
    let hash = auth.hash_password(password).unwrap();
    
    assert!(auth.verify_password(password, &hash).unwrap());
    assert!(!auth.verify_password("wrong-password", &hash).unwrap());
}

#[test]
fn test_jwt_tokens() {
    let auth = AuthManager::new("test-secret", 24);
    
    let user = User {
        id: uuid::Uuid::new_v4(),
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Admin,
        created_at: chrono::Utc::now(),
        last_login: None,
        active: true,
    };

    let token = auth.create_token(&user).unwrap();
    let claims = auth.verify_token(&token).unwrap();
    
    assert_eq!(claims.username, "testuser");
    assert!(matches!(claims.role, UserRole::Admin));
}