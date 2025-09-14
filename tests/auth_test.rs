mod common;

use dls_server::auth::{AuthManager, UserRole, User};
use chrono::Utc;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "test-secret-key-for-authentication-testing";

#[tokio::test]
async fn test_password_hashing_and_verification() {
    common::setup();
    
    let auth_manager = AuthManager::new(TEST_JWT_SECRET, 24);
    
    let password = "secure_password_123";
    let hash = auth_manager.hash_password(password).unwrap();
    
    // Verify correct password
    assert!(auth_manager.verify_password(password, &hash).unwrap());
    
    // Verify incorrect password
    assert!(!auth_manager.verify_password("wrong_password", &hash).unwrap());
    
    // Verify different passwords create different hashes
    let hash2 = auth_manager.hash_password(password).unwrap();
    assert_ne!(hash, hash2);
}

#[tokio::test]
async fn test_jwt_token_creation_and_verification() {
    common::setup();
    
    let auth_manager = AuthManager::new(TEST_JWT_SECRET, 24);
    
    let user = User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Operator,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    // Create token
    let token = auth_manager.create_token(&user).unwrap();
    assert!(!token.is_empty());
    
    // Verify token
    let claims = auth_manager.verify_token(&token).unwrap();
    assert_eq!(claims.username, user.username);
    assert_eq!(claims.role, user.role);
}

#[tokio::test]
async fn test_token_refresh() {
    common::setup();
    
    let auth_manager = AuthManager::new(TEST_JWT_SECRET, 24);
    
    let user = User {
        id: Uuid::new_v4(),
        username: "refreshuser".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Admin,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    let original_token = auth_manager.create_token(&user).unwrap();
    let refreshed_token = auth_manager.refresh_token(&original_token).unwrap();
    
    // Both tokens should be valid but different
    assert_ne!(original_token, refreshed_token);
    
    let original_claims = auth_manager.verify_token(&original_token).unwrap();
    let refreshed_claims = auth_manager.verify_token(&refreshed_token).unwrap();
    
    assert_eq!(original_claims.username, refreshed_claims.username);
    assert_eq!(original_claims.role, refreshed_claims.role);
}

#[tokio::test]
async fn test_user_role_serialization() {
    common::setup();
    
    // Test Display trait
    assert_eq!(UserRole::Admin.to_string(), "admin");
    assert_eq!(UserRole::Operator.to_string(), "operator");
    assert_eq!(UserRole::Viewer.to_string(), "viewer");
    
    // Test FromStr trait
    assert_eq!("admin".parse::<UserRole>().unwrap(), UserRole::Admin);
    assert_eq!("operator".parse::<UserRole>().unwrap(), UserRole::Operator);
    assert_eq!("viewer".parse::<UserRole>().unwrap(), UserRole::Viewer);
    assert_eq!("ADMIN".parse::<UserRole>().unwrap(), UserRole::Admin); // Case insensitive
    
    // Test invalid role
    assert!("invalid".parse::<UserRole>().is_err());
}

#[tokio::test]
async fn test_role_based_permissions() {
    common::setup();
    
    let auth_manager = AuthManager::new(TEST_JWT_SECRET, 24);
    let auth_middleware = dls_server::auth::AuthMiddleware::new(auth_manager);
    
    // Test admin permissions (should have access to everything)
    let admin_user = User {
        id: Uuid::new_v4(),
        username: "admin".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Admin,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    let admin_token = auth_middleware.auth_manager.create_token(&admin_user).unwrap();
    let admin_claims = auth_middleware.auth_manager.verify_token(&admin_token).unwrap();
    
    assert!(auth_middleware.require_role(&admin_claims, &UserRole::Admin).is_ok());
    assert!(auth_middleware.require_role(&admin_claims, &UserRole::Operator).is_ok());
    assert!(auth_middleware.require_role(&admin_claims, &UserRole::Viewer).is_ok());
    
    // Test operator permissions
    let operator_user = User {
        id: Uuid::new_v4(),
        username: "operator".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Operator,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    let operator_token = auth_middleware.auth_manager.create_token(&operator_user).unwrap();
    let operator_claims = auth_middleware.auth_manager.verify_token(&operator_token).unwrap();
    
    assert!(auth_middleware.require_role(&operator_claims, &UserRole::Admin).is_err());
    assert!(auth_middleware.require_role(&operator_claims, &UserRole::Operator).is_ok());
    assert!(auth_middleware.require_role(&operator_claims, &UserRole::Viewer).is_ok());
    
    // Test viewer permissions
    let viewer_user = User {
        id: Uuid::new_v4(),
        username: "viewer".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Viewer,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    let viewer_token = auth_middleware.auth_manager.create_token(&viewer_user).unwrap();
    let viewer_claims = auth_middleware.auth_manager.verify_token(&viewer_token).unwrap();
    
    assert!(auth_middleware.require_role(&viewer_claims, &UserRole::Admin).is_err());
    assert!(auth_middleware.require_role(&viewer_claims, &UserRole::Operator).is_err());
    assert!(auth_middleware.require_role(&viewer_claims, &UserRole::Viewer).is_ok());
}

#[tokio::test]
async fn test_auth_middleware_header_parsing() {
    common::setup();
    
    let auth_manager = AuthManager::new(TEST_JWT_SECRET, 24);
    let auth_middleware = dls_server::auth::AuthMiddleware::new(auth_manager);
    
    let user = User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Operator,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    let token = auth_middleware.auth_manager.create_token(&user).unwrap();
    
    // Valid Bearer token
    let auth_header = format!("Bearer {}", token);
    let claims = auth_middleware.verify_request(Some(&auth_header)).unwrap();
    assert_eq!(claims.username, user.username);
    
    // Missing authorization header
    assert!(auth_middleware.verify_request(None).is_err());
    
    // Invalid header format (missing Bearer)
    assert!(auth_middleware.verify_request(Some(&token)).is_err());
    
    // Invalid header format (wrong prefix)
    assert!(auth_middleware.verify_request(Some(&format!("Basic {}", token))).is_err());
}

#[tokio::test]
async fn test_invalid_token_handling() {
    common::setup();
    
    let auth_manager = AuthManager::new(TEST_JWT_SECRET, 24);
    
    // Test completely invalid token
    assert!(auth_manager.verify_token("invalid_token").is_err());
    
    // Test empty token
    assert!(auth_manager.verify_token("").is_err());
    
    // Test token with wrong secret
    let other_auth_manager = AuthManager::new("different_secret", 24);
    let user = User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        role: UserRole::Viewer,
        created_at: Utc::now(),
        last_login: None,
        active: true,
    };
    
    let token_wrong_secret = other_auth_manager.create_token(&user).unwrap();
    assert!(auth_manager.verify_token(&token_wrong_secret).is_err());
}

#[tokio::test]
async fn test_user_info_serialization() {
    common::setup();
    
    let user = User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        password_hash: "password_hash".to_string(),
        role: UserRole::Admin,
        created_at: Utc::now(),
        last_login: Some(Utc::now()),
        active: true,
    };
    
    let user_info: dls_server::auth::UserInfo = user.into();
    
    // Test JSON serialization
    let json = serde_json::to_string(&user_info).unwrap();
    let deserialized: dls_server::auth::UserInfo = serde_json::from_str(&json).unwrap();
    
    assert_eq!(user_info.username, deserialized.username);
    assert_eq!(user_info.role, deserialized.role);
    assert_eq!(user_info.id, deserialized.id);
}

// Note: Full database integration tests would require a PostgreSQL test instance
// These tests focus on the core authentication logic and data structures