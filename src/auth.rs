use crate::error::{DlsError, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub username: String,
    pub role: UserRole,
}

#[derive(Debug)]
pub struct AuthManager {
    jwt_key: HS256Key,
    token_expiry_hours: u64,
}

impl AuthManager {
    pub fn new(secret: &str, token_expiry_hours: u64) -> Self {
        let jwt_key = HS256Key::from_bytes(secret.as_bytes());
        
        Self {
            jwt_key,
            token_expiry_hours,
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| DlsError::Auth(format!("Failed to hash password: {}", e)))?;
        
        Ok(password_hash.to_string())
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| DlsError::Auth(format!("Invalid password hash: {}", e)))?;
        
        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn create_token(&self, user: &User) -> Result<String> {
        let claims = Claims {
            username: user.username.clone(),
            role: user.role.clone(),
        };

        let jwt_claims = JWTClaims {
            issued_at: Some(Clock::now_since_epoch()),
            expires_at: Some(Clock::now_since_epoch() + Duration::from_secs(self.token_expiry_hours * 3600)),
            invalid_before: None,
            issuer: None,
            subject: Some(user.id.to_string()),
            audiences: None,
            jwt_id: None,
            nonce: None,
            custom: claims,
        };

        let token = self.jwt_key
            .authenticate(jwt_claims)
            .map_err(|e| DlsError::Auth(format!("Failed to create token: {}", e)))?;
        
        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let jwt_claims = self.jwt_key
            .verify_token::<Claims>(token, None)
            .map_err(|e| DlsError::Auth(format!("Invalid token: {}", e)))?;
        
        Ok(jwt_claims.custom)
    }

    pub fn refresh_token(&self, token: &str) -> Result<String> {
        let claims = self.verify_token(token)?;
        
        let user = User {
            id: uuid::Uuid::new_v4(),
            username: claims.username,
            password_hash: String::new(),
            role: claims.role,
            created_at: chrono::Utc::now(),
            last_login: None,
            active: true,
        };
        
        self.create_token(&user)
    }
}

#[derive(Debug)]
pub struct AuthMiddleware {
    auth_manager: AuthManager,
}

impl AuthMiddleware {
    pub fn new(auth_manager: AuthManager) -> Self {
        Self { auth_manager }
    }

    pub fn verify_request(&self, auth_header: Option<&str>) -> Result<Claims> {
        let auth_header = auth_header
            .ok_or_else(|| DlsError::Auth("Missing authorization header".to_string()))?;
        
        if !auth_header.starts_with("Bearer ") {
            return Err(DlsError::Auth("Invalid authorization header format".to_string()));
        }
        
        let token = &auth_header[7..];
        self.auth_manager.verify_token(token)
    }

    pub fn require_role(&self, claims: &Claims, required_role: &UserRole) -> Result<()> {
        match (&claims.role, required_role) {
            (UserRole::Admin, _) => Ok(()),
            (UserRole::Operator, UserRole::Operator) => Ok(()),
            (UserRole::Operator, UserRole::Viewer) => Ok(()),
            (UserRole::Viewer, UserRole::Viewer) => Ok(()),
            _ => Err(DlsError::Auth("Insufficient permissions".to_string())),
        }
    }
}