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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::Operator => write!(f, "operator"),
            UserRole::Viewer => write!(f, "viewer"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = crate::error::DlsError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(UserRole::Admin),
            "operator" => Ok(UserRole::Operator),
            "viewer" => Ok(UserRole::Viewer),
            _ => Err(crate::error::DlsError::Auth(format!("Invalid user role: {}", s))),
        }
    }
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
    pub auth_manager: AuthManager,
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

#[derive(Debug)]
pub struct UserService {
    auth_manager: AuthManager,
    db: std::sync::Arc<crate::database::DatabaseManager>,
}

impl UserService {
    pub fn new(auth_manager: AuthManager, db: std::sync::Arc<crate::database::DatabaseManager>) -> Self {
        Self { auth_manager, db }
    }

    pub async fn create_user(&self, username: &str, password: &str, role: UserRole, 
                            email: Option<&str>, created_by: Option<uuid::Uuid>) -> Result<uuid::Uuid> {
        let password_hash = self.auth_manager.hash_password(password)?;
        self.db.create_user(username, &password_hash, role, email, created_by).await
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<(User, String)> {
        let user_record = self.db.get_user_by_username(username).await?
            .ok_or_else(|| DlsError::Auth("Invalid credentials".to_string()))?;

        if !self.auth_manager.verify_password(password, &user_record.password_hash)? {
            return Err(DlsError::Auth("Invalid credentials".to_string()));
        }

        let user = user_record.to_user()?;
        let token = self.auth_manager.create_token(&user)?;

        // Update last login
        self.db.update_user_last_login(user.id).await?;

        Ok((user, token))
    }

    pub async fn verify_token(&self, token: &str) -> Result<User> {
        let claims = self.auth_manager.verify_token(token)?;
        
        let user_record = self.db.get_user_by_username(&claims.username).await?
            .ok_or_else(|| DlsError::Auth("User not found".to_string()))?;

        user_record.to_user()
    }

    pub async fn change_password(&self, user_id: uuid::Uuid, old_password: &str, new_password: &str) -> Result<()> {
        let user_record = self.db.get_user_by_id(user_id).await?
            .ok_or_else(|| DlsError::Auth("User not found".to_string()))?;

        if !self.auth_manager.verify_password(old_password, &user_record.password_hash)? {
            return Err(DlsError::Auth("Invalid current password".to_string()));
        }

        let new_password_hash = self.auth_manager.hash_password(new_password)?;
        self.db.update_user_password(user_id, &new_password_hash).await
    }

    pub async fn reset_password(&self, user_id: uuid::Uuid, new_password: &str) -> Result<()> {
        let new_password_hash = self.auth_manager.hash_password(new_password)?;
        self.db.update_user_password(user_id, &new_password_hash).await
    }

    pub async fn update_user_role(&self, user_id: uuid::Uuid, role: UserRole) -> Result<()> {
        self.db.update_user_role(user_id, role).await
    }

    pub async fn deactivate_user(&self, user_id: uuid::Uuid) -> Result<()> {
        self.db.deactivate_user(user_id).await
    }

    pub async fn list_users(&self, active_only: bool) -> Result<Vec<User>> {
        let user_records = self.db.list_users(active_only).await?;
        let mut users = Vec::new();
        
        for record in user_records {
            users.push(record.to_user()?);
        }
        
        Ok(users)
    }

    pub async fn get_user_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>> {
        if let Some(record) = self.db.get_user_by_id(user_id).await? {
            Ok(Some(record.to_user()?))
        } else {
            Ok(None)
        }
    }

    pub async fn create_default_admin(&self, username: &str, password: &str) -> Result<uuid::Uuid> {
        let password_hash = self.auth_manager.hash_password(password)?;
        self.db.create_default_admin(username, &password_hash).await
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: uuid::Uuid,
    pub username: String,
    pub role: UserRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<User> for UserInfo {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            role: user.role,
            created_at: user.created_at,
            last_login: user.last_login,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: UserRole,
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    pub role: UserRole,
}