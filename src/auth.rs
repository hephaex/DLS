use crate::error::{DlsError, Result};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jwt_simple::prelude::*;
use ldap3::{LdapConn, Scope, SearchEntry};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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
    Guest,
    ServiceAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticationProvider {
    Local,
    Ldap,
    ActiveDirectory,
    Saml,
    OAuth2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub server: String,
    pub port: u16,
    pub use_tls: bool,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_base_dn: String,
    pub user_filter: String,
    pub user_id_attribute: String,
    pub user_name_attribute: String,
    pub user_email_attribute: String,
    pub group_base_dn: String,
    pub group_filter: String,
    pub group_member_attribute: String,
    pub admin_groups: Vec<String>,
    pub operator_groups: Vec<String>,
    pub viewer_groups: Vec<String>,
    pub connection_timeout_secs: u64,
    pub search_timeout_secs: u64,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            server: "ldap.example.com".to_string(),
            port: 389,
            use_tls: true,
            bind_dn: "cn=dls-service,ou=service-accounts,dc=example,dc=com".to_string(),
            bind_password: "".to_string(),
            user_base_dn: "ou=users,dc=example,dc=com".to_string(),
            user_filter: "(&(objectClass=person)(sAMAccountName={username}))".to_string(),
            user_id_attribute: "sAMAccountName".to_string(),
            user_name_attribute: "displayName".to_string(),
            user_email_attribute: "mail".to_string(),
            group_base_dn: "ou=groups,dc=example,dc=com".to_string(),
            group_filter: "(&(objectClass=group)(member={user_dn}))".to_string(),
            group_member_attribute: "member".to_string(),
            admin_groups: vec!["CN=DLS-Admins,OU=Groups,DC=example,DC=com".to_string()],
            operator_groups: vec!["CN=DLS-Operators,OU=Groups,DC=example,DC=com".to_string()],
            viewer_groups: vec!["CN=DLS-Viewers,OU=Groups,DC=example,DC=com".to_string()],
            connection_timeout_secs: 30,
            search_timeout_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseAuthConfig {
    pub enabled: bool,
    pub primary_provider: AuthenticationProvider,
    pub fallback_to_local: bool,
    pub ldap: Option<LdapConfig>,
    pub session_timeout_minutes: u64,
    pub max_concurrent_sessions: u32,
    pub require_mfa: bool,
    pub password_complexity_enabled: bool,
    pub password_min_length: u32,
    pub password_require_special: bool,
    pub password_require_numbers: bool,
    pub password_require_uppercase: bool,
    pub password_require_lowercase: bool,
    pub account_lockout_enabled: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u64,
    pub audit_authentication: bool,
}

impl Default for EnterpriseAuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            primary_provider: AuthenticationProvider::Local,
            fallback_to_local: true,
            ldap: Some(LdapConfig::default()),
            session_timeout_minutes: 480,
            max_concurrent_sessions: 5,
            require_mfa: false,
            password_complexity_enabled: true,
            password_min_length: 12,
            password_require_special: true,
            password_require_numbers: true,
            password_require_uppercase: true,
            password_require_lowercase: true,
            account_lockout_enabled: true,
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
            audit_authentication: true,
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::Operator => write!(f, "operator"),
            UserRole::Viewer => write!(f, "viewer"),
            UserRole::Guest => write!(f, "guest"),
            UserRole::ServiceAccount => write!(f, "service_account"),
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
            "guest" => Ok(UserRole::Guest),
            "service_account" | "serviceaccount" => Ok(UserRole::ServiceAccount),
            _ => Err(crate::error::DlsError::Auth(format!(
                "Invalid user role: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub username: String,
    pub role: UserRole,
    pub provider: AuthenticationProvider,
    pub session_id: String,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: String,
    pub user_id: uuid::Uuid,
    pub username: String,
    pub provider: AuthenticationProvider,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationAttempt {
    pub id: uuid::Uuid,
    pub username: String,
    pub provider: AuthenticationProvider,
    pub success: bool,
    pub ip_address: String,
    pub user_agent: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLockout {
    pub username: String,
    pub locked_at: chrono::DateTime<chrono::Utc>,
    pub unlock_at: chrono::DateTime<chrono::Utc>,
    pub failed_attempts: u32,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct LdapAuthenticator {
    config: LdapConfig,
    connection_pool: Arc<RwLock<Vec<LdapConn>>>,
}

impl LdapAuthenticator {
    pub async fn new(config: LdapConfig) -> Result<Self> {
        let authenticator = Self {
            config,
            connection_pool: Arc::new(RwLock::new(Vec::new())),
        };

        // Initialize connection pool
        authenticator.ensure_connection_pool().await?;

        Ok(authenticator)
    }

    async fn ensure_connection_pool(&self) -> Result<()> {
        let mut pool = self.connection_pool.write().await;

        if pool.is_empty() {
            // Create initial connections
            for _ in 0..5 {
                if let Ok(conn) = self.create_connection().await {
                    pool.push(conn);
                }
            }
        }

        Ok(())
    }

    async fn create_connection(&self) -> Result<LdapConn> {
        let ldap_url = if self.config.use_tls {
            format!("ldaps://{}:{}", self.config.server, self.config.port)
        } else {
            format!("ldap://{}:{}", self.config.server, self.config.port)
        };

        let mut ldap = LdapConn::new(&ldap_url)
            .map_err(|e| DlsError::Auth(format!("Failed to create LDAP connection: {}", e)))?;

        // Bind with service account
        let bind_result = ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password);
        bind_result.map_err(|e| DlsError::Auth(format!("Failed to bind to LDAP: {}", e)))?;

        Ok(ldap)
    }

    async fn get_connection(&self) -> Result<LdapConn> {
        let mut pool = self.connection_pool.write().await;

        if let Some(conn) = pool.pop() {
            Ok(conn)
        } else {
            // Create new connection if pool is empty
            self.create_connection().await
        }
    }

    async fn return_connection(&self, conn: LdapConn) {
        let mut pool = self.connection_pool.write().await;
        if pool.len() < 10 {
            pool.push(conn);
        }
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(User, Vec<String>)> {
        let user_dn = self.find_user_dn(username).await?;

        // Create new connection for authentication
        let ldap_url = if self.config.use_tls {
            format!("ldaps://{}:{}", self.config.server, self.config.port)
        } else {
            format!("ldap://{}:{}", self.config.server, self.config.port)
        };

        let mut auth_ldap = LdapConn::new(&ldap_url)
            .map_err(|e| DlsError::Auth(format!("Failed to create auth LDAP connection: {}", e)))?;

        // Try to bind with user credentials
        let bind_result = auth_ldap.simple_bind(&user_dn, password);

        match bind_result {
            Ok(_) => {
                // Authentication successful, get user info and groups
                let user_info = self.get_user_info(&user_dn).await?;
                let groups = self.get_user_groups(&user_dn).await?;
                Ok((user_info, groups))
            }
            Err(_) => Err(DlsError::Auth("Invalid credentials".to_string())),
        }
    }

    async fn find_user_dn(&self, username: &str) -> Result<String> {
        let mut ldap = self.get_connection().await?;

        let filter = self.config.user_filter.replace("{username}", username);
        let search_result = ldap
            .search(
                &self.config.user_base_dn,
                Scope::Subtree,
                &filter,
                vec!["dn"],
            )
            .map_err(|e| DlsError::Auth(format!("LDAP search failed: {}", e)))?;

        let entries = search_result.0;
        self.return_connection(ldap).await;

        if entries.is_empty() {
            return Err(DlsError::Auth("User not found".to_string()));
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        Ok(entry.dn)
    }

    async fn get_user_info(&self, user_dn: &str) -> Result<User> {
        let mut ldap = self.get_connection().await?;

        let search_result = ldap
            .search(
                user_dn,
                Scope::Base,
                "(objectClass=*)",
                vec![
                    &self.config.user_id_attribute,
                    &self.config.user_name_attribute,
                    &self.config.user_email_attribute,
                ],
            )
            .map_err(|e| DlsError::Auth(format!("Failed to get user info: {}", e)))?;

        let entries = search_result.0;
        self.return_connection(ldap).await;

        if entries.is_empty() {
            return Err(DlsError::Auth("User not found".to_string()));
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());

        let username = entry
            .attrs
            .get(&self.config.user_id_attribute)
            .and_then(|v| v.first())
            .ok_or_else(|| DlsError::Auth("Missing user ID attribute".to_string()))?
            .clone();

        Ok(User {
            id: uuid::Uuid::new_v4(),
            username,
            password_hash: String::new(),
            role: UserRole::Viewer, // Will be determined by group membership
            created_at: chrono::Utc::now(),
            last_login: Some(chrono::Utc::now()),
            active: true,
        })
    }

    async fn get_user_groups(&self, user_dn: &str) -> Result<Vec<String>> {
        let mut ldap = self.get_connection().await?;

        let filter = self.config.group_filter.replace("{user_dn}", user_dn);
        let search_result = ldap
            .search(
                &self.config.group_base_dn,
                Scope::Subtree,
                &filter,
                vec!["dn", "cn"],
            )
            .map_err(|e| DlsError::Auth(format!("Failed to get user groups: {}", e)))?;

        let entries = search_result.0;
        self.return_connection(ldap).await;

        let mut groups = Vec::new();
        for entry_result in entries {
            let entry = SearchEntry::construct(entry_result);
            groups.push(entry.dn);
        }

        Ok(groups)
    }

    pub fn determine_role_from_groups(&self, groups: &[String]) -> UserRole {
        // Check admin groups first
        for admin_group in &self.config.admin_groups {
            if groups.contains(admin_group) {
                return UserRole::Admin;
            }
        }

        // Check operator groups
        for operator_group in &self.config.operator_groups {
            if groups.contains(operator_group) {
                return UserRole::Operator;
            }
        }

        // Check viewer groups
        for viewer_group in &self.config.viewer_groups {
            if groups.contains(viewer_group) {
                return UserRole::Viewer;
            }
        }

        // Default to guest if no matching groups
        UserRole::Guest
    }

    pub async fn test_connection(&self) -> Result<()> {
        let _conn = self.get_connection().await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AuthManager {
    jwt_key: HS256Key,
    token_expiry_hours: u64,
    config: EnterpriseAuthConfig,
    ldap_authenticator: Option<Arc<LdapAuthenticator>>,
    sessions: Arc<RwLock<HashMap<String, AuthSession>>>,
    failed_attempts: Arc<RwLock<HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>>>,
    locked_accounts: Arc<RwLock<HashMap<String, AccountLockout>>>,
    password_regex: Option<Regex>,
}

impl AuthManager {
    pub fn new(secret: &str, token_expiry_hours: u64) -> Self {
        let jwt_key = HS256Key::from_bytes(secret.as_bytes());
        let config = EnterpriseAuthConfig::default();

        Self {
            jwt_key,
            token_expiry_hours,
            config,
            ldap_authenticator: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            locked_accounts: Arc::new(RwLock::new(HashMap::new())),
            password_regex: None,
        }
    }

    pub async fn new_with_config(
        secret: &str,
        token_expiry_hours: u64,
        config: EnterpriseAuthConfig,
    ) -> Result<Self> {
        let jwt_key = HS256Key::from_bytes(secret.as_bytes());

        let ldap_authenticator = if let Some(ldap_config) = &config.ldap {
            Some(Arc::new(LdapAuthenticator::new(ldap_config.clone()).await?))
        } else {
            None
        };

        let password_regex = if config.password_complexity_enabled {
            let mut pattern = String::from("^");

            if config.password_require_lowercase {
                pattern.push_str("(?=.*[a-z])");
            }
            if config.password_require_uppercase {
                pattern.push_str("(?=.*[A-Z])");
            }
            if config.password_require_numbers {
                pattern.push_str("(?=.*\\d)");
            }
            if config.password_require_special {
                pattern.push_str("(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?])");
            }

            pattern.push_str(&format!(".{{{},}}$", config.password_min_length));

            Some(
                Regex::new(&pattern)
                    .map_err(|e| DlsError::Auth(format!("Invalid password regex: {}", e)))?,
            )
        } else {
            None
        };

        Ok(Self {
            jwt_key,
            token_expiry_hours,
            config,
            ldap_authenticator,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            locked_accounts: Arc::new(RwLock::new(HashMap::new())),
            password_regex,
        })
    }

    pub async fn is_account_locked(&self, username: &str) -> bool {
        let locked_accounts = self.locked_accounts.read().await;
        if let Some(lockout) = locked_accounts.get(username) {
            lockout.active && lockout.unlock_at > chrono::Utc::now()
        } else {
            false
        }
    }

    pub async fn record_failed_attempt(&self, username: &str) -> Result<()> {
        if !self.config.account_lockout_enabled {
            return Ok(());
        }

        let mut failed_attempts = self.failed_attempts.write().await;
        let now = chrono::Utc::now();
        let attempts = failed_attempts
            .entry(username.to_string())
            .or_insert_with(Vec::new);

        // Clean old attempts (older than lockout duration)
        let cutoff = now - chrono::Duration::minutes(self.config.lockout_duration_minutes as i64);
        attempts.retain(|&attempt| attempt > cutoff);

        attempts.push(now);

        if attempts.len() >= self.config.max_failed_attempts as usize {
            // Lock the account
            let mut locked_accounts = self.locked_accounts.write().await;
            locked_accounts.insert(
                username.to_string(),
                AccountLockout {
                    username: username.to_string(),
                    locked_at: now,
                    unlock_at: now
                        + chrono::Duration::minutes(self.config.lockout_duration_minutes as i64),
                    failed_attempts: attempts.len() as u32,
                    active: true,
                },
            );

            // Clear failed attempts for this user
            attempts.clear();
        }

        Ok(())
    }

    pub async fn clear_failed_attempts(&self, username: &str) {
        let mut failed_attempts = self.failed_attempts.write().await;
        failed_attempts.remove(username);
    }

    pub fn validate_password_complexity(&self, password: &str) -> Result<()> {
        if !self.config.password_complexity_enabled {
            return Ok(());
        }

        if password.len() < self.config.password_min_length as usize {
            return Err(DlsError::Auth(format!(
                "Password must be at least {} characters long",
                self.config.password_min_length
            )));
        }

        if let Some(regex) = &self.password_regex {
            if !regex.is_match(password) {
                return Err(DlsError::Auth(
                    "Password does not meet complexity requirements".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub async fn authenticate_enterprise(
        &self,
        username: &str,
        password: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(User, String)> {
        // Check if account is locked
        if self.is_account_locked(username).await {
            return Err(DlsError::Auth(
                "Account is locked due to too many failed attempts".to_string(),
            ));
        }

        let mut user: User;
        let groups = Vec::new();
        let provider: AuthenticationProvider;

        match self.config.primary_provider {
            AuthenticationProvider::Ldap | AuthenticationProvider::ActiveDirectory => {
                if let Some(ldap_auth) = &self.ldap_authenticator {
                    match ldap_auth.authenticate(username, password).await {
                        Ok((ldap_user, ldap_groups)) => {
                            user = ldap_user;
                            let _groups = ldap_groups.clone();
                            user.role = ldap_auth.determine_role_from_groups(&ldap_groups);
                            provider = self.config.primary_provider.clone();
                        }
                        Err(e) => {
                            self.record_failed_attempt(username).await?;
                            if self.config.fallback_to_local {
                                // Try local authentication
                                return self
                                    .authenticate_local(username, password, ip_address, user_agent)
                                    .await;
                            } else {
                                return Err(e);
                            }
                        }
                    }
                } else {
                    return Err(DlsError::Auth(
                        "LDAP authenticator not configured".to_string(),
                    ));
                }
            }
            _ => {
                // Default to local authentication
                return self
                    .authenticate_local(username, password, ip_address, user_agent)
                    .await;
            }
        }

        // Clear failed attempts on successful authentication
        self.clear_failed_attempts(username).await;

        // Create session
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = AuthSession {
            id: session_id.clone(),
            user_id: user.id,
            username: user.username.clone(),
            provider: provider.clone(),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            expires_at: chrono::Utc::now()
                + chrono::Duration::minutes(self.config.session_timeout_minutes as i64),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            active: true,
        };

        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        // Create token with enhanced claims
        let token = self.create_enterprise_token(&user, &session_id, &groups, &provider)?;

        Ok((user, token))
    }

    pub async fn authenticate_local(
        &self,
        _username: &str,
        _password: &str,
        _ip_address: &str,
        _user_agent: &str,
    ) -> Result<(User, String)> {
        // This is a placeholder - in real implementation, this would authenticate against local database
        Err(DlsError::Auth(
            "Local authentication not implemented".to_string(),
        ))
    }

    pub fn create_enterprise_token(
        &self,
        user: &User,
        session_id: &str,
        groups: &[String],
        provider: &AuthenticationProvider,
    ) -> Result<String> {
        let permissions = self.get_permissions_for_role(&user.role);

        let claims = Claims {
            username: user.username.clone(),
            role: user.role.clone(),
            provider: provider.clone(),
            session_id: session_id.to_string(),
            groups: groups.to_vec(),
            permissions,
        };

        let jwt_claims = JWTClaims {
            issued_at: Some(Clock::now_since_epoch()),
            expires_at: Some(
                Clock::now_since_epoch() + Duration::from_secs(self.token_expiry_hours * 3600),
            ),
            invalid_before: None,
            issuer: Some("DLS-Server".to_string()),
            subject: Some(user.id.to_string()),
            audiences: None,
            jwt_id: Some(session_id.to_string()),
            nonce: None,
            custom: claims,
        };

        self.jwt_key
            .authenticate(jwt_claims)
            .map_err(|e| DlsError::Auth(format!("Failed to create token: {}", e)))
    }

    fn get_permissions_for_role(&self, role: &UserRole) -> Vec<String> {
        match role {
            UserRole::Admin => vec![
                "system:read".to_string(),
                "system:write".to_string(),
                "system:admin".to_string(),
                "users:manage".to_string(),
                "images:manage".to_string(),
                "clients:manage".to_string(),
                "config:manage".to_string(),
            ],
            UserRole::Operator => vec![
                "system:read".to_string(),
                "system:write".to_string(),
                "images:manage".to_string(),
                "clients:manage".to_string(),
            ],
            UserRole::Viewer => vec![
                "system:read".to_string(),
                "clients:read".to_string(),
                "images:read".to_string(),
            ],
            UserRole::Guest => vec!["system:read".to_string()],
            UserRole::ServiceAccount => vec!["api:access".to_string(), "system:read".to_string()],
        }
    }

    pub async fn verify_enterprise_token(&self, token: &str) -> Result<Claims> {
        let jwt_claims = self
            .jwt_key
            .verify_token::<Claims>(token, None)
            .map_err(|e| DlsError::Auth(format!("Invalid token: {}", e)))?;

        let claims = jwt_claims.custom;

        // Verify session is still active
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&claims.session_id) {
            if !session.active || session.expires_at < chrono::Utc::now() {
                return Err(DlsError::Auth("Session expired".to_string()));
            }
        } else {
            return Err(DlsError::Auth("Session not found".to_string()));
        }

        Ok(claims)
    }

    pub async fn refresh_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = chrono::Utc::now();
            session.expires_at = chrono::Utc::now()
                + chrono::Duration::minutes(self.config.session_timeout_minutes as i64);
            Ok(())
        } else {
            Err(DlsError::Auth("Session not found".to_string()))
        }
    }

    pub async fn invalidate_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.active = false;
            Ok(())
        } else {
            Err(DlsError::Auth("Session not found".to_string()))
        }
    }

    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        sessions.retain(|_, session| session.active && session.expires_at > now);
    }

    pub async fn get_active_sessions_for_user(&self, username: &str) -> Vec<AuthSession> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|session| {
                session.username == username
                    && session.active
                    && session.expires_at > chrono::Utc::now()
            })
            .cloned()
            .collect()
    }

    pub async fn test_ldap_connection(&self) -> Result<()> {
        if let Some(ldap_auth) = &self.ldap_authenticator {
            ldap_auth.test_connection().await
        } else {
            Err(DlsError::Auth(
                "LDAP authenticator not configured".to_string(),
            ))
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<String> {
        // Validate password complexity first
        self.validate_password_complexity(password)?;

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

    // Legacy create_token method for backward compatibility
    pub fn create_token(&self, user: &User) -> Result<String> {
        let claims = Claims {
            username: user.username.clone(),
            role: user.role.clone(),
            provider: AuthenticationProvider::Local,
            session_id: String::new(),
            groups: Vec::new(),
            permissions: self.get_permissions_for_role(&user.role),
        };

        let jwt_claims = JWTClaims {
            issued_at: Some(Clock::now_since_epoch()),
            expires_at: Some(
                Clock::now_since_epoch() + Duration::from_secs(self.token_expiry_hours * 3600),
            ),
            invalid_before: None,
            issuer: Some("DLS-Server".to_string()),
            subject: Some(user.id.to_string()),
            audiences: None,
            jwt_id: None,
            nonce: None,
            custom: claims,
        };

        self.jwt_key
            .authenticate(jwt_claims)
            .map_err(|e| DlsError::Auth(format!("Failed to create token: {}", e)))
    }

    // Legacy verify_token method for backward compatibility
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let jwt_claims = self
            .jwt_key
            .verify_token::<Claims>(token, None)
            .map_err(|e| DlsError::Auth(format!("Invalid token: {}", e)))?;

        Ok(jwt_claims.custom)
    }

    pub async fn refresh_token(&self, token: &str) -> Result<String> {
        let claims = self.verify_token(token)?;

        // Refresh the session if session_id is present
        if !claims.session_id.is_empty() {
            self.refresh_session(&claims.session_id).await?;
        }

        let user = User {
            id: uuid::Uuid::new_v4(),
            username: claims.username,
            password_hash: String::new(),
            role: claims.role,
            created_at: chrono::Utc::now(),
            last_login: None,
            active: true,
        };

        self.create_enterprise_token(&user, &claims.session_id, &claims.groups, &claims.provider)
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
            return Err(DlsError::Auth(
                "Invalid authorization header format".to_string(),
            ));
        }

        let token = &auth_header[7..];
        self.auth_manager.verify_token(token)
    }

    pub async fn verify_enterprise_request(&self, auth_header: Option<&str>) -> Result<Claims> {
        let auth_header = auth_header
            .ok_or_else(|| DlsError::Auth("Missing authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(DlsError::Auth(
                "Invalid authorization header format".to_string(),
            ));
        }

        let token = &auth_header[7..];
        self.auth_manager.verify_enterprise_token(token).await
    }

    pub fn require_role(&self, claims: &Claims, required_role: &UserRole) -> Result<()> {
        match (&claims.role, required_role) {
            (UserRole::Admin, _) => Ok(()),
            (UserRole::Operator, UserRole::Operator) => Ok(()),
            (UserRole::Operator, UserRole::Viewer) => Ok(()),
            (UserRole::Operator, UserRole::Guest) => Ok(()),
            (UserRole::Viewer, UserRole::Viewer) => Ok(()),
            (UserRole::Viewer, UserRole::Guest) => Ok(()),
            (UserRole::Guest, UserRole::Guest) => Ok(()),
            (UserRole::ServiceAccount, UserRole::ServiceAccount) => Ok(()),
            _ => Err(DlsError::Auth("Insufficient permissions".to_string())),
        }
    }

    pub fn require_permission(&self, claims: &Claims, required_permission: &str) -> Result<()> {
        if claims
            .permissions
            .contains(&required_permission.to_string())
        {
            Ok(())
        } else {
            Err(DlsError::Auth(format!(
                "Missing required permission: {}",
                required_permission
            )))
        }
    }

    pub fn require_group_membership(&self, claims: &Claims, required_group: &str) -> Result<()> {
        if claims
            .groups
            .iter()
            .any(|group| group.contains(required_group))
        {
            Ok(())
        } else {
            Err(DlsError::Auth(format!(
                "Missing required group membership: {}",
                required_group
            )))
        }
    }
}

#[derive(Debug)]
pub struct UserService {
    auth_manager: AuthManager,
    db: std::sync::Arc<crate::database::DatabaseManager>,
}

impl UserService {
    pub fn new(
        auth_manager: AuthManager,
        db: std::sync::Arc<crate::database::DatabaseManager>,
    ) -> Self {
        Self { auth_manager, db }
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: UserRole,
        email: Option<&str>,
        created_by: Option<uuid::Uuid>,
    ) -> Result<uuid::Uuid> {
        let password_hash = self.auth_manager.hash_password(password)?;
        self.db
            .create_user(username, &password_hash, role, email, created_by)
            .await
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(User, String)> {
        // Try enterprise authentication first
        match self
            .auth_manager
            .authenticate_enterprise(username, password, ip_address, user_agent)
            .await
        {
            Ok(result) => {
                // Update last login
                self.db.update_user_last_login(result.0.id).await?;
                Ok(result)
            }
            Err(_) => {
                // Fallback to legacy authentication
                let user_record = self
                    .db
                    .get_user_by_username(username)
                    .await?
                    .ok_or_else(|| DlsError::Auth("Invalid credentials".to_string()))?;

                if !self
                    .auth_manager
                    .verify_password(password, &user_record.password_hash)?
                {
                    return Err(DlsError::Auth("Invalid credentials".to_string()));
                }

                let user = user_record.to_user()?;
                let token = self.auth_manager.create_token(&user)?;

                // Update last login
                self.db.update_user_last_login(user.id).await?;

                Ok((user, token))
            }
        }
    }

    pub async fn verify_token(&self, token: &str) -> Result<User> {
        let claims = self.auth_manager.verify_token(token)?;

        let user_record = self
            .db
            .get_user_by_username(&claims.username)
            .await?
            .ok_or_else(|| DlsError::Auth("User not found".to_string()))?;

        user_record.to_user()
    }

    pub async fn change_password(
        &self,
        user_id: uuid::Uuid,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let user_record = self
            .db
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| DlsError::Auth("User not found".to_string()))?;

        if !self
            .auth_manager
            .verify_password(old_password, &user_record.password_hash)?
        {
            return Err(DlsError::Auth("Invalid current password".to_string()));
        }

        let new_password_hash = self.auth_manager.hash_password(new_password)?;
        self.db
            .update_user_password(user_id, &new_password_hash)
            .await
    }

    pub async fn reset_password(&self, user_id: uuid::Uuid, new_password: &str) -> Result<()> {
        let new_password_hash = self.auth_manager.hash_password(new_password)?;
        self.db
            .update_user_password(user_id, &new_password_hash)
            .await
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

#[derive(Debug, Serialize, Deserialize)]
pub struct EnterpriseLoginRequest {
    pub username: String,
    pub password: String,
    pub provider: Option<AuthenticationProvider>,
    pub mfa_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnterpriseLoginResponse {
    pub token: String,
    pub user: EnterpriseUserInfo,
    pub session_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub permissions: Vec<String>,
    pub groups: Vec<String>,
    pub provider: AuthenticationProvider,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnterpriseUserInfo {
    pub id: uuid::Uuid,
    pub username: String,
    pub role: UserRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub provider: AuthenticationProvider,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: uuid::Uuid,
    pub username: String,
    pub provider: AuthenticationProvider,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub active: bool,
}

impl From<AuthSession> for SessionInfo {
    fn from(session: AuthSession) -> Self {
        Self {
            id: session.id,
            user_id: session.user_id,
            username: session.username,
            provider: session.provider,
            created_at: session.created_at,
            last_activity: session.last_activity,
            expires_at: session.expires_at,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            active: session.active,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LdapConfigRequest {
    pub server: String,
    pub port: u16,
    pub use_tls: bool,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_base_dn: String,
    pub user_filter: String,
    pub group_base_dn: String,
    pub group_filter: String,
    pub admin_groups: Vec<String>,
    pub operator_groups: Vec<String>,
    pub viewer_groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LdapTestResult {
    pub success: bool,
    pub message: String,
    pub connection_time_ms: u64,
    pub user_count: Option<u32>,
    pub group_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationAuditLog {
    pub id: uuid::Uuid,
    pub username: String,
    pub provider: AuthenticationProvider,
    pub success: bool,
    pub ip_address: String,
    pub user_agent: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub failure_reason: Option<String>,
    pub session_id: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountLockoutInfo {
    pub username: String,
    pub locked_at: chrono::DateTime<chrono::Utc>,
    pub unlock_at: chrono::DateTime<chrono::Utc>,
    pub failed_attempts: u32,
    pub active: bool,
    pub remaining_lockout_minutes: i64,
}

impl From<AccountLockout> for AccountLockoutInfo {
    fn from(lockout: AccountLockout) -> Self {
        let remaining_minutes = (lockout.unlock_at - chrono::Utc::now()).num_minutes();
        Self {
            username: lockout.username,
            locked_at: lockout.locked_at,
            unlock_at: lockout.unlock_at,
            failed_attempts: lockout.failed_attempts,
            active: lockout.active,
            remaining_lockout_minutes: remaining_minutes.max(0),
        }
    }
}

// Enterprise authentication service for managing authentication flows
#[derive(Debug)]
pub struct EnterpriseAuthService {
    auth_manager: Arc<AuthManager>,
    db: Option<Arc<crate::database::DatabaseManager>>,
    audit_enabled: bool,
}

impl EnterpriseAuthService {
    pub fn new(auth_manager: Arc<AuthManager>) -> Self {
        Self {
            auth_manager,
            db: None,
            audit_enabled: true,
        }
    }

    pub fn with_database(mut self, db: Arc<crate::database::DatabaseManager>) -> Self {
        self.db = Some(db);
        self
    }

    pub async fn authenticate(
        &self,
        request: EnterpriseLoginRequest,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<EnterpriseLoginResponse> {
        let start_time = std::time::Instant::now();

        let result = self
            .auth_manager
            .authenticate_enterprise(&request.username, &request.password, ip_address, user_agent)
            .await;

        let _elapsed = start_time.elapsed();

        match result {
            Ok((user, token)) => {
                // Get claims from token to extract additional info
                let claims = self.auth_manager.verify_token(&token)?;

                let response = EnterpriseLoginResponse {
                    token,
                    session_id: claims.session_id.clone(),
                    expires_at: chrono::Utc::now() + chrono::Duration::minutes(480), // 8 hours default
                    permissions: claims.permissions.clone(),
                    groups: claims.groups.clone(),
                    provider: claims.provider.clone(),
                    user: EnterpriseUserInfo {
                        id: user.id,
                        username: user.username.clone(),
                        role: user.role.clone(),
                        created_at: user.created_at,
                        last_login: user.last_login,
                        provider: claims.provider.clone(),
                        groups: claims.groups.clone(),
                        permissions: claims.permissions,
                    },
                };

                // Audit successful authentication
                if self.audit_enabled {
                    self.audit_authentication(
                        &request.username,
                        &claims.provider,
                        true,
                        ip_address,
                        user_agent,
                        None,
                        &Some(claims.session_id.clone()),
                        &claims.groups,
                    )
                    .await;
                }

                Ok(response)
            }
            Err(e) => {
                // Audit failed authentication
                if self.audit_enabled {
                    let provider = request.provider.unwrap_or(AuthenticationProvider::Local);
                    self.audit_authentication(
                        &request.username,
                        &provider,
                        false,
                        ip_address,
                        user_agent,
                        Some(e.to_string()),
                        &None,
                        &Vec::new(),
                    )
                    .await;
                }
                Err(e)
            }
        }
    }

    pub async fn get_active_sessions(&self, username: &str) -> Result<Vec<SessionInfo>> {
        let sessions = self
            .auth_manager
            .get_active_sessions_for_user(username)
            .await;
        Ok(sessions.into_iter().map(SessionInfo::from).collect())
    }

    pub async fn invalidate_session(&self, session_id: &str) -> Result<()> {
        self.auth_manager.invalidate_session(session_id).await
    }

    pub async fn test_ldap_configuration(
        &self,
        config: LdapConfigRequest,
    ) -> Result<LdapTestResult> {
        let ldap_config = LdapConfig {
            server: config.server,
            port: config.port,
            use_tls: config.use_tls,
            bind_dn: config.bind_dn,
            bind_password: config.bind_password,
            user_base_dn: config.user_base_dn,
            user_filter: config.user_filter,
            user_id_attribute: "sAMAccountName".to_string(),
            user_name_attribute: "displayName".to_string(),
            user_email_attribute: "mail".to_string(),
            group_base_dn: config.group_base_dn,
            group_filter: config.group_filter,
            group_member_attribute: "member".to_string(),
            admin_groups: config.admin_groups,
            operator_groups: config.operator_groups,
            viewer_groups: config.viewer_groups,
            connection_timeout_secs: 30,
            search_timeout_secs: 10,
        };

        let start_time = std::time::Instant::now();

        match LdapAuthenticator::new(ldap_config).await {
            Ok(authenticator) => match authenticator.test_connection().await {
                Ok(_) => {
                    let elapsed = start_time.elapsed();
                    Ok(LdapTestResult {
                        success: true,
                        message: "LDAP connection successful".to_string(),
                        connection_time_ms: elapsed.as_millis() as u64,
                        user_count: None,
                        group_count: None,
                    })
                }
                Err(e) => Ok(LdapTestResult {
                    success: false,
                    message: format!("LDAP connection failed: {}", e),
                    connection_time_ms: start_time.elapsed().as_millis() as u64,
                    user_count: None,
                    group_count: None,
                }),
            },
            Err(e) => Ok(LdapTestResult {
                success: false,
                message: format!("Failed to create LDAP authenticator: {}", e),
                connection_time_ms: start_time.elapsed().as_millis() as u64,
                user_count: None,
                group_count: None,
            }),
        }
    }

    async fn audit_authentication(
        &self,
        username: &str,
        provider: &AuthenticationProvider,
        success: bool,
        ip_address: &str,
        user_agent: &str,
        failure_reason: Option<String>,
        session_id: &Option<String>,
        groups: &[String],
    ) {
        let _audit_entry = AuthenticationAuditLog {
            id: uuid::Uuid::new_v4(),
            username: username.to_string(),
            provider: provider.clone(),
            success,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            timestamp: chrono::Utc::now(),
            failure_reason,
            session_id: session_id.clone(),
            groups: groups.to_vec(),
        };

        // In a real implementation, this would be stored in the database
        tracing::info!(
            username = username,
            provider = ?provider,
            success = success,
            ip_address = ip_address,
            "Authentication attempt"
        );
    }
}
