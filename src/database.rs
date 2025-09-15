use crate::auth::{User, UserRole};
use crate::error::{DlsError, Result};
use crate::storage::{DiskImage, ImageFormat};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::FromRow;
use tracing::{debug, info};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DatabaseManager {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub active: bool,
    pub created_by: Option<Uuid>,
}

impl UserRecord {
    pub fn get_role(&self) -> Result<UserRole> {
        self.role.parse()
    }
    
    pub fn set_role(&mut self, role: UserRole) {
        self.role = role.to_string();
    }
    
    pub fn to_user(&self) -> Result<User> {
        Ok(User {
            id: self.id,
            username: self.username.clone(),
            password_hash: self.password_hash.clone(),
            role: self.get_role()?,
            created_at: self.created_at,
            last_login: self.last_login,
            active: self.active,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ImageMetadata {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub os_type: Option<String>,
    pub size_bytes: i64,
    pub format: String,
    pub path: String,
    pub zfs_dataset: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub tags: Option<serde_json::Value>,
    pub is_template: bool,
    pub parent_image_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ClientConfiguration {
    pub id: Uuid,
    pub mac_address: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub assigned_image_id: Option<Uuid>,
    pub boot_mode: String, // Store as string in database
    pub cpu_cores: i32,
    pub memory_mb: i32,
    pub network_config: Option<serde_json::Value>,
    pub custom_boot_params: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_boot_at: Option<DateTime<Utc>>,
    pub boot_count: i64,
}

impl ClientConfiguration {
    pub fn get_boot_mode(&self) -> Result<BootMode> {
        self.boot_mode.parse()
    }
    
    pub fn set_boot_mode(&mut self, mode: BootMode) {
        self.boot_mode = mode.to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BootMode {
    PXE,
    UEFI,
    Legacy,
}

impl std::fmt::Display for BootMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootMode::PXE => write!(f, "pxe"),
            BootMode::UEFI => write!(f, "uefi"),
            BootMode::Legacy => write!(f, "legacy"),
        }
    }
}

impl std::str::FromStr for BootMode {
    type Err = DlsError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pxe" => Ok(BootMode::PXE),
            "uefi" => Ok(BootMode::UEFI),
            "legacy" => Ok(BootMode::Legacy),
            _ => Err(DlsError::Database(format!("Invalid boot mode: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BootSession {
    pub id: Uuid,
    pub client_id: Uuid,
    pub image_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: String, // Store as string in database
    pub boot_time_seconds: Option<i32>,
    pub error_message: Option<String>,
    pub client_ip: Option<String>,
    pub boot_server_ip: Option<String>,
}

impl BootSession {
    pub fn get_status(&self) -> Result<SessionStatus> {
        self.status.parse()
    }
    
    pub fn set_status(&mut self, status: SessionStatus) {
        self.status = status.to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Starting,
    Booting,
    Running,
    Shutdown,
    Error,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Starting => write!(f, "starting"),
            SessionStatus::Booting => write!(f, "booting"),
            SessionStatus::Running => write!(f, "running"),
            SessionStatus::Shutdown => write!(f, "shutdown"),
            SessionStatus::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for SessionStatus {
    type Err = DlsError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "starting" => Ok(SessionStatus::Starting),
            "booting" => Ok(SessionStatus::Booting),
            "running" => Ok(SessionStatus::Running),
            "shutdown" => Ok(SessionStatus::Shutdown),
            "error" => Ok(SessionStatus::Error),
            _ => Err(DlsError::Database(format!("Invalid session status: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ImageSnapshot {
    pub id: Uuid,
    pub image_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub zfs_snapshot_name: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NetworkRange {
    pub id: Uuid,
    pub name: String,
    pub network_address: String,
    pub subnet_mask: String,
    pub gateway: String,
    pub dns_servers: Option<serde_json::Value>,
    pub dhcp_range_start: String,
    pub dhcp_range_end: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DatabaseManager {
    pub async fn new(database_url: &str) -> Result<Self> {
        info!("Connecting to database: {}", database_url.split('@').last().unwrap_or("****"));
        
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .connect(database_url)
            .await
            .map_err(|e| DlsError::Database(format!("Failed to connect to database: {}", e)))?;

        let db = Self { pool };
        db.run_migrations().await?;
        
        info!("Database connection established and migrations completed");
        Ok(db)
    }

    pub async fn run_migrations(&self) -> Result<()> {
        info!("Running database migrations");
        
        // Enable UUID extension
        sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
            .execute(&self.pool)
            .await
            .map_err(|e| DlsError::Database(format!("Failed to enable UUID extension: {}", e)))?;

        // Create users table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'operator', 'viewer')),
                email VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_by UUID REFERENCES users(id) ON DELETE SET NULL,
                CONSTRAINT username_length CHECK (char_length(username) >= 3),
                CONSTRAINT email_format CHECK (email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' OR email IS NULL)
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create users table: {}", e)))?;

        // Create images table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS images (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                name VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                os_type VARCHAR(100),
                size_bytes BIGINT NOT NULL,
                format VARCHAR(20) NOT NULL CHECK (format IN ('raw', 'qcow2', 'vhdx')),
                path TEXT NOT NULL,
                zfs_dataset VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_by UUID,
                tags JSONB,
                is_template BOOLEAN NOT NULL DEFAULT FALSE,
                parent_image_id UUID REFERENCES images(id) ON DELETE SET NULL,
                CONSTRAINT valid_size CHECK (size_bytes > 0)
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create images table: {}", e)))?;

        // Create clients table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS clients (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                mac_address VARCHAR(17) NOT NULL UNIQUE,
                hostname VARCHAR(255) NOT NULL,
                ip_address INET,
                assigned_image_id UUID REFERENCES images(id) ON DELETE SET NULL,
                boot_mode VARCHAR(10) NOT NULL DEFAULT 'pxe' CHECK (boot_mode IN ('pxe', 'uefi', 'legacy')),
                cpu_cores INTEGER NOT NULL DEFAULT 2 CHECK (cpu_cores > 0),
                memory_mb INTEGER NOT NULL DEFAULT 2048 CHECK (memory_mb > 0),
                network_config JSONB,
                custom_boot_params TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_boot_at TIMESTAMPTZ,
                boot_count BIGINT NOT NULL DEFAULT 0
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create clients table: {}", e)))?;

        // Create boot_sessions table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS boot_sessions (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                image_id UUID NOT NULL REFERENCES images(id) ON DELETE CASCADE,
                started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ended_at TIMESTAMPTZ,
                status VARCHAR(10) NOT NULL DEFAULT 'starting' CHECK (status IN ('starting', 'booting', 'running', 'shutdown', 'error')),
                boot_time_seconds INTEGER CHECK (boot_time_seconds >= 0),
                error_message TEXT,
                client_ip INET,
                boot_server_ip INET
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create boot_sessions table: {}", e)))?;

        // Create image_snapshots table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS image_snapshots (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                image_id UUID NOT NULL REFERENCES images(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                zfs_snapshot_name VARCHAR(500) NOT NULL,
                size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_by UUID,
                UNIQUE(image_id, name)
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create image_snapshots table: {}", e)))?;

        // Create network_ranges table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS network_ranges (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                name VARCHAR(255) NOT NULL UNIQUE,
                network_address INET NOT NULL,
                subnet_mask INET NOT NULL,
                gateway INET NOT NULL,
                dns_servers JSONB,
                dhcp_range_start INET NOT NULL,
                dhcp_range_end INET NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create network_ranges table: {}", e)))?;

        // Create indexes for performance
        let indexes = vec![
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)",
            "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)",
            "CREATE INDEX IF NOT EXISTS idx_images_name ON images(name)",
            "CREATE INDEX IF NOT EXISTS idx_images_os_type ON images(os_type)",
            "CREATE INDEX IF NOT EXISTS idx_images_is_template ON images(is_template)",
            "CREATE INDEX IF NOT EXISTS idx_clients_mac_address ON clients(mac_address)",
            "CREATE INDEX IF NOT EXISTS idx_clients_hostname ON clients(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_clients_enabled ON clients(enabled)",
            "CREATE INDEX IF NOT EXISTS idx_boot_sessions_client_id ON boot_sessions(client_id)",
            "CREATE INDEX IF NOT EXISTS idx_boot_sessions_started_at ON boot_sessions(started_at)",
            "CREATE INDEX IF NOT EXISTS idx_boot_sessions_status ON boot_sessions(status)",
            "CREATE INDEX IF NOT EXISTS idx_image_snapshots_image_id ON image_snapshots(image_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_ranges_enabled ON network_ranges(enabled)",
        ];

        for index_sql in indexes {
            sqlx::query(index_sql)
                .execute(&self.pool)
                .await
                .map_err(|e| DlsError::Database(format!("Failed to create index: {}", e)))?;
        }

        // Create triggers for updated_at columns
        let trigger_functions = vec![
            r#"
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = NOW();
                RETURN NEW;
            END;
            $$ language 'plpgsql';
            "#,
        ];

        let triggers = vec![
            "CREATE TRIGGER update_images_updated_at BEFORE UPDATE ON images FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()",
            "CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()",
            "CREATE TRIGGER update_network_ranges_updated_at BEFORE UPDATE ON network_ranges FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()",
        ];

        for function_sql in trigger_functions {
            sqlx::query(function_sql)
                .execute(&self.pool)
                .await
                .map_err(|e| DlsError::Database(format!("Failed to create trigger function: {}", e)))?;
        }

        for trigger_sql in triggers {
            sqlx::query(&format!("DROP TRIGGER IF EXISTS {} ON {}", 
                trigger_sql.split_whitespace().nth(2).unwrap(),
                trigger_sql.split_whitespace().nth(5).unwrap()))
                .execute(&self.pool)
                .await
                .ok(); // Ignore errors for non-existent triggers

            sqlx::query(trigger_sql)
                .execute(&self.pool)
                .await
                .map_err(|e| DlsError::Database(format!("Failed to create trigger: {}", e)))?;
        }

        info!("Database migrations completed successfully");
        Ok(())
    }

    // Image metadata operations
    pub async fn save_image_metadata(&self, image: &DiskImage) -> Result<()> {
        debug!("Saving image metadata for: {}", image.id);
        
        sqlx::query(r#"
            INSERT INTO images (id, name, description, os_type, size_bytes, format, path, zfs_dataset, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                os_type = EXCLUDED.os_type,
                size_bytes = EXCLUDED.size_bytes,
                format = EXCLUDED.format,
                path = EXCLUDED.path,
                zfs_dataset = EXCLUDED.zfs_dataset,
                updated_at = NOW()
        "#)
        .bind(image.id)
        .bind(&image.name)
        .bind(&image.description)
        .bind(&image.os_type)
        .bind(image.size_bytes as i64)
        .bind(&format!("{:?}", image.format).to_lowercase())
        .bind(&image.path)
        .bind(format!("images/{}", image.id))
        .bind(image.created_at)
        .bind(image.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to save image metadata: {}", e)))?;

        debug!("Successfully saved image metadata for: {}", image.id);
        Ok(())
    }

    pub async fn get_image_metadata(&self, id: Uuid) -> Result<Option<ImageMetadata>> {
        debug!("Getting image metadata for: {}", id);
        
        let result = sqlx::query_as::<_, ImageMetadata>(
            "SELECT * FROM images WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to get image metadata: {}", e)))?;

        Ok(result)
    }

    pub async fn list_images(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<ImageMetadata>> {
        debug!("Listing images with limit: {:?}, offset: {:?}", limit, offset);
        
        let images = sqlx::query_as::<_, ImageMetadata>(r#"
            SELECT * FROM images 
            ORDER BY created_at DESC 
            LIMIT $1 OFFSET $2
        "#)
        .bind(limit.unwrap_or(100))
        .bind(offset.unwrap_or(0))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to list images: {}", e)))?;

        debug!("Retrieved {} images", images.len());
        Ok(images)
    }

    pub async fn delete_image_metadata(&self, id: Uuid) -> Result<()> {
        debug!("Deleting image metadata for: {}", id);
        
        let result = sqlx::query("DELETE FROM images WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| DlsError::Database(format!("Failed to delete image metadata: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(DlsError::Database(format!("Image not found: {}", id)));
        }

        debug!("Successfully deleted image metadata for: {}", id);
        Ok(())
    }

    // Client configuration operations
    pub async fn save_client_config(&self, client_id: Uuid, mac_address: &str, hostname: &str, 
                                    ip_address: Option<&str>, assigned_image_id: Option<Uuid>, 
                                    boot_mode: BootMode, cpu_cores: i32, memory_mb: i32,
                                    network_config: Option<&serde_json::Value>, 
                                    custom_boot_params: Option<&str>, enabled: bool) -> Result<()> {
        debug!("Saving client configuration for: {}", mac_address);
        
        sqlx::query(r#"
            INSERT INTO clients (id, mac_address, hostname, ip_address, assigned_image_id, boot_mode, 
                               cpu_cores, memory_mb, network_config, custom_boot_params, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                mac_address = EXCLUDED.mac_address,
                hostname = EXCLUDED.hostname,
                ip_address = EXCLUDED.ip_address,
                assigned_image_id = EXCLUDED.assigned_image_id,
                boot_mode = EXCLUDED.boot_mode,
                cpu_cores = EXCLUDED.cpu_cores,
                memory_mb = EXCLUDED.memory_mb,
                network_config = EXCLUDED.network_config,
                custom_boot_params = EXCLUDED.custom_boot_params,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
        "#)
        .bind(client_id)
        .bind(mac_address)
        .bind(hostname)
        .bind(ip_address)
        .bind(assigned_image_id)
        .bind(boot_mode.to_string())
        .bind(cpu_cores)
        .bind(memory_mb)
        .bind(network_config)
        .bind(custom_boot_params)
        .bind(enabled)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to save client configuration: {}", e)))?;

        debug!("Successfully saved client configuration for: {}", mac_address);
        Ok(())
    }

    pub async fn get_client_by_mac(&self, mac_address: &str) -> Result<Option<ClientConfiguration>> {
        debug!("Getting client configuration for MAC: {}", mac_address);
        
        let client = sqlx::query_as::<_, ClientConfiguration>(
            "SELECT * FROM clients WHERE mac_address = $1"
        )
        .bind(mac_address)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to get client configuration: {}", e)))?;

        Ok(client)
    }

    pub async fn list_clients(&self, enabled_only: bool) -> Result<Vec<ClientConfiguration>> {
        debug!("Listing clients (enabled_only: {})", enabled_only);
        
        let query = if enabled_only {
            "SELECT * FROM clients WHERE enabled = true ORDER BY hostname"
        } else {
            "SELECT * FROM clients ORDER BY hostname"
        };

        let clients = sqlx::query_as::<_, ClientConfiguration>(query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DlsError::Database(format!("Failed to list clients: {}", e)))?;

        debug!("Retrieved {} clients", clients.len());
        Ok(clients)
    }

    // Boot session tracking
    pub async fn create_boot_session(&self, client_id: Uuid, image_id: Uuid, client_ip: Option<String>, boot_server_ip: Option<String>) -> Result<Uuid> {
        debug!("Creating boot session for client: {}, image: {}", client_id, image_id);
        
        let session_id = Uuid::new_v4();
        
        sqlx::query(r#"
            INSERT INTO boot_sessions (id, client_id, image_id, client_ip, boot_server_ip)
            VALUES ($1, $2, $3, $4, $5)
        "#)
        .bind(session_id)
        .bind(client_id)
        .bind(image_id)
        .bind(&client_ip)
        .bind(&boot_server_ip)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create boot session: {}", e)))?;

        // Update client boot count and last boot time
        sqlx::query(r#"
            UPDATE clients 
            SET boot_count = boot_count + 1, last_boot_at = NOW(), updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to update client boot stats: {}", e)))?;

        debug!("Successfully created boot session: {}", session_id);
        Ok(session_id)
    }

    pub async fn update_boot_session_status(&self, session_id: Uuid, status: SessionStatus, error_message: Option<String>) -> Result<()> {
        debug!("Updating boot session {} status to: {:?}", session_id, status);
        
        let ended_at = matches!(status, SessionStatus::Shutdown | SessionStatus::Error)
            .then(|| Utc::now());

        sqlx::query(r#"
            UPDATE boot_sessions 
            SET status = $2, error_message = $3, ended_at = $4
            WHERE id = $1
        "#)
        .bind(session_id)
        .bind(status.to_string())
        .bind(&error_message)
        .bind(ended_at)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to update boot session status: {}", e)))?;

        debug!("Successfully updated boot session status");
        Ok(())
    }

    pub async fn get_active_sessions(&self) -> Result<Vec<BootSession>> {
        debug!("Getting active boot sessions");
        
        let sessions = sqlx::query_as::<_, BootSession>(r#"
            SELECT * FROM boot_sessions 
            WHERE status IN ('starting', 'booting', 'running')
            ORDER BY started_at DESC
        "#)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to get active sessions: {}", e)))?;

        debug!("Retrieved {} active sessions", sessions.len());
        Ok(sessions)
    }

    // User management operations
    pub async fn create_user(&self, username: &str, password_hash: &str, role: UserRole, 
                             email: Option<&str>, created_by: Option<Uuid>) -> Result<Uuid> {
        debug!("Creating user: {}", username);
        
        let user_id = Uuid::new_v4();
        
        sqlx::query(r#"
            INSERT INTO users (id, username, password_hash, role, email, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
        "#)
        .bind(user_id)
        .bind(username)
        .bind(password_hash)
        .bind(role.to_string())
        .bind(email)
        .bind(created_by)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to create user: {}", e)))?;

        debug!("Successfully created user: {} with ID: {}", username, user_id);
        Ok(user_id)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<UserRecord>> {
        debug!("Getting user by username: {}", username);
        
        let user = sqlx::query_as::<_, UserRecord>(
            "SELECT * FROM users WHERE username = $1 AND active = true"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to get user by username: {}", e)))?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>> {
        debug!("Getting user by ID: {}", user_id);
        
        let user = sqlx::query_as::<_, UserRecord>(
            "SELECT * FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to get user by ID: {}", e)))?;

        Ok(user)
    }

    pub async fn list_users(&self, active_only: bool) -> Result<Vec<UserRecord>> {
        debug!("Listing users (active_only: {})", active_only);
        
        let query = if active_only {
            "SELECT * FROM users WHERE active = true ORDER BY username"
        } else {
            "SELECT * FROM users ORDER BY username"
        };

        let users = sqlx::query_as::<_, UserRecord>(query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DlsError::Database(format!("Failed to list users: {}", e)))?;

        debug!("Retrieved {} users", users.len());
        Ok(users)
    }

    pub async fn update_user_password(&self, user_id: Uuid, password_hash: &str) -> Result<()> {
        debug!("Updating password for user: {}", user_id);
        
        let result = sqlx::query(r#"
            UPDATE users 
            SET password_hash = $2, updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(user_id)
        .bind(password_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to update user password: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(DlsError::Database(format!("User not found: {}", user_id)));
        }

        debug!("Successfully updated password for user: {}", user_id);
        Ok(())
    }

    pub async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<()> {
        debug!("Updating role for user: {} to {:?}", user_id, role);
        
        let result = sqlx::query(r#"
            UPDATE users 
            SET role = $2, updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(user_id)
        .bind(role.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to update user role: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(DlsError::Database(format!("User not found: {}", user_id)));
        }

        debug!("Successfully updated role for user: {}", user_id);
        Ok(())
    }

    pub async fn update_user_last_login(&self, user_id: Uuid) -> Result<()> {
        debug!("Updating last login for user: {}", user_id);
        
        sqlx::query(r#"
            UPDATE users 
            SET last_login = NOW(), updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to update user last login: {}", e)))?;

        debug!("Successfully updated last login for user: {}", user_id);
        Ok(())
    }

    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<()> {
        debug!("Deactivating user: {}", user_id);
        
        let result = sqlx::query(r#"
            UPDATE users 
            SET active = false, updated_at = NOW()
            WHERE id = $1
        "#)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to deactivate user: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(DlsError::Database(format!("User not found: {}", user_id)));
        }

        debug!("Successfully deactivated user: {}", user_id);
        Ok(())
    }

    pub async fn create_default_admin(&self, username: &str, password_hash: &str) -> Result<Uuid> {
        info!("Creating default admin user: {}", username);
        
        // Check if any admin users exist
        let admin_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = true"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DlsError::Database(format!("Failed to check admin users: {}", e)))?;

        if admin_count.0 > 0 {
            return Err(DlsError::Database("Admin user already exists".to_string()));
        }

        self.create_user(username, password_hash, UserRole::Admin, None, None).await
    }

    pub async fn health_check(&self) -> Result<()> {
        debug!("Performing database health check");
        
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| DlsError::Database(format!("Database health check failed: {}", e)))?;

        debug!("Database health check passed");
        Ok(())
    }
}

impl From<ImageFormat> for String {
    fn from(format: ImageFormat) -> Self {
        match format {
            ImageFormat::Raw => "raw".to_string(),
            ImageFormat::Qcow2 => "qcow2".to_string(),
            ImageFormat::Vhdx => "vhdx".to_string(),
        }
    }
}