use thiserror::Error;

#[derive(Error, Debug)]
pub enum DlsError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Authentication error: {0}")]
    Auth(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    
    #[error("Command failed: {0}")]
    CommandFailed(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Report generation in progress")]
    ReportGenerationInProgress,
    
    #[error("Report not found: {0}")]
    ReportNotFound(String),
    
    #[error("Invalid report format: {0}")]
    InvalidReportFormat(String),
    
    #[error("Compliance error: {0}")]
    Compliance(String),
    
    #[error("Audit trail error: {0}")]
    AuditTrail(String),
    
    #[error("Access denied: {0}")]
    AccessDenied(String),
    
    #[error("Tenant error: {0}")]
    TenantError(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, DlsError>;
pub type Error = DlsError;