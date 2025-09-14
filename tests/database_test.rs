mod common;

use dls_server::database::{BootMode, SessionStatus};
use std::str::FromStr;

#[tokio::test]
async fn test_boot_mode_serialization() {
    common::setup();
    
    // Test BootMode to_string conversion
    assert_eq!(BootMode::PXE.to_string(), "pxe");
    assert_eq!(BootMode::UEFI.to_string(), "uefi");
    assert_eq!(BootMode::Legacy.to_string(), "legacy");
    
    // Test BootMode from_str conversion
    assert_eq!(BootMode::from_str("pxe").unwrap(), BootMode::PXE);
    assert_eq!(BootMode::from_str("uefi").unwrap(), BootMode::UEFI);
    assert_eq!(BootMode::from_str("legacy").unwrap(), BootMode::Legacy);
    assert_eq!(BootMode::from_str("UEFI").unwrap(), BootMode::UEFI); // Case insensitive
    
    // Test invalid boot mode
    assert!(BootMode::from_str("invalid").is_err());
}

#[tokio::test]
async fn test_session_status_serialization() {
    common::setup();
    
    // Test SessionStatus to_string conversion
    assert_eq!(SessionStatus::Starting.to_string(), "starting");
    assert_eq!(SessionStatus::Booting.to_string(), "booting");
    assert_eq!(SessionStatus::Running.to_string(), "running");
    assert_eq!(SessionStatus::Shutdown.to_string(), "shutdown");
    assert_eq!(SessionStatus::Error.to_string(), "error");
    
    // Test SessionStatus from_str conversion
    assert_eq!(SessionStatus::from_str("starting").unwrap(), SessionStatus::Starting);
    assert_eq!(SessionStatus::from_str("booting").unwrap(), SessionStatus::Booting);
    assert_eq!(SessionStatus::from_str("running").unwrap(), SessionStatus::Running);
    assert_eq!(SessionStatus::from_str("shutdown").unwrap(), SessionStatus::Shutdown);
    assert_eq!(SessionStatus::from_str("error").unwrap(), SessionStatus::Error);
    assert_eq!(SessionStatus::from_str("RUNNING").unwrap(), SessionStatus::Running); // Case insensitive
    
    // Test invalid session status
    assert!(SessionStatus::from_str("invalid").is_err());
}

#[tokio::test]
async fn test_database_schema_types() {
    common::setup();
    
    // Test that our types implement the necessary traits for serialization
    use serde_json;
    
    let boot_mode = BootMode::UEFI;
    let serialized = serde_json::to_string(&boot_mode).unwrap();
    let deserialized: BootMode = serde_json::from_str(&serialized).unwrap();
    assert_eq!(boot_mode, deserialized);
    
    let session_status = SessionStatus::Running;
    let serialized = serde_json::to_string(&session_status).unwrap();
    let deserialized: SessionStatus = serde_json::from_str(&serialized).unwrap();
    assert_eq!(session_status, deserialized);
}

// Note: Full database tests would require a PostgreSQL test instance
// This demonstrates the schema structure and type safety without external dependencies