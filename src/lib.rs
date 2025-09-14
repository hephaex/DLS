pub mod config;
pub mod database;
pub mod error;
pub mod storage;
pub mod network;
pub mod auth;
pub mod monitoring;
pub mod boot;

pub fn hello() -> String {
    "Hello from DLS Server!".to_string()
}