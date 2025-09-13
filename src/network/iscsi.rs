use crate::error::{DlsError, Result};
use tracing::{error, info, warn};

#[derive(Debug)]
pub struct IscsiTarget {
    target_name: String,
    running: bool,
}

impl IscsiTarget {
    pub fn new(target_name: String) -> Self {
        Self {
            target_name,
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(DlsError::Network("iSCSI target already running".to_string()));
        }

        info!("Starting iSCSI target: {}", self.target_name);
        
        warn!("iSCSI target is not fully implemented in development mode");
        
        self.running = true;
        info!("iSCSI target started (stub implementation)");
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        self.running = false;
        info!("iSCSI target stopped");
        Ok(())
    }

    pub async fn add_lun(&mut self, _lun_id: u32, _image_path: &str) -> Result<()> {
        if !self.running {
            return Err(DlsError::Network("iSCSI target not running".to_string()));
        }

        warn!("add_lun not implemented in development mode");
        Ok(())
    }

    pub async fn remove_lun(&mut self, _lun_id: u32) -> Result<()> {
        if !self.running {
            return Err(DlsError::Network("iSCSI target not running".to_string()));
        }

        warn!("remove_lun not implemented in development mode");
        Ok(())
    }
}