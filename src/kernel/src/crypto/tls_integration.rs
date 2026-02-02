#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::sync::Mutex;
use redmi_tls::runtime::loops::primary_loop::PrimaryLoop;

#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    pub security_level: u8,
    pub encryption_method: String,
    pub master_key: String,
    pub boot_token: String,
    pub certificate_path: String,
    pub private_key_path: String,
    pub ca_bundle_path: String,
    pub min_tls_version: String,
    pub preferred_ciphers: Vec<String>,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            security_level: 5,
            encryption_method: "AES-256-CTR".to_string(),
            master_key: String::new(),
            boot_token: String::new(),
            certificate_path: "/etc/redmi/certs/server.pem".to_string(),
            private_key_path: "/etc/redmi/certs/server.key".to_string(),
            ca_bundle_path: "/etc/redmi/certs/ca-bundle.pem".to_string(),
            min_tls_version: "1.3".to_string(),
            preferred_ciphers: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
        }
    }
}

pub struct TlsIntegrationManager {
    config: Arc<Mutex<TlsSecurityConfig>>,
    initialized: Arc<Mutex<bool>>,
    primary_loop: Option<Arc<PrimaryLoop>>,
}

impl TlsIntegrationManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(TlsSecurityConfig::default())),
            initialized: Arc::new(Mutex::new(false)),
            primary_loop: None,
        }
    }

    pub fn with_primary_loop(primary_loop: Arc<PrimaryLoop>) -> Self {
        Self {
            config: Arc::new(Mutex::new(TlsSecurityConfig::default())),
            initialized: Arc::new(Mutex::new(false)),
            primary_loop: Some(primary_loop),
        }
    }

    pub fn initialize_from_yaml(&self, yaml_security_level: &str, 
                               encryption_method: &str,
                               master_key: &str,
                               boot_token: &str) -> Result<(), String> {
        let level: u8 = yaml_security_level.parse()
            .unwrap_or(5);
        
        let mut config = self.config.lock();
        config.security_level = level;
        config.encryption_method = encryption_method.to_string();
        config.master_key = master_key.to_string();
        config.boot_token = boot_token.to_string();

        let mut initialized = self.initialized.lock();
        *initialized = true;

        Ok(())
    }

    pub fn get_config(&self) -> TlsSecurityConfig {
        self.config.lock().clone()
    }

    pub fn set_encryption_method(&self, method: &str) -> Result<(), String> {
        let mut config = self.config.lock();
        config.encryption_method = method.to_string();
        Ok(())
    }

    pub fn set_security_level(&self, level: u8) -> Result<(), String> {
        if level > 10 {
            return Err("Security level must be 0-10".to_string());
        }
        let mut config = self.config.lock();
        config.security_level = level;
        Ok(())
    }

    pub fn get_master_key(&self) -> String {
        self.config.lock().master_key.clone()
    }

    pub fn get_boot_token(&self) -> String {
        self.config.lock().boot_token.clone()
    }

    pub fn verify_tls_configuration(&self) -> Result<(), String> {
        let config = self.config.lock();
        
        if config.master_key.is_empty() {
            return Err("Master key not configured".to_string());
        }
        
        if config.boot_token.is_empty() {
            return Err("Boot token not configured".to_string());
        }
        
        if config.security_level == 0 {
            return Err("Security level must be > 0".to_string());
        }

        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        *self.initialized.lock()
    }

    pub fn get_primary_loop(&self) -> Option<Arc<PrimaryLoop>> {
        self.primary_loop.clone()
    }

    pub fn set_primary_loop(&mut self, primary_loop: Arc<PrimaryLoop>) {
        self.primary_loop = Some(primary_loop);
    }
}

impl Default for TlsIntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_creation() {
        let manager = TlsIntegrationManager::new();
        assert!(!manager.is_initialized());
    }

    #[test]
    fn test_tls_initialization() {
        let manager = TlsIntegrationManager::new();
        let result = manager.initialize_from_yaml("5", "AES-256-CTR", "test_key", "test_token");
        assert!(result.is_ok());
        assert!(manager.is_initialized());
    }

    #[test]
    fn test_tls_security_level() {
        let manager = TlsIntegrationManager::new();
        assert!(manager.set_security_level(5).is_ok());
        assert!(manager.set_security_level(11).is_err());
    }

    #[test]
    fn test_tls_verify_config() {
        let manager = TlsIntegrationManager::new();
        assert!(manager.verify_tls_configuration().is_err());
        
        manager.initialize_from_yaml("5", "AES-256-CTR", "test_key", "test_token").unwrap();
        assert!(manager.verify_tls_configuration().is_ok());
    }
}
