#![cfg_attr(not(feature = "real_tls"), no_std)]

#[cfg(not(feature = "real_tls"))]
extern crate alloc;
#[cfg(feature = "real_tls")]
extern crate std as alloc;

pub mod utils;

pub mod api;
pub mod optimization;
pub mod validation;

pub use api::kernel::callbacks;
pub use api::kernel::spinlock;
pub use api::kernel::task_queue;
pub use api::kernel::session_timeout;
pub use api::kernel::time_abstraction;
pub use api::kernel::hardening;
pub use api::kernel::mutex;
pub use api::kernel::rng;
pub use optimization::arm;

pub mod config {
    extern crate alloc;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use anyhow::Result;
    #[cfg(feature = "real_tls")]
    use serde::Deserialize;
    #[cfg(feature = "real_tls")]
    use serde_yaml::Value;

    #[derive(Clone, Debug)]
    pub struct TlsConfig {
        pub main_token: Option<String>,
        pub other_token: Option<String>,
        pub cert_path: Option<String>,
        pub key_path: Option<String>,
        pub tls_variable: Option<String>,
        pub imei1: Option<String>,
        pub imei2: Option<String>,
        pub serial: Option<String>,
        pub security_level: Option<String>,
        pub encryption_method: Option<String>,
        pub master_key: Option<String>,
        pub boot_token: Option<String>,
    }

    #[cfg(feature = "real_tls")]
    #[derive(Deserialize)]
    struct RootConfig {
        device: Option<DeviceConfig>,
        security: Option<SecurityConfig>,
        tls: Option<TlsSection>,
    }

    #[cfg(feature = "real_tls")]
    #[derive(Deserialize)]
    struct DeviceConfig {
        imei1: Option<String>,
        imei2: Option<String>,
        #[serde(rename = "s/n")]
        serial: Option<String>,
    }

    #[cfg(feature = "real_tls")]
    #[derive(Deserialize)]
    struct SecurityConfig {
        level: Option<Value>,
        encryption: Option<String>,
        master_key: Option<String>,
        boot_token: Option<String>,
    }

    #[cfg(feature = "real_tls")]
    #[derive(Deserialize)]
    struct TlsSection {
        certificate_path: Option<String>,
        private_key_path: Option<String>,
    }

    pub fn get_optional(_key: &str) -> Option<String> {
        None
    }

    #[cfg(feature = "real_tls")]
    fn value_to_string(value: Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    #[cfg(feature = "real_tls")]
    pub fn load_from_yaml(yaml_path: &str) -> Result<TlsConfig> {
        use std::fs;
        let yaml_content = fs::read_to_string(yaml_path)
            .map_err(|e| anyhow::anyhow!("Failed to read YAML from {}: {}", yaml_path, e))?;

        let parsed: RootConfig = serde_yaml::from_str(&yaml_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse YAML: {}", e))?;

        let device = parsed.device.unwrap_or(DeviceConfig {
            imei1: None,
            imei2: None,
            serial: None,
        });
        let security = parsed.security.unwrap_or(SecurityConfig {
            level: None,
            encryption: None,
            master_key: None,
            boot_token: None,
        });
        let tls = parsed.tls.unwrap_or(TlsSection {
            certificate_path: None,
            private_key_path: None,
        });

        let cfg = TlsConfig {
            main_token: None,
            other_token: None,
            cert_path: tls.certificate_path,
            key_path: tls.private_key_path,
            tls_variable: None,
            imei1: device.imei1,
            imei2: device.imei2,
            serial: device.serial,
            security_level: security.level.and_then(value_to_string),
            encryption_method: security.encryption,
            master_key: security.master_key,
            boot_token: security.boot_token,
        };
        Ok(cfg)
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn load_from_yaml(_yaml_path: &str) -> Result<TlsConfig> {
        Err(anyhow::anyhow!("load_from_yaml requires real_tls feature"))
    }

    #[cfg(feature = "real_tls")]
    pub fn load_full(yaml_path: &str, cert_path: &str, key_path: &str) -> Result<(TlsConfig, Vec<u8>, Vec<u8>)> {
        use std::fs;
        let cfg = load_from_yaml(yaml_path)?;
        let cert_bytes = fs::read(cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to read cert from {}: {}", cert_path, e))?;
        let key_bytes = fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read key from {}: {}", key_path, e))?;
        Ok((cfg, cert_bytes, key_bytes))
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn load_full(_yaml_path: &str, _cert_path: &str, _key_path: &str) -> Result<(TlsConfig, Vec<u8>, Vec<u8>)> {
        Err(anyhow::anyhow!("load_full requires real_tls feature"))
    }

    #[cfg(feature = "real_tls")]
    pub fn yaml_integrity_checksum(yaml_path: &str) -> Result<String> {
        use std::fs;
        use sha2::{Sha256, Digest};
        let content = fs::read(yaml_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn yaml_integrity_checksum(_yaml_path: &str) -> Result<String> {
        Err(anyhow::anyhow!("yaml_integrity_checksum requires real_tls feature"))
    }

    #[cfg(feature = "real_tls")]
    pub fn has_yaml(yaml_path: &str) -> bool {
        use std::fs;
        fs::metadata(yaml_path).is_ok()
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn has_yaml(_yaml_path: &str) -> bool {
        false
    }

    #[cfg(feature = "real_tls")]
    pub fn cert_fingerprint(cert_path: &str) -> Result<String> {
        use std::fs;
        use sha2::{Sha256, Digest};
        let cert_bytes = fs::read(cert_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&cert_bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn cert_fingerprint(_cert_path: &str) -> Result<String> {
        Err(anyhow::anyhow!("cert_fingerprint requires real_tls feature"))
    }

    #[cfg(feature = "real_tls")]
    pub fn key_fingerprint(key_path: &str) -> Result<String> {
        use std::fs;
        use sha2::{Sha256, Digest};
        let key_bytes = fs::read(key_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&key_bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn key_fingerprint(_key_path: &str) -> Result<String> {
        Ok("default_key_fingerprint".to_string())
    }

    #[cfg(feature = "real_tls")]
    pub fn load_file_bytes(path: &str) -> Result<Vec<u8>> {
        use std::fs;
        fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path, e))
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn load_file_bytes(_path: &str) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    #[cfg(feature = "real_tls")]
    pub fn load_cert_and_key(cert_path: &str, key_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        use std::fs;
        let cert_bytes = fs::read(cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to read cert from {}: {}", cert_path, e))?;
        let key_bytes = fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read key from {}: {}", key_path, e))?;
        Ok((cert_bytes, key_bytes))
    }

    #[cfg(not(feature = "real_tls"))]
    pub fn load_cert_and_key(_cert_path: &str, _key_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((Vec::new(), Vec::new()))
    }

    impl TlsConfig {
        pub fn load_from_yaml(yaml_path: &str) -> Result<Self> {
            load_from_yaml(yaml_path)
        }

        pub fn load_full(yaml_path: &str, cert_path: &str, key_path: &str) -> Result<(Self, Vec<u8>, Vec<u8>)> {
            load_full(yaml_path, cert_path, key_path)
        }
    }
}

pub mod core;
pub mod hsm;
pub mod runtime;
pub mod security;
pub mod services;
pub mod telemetry;

pub use api::{
    TLSClient, TLSServer, ComponentTokenManager, ComponentToken, ComponentSignature, 
    ComponentType, ComponentAPIHandler
};
pub use telemetry::HeartbeatMonitor;
pub use api::ia::{
    IALauncher, IALaunchConfig,
    init_ia_launcher_phone_mode, init_ia_launcher_dev_mode, 
    pump_ia_tls_events, is_ia_launcher_active, get_ia_tls_port,
};
pub use core::handshake::TLSHandshakeCoordinator;
pub use core::crypto::crypto::CryptoKey;
pub use core::tls_handshake::{TlsHandshake, HandshakeMessageType};
pub use security::detection::honeypot::HoneypotSystem;
pub use runtime::loops::{
    primary_loop::{PrimaryLoop, PrimaryMessage, PrimaryChannel},
    secondary_loop::{SecondaryLoop, SecondaryMessage, SecondaryChannel},
    third_loop::{ThirdLoop, ThirdMessage, ThirdChannel},
    forth_loop::{ForthLoop, ForthMessage, ForthChannel},
    external_loop::{ExternalLoop, ExternalMessage, ExternalChannel},
};
pub use services::session_manager::SessionManager;
pub use api::token::TokenManager;

pub use core::crypto;
pub use security::detection::honeypot;
pub use runtime::loops::{primary_loop, secondary_loop, third_loop, forth_loop, external_loop};
pub use services::session_manager;
pub use api::component_token;
pub use runtime::traffic::heartbeat;
pub use api::server;
pub use api::client;
pub use utils::{SecretVec, SecretKey, secret_loader};
pub use utils::secret_loader::SecretLoader;
pub use api::component_api::{
    IssueTokenRequest, IssueTokenResponse, OpenSessionRequest, OpenSessionResponse,
    SignActionRequest, SignActionResponse, VerifySignatureRequest, HeartbeatRequest,
    ValidateTokenRequest, RotateTokenRequest,
};

pub use core::tls_orchestrator::{TlsOrchestrator, TlsSessionState};

pub mod run;