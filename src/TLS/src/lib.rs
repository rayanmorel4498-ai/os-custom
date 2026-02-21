#![no_std]

use ::core::ptr;



extern crate alloc;
use alloc::string::ToString;
 

pub mod utils;

pub mod api;
pub mod optimization;
pub mod validation;

pub use api::kernel::callbacks as kernel_callbacks;
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
    use alloc::string::String;
    use alloc::vec::Vec;
    use anyhow::Result;

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

    #[derive(Clone, Debug)]
    pub struct BuildOrderEntry {
        pub name: String,
        pub required: bool,
        pub depends_on: Vec<String>,
    }

    #[derive(Clone, Debug)]
    pub struct RunOrderEntry {
        pub name: String,
        pub required: bool,
        pub depends_on: Vec<String>,
    }

    pub const SPKI_FINGERPRINT_HEX: &str = "";

    pub fn get_optional(key: &str) -> Option<String> {
        let _ = key.len();
        None
    }

    pub(crate) fn normalize_hex(value: &str) -> Result<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() % 2 != 0 {
            return Err(anyhow::anyhow!("bootstrap_key invalid"));
        }
        if !trimmed
            .as_bytes()
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
        {
            return Err(anyhow::anyhow!("bootstrap_key invalid"));
        }
        Ok(trimmed.to_ascii_lowercase())
    }

    pub fn load_secure_build_order(yaml_path: &str) -> Result<Vec<BuildOrderEntry>> {
        let _ = yaml_path.len();
        crate::run::load_secure_build_order(yaml_path)
    }

    pub fn load_secure_run_order(yaml_path: &str) -> Result<Vec<RunOrderEntry>> {
        let _ = yaml_path.len();
        crate::run::load_secure_run_order(yaml_path)
    }

    pub fn load_bootstrap_key(yaml_path: &str) -> Result<String> {
        let _ = yaml_path.len();
        let key = crate::run::load_bootstrap_key(yaml_path)?;
        normalize_hex(&key)
    }

    pub fn validate_build_order(entries: &[BuildOrderEntry]) -> Result<()> {
        if entries.is_empty() {
            return Err(anyhow::anyhow!("build_order is empty"));
        }
        Ok(())
    }
    pub fn load_from_yaml(yaml_path: &str) -> Result<TlsConfig> {
        crate::utils::config::ensure_required_secrets()
            .map_err(|e| anyhow::anyhow!(e))?;
        let _ = yaml_path.len();
        let master_key = crate::utils::config::Config::runtime_master_key();
        let boot_token = crate::utils::config::Config::runtime_boot_token();

        Ok(TlsConfig {
            main_token: None,
            other_token: None,
            cert_path: None,
            key_path: None,
            tls_variable: None,
            imei1: None,
            imei2: None,
            serial: None,
            security_level: None,
            encryption_method: None,
            master_key: if master_key.is_empty() { None } else { Some(master_key) },
            boot_token: if boot_token.is_empty() { None } else { Some(boot_token) },
        })
    }

    
    pub fn load_full(yaml_path: &str, cert_path: &str, key_path: &str) -> Result<(TlsConfig, Vec<u8>, Vec<u8>)> {
        let _ = (yaml_path.len(), cert_path.len(), key_path.len());
        Err(anyhow::anyhow!("configuration universelle non implémentée"))
    }
    pub fn yaml_integrity_checksum(yaml_path: &str) -> Result<String> {
        let _ = yaml_path.len();
        Err(anyhow::anyhow!("yaml_integrity_checksum indisponible en no_std"))
    }
    pub fn has_yaml(yaml_path: &str) -> bool {
        let _ = yaml_path.len();
        false
    }
    pub fn cert_fingerprint(cert_path: &str) -> Result<String> {
        let _ = cert_path.len();
        Err(anyhow::anyhow!("cert_fingerprint indisponible en no_std"))
    }
    pub fn key_fingerprint(key_path: &str) -> Result<String> {
        let _ = key_path.len();
        Err(anyhow::anyhow!("key_fingerprint indisponible en no_std"))
    }
    pub fn load_file_bytes(path: &str) -> Result<Vec<u8>> {
        let _ = path.len();
        Ok(Vec::new())
    }
    pub fn load_cert_and_key(cert_path: &str, key_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let _ = (cert_path.len(), key_path.len());
        crate::run::load_cert_and_key(cert_path, key_path)
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
    TLSClient, ComponentTokenManager, ComponentToken, ComponentSignature,
    ComponentType, ComponentAPIHandler
};
pub use api::TLSServer;
pub use telemetry::HeartbeatMonitor;
pub use services::{
    ApiGateway,
    ApiCatalog,
    ModuleBundle,
    ApiCallResolution,
    GatewayErrorCode,
    GatewayError,
    GatewayMetricsSnapshot,
    BundleRequest,
    BundleResponse,
};
pub use api::IA::{
    IALauncher, IALaunchConfig,
    init_ia_launcher_phone_mode, init_ia_launcher_dev_mode,
    pump_ia_events, is_ia_launcher_active,
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

pub fn compile_all() {
    let _s: alloc::string::String = "".to_string();
    let _ = api::config::ipc_format::write_error as fn(&mut [u8], &str) -> usize;
    let _ = api::config::ipc_format::write_response as fn(&mut [u8], &str) -> usize;
    let _ = runtime::loops::control_loop::build_all_loop_guards as fn() -> Option<runtime::loops::control_loop::LoopGuards>;
    let _ = runtime::loops::secondary_loop::SecondaryLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::secondary_loop::SecondaryLoop;
    let _ = runtime::loops::forth_loop::ForthLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::forth_loop::ForthLoop;
    let _ = runtime::loops::external_loop::ExternalLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::external_loop::ExternalLoop;
    let _ = security::detection::watchdog::analyze_full_system as fn() -> security::detection::watchdog::SystemAuditReport;
    let _ = api::config::ephemeral_api::components as fn() -> &'static [&'static str];
    let _ = api::config::ephemeral_api::secret_for_component as fn(&str) -> Option<[u8; 16]>;
}

pub fn init_server_logic() {
    let _ = runtime::loops::primary_loop::PrimaryLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::primary_loop::PrimaryLoop;
    let _ = runtime::loops::secondary_loop::SecondaryLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::secondary_loop::SecondaryLoop;
    let _ = runtime::loops::third_loop::ThirdLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::third_loop::ThirdLoop;
    let _ = runtime::loops::forth_loop::ForthLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::forth_loop::ForthLoop;
    let _ = runtime::loops::external_loop::ExternalLoop::new as fn(alloc::sync::Arc<services::session_manager::SessionManager>, alloc::sync::Arc<core::crypto::crypto::CryptoKey>, alloc::sync::Arc<security::detection::honeypot::HoneypotSystem>) -> runtime::loops::external_loop::ExternalLoop;
}

pub fn bootstrap_init() {
    run::init_signal_handlers();
    run::tls_log("[run] démarrage TLS (init only)");
    run::tls_log(&alloc::format!(
        "[run] bootstrap socket target: {}",
        api::config::ipc_mux::CONTROL_SOCKET_PATH
    ));
    run::ensure_secure_yaml_loaded();
    run::init_all_loops();
    run::log_sandbox_state();
    api::config::ipc_mux::ensure_control_listener();
}
pub use services::session_manager;
pub use api::component_token;
pub use runtime::traffic::heartbeat;
pub use api::config::server;
pub use api::client;
pub use utils::{SecretVec, SecretKey, secret_loader};
pub use utils::secret_loader::SecretLoader;
pub use api::component_api::{
    IssueTokenRequest, IssueTokenResponse, OpenSessionRequest, OpenSessionResponse,
    SignActionRequest, SignActionResponse, VerifySignatureRequest, HeartbeatRequest,
    ValidateTokenRequest, RotateTokenRequest,
};

pub use core::tls_orchestrator::{TlsOrchestrator, TlsSessionState};
pub use security::{SecretProvider, SecretProviderError};
pub use security::secure_element::SecureElementError;

pub mod run {
    extern crate alloc;

    use alloc::string::String;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::api::config::ipc_format::{write_error, write_response, verify_custom_sig};
    use crate::api::config::ephemeral_api::secret_for_component;
    use crate::runtime::loops::control_loop;
    use crate::runtime::loops::sandbox;

    pub static BUILTIN_SECURE_YAML: &str = "";

    static INCOMING_CONTROL_ENABLED: AtomicBool = AtomicBool::new(true);
    static BUILD_MODE_ACTIVE: AtomicBool = AtomicBool::new(true);

    pub fn tls_log(msg: &str) { let _ = msg.len(); }

    pub fn log_hardware_request_refused(reason: &str) { let _ = reason.len(); }

    pub fn allow_incoming_control() -> bool {
        INCOMING_CONTROL_ENABLED.load(Ordering::SeqCst)
    }

    pub fn is_build_mode_active() -> bool {
        BUILD_MODE_ACTIVE.load(Ordering::SeqCst)
    }

    pub fn init_signal_handlers() {}

    pub fn ensure_secure_yaml_loaded() {
        if crate::utils::config::secure_yaml_loaded() {
            return;
        }
        if !BUILTIN_SECURE_YAML.is_empty() {
            let _ = crate::utils::config::set_secure_yaml_content(BUILTIN_SECURE_YAML);
        }
    }

    pub fn init_all_loops() {
        let _ = control_loop::build_all_loop_guards();
        sandbox::set_tls_sandbox_active(true);
        crate::api::config::ipc_mux::set_primary_sandbox_ready();
        crate::api::config::ipc_mux::set_secondary_sandbox_ready();
    }

    pub fn log_sandbox_state() {}

    pub fn handle_build_sign_request(req: &[u8], resp: &mut [u8]) -> usize {
        let Ok(s) = core::str::from_utf8(req) else {
            return write_error(resp, "bad_format");
        };
        if !s.is_ascii() || s.as_bytes().iter().any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
            return write_error(resp, "bad_format");
        }
        let Some(rest) = s.strip_prefix("BUILD_SIGN_REQ;") else {
            return write_error(resp, "bad_format");
        };

        let mut v = None;
        let mut op = None;
        let mut mode = None;
        let mut first_run = None;
        let mut component = None;
        let mut hardware_id = None;
        let mut kernel_id = None;
        let mut capture_id = None;
        let mut nonce = None;
        let mut sig = None;

        for part in rest.split(';') {
            if let Some(val) = part.strip_prefix("v=") {
                v = Some(val);
            } else if let Some(val) = part.strip_prefix("op=") {
                op = Some(val);
            } else if let Some(val) = part.strip_prefix("mode=") {
                mode = Some(val);
            } else if let Some(val) = part.strip_prefix("first_run=") {
                first_run = Some(val);
            } else if let Some(val) = part.strip_prefix("component=") {
                component = Some(val);
            } else if let Some(val) = part.strip_prefix("hardware_id=") {
                hardware_id = Some(val);
            } else if let Some(val) = part.strip_prefix("kernel_id=") {
                kernel_id = Some(val);
            } else if let Some(val) = part.strip_prefix("capture_id=") {
                capture_id = Some(val);
            } else if let Some(val) = part.strip_prefix("nonce=") {
                nonce = Some(val);
            } else if let Some(val) = part.strip_prefix("sig=") {
                sig = Some(val);
            } else {
                return write_error(resp, "bad_format");
            }
        }

        if v != Some("1") || op != Some("SIGN") || mode != Some("run") || first_run != Some("1") {
            return write_error(resp, "bad_format");
        }

        let component = match component {
            Some(val) => val,
            None => return write_error(resp, "bad_format"),
        };

        let (id_key, id_val) = match component {
            "hardware" => ("hardware_id", hardware_id),
            "kernel" => ("kernel_id", kernel_id),
            "capture_module" => ("capture_id", capture_id),
            _ => return write_error(resp, "bad_component"),
        };

        let id_val = match id_val {
            Some(val) => val,
            None => return write_error(resp, "bad_format"),
        };
        let nonce = match nonce {
            Some(val) => val,
            None => return write_error(resp, "bad_format"),
        };
        let sig = match sig {
            Some(val) => val,
            None => return write_error(resp, "bad_format"),
        };

        if !is_hex_len(id_val, 16) || !is_hex_len(nonce, 16) || !is_hex_len(sig, 32) {
            return write_error(resp, "bad_format");
        }

        if secret_for_component(component).is_none() {
            return write_error(resp, "signing_unavailable");
        }

        let msg = alloc::format!(
            "BUILD_SIGN_REQ;v=1;op=SIGN;mode=run;first_run=1;{}={};nonce={}",
            id_key,
            id_val,
            nonce
        );
        if !verify_custom_sig(component, &msg, Some(nonce), sig) {
            return write_error(resp, "bad_sig");
        }

        let out = alloc::format!(
            "BUILD_SIGN_OK;v=1;component={};{}={};nonce={};sig={}",
            component,
            id_key,
            id_val,
            nonce,
            sig
        );
        write_response(resp, &out)
    }

    fn parse_yaml_value(raw: &str) -> String {
        let without_comment = if let Some(pos) = raw.find('#') {
            &raw[..pos]
        } else {
            raw
        };
        without_comment.trim().trim_matches('"').to_string()
    }

    fn load_yaml_value(section: &str, key: &str) -> Option<String> {
        let content = crate::utils::config::secure_yaml_content()?;
        let mut current_section = "";
        for line in content.lines() {
            let trimmed = line.trim_end();
            if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
                continue;
            }
            if !trimmed.starts_with(' ') && trimmed.ends_with(':') {
                current_section = trimmed.trim_end_matches(':').trim();
                continue;
            }
            if current_section == section {
                let l = trimmed.trim_start();
                if let Some((k, v)) = l.split_once(':') {
                    if k.trim() == key {
                        return Some(parse_yaml_value(v));
                    }
                }
            }
        }
        None
    }

    pub fn load_bootstrap_key(yaml_path: &str) -> anyhow::Result<String> {
        ensure_secure_yaml_loaded();
        let _ = yaml_path.len();
        let key = load_yaml_value("security", "bootstrap_key").unwrap_or_default();
        if key.trim().is_empty() {
            return Err(anyhow::anyhow!("bootstrap_key invalid"));
        }
        Ok(key)
    }

    pub fn load_secure_build_order(yaml_path: &str) -> anyhow::Result<Vec<crate::config::BuildOrderEntry>> {
        ensure_secure_yaml_loaded();
        let _ = yaml_path.len();
        parse_order_section("build_order")
    }

    pub fn load_secure_run_order(yaml_path: &str) -> anyhow::Result<Vec<crate::config::RunOrderEntry>> {
        ensure_secure_yaml_loaded();
        let _ = yaml_path.len();
        parse_run_order_section("run_order")
    }

    fn parse_order_section(section: &str) -> anyhow::Result<Vec<crate::config::BuildOrderEntry>> {
        let content = crate::utils::config::secure_yaml_content().unwrap_or_default();
        let mut entries = Vec::new();
        let mut in_section = false;
        let mut current_name = None;
        let mut current_required = None;
        let mut current_depends: Vec<String> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim_end();
            if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
                continue;
            }
            if !trimmed.starts_with(' ') && trimmed.ends_with(':') {
                in_section = trimmed.trim_end_matches(':').trim() == section;
                continue;
            }
            if !in_section {
                continue;
            }
            let l = trimmed.trim_start();
            if let Some(name) = l.strip_prefix("- name:") {
                if let (Some(n), Some(r)) = (current_name.take(), current_required.take()) {
                    entries.push(crate::config::BuildOrderEntry {
                        name: n,
                        required: r,
                        depends_on: current_depends.clone(),
                    });
                }
                current_depends.clear();
                current_name = Some(parse_yaml_value(name));
                current_required = None;
                continue;
            }
            if let Some(req) = l.strip_prefix("required:") {
                current_required = Some(parse_yaml_value(req) == "true");
                continue;
            }
            if let Some(dep) = l.strip_prefix("depends_on:") {
                let raw = parse_yaml_value(dep);
                let list = raw.trim().trim_start_matches('[').trim_end_matches(']');
                current_depends = list
                    .split(',')
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_string())
                    .collect();
                continue;
            }
        }
        if let (Some(n), Some(r)) = (current_name.take(), current_required.take()) {
            entries.push(crate::config::BuildOrderEntry {
                name: n,
                required: r,
                depends_on: current_depends,
            });
        }
        Ok(entries)
    }

    fn parse_run_order_section(section: &str) -> anyhow::Result<Vec<crate::config::RunOrderEntry>> {
        let content = crate::utils::config::secure_yaml_content().unwrap_or_default();
        let mut entries = Vec::new();
        let mut in_section = false;
        let mut current_name = None;
        let mut current_required = None;
        let mut current_depends: Vec<String> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim_end();
            if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
                continue;
            }
            if !trimmed.starts_with(' ') && trimmed.ends_with(':') {
                in_section = trimmed.trim_end_matches(':').trim() == section;
                continue;
            }
            if !in_section {
                continue;
            }
            let l = trimmed.trim_start();
            if let Some(name) = l.strip_prefix("- name:") {
                if let (Some(n), Some(r)) = (current_name.take(), current_required.take()) {
                    entries.push(crate::config::RunOrderEntry {
                        name: n,
                        required: r,
                        depends_on: current_depends.clone(),
                    });
                }
                current_depends.clear();
                current_name = Some(parse_yaml_value(name));
                current_required = None;
                continue;
            }
            if let Some(req) = l.strip_prefix("required:") {
                current_required = Some(parse_yaml_value(req) == "true");
                continue;
            }
            if let Some(dep) = l.strip_prefix("depends_on:") {
                let raw = parse_yaml_value(dep);
                let list = raw.trim().trim_start_matches('[').trim_end_matches(']');
                current_depends = list
                    .split(',')
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_string())
                    .collect();
                continue;
            }
        }
        if let (Some(n), Some(r)) = (current_name.take(), current_required.take()) {
            entries.push(crate::config::RunOrderEntry {
                name: n,
                required: r,
                depends_on: current_depends,
            });
        }
        Ok(entries)
    }

    pub fn load_cert_and_key(cert_path: &str, key_path: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let _ = (cert_path.len(), key_path.len());
        Ok((Vec::new(), Vec::new()))
    }

    pub fn get_master_key() -> &'static str { "" }
    pub fn get_session_key() -> &'static str { "" }
    pub fn get_hardware_binding_secret() -> &'static str { "" }
    pub fn get_hardware_secret() -> &'static str { "" }
    pub fn get_kernel_seed() -> &'static str { "" }
    pub fn get_kernel_secret() -> &'static str { "" }
    pub fn get_network_firewall_secret() -> &'static str { "" }
    pub fn get_internal_api_secret() -> &'static str { "" }
    pub fn get_integrity_check_secret() -> &'static str { "" }
    pub fn get_hardware_id() -> &'static str { "" }
    pub fn get_kernel_id() -> &'static str { "" }
    pub fn get_ia_id() -> &'static str { "" }
    pub fn get_capture_id() -> &'static str { "" }
    pub fn get_ia_secret() -> &'static str { "" }
    pub fn get_capture_secret() -> &'static str { "" }
    pub fn get_bootstrap_key() -> &'static str { "" }
    pub fn get_boot_secret() -> &'static str { "" }
    pub fn get_boot_token() -> Option<&'static str> { None }

    fn is_hex_len(s: &str, bytes_len: usize) -> bool {
        if s.len() != bytes_len * 2 { return false; }
        s.as_bytes().iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
    }
}

pub fn get_runtime_metrics_collector() -> *const crate::runtime::metrics_collector::MetricsCollector {
    // default: check a dedicated global runtime collector, else null
    if let Some(col) = crate::GLOBAL_RUNTIME_METRICS.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(col);
    }
    ptr::null()
}

pub fn get_service_metrics_collector() -> *const crate::services::metrics::MetricsCollector {
    if let Some(col) = crate::GLOBAL_SERVICE_METRICS.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(col);
    }
    ptr::null()
}

pub fn get_anomaly_detection() -> *const crate::security::AnomalyDetection {
    if let Some(det) = crate::GLOBAL_ANOMALY.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(det);
    }
    ptr::null()
}

pub fn get_honeypot_system() -> *const crate::security::HoneypotSystem {
    if let Some(h) = crate::GLOBAL_HONEYPOT.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(h);
    }
    ptr::null()
}

pub fn get_security_logger() -> *const crate::security::SecurityLogger {
    if let Some(l) = crate::GLOBAL_SECURITY_LOGGER.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(l);
    }
    ptr::null()
}

pub fn get_circuit_breaker() -> *const crate::security::CircuitBreaker {
    if let Some(cb) = crate::GLOBAL_CIRCUIT_BREAKER.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(cb);
    }
    ptr::null()
}

pub fn get_key_rotation_manager() -> *const crate::security::KeyRotationManager {
    if let Some(k) = crate::GLOBAL_KEY_ROTATION_MANAGER.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(k);
    }
    ptr::null()
}

pub fn get_key_update_manager() -> *const crate::security::KeyUpdateManager {
    if let Some(k) = crate::GLOBAL_KEY_UPDATE_MANAGER.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(k);
    }
    ptr::null()
}

pub fn get_auto_rekeying() -> *const crate::security::AutomaticRekeying {
    if let Some(a) = crate::GLOBAL_AUTO_REKEYING.lock().as_ref() {
        return alloc::sync::Arc::as_ptr(a);
    }
    ptr::null()
}

// Globals and setters for externally created singletons
pub static GLOBAL_RUNTIME_METRICS: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::runtime::metrics_collector::MetricsCollector>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_HONEYPOT: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::detection::honeypot::HoneypotSystem>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_SERVICE_METRICS: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::services::metrics::MetricsCollector>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_ANOMALY: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::AnomalyDetection>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_SECURITY_LOGGER: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::SecurityLogger>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_CIRCUIT_BREAKER: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::rate_control::circuit_breaker::CircuitBreaker>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_KEY_ROTATION_MANAGER: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::keys::key_rotation::KeyRotationManager>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_KEY_UPDATE_MANAGER: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::keys::key_update::KeyUpdateManager>>> = crate::utils::spinlock_manager::SpinLock::new(None);
pub static GLOBAL_AUTO_REKEYING: crate::utils::spinlock_manager::SpinLock<Option<alloc::sync::Arc<crate::security::keys::automatic_rekeying::AutomaticRekeying>>> = crate::utils::spinlock_manager::SpinLock::new(None);

pub fn set_global_runtime_metrics(col: alloc::sync::Arc<crate::runtime::metrics_collector::MetricsCollector>) {
    *GLOBAL_RUNTIME_METRICS.lock() = Some(col);
}

pub fn set_global_honeypot(h: alloc::sync::Arc<crate::security::detection::honeypot::HoneypotSystem>) {
    *GLOBAL_HONEYPOT.lock() = Some(h);
}

pub fn set_global_service_metrics(col: alloc::sync::Arc<crate::services::metrics::MetricsCollector>) {
    *GLOBAL_SERVICE_METRICS.lock() = Some(col);
}

pub fn set_global_anomaly(det: alloc::sync::Arc<crate::security::AnomalyDetection>) {
    *GLOBAL_ANOMALY.lock() = Some(det);
}

pub fn set_global_security_logger(l: alloc::sync::Arc<crate::security::SecurityLogger>) {
    *GLOBAL_SECURITY_LOGGER.lock() = Some(l);
}

pub fn set_global_circuit_breaker(cb: alloc::sync::Arc<crate::security::rate_control::circuit_breaker::CircuitBreaker>) {
    *GLOBAL_CIRCUIT_BREAKER.lock() = Some(cb);
}

pub fn set_global_key_rotation_manager(k: alloc::sync::Arc<crate::security::keys::key_rotation::KeyRotationManager>) {
    *GLOBAL_KEY_ROTATION_MANAGER.lock() = Some(k);
}

pub fn set_global_key_update_manager(k: alloc::sync::Arc<crate::security::keys::key_update::KeyUpdateManager>) {
    *GLOBAL_KEY_UPDATE_MANAGER.lock() = Some(k);
}

pub fn set_global_auto_rekeying(a: alloc::sync::Arc<crate::security::keys::automatic_rekeying::AutomaticRekeying>) {
    *GLOBAL_AUTO_REKEYING.lock() = Some(a);
}
