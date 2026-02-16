#![no_std]
#![allow(dead_code)]

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[path = "engine/benches/mod.rs"]
pub mod benches;
#[path = "engine/core/mod.rs"]
pub mod core;
#[path = "handlers/mod.rs"]
pub mod handlers;
#[path = "io/mod.rs"]
pub mod io;
#[path = "security/mod.rs"]
pub mod security;
#[path = "engine/modes/mod.rs"]
pub mod engine_modes;
#[path = "ai/mod.rs"]
pub mod ai;
#[cfg(any(test, feature = "capture_module_ipc"))]
#[path = "capture_module/mod.rs"]
pub mod capture_module;
#[path = "modules/mod.rs"]
pub mod modules;
#[path = "tasks/mod.rs"]
pub mod tasks;
#[path = "utils/mod.rs"]
pub mod utils;
#[path = "time/mod.rs"]
pub mod time;
#[path = "modules/chat/mod.rs"]
pub mod chat;
#[cfg(feature = "ml_full")]
#[path = "engine/ml/mod.rs"]
pub mod ml;
#[cfg(not(feature = "ml_full"))]
pub mod ml {
    pub struct FaceModel;
    pub struct VoiceModel;
    pub struct FingerprintModel;

    fn cosine_similarity_bytes(a: &[u8], b: &[u8]) -> f32 {
        let len = core::cmp::min(a.len(), b.len());
        if len == 0 {
            return 0.0;
        }

        let mut dot = 0.0f32;
        let mut norm_a = 0.0f32;
        let mut norm_b = 0.0f32;

        for i in 0..len {
            let fa = a[i] as f32 / 255.0;
            let fb = b[i] as f32 / 255.0;
            dot += fa * fb;
            norm_a += fa * fa;
            norm_b += fb * fb;
        }

        if norm_a <= f32::EPSILON || norm_b <= f32::EPSILON {
            return 0.0;
        }

        let denom = norm_a.sqrt() * norm_b.sqrt();
        (dot / denom).clamp(0.0, 1.0)
    }

    impl FaceModel {
        pub fn new() -> Self {
            FaceModel
        }

        pub fn similarity(&self, _a: &[u8], _b: &[u8]) -> f32 {
            cosine_similarity_bytes(_a, _b)
        }
    }

    impl VoiceModel {
        pub fn new() -> Self {
            VoiceModel
        }

        pub fn similarity(&self, _a: &[u8], _b: &[u8]) -> f32 {
            cosine_similarity_bytes(_a, _b)
        }
    }

    impl FingerprintModel {
        pub fn new() -> Self {
            FingerprintModel
        }

        pub fn similarity(&self, _a: &[u8], _b: &[u8]) -> f32 {
            cosine_similarity_bytes(_a, _b)
        }
    }
}
#[path = "security/loop/mod.rs"]
pub mod r#loop;
#[path = "app/init.rs"]
pub mod init;

pub mod prelude {
    pub use alloc::{string::String, string::ToString, vec::Vec, collections::BTreeMap, format};
}

use serde::{Deserialize, Serialize};
use prelude::{String, Vec};
use alloc::collections::BTreeMap;
use spin::Mutex;
type YamlValue = ();

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

#[derive(Clone, Debug)]
pub struct IaConfig {
    pub version: String,
    pub mode: String,
    pub max_threads: u32,
    pub cache_size_mb: u32,
    pub quantization_support: bool,
    pub api_received_port: u16,
    pub api_sent_port: u16,
}

#[derive(Clone, Debug)]
pub struct GlobalDeviceConfig {
    pub name: String,
    pub model: String,
    pub architecture: String,
    pub cpu_cores: u32,
    pub ram_mb: u32,
}

#[derive(Clone, Debug)]
pub struct GlobalSecurityConfig {
    pub encryption_level: u32,
    pub tls_enabled: bool,
    pub tls_version: String,
    pub certificate_path: String,
}

#[derive(Clone, Debug)]
pub struct GlobalHardwareConfig {
    pub gpu_available: bool,
    pub neon_available: bool,
    pub max_frequency_mhz: u32,
}

pub struct GlobalConfigState {
    pub ia_config: Mutex<Option<IaConfig>>,
    pub device_config: Mutex<Option<GlobalDeviceConfig>>,
    pub security_config: Mutex<Option<GlobalSecurityConfig>>,
    pub hardware_config: Mutex<Option<GlobalHardwareConfig>>,
    pub raw_config: Mutex<Option<BTreeMap<String, YamlValue>>>,
}

impl Clone for GlobalConfigState {
    fn clone(&self) -> Self {
        GlobalConfigState {
            ia_config: Mutex::new(self.ia_config.lock().clone()),
            device_config: Mutex::new(self.device_config.lock().clone()),
            security_config: Mutex::new(self.security_config.lock().clone()),
            hardware_config: Mutex::new(self.hardware_config.lock().clone()),
            raw_config: Mutex::new(self.raw_config.lock().clone()),
        }
    }
}

impl GlobalConfigState {
    pub fn new() -> Self {
        GlobalConfigState {
            ia_config: Mutex::new(None),
            device_config: Mutex::new(None),
            security_config: Mutex::new(None),
            hardware_config: Mutex::new(None),
            raw_config: Mutex::new(None),
        }
    }

    pub fn load_from_yaml(&self, _yaml_content: &str) -> Result<(), String> {
        Err("serde_yaml disabled: enable feature \"std\"".into())
    }
}

impl Default for GlobalConfigState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GLOBAL STATE
// ============================================================================

pub static GLOBAL_CONFIG: Mutex<Option<GlobalConfigState>> = Mutex::new(None);

pub fn init_from_yaml(yaml_content: &str) -> Result<(), String> {
    let global_config = GlobalConfigState::new();
    global_config.load_from_yaml(yaml_content)?;
    
    let mut config_lock = GLOBAL_CONFIG.lock();
    *config_lock = Some(global_config);
    
    Ok(())
}

pub fn get_global_config() -> Option<GlobalConfigState> {
    GLOBAL_CONFIG.lock().clone()
}

// ============================================================================
// LEGACY SECURE CONFIG (for backward compatibility)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureConfig {
    pub device: DeviceConfigLegacy,
    pub security: SecurityConfigLegacy,
    pub hardware: HardwareConfigLegacy,
    pub connectivity: ConnectivityConfig,
    pub ia_ml: IaMlConfig,
    pub ai: AiConfig,
    pub kernel: KernelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfigLegacy {
    pub name: String,
    pub model: String,
    pub architecture: String,
    pub manufacturer: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfigLegacy {
    pub level: u32,
    pub encryption: String,
    pub secure_boot: bool,
    pub master_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareConfigLegacy {
    pub cpu: CpuConfig,
    pub gpu: GpuConfig,
    pub ram: RamConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuConfig {
    pub cores: u32,
    pub freq_max_mhz: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuConfig {
    #[serde(rename = "type")]
    pub gpu_type: String,
    pub freq_max_mhz: u32,
    pub memory_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RamConfig {
    pub total_gb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityConfig {
    pub cellular: Vec<String>,
    pub wireless: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IaMlConfig {
    pub version: String,
    pub modules: u32,
    pub deep_learning: bool,
    pub code_analysis: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub module_state: String,
    pub model_dir: String,
    pub data_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    pub memory_pool_mb: u32,
    pub io_scheduler: String,
}

impl SecureConfig {
    pub fn from_yaml(yaml_str: &str) -> Result<Self, String> {
        let _ = yaml_str;
        Err("serde_yaml disabled: enable feature \"std\"".into())
    }

    pub fn to_yaml(&self) -> Result<String, String> {
        Err("serde_yaml disabled: enable feature \"std\"".into())
    }
}




