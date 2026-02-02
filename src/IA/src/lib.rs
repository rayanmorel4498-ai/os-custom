#![no_std]
#![allow(dead_code)]

extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub mod benches;
pub mod core;
pub mod engine_modes;
pub mod modules;
pub mod tasks;
pub mod utils;
pub mod chat;
pub mod ml;
pub mod r#loop;

pub mod prelude {
    pub use alloc::{string::String, vec::Vec, collections::BTreeMap, format};
}

use serde::{Deserialize, Serialize};
use prelude::{String, Vec, format};
use alloc::collections::BTreeMap;
use spin::Mutex;
use serde_yaml::Value;

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
    pub raw_config: Mutex<Option<BTreeMap<String, Value>>>,
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

    pub fn load_from_yaml(&self, yaml_content: &str) -> Result<(), String> {
        let parsed: Value = serde_yaml::from_str(yaml_content)
            .map_err(|e| format!("YAML parse error: {:?}", e))?;

        let mut raw = self.raw_config.lock();
        *raw = Some(self.extract_mapping(&parsed));
        drop(raw);

        self.extract_ia_config(&parsed)?;
        self.extract_device_config(&parsed)?;
        self.extract_security_config(&parsed)?;
        self.extract_hardware_config(&parsed)?;

        Ok(())
    }

    fn extract_mapping(&self, value: &Value) -> BTreeMap<String, Value> {
        let mut map = BTreeMap::new();
        if let Some(mapping) = value.as_mapping() {
            for (k, v) in mapping.iter() {
                if let Some(key_str) = k.as_str() {
                    map.insert(key_str.into(), v.clone());
                }
            }
        }
        map
    }

    fn extract_ia_config(&self, yaml: &Value) -> Result<(), String> {
        let ia = yaml.get("ia_ml")
            .ok_or("Missing ia_ml section")?;

        let version = ia.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("2.0")
            .into();

        let mode = ia.get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("autonomous")
            .into();

        let max_threads = ia.get("max_threads")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as u32;

        let cache_size_mb = ia.get("cache_size_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(64) as u32;

        let quantization_support = ia.get("quantization_support")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let config = IaConfig {
            version,
            mode,
            max_threads,
            cache_size_mb,
            quantization_support,
            api_received_port: 5551,
            api_sent_port: 5552,
        };

        *self.ia_config.lock() = Some(config);
        Ok(())
    }

    fn extract_device_config(&self, yaml: &Value) -> Result<(), String> {
        let device = yaml.get("device")
            .ok_or("Missing device section")?;

        let name = device.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Redmi-15c")
            .into();

        let model = device.get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .into();

        let architecture = device.get("architecture")
            .and_then(|v| v.as_str())
            .unwrap_or("ARM64")
            .into();

        let cpu_cores = device.get("cpu_cores")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as u32;

        let ram_mb = device.get("ram_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(4096) as u32;

        let config = GlobalDeviceConfig {
            name,
            model,
            architecture,
            cpu_cores,
            ram_mb,
        };

        *self.device_config.lock() = Some(config);
        Ok(())
    }

    fn extract_security_config(&self, yaml: &Value) -> Result<(), String> {
        let security = yaml.get("security")
            .ok_or("Missing security section")?;

        let encryption_level = security.get("level")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u32;

        let tls = yaml.get("tls")
            .ok_or("Missing tls section")?;

        let tls_enabled = tls.get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let tls_version = tls.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1.3")
            .into();

        let certificate_path = tls.get("cert_path")
            .and_then(|v| v.as_str())
            .unwrap_or("/etc/ssl/certs/device.pem")
            .into();

        let config = GlobalSecurityConfig {
            encryption_level,
            tls_enabled,
            tls_version,
            certificate_path,
        };

        *self.security_config.lock() = Some(config);
        Ok(())
    }

    fn extract_hardware_config(&self, yaml: &Value) -> Result<(), String> {
        let hardware = yaml.get("hardware")
            .ok_or("Missing hardware section")?;

        let gpu_available = hardware.get("gpu_available")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let neon_available = hardware.get("neon_available")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let max_frequency_mhz = hardware.get("max_frequency_mhz")
            .and_then(|v| v.as_u64())
            .unwrap_or(2400) as u32;

        let config = GlobalHardwareConfig {
            gpu_available,
            neon_available,
            max_frequency_mhz,
        };

        *self.hardware_config.lock() = Some(config);
        Ok(())
    }

    pub fn get_ia_config(&self) -> Option<IaConfig> {
        self.ia_config.lock().clone()
    }

    pub fn get_device_config(&self) -> Option<GlobalDeviceConfig> {
        self.device_config.lock().clone()
    }

    pub fn get_security_config(&self) -> Option<GlobalSecurityConfig> {
        self.security_config.lock().clone()
    }

    pub fn get_hardware_config(&self) -> Option<GlobalHardwareConfig> {
        self.hardware_config.lock().clone()
    }

    pub fn is_loaded(&self) -> bool {
        self.ia_config.lock().is_some()
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
        serde_yaml::from_str(yaml_str)
            .map_err(|e| format!("YAML parse error: {}", e))
    }

    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self)
            .map_err(|e| format!("YAML serialize error: {}", e))
    }
}




