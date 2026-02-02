use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    pub version: String,
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub boot_state: String,
    pub subsystems: Vec<Subsystem>,
    pub sandbox_config: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subsystem {
    pub name: String,
    pub enabled: bool,
    pub priority: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub modules: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub cpu_quota_percent: u32,
    pub memory_quota_mb: u32,
    pub fd_limit: u32,
    pub allowed_syscalls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareApiPoolConfig {
    pub enabled: bool,
    pub request_handlers: Vec<RequestHandler>,
    pub resources: Resources,
    pub hardware_interfaces: HardwareInterfaces,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHandler {
    pub name: String,
    pub timeout_ms: u32,
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resources {
    pub max_pending_requests: u32,
    pub max_pending_responses: u32,
    pub request_id_bits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInterfaces {
    pub cpu: CpuInterface,
    pub gpu: GpuInterface,
    pub ram: RamInterface,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInterface {
    pub cores: u32,
    pub frequency_mhz: u32,
    pub status_check_interval_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInterface {
    pub enabled: bool,
    pub frequency_mhz: u32,
    pub memory_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RamInterface {
    pub total_mb: u32,
    pub available_mb: u32,
    pub page_size_kb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureYamlRoot {
    pub kernel: KernelConfig,
    pub hardware_api_pool: HardwareApiPoolConfig,
}

impl KernelConfig {
    pub fn is_subsystem_enabled(&self, name: &str) -> bool {
        self.subsystems
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.enabled)
            .unwrap_or(false)
    }

    pub fn get_subsystem_priority(&self, name: &str) -> Option<String> {
        self.subsystems
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.priority.clone())
    }
}

impl HardwareApiPoolConfig {
    pub fn get_handler_timeout(&self, handler_name: &str) -> Option<u32> {
        self.request_handlers
            .iter()
            .find(|h| h.name == handler_name)
            .map(|h| h.timeout_ms)
    }

    pub fn get_handler_retry_count(&self, handler_name: &str) -> Option<u32> {
        self.request_handlers
            .iter()
            .find(|h| h.name == handler_name)
            .map(|h| h.retry_count)
    }
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            version: "15c".into(),
            major: 1,
            minor: 0,
            patch: 0,
            boot_state: "PreBoot".into(),
            subsystems: alloc::vec![],
            sandbox_config: SandboxConfig::default(),
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            cpu_quota_percent: 50,
            memory_quota_mb: 512,
            fd_limit: 32,
            allowed_syscalls: 128,
        }
    }
}

impl Default for HardwareApiPoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            request_handlers: alloc::vec![],
            resources: Resources::default(),
            hardware_interfaces: HardwareInterfaces::default(),
        }
    }
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            max_pending_requests: 1000,
            max_pending_responses: 1000,
            request_id_bits: 64,
        }
    }
}

impl Default for HardwareInterfaces {
    fn default() -> Self {
        Self {
            cpu: CpuInterface::default(),
            gpu: GpuInterface::default(),
            ram: RamInterface::default(),
        }
    }
}

impl Default for CpuInterface {
    fn default() -> Self {
        Self {
            cores: 8,
            frequency_mhz: 2400,
            status_check_interval_ms: 1000,
        }
    }
}

impl Default for GpuInterface {
    fn default() -> Self {
        Self {
            enabled: true,
            frequency_mhz: 900,
            memory_mb: 2048,
        }
    }
}

impl Default for RamInterface {
    fn default() -> Self {
        Self {
            total_mb: 6144,
            available_mb: 5120,
            page_size_kb: 4,
        }
    }
}
