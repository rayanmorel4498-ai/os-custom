use alloc::string::String;
use crate::config::types::{SecureYamlRoot, KernelConfig, HardwareApiPoolConfig};

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load_from_yaml(yaml_content: &str) -> Result<SecureYamlRoot, String> {
        serde_yaml::from_str(yaml_content).map_err(|e| {
            alloc::format!("Failed to parse YAML: {}", e)
        })
    }

    pub fn load_kernel_config(yaml_content: &str) -> Result<KernelConfig, String> {
        let root = Self::load_from_yaml(yaml_content)?;
        Ok(root.kernel)
    }

    pub fn load_hardware_config(yaml_content: &str) -> Result<HardwareApiPoolConfig, String> {
        let root = Self::load_from_yaml(yaml_content)?;
        Ok(root.hardware_api_pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_kernel_config() {
        let yaml = r#"
kernel:
  version: "15c"
  major: 1
  minor: 0
  patch: 0
  boot_state: "PreBoot"
  subsystems: []
  sandbox_config:
    cpu_quota_percent: 50
    memory_quota_mb: 512
    fd_limit: 32
    allowed_syscalls: 128
hardware_api_pool:
  enabled: true
  request_handlers: []
  resources:
    max_pending_requests: 1000
    max_pending_responses: 1000
    request_id_bits: 64
  hardware_interfaces:
    cpu:
      cores: 8
      frequency_mhz: 2400
      status_check_interval_ms: 1000
    gpu:
      enabled: true
      frequency_mhz: 900
      memory_mb: 2048
    ram:
      total_mb: 6144
      available_mb: 5120
      page_size_kb: 4
"#;
        let config = ConfigLoader::load_kernel_config(yaml);
        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.version, "15c");
        assert_eq!(cfg.major, 1);
    }
}
