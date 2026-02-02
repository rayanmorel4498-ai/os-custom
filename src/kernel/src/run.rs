use alloc::sync::Arc;
use alloc::string::String;
use alloc::format;
use crate::services::{HardwareBridge, HardwareMessage, HardwareResponse};
use crate::config::{ConfigLoader, KernelConfig, HardwareApiPoolConfig};
use redmi_hardware::config::HardwareCommandPool;

fn build_hardware_pool(config: &HardwareApiPoolConfig) -> Result<Arc<HardwareCommandPool>, String> {
    if !config.enabled {
        return Err("Hardware pool disabled".into());
    }

    Ok(Arc::new(HardwareCommandPool::new(
        config.resources.max_pending_requests,
        config.resources.max_pending_responses,
    )))
}

pub struct KernelClient {
    primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
    hardware_bridge: HardwareBridge,
    kernel_config: KernelConfig,
    hardware_config: HardwareApiPoolConfig,
}

impl KernelClient {
    pub fn connect(
        primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
    ) -> Result<Self, String> {
        let kernel_config = KernelConfig::default();
        let hardware_config = HardwareApiPoolConfig::default();
        let hardware_pool = build_hardware_pool(&hardware_config)?;
        let hardware_bridge = HardwareBridge::with_pool(primary_loop.clone(), hardware_pool)?;
        
        Ok(Self {
            primary_loop,
            hardware_bridge,
            kernel_config,
            hardware_config,
        })
    }

    pub fn with_config(
        primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
        yaml_content: &str,
    ) -> Result<Self, String> {
        let kernel_config = ConfigLoader::load_kernel_config(yaml_content)?;
        let hardware_config = ConfigLoader::load_hardware_config(yaml_content)?;
        let hardware_pool = build_hardware_pool(&hardware_config)?;
        let hardware_bridge = HardwareBridge::with_pool(primary_loop.clone(), hardware_pool)?;
        
        Ok(Self {
            primary_loop,
            hardware_bridge,
            kernel_config,
            hardware_config,
        })
    }

    pub fn get_kernel_config(&self) -> &KernelConfig {
        &self.kernel_config
    }

    pub fn get_hardware_config(&self) -> &HardwareApiPoolConfig {
        &self.hardware_config
    }

    pub fn get_hardware_status(&self) -> Result<(usize, String), String> {
        let count = self.hardware_bridge.get_hardware_count();
        Ok((count, format!("Hardware available: {} sessions", count)))
    }

    pub fn query_cpu_status(&self, token: &str) -> Result<HardwareResponse, String> {
        self.hardware_bridge.send_message(HardwareMessage::GetCpuStatus, token)
    }

    pub fn query_gpu_status(&self, token: &str) -> Result<HardwareResponse, String> {
        self.hardware_bridge.send_message(HardwareMessage::GetGpuStatus, token)
    }

    pub fn query_ram_status(&self, token: &str) -> Result<HardwareResponse, String> {
        self.hardware_bridge.send_message(HardwareMessage::GetRamStatus, token)
    }

    pub fn query_power_status(&self, token: &str) -> Result<HardwareResponse, String> {
        self.hardware_bridge.send_message(HardwareMessage::GetPowerStatus, token)
    }

    pub fn query_thermal_status(&self, token: &str) -> Result<HardwareResponse, String> {
        self.hardware_bridge.send_message(HardwareMessage::GetThermalStatus, token)
    }

    pub fn query_hardware(&self, message: HardwareMessage, token: &str) -> Result<HardwareResponse, String> {
        self.hardware_bridge.send_message_async(message, token)
    }

    pub fn poll_hardware_health(&self) -> Result<usize, String> {
        let processed = self.hardware_bridge.process_pending_hardware_requests();
        Ok(processed)
    }

}

pub fn run_kernel_with_hardware(
    primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
) -> Result<KernelClient, String> {
    KernelClient::connect(primary_loop)
}

pub fn check_hardware_availability(
    primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
) -> bool {
    !primary_loop.get_hardware_sessions().is_empty()
}

pub fn get_hardware_session_count(
    primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
) -> usize {
    primary_loop.get_hardware_sessions().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_pool_disabled_returns_err() {
        let mut cfg = HardwareApiPoolConfig::default();
        cfg.enabled = false;
        assert!(build_hardware_pool(&cfg).is_err());
    }

    #[test]
    fn build_pool_creates_empty_pool() {
        let mut cfg = HardwareApiPoolConfig::default();
        cfg.resources.max_pending_requests = 2;
        cfg.resources.max_pending_responses = 2;
        let pool = build_hardware_pool(&cfg).unwrap();
        let pending = pool.pending_request_count();
        assert_eq!(pending, 0);
    }
}
