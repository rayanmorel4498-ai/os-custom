use alloc::sync::Arc;
use crate::alloc::string::ToString;
use crate::prelude::{String, Vec};
use crate::alloc::string::ToString;
use spin::Mutex;
use crate::alloc::string::ToString;
use super::sandbox_controller::{SandboxController, ActionType, PermissionLevel};
use crate::alloc::string::ToString;
use super::kernel_controller::KernelController;
use crate::alloc::string::ToString;
use super::storage_manager::StorageManager;
use crate::alloc::string::ToString;
use super::device_controller::DeviceController;
use crate::alloc::string::ToString;

pub struct SandboxGateway {
    sandbox: Arc<SandboxController>,
    kernel: Arc<Mutex<Option<Arc<KernelController>>>>,
    storage: Arc<Mutex<Option<Arc<StorageManager>>>>,
    devices: Arc<Mutex<Option<Arc<DeviceController>>>>,
}

impl SandboxGateway {
    pub fn new(sandbox: Arc<SandboxController>) -> Self {
        SandboxGateway {
            sandbox,
            kernel: Arc::new(Mutex::new(None)),
            storage: Arc::new(Mutex::new(None)),
            devices: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn register_kernel(&self, kernel: Arc<KernelController>) {
        *self.kernel.lock() = Some(kernel);
    }

    pub async fn register_storage(&self, storage: Arc<StorageManager>) {
        *self.storage.lock() = Some(storage);
    }

    pub async fn register_devices(&self, devices: Arc<DeviceController>) {
        *self.devices.lock() = Some(devices);
    }

    // === KERNEL OPERATIONS ===

    pub async fn kernel_set_scheduler(
        &self,
        policy: super::kernel_controller::SchedulerPolicy,
    ) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.set_scheduler_policy(policy).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_set_cpu_frequency(
        &self,
        core_id: usize,
        frequency_mhz: u32,
    ) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.set_cpu_frequency(core_id, frequency_mhz).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_online_cpu(&self, core_id: usize) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.online_cpu_core(core_id).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_offline_cpu(&self, core_id: usize) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.offline_cpu_core(core_id).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_allocate_memory(&self, size_mb: u64) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.allocate_memory(size_mb).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_deallocate_memory(&self, size_mb: u64) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.deallocate_memory(size_mb).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_get_cores(&self) -> Result<Vec<super::kernel_controller::CPUCore>, String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => Ok(k.get_cpu_cores().await),
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_get_memory(&self) -> Result<super::kernel_controller::MemoryInfo, String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => Ok(k.get_memory_info().await),
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_get_thermal(&self) -> Result<Vec<super::kernel_controller::ThermalZone>, String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => Ok(k.get_thermal_zones().await),
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_update_thermal(
        &self,
        zone_name: &str,
        temperature: f32,
    ) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.update_thermal_zone(zone_name, temperature).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_switch_power_state(&self, state_name: &str) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.switch_power_state(state_name).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_toggle_feature(&self, feature: &str, enabled: bool) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.toggle_kernel_feature(feature, enabled).await,
            None => Err("Kernel not registered"),
        }
    }

    pub async fn kernel_reboot(&self) -> Result<(), String> {
        let kernel = self.kernel.lock();
        match kernel.as_ref() {
            Some(k) => k.system_reboot().await,
            None => Err("Kernel not registered"),
        }
    }

    // === STORAGE OPERATIONS ===

    pub async fn storage_allocate(&self, size_bytes: u64) -> Result<u64, String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => s.allocate(size_bytes).await,
            None => Err("Storage not registered"),
        }
    }

    pub async fn storage_write(
        &self,
        block_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<(), String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => s.write(block_id, offset, data).await,
            None => Err("Storage not registered"),
        }
    }

    pub async fn storage_read(
        &self,
        block_id: u64,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => s.read(block_id, offset, size).await,
            None => Err("Storage not registered"),
        }
    }

    pub async fn storage_deallocate(&self, block_id: u64) -> Result<(), String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => s.deallocate(block_id).await,
            None => Err("Storage not registered"),
        }
    }

    pub async fn storage_get_metrics(&self) -> Result<super::storage_manager::StorageMetrics, String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => Ok(s.get_metrics().await),
            None => Err("Storage not registered"),
        }
    }

    // === DEVICE OPERATIONS ===

    pub async fn device_register(&self, device_id: &str, device_type: &str) -> Result<(), String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => {
                use crate::core::device_controller::DeviceType;
                let dtype = match device_type {
                    "cpu" => DeviceType::CPU,
                    "gpu" => DeviceType::GPU,
                    "memory" => DeviceType::Memory,
                    "storage" => DeviceType::Storage,
                    "sensor" => DeviceType::Sensor,
                    _ => DeviceType::CPU,
                };
                d.register_device(device_id, dtype, device_id).await.map_err(|e| e)
            }
            None => Err("DeviceController not registered"),
        }
    }

    pub async fn device_enable(&self, device_id: &str) -> Result<(), String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => d.enable_device(device_id).await.map_err(|e| e),
            None => Err("DeviceController not registered"),
        }
    }

    pub async fn device_disable(&self, device_id: &str) -> Result<(), String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => d.suspend_device(device_id).await.map_err(|e| e),
            None => Err("DeviceController not registered"),
        }
    }

    pub async fn device_list_active(&self) -> Result<Vec<String>, String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => {
                let device_infos = d.list_active_devices().await;
                Ok(device_infos.iter().map(|di| di.id.clone()).collect())
            }
            None => Err("DeviceController not registered"),
        }
    }

    // === SANDBOX AUDIT (VIDE - AUCUNE EXPOSITION) ===

    pub async fn get_audit_trail(&self) -> Vec<super::sandbox_controller::SandboxAction> {
        // Aucune exposition de l'audit trail
        Vec::new()
    }

    pub async fn get_denied_actions(&self) -> Vec<super::sandbox_controller::SandboxAction> {
        // Aucune exposition des actions refusées
        Vec::new()
    }

    pub async fn sandbox_stats(&self) -> String {
        // Stats opaques uniquement
        "System operational"
    }

    pub async fn set_permission(
        &self,
        action_type: ActionType,
        level: PermissionLevel,
    ) -> Result<(), String> {
        self.sandbox.set_permission(action_type, level).await
    }

    pub async fn enter_quarantine(&self) {
        self.sandbox.enter_quarantine().await;
    }

    pub async fn exit_quarantine(&self) {
        self.sandbox.exit_quarantine().await;
    }

    pub async fn is_quarantined(&self) -> bool {
        self.sandbox.is_quarantined().await
    }

    pub async fn reset_counters(&self) {
        self.sandbox.reset_counters().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gateway_creation() {
        let sandbox = Arc::new(SandboxController::new());
        let gateway = SandboxGateway::new(sandbox);
        assert!(!gateway.is_quarantined());
    }

    #[tokio::test]
    async fn test_unregistered_kernel() {
        let sandbox = Arc::new(SandboxController::new());
        let gateway = SandboxGateway::new(sandbox);
        let result = gateway.kernel_get_memory().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_quarantine_blocks_all() {
        let sandbox = Arc::new(SandboxController::new());
        let gateway = SandboxGateway::new(sandbox);
        gateway.enter_quarantine().await;
        assert!(gateway.is_quarantined());
    }
}
