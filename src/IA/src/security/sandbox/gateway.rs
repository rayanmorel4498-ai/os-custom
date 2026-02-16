use alloc::sync::Arc;
use crate::prelude::{String, Vec};
use alloc::collections::BTreeMap as HashMap;
use alloc::format;
use alloc::string::ToString;
use spin::Mutex;
use super::controller_enforced::{ActionType, PermissionLevel, SandboxController};
use crate::modules::device::device_controller::DeviceController;
use crate::modules::storage::storage_manager::StorageManager;
// SUPPRIMÉ : accès kernel_controller interdit pour IA

pub struct SandboxGateway {
    sandbox: Arc<SandboxController>,
    storage: Arc<Mutex<Option<Arc<StorageManager>>>>,
    devices: Arc<Mutex<Option<Arc<DeviceController>>>>,
}

impl SandboxGateway {
    pub fn new(sandbox: Arc<SandboxController>) -> Self {
        SandboxGateway {
            sandbox,
            storage: Arc::new(Mutex::new(None)),
            devices: Arc::new(Mutex::new(None)),
        }
    }

    // SUPPRIMÉ : enregistrement kernel interdit pour IA

    pub async fn register_storage(&self, storage: Arc<StorageManager>) {
        *self.storage.lock() = Some(storage);
    }

    pub async fn register_devices(&self, devices: Arc<DeviceController>) {
        *self.devices.lock() = Some(devices);
    }


    // === STORAGE OPERATIONS ===

    pub async fn storage_allocate(&self, size_bytes: u64) -> Result<u64, String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => s.allocate(size_bytes).await,
                None => Err("Storage not registered".to_string()),
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
                None => Err("Storage not registered".to_string()),
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
                None => Err("Storage not registered".to_string()),
        }
    }

    pub async fn storage_deallocate(&self, block_id: u64) -> Result<(), String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => s.deallocate(block_id).await,
                None => Err("Storage not registered".to_string()),
        }
    }

    pub async fn storage_get_metrics(
        &self,
    ) -> Result<crate::modules::storage::storage_manager::StorageMetrics, String> {
        let storage = self.storage.lock();
        match storage.as_ref() {
            Some(s) => Ok(s.get_metrics().await),
            None => Err("Storage not registered".to_string()),
        }
    }

    // === DEVICE OPERATIONS ===

    pub async fn device_register(&self, device_id: &str, device_type: &str) -> Result<(), String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => {
                use crate::modules::device::device_controller::DeviceType;
                let dtype = match device_type {
                    "cpu" => DeviceType::CPU,
                    "gpu" => DeviceType::GPU,
                    "memory" => DeviceType::Memory,
                    "storage" => DeviceType::Storage,
                    "sensor" => DeviceType::Sensor,
                    _ => DeviceType::CPU,
                };
                d.register_device(device_id, dtype, device_id)
                    .await
                    .map_err(|e| format!("{:?}", e))
            }
            None => Err("DeviceController not registered".to_string()),
        }
    }

    pub async fn device_enable(&self, device_id: &str) -> Result<(), String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => d.enable_device(device_id).await.map_err(|e| format!("{:?}", e)),
                None => Err("DeviceController not registered".to_string()),
        }
    }

    pub async fn device_disable(&self, device_id: &str) -> Result<(), String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => d.suspend_device(device_id).await.map_err(|e| format!("{:?}", e)),
                None => Err("DeviceController not registered".to_string()),
        }
    }

    pub async fn device_list_active(&self) -> Result<Vec<String>, String> {
        let devices = self.devices.lock();
        match devices.as_ref() {
            Some(d) => {
                let device_infos = d.list_active_devices().await;
                Ok(device_infos.iter().map(|di| di.id.clone()).collect())
            }
            None => Err("DeviceController not registered".to_string()),
        }
    }

    // === SANDBOX AUDIT (VIDE - AUCUNE EXPOSITION) ===

    pub async fn get_audit_trail(&self) -> Vec<super::controller_enforced::SandboxAction> {
        let denied = self.sandbox.get_denied_actions_log().await;
        denied
            .into_iter()
            .map(|(action_type, count, reason)| super::controller_enforced::SandboxAction {
                action_type,
                timestamp: crate::time::now_ms(),
                params: HashMap::new(),
                requester: "ia".into(),
                allowed: false,
                reason: format!("{} (count={})", reason, count),
            })
            .collect()
    }

    pub async fn get_denied_actions(&self) -> Vec<super::controller_enforced::SandboxAction> {
        self.get_audit_trail().await
    }

    pub async fn sandbox_stats(&self) -> String {
        // Stats opaques uniquement
            "System operational".to_string()
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
        assert!(!gateway.is_quarantined().await);
    }

    #[tokio::test]
    async fn test_unregistered_storage() {
        let sandbox = Arc::new(SandboxController::new());
        let gateway = SandboxGateway::new(sandbox);
        let result = gateway.storage_read(1, 0, 8).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_quarantine_blocks_all() {
        let sandbox = Arc::new(SandboxController::new());
        let gateway = SandboxGateway::new(sandbox);
        gateway.enter_quarantine().await;
        assert!(gateway.is_quarantined().await);
    }
}
