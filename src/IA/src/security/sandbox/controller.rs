use alloc::collections::BTreeMap as HashMap;
use alloc::format;
use crate::prelude::{String, Vec};
use alloc::sync::Arc;
use spin::Mutex;
use super::crypto_core::EncryptedVault;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum ActionType {
    KernelScheduler,
    KernelCPU,
    KernelMemory,
    KernelThermal,
    KernelPower,
    KernelReboot,
    StorageRead,
    StorageWrite,
    StorageAllocate,
    StorageDeallocate,
    DeviceControl,
    DeviceEnable,
    DeviceDisable,
    CommunicationSend,
    CommunicationReceive,
    CommunicationConfig,
    SystemIntegrity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PermissionLevel {
    Denied,
    ReadOnly,
    Restricted,
    Full,
}

#[derive(Debug, Clone)]
pub struct SandboxAction {
    pub action_type: ActionType,
    pub timestamp: u64,
    pub params: HashMap<String, String>,
    pub requester: String,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct PermissionPolicy {
    pub action: ActionType,
    pub level: PermissionLevel,
    pub max_frequency_per_minute: Option<u32>,
    pub critical_action: bool,
}

pub struct SandboxController {
    permissions: Arc<Mutex<HashMap<ActionType, PermissionLevel>>>,
    policies: Arc<Mutex<Vec<PermissionPolicy>>>,
    vault: Arc<EncryptedVault>,
    action_counter: Arc<Mutex<HashMap<ActionType, u32>>>,
    last_critical_action: Arc<Mutex<Option<u64>>>,
    quarantine_mode: Arc<Mutex<bool>>,
}

impl SandboxController {
    pub fn new() -> Self {
        let mut permissions = HashMap::new();

        permissions.insert(ActionType::KernelScheduler, PermissionLevel::Denied);
        permissions.insert(ActionType::KernelCPU, PermissionLevel::ReadOnly);
        permissions.insert(ActionType::KernelMemory, PermissionLevel::ReadOnly);
        permissions.insert(ActionType::KernelThermal, PermissionLevel::ReadOnly);
        permissions.insert(ActionType::KernelPower, PermissionLevel::Denied);
        permissions.insert(ActionType::KernelReboot, PermissionLevel::Denied);
        permissions.insert(ActionType::StorageRead, PermissionLevel::ReadOnly);
        permissions.insert(ActionType::StorageWrite, PermissionLevel::Restricted);
        permissions.insert(ActionType::StorageAllocate, PermissionLevel::Restricted);
        permissions.insert(ActionType::StorageDeallocate, PermissionLevel::Restricted);
        permissions.insert(ActionType::DeviceControl, PermissionLevel::Restricted);
        permissions.insert(ActionType::DeviceEnable, PermissionLevel::Restricted);
        permissions.insert(ActionType::DeviceDisable, PermissionLevel::Restricted);
        permissions.insert(ActionType::CommunicationSend, PermissionLevel::Restricted);
        permissions.insert(ActionType::CommunicationReceive, PermissionLevel::Full);
        permissions.insert(ActionType::CommunicationConfig, PermissionLevel::Restricted);
        permissions.insert(ActionType::SystemIntegrity, PermissionLevel::Full);

        let mut policies = Vec::new();

        policies.push(PermissionPolicy {
            action: ActionType::KernelReboot,
            level: PermissionLevel::Denied,
            max_frequency_per_minute: None,
            critical_action: true,
        });

        policies.push(PermissionPolicy {
            action: ActionType::KernelPower,
            level: PermissionLevel::Restricted,
            max_frequency_per_minute: Some(5),
            critical_action: true,
        });

        policies.push(PermissionPolicy {
            action: ActionType::DeviceDisable,
            level: PermissionLevel::Restricted,
            max_frequency_per_minute: Some(10),
            critical_action: false,
        });

        SandboxController {
            permissions: Arc::new(Mutex::new(permissions)),
            policies: Arc::new(Mutex::new(policies)),
            vault: Arc::new(EncryptedVault::new()),
            action_counter: Arc::new(Mutex::new(HashMap::new())),
            last_critical_action: Arc::new(Mutex::new(None)),
            quarantine_mode: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn validate_action(
        &self,
        action_type: ActionType,
        params: HashMap<String, String>,
    ) -> Result<bool, String> {
        if *self.quarantine_mode.lock() {
            self.record_action_internal(
                action_type.clone(),
                params,
                "ia",
                false,
                "Sandbox en mode quarantaine",
            )
            .await;
            return Err("Sandbox quarantine mode active".into());
        }

        let permissions = self.permissions.lock();
        let level = permissions
            .get(&action_type)
            .cloned()
            .unwrap_or(PermissionLevel::Denied);

        drop(permissions);

        match level {
            PermissionLevel::Denied => {
                self.record_action_internal(
                    action_type.clone(),
                    params,
                    "ia",
                    false,
                    "Action denied by policy",
                )
                .await;
                Err("Action denied".into())
            }
            PermissionLevel::ReadOnly => {
                if self.is_write_action(&action_type) {
                    self.record_action_internal(
                        action_type.clone(),
                        params,
                        "ia",
                        false,
                        "Write action denied (read-only mode)",
                    )
                    .await;
                    return Err("Read-only policy violation".into());
                }
                self.check_frequency_limit(&action_type).await
            }
            PermissionLevel::Restricted => self.check_frequency_limit(&action_type).await,
            PermissionLevel::Full => {
                self.record_action_internal(action_type, params, "ia", true, "Allowed")
                    .await;
                Ok(true)
            }
        }
    }

    async fn check_frequency_limit(&self, action_type: &ActionType) -> Result<bool, String> {
        let mut counter = self.action_counter.lock();
        let current_count = counter.entry(action_type.clone()).or_insert(0);
        *current_count += 1;

        let policies = self.policies.lock();
        for policy in policies.iter() {
            if policy.action == *action_type {
                if let Some(max_freq) = policy.max_frequency_per_minute {
                    if *current_count > max_freq {
                        drop(policies);
                        self.record_action_internal(
                            action_type.clone(),
                            HashMap::new(),
                            "ia",
                            false,
                            &format!("Frequency limit exceeded (max {} per min)", max_freq),
                        )
                        .await;
                        return Err("Frequency limit exceeded".into());
                    }
                }

                if policy.critical_action {
                    let mut last_critical = self.last_critical_action.lock();
                    let now = 0u64;
                    if let Some(last_time) = *last_critical {
                        if now - last_time < 5 {
                            drop(policies);
                            self.record_action_internal(
                                action_type.clone(),
                                HashMap::new(),
                                "ia",
                                false,
                                "Critical action cooldown active (5 seconds)",
                            )
                            .await;
                            return Err("Critical action cooldown".into());
                        }
                    }
                    *last_critical = Some(now);
                }
                break;
            }
        }

        drop(policies);
        self.record_action_internal(action_type.clone(), HashMap::new(), "ia", true, "Allowed")
            .await;
        Ok(true)
    }

    async fn record_action_internal(
        &self,
        action_type: ActionType,
        params: HashMap<String, String>,
        requester: &str,
        allowed: bool,
        reason: &str,
    ) {
        let _action = SandboxAction {
            action_type,
            timestamp: 0,
            params,
            requester: requester.into(),
            allowed,
            reason: reason.into(),
        };

        let _ = self.vault;
    }

    fn is_write_action(&self, action: &ActionType) -> bool {
        matches!(
            action,
            ActionType::StorageWrite
                | ActionType::StorageAllocate
                | ActionType::StorageDeallocate
                | ActionType::DeviceDisable
                | ActionType::DeviceEnable
                | ActionType::KernelPower
                | ActionType::KernelReboot
        )
    }
}

impl Default for SandboxController {
    fn default() -> Self {
        Self::new()
    }
}
