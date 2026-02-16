use alloc::collections::BTreeMap as HashMap;
use crate::prelude::{String, Vec};
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use spin::Mutex;
use super::crypto_core::EncryptedVault;
use crate::time;
use crate::utils::{logger, observability};
use crate::utils::error::ErrorCode;

#[derive(Debug, Clone, PartialEq, Hash, Eq, Ord, PartialOrd)]
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

/// Contrôleur sandbox avec enforcement RÉEL des permissions
pub struct SandboxController {
    permissions: Arc<Mutex<HashMap<ActionType, PermissionLevel>>>,
    policies: Arc<Mutex<Vec<PermissionPolicy>>>,
    vault: Arc<EncryptedVault>,
    action_counter: Arc<Mutex<HashMap<ActionType, u32>>>,
    last_critical_action: Arc<Mutex<Option<u64>>>,
    quarantine_mode: Arc<Mutex<bool>>,
    quarantine_until: Arc<Mutex<Option<u64>>>,
    allowlist: Arc<Mutex<HashMap<ActionType, bool>>>,
    module_limits: Arc<Mutex<HashMap<String, ModuleLimits>>>,
    module_caps: Arc<Mutex<HashMap<String, ModuleCapabilities>>>,
    module_usage: Arc<Mutex<HashMap<String, ModuleUsage>>>,
    
    // Enforcement RÉEL: bloque les actions au lieu de les valider
    denied_actions_log: Arc<Mutex<Vec<DeniedAction>>>,
    enforcement_active: Arc<Mutex<bool>>,
    blocked_until: Arc<Mutex<HashMap<ActionType, u64>>>,
}

#[derive(Debug, Clone)]
struct DeniedAction {
    action_type: ActionType,
    timestamp: u64,
    reason: String,
    blocked_count: u32,
}

#[derive(Clone, Copy)]
pub struct ModuleLimits {
    pub cpu_ms: u64,
    pub ram_mb: u64,
    pub io_ops: u64,
    pub window_ms: u64,
    pub breaker_threshold: u32,
    pub breaker_open_ms: u64,
}

#[derive(Clone, Copy)]
pub struct ModuleCapabilities {
    pub fs: bool,
    pub network: bool,
    pub ipc: bool,
    pub gpu: bool,
    pub kernel: bool,
    pub device: bool,
    pub storage: bool,
    pub system: bool,
    pub memory: bool,
    pub power: bool,
}

#[derive(Clone, Copy)]
struct ModuleUsage {
    window_start_ms: u64,
    cpu_ms: u64,
    ram_mb: u64,
    io_ops: u64,
    abuse_count: u32,
    breaker_until_ms: u64,
}

impl SandboxController {
    pub fn new() -> Self {
        let mut permissions = HashMap::new();
        
        // Permissions par défaut - l'IA a accès limité aux ressources système
        permissions.insert(ActionType::KernelScheduler, PermissionLevel::Restricted);
        permissions.insert(ActionType::KernelCPU, PermissionLevel::Restricted);
        permissions.insert(ActionType::KernelMemory, PermissionLevel::Restricted);
        permissions.insert(ActionType::KernelThermal, PermissionLevel::Full);
        permissions.insert(ActionType::KernelPower, PermissionLevel::Denied);
        permissions.insert(ActionType::KernelReboot, PermissionLevel::Denied);
        permissions.insert(ActionType::StorageRead, PermissionLevel::Full);
        permissions.insert(ActionType::StorageWrite, PermissionLevel::Restricted);
        permissions.insert(ActionType::StorageAllocate, PermissionLevel::Restricted);
        permissions.insert(ActionType::StorageDeallocate, PermissionLevel::Restricted);
        permissions.insert(ActionType::DeviceControl, PermissionLevel::Restricted);
        permissions.insert(ActionType::DeviceEnable, PermissionLevel::Denied);
        permissions.insert(ActionType::DeviceDisable, PermissionLevel::Denied);
        permissions.insert(ActionType::CommunicationSend, PermissionLevel::Restricted);
        permissions.insert(ActionType::CommunicationReceive, PermissionLevel::Full);
        permissions.insert(ActionType::CommunicationConfig, PermissionLevel::Denied);
        permissions.insert(ActionType::SystemIntegrity, PermissionLevel::Full);
        
        let mut policies = Vec::new();
        
        // Politiques de sécurité: fréquence limitée pour les opérations sensibles
        policies.push(PermissionPolicy {
            action: ActionType::StorageWrite,
            level: PermissionLevel::Restricted,
            max_frequency_per_minute: Some(100),
            critical_action: false,
        });
        
        policies.push(PermissionPolicy {
            action: ActionType::CommunicationSend,
            level: PermissionLevel::Restricted,
            max_frequency_per_minute: Some(50),
            critical_action: false,
        });
        
        policies.push(PermissionPolicy {
            action: ActionType::KernelMemory,
            level: PermissionLevel::Restricted,
            max_frequency_per_minute: Some(200),
            critical_action: true,
        });
        
        SandboxController {
            permissions: Arc::new(Mutex::new(permissions)),
            policies: Arc::new(Mutex::new(policies)),
            vault: Arc::new(EncryptedVault::new()),
            action_counter: Arc::new(Mutex::new(HashMap::new())),
            last_critical_action: Arc::new(Mutex::new(None)),
            quarantine_mode: Arc::new(Mutex::new(false)),
            quarantine_until: Arc::new(Mutex::new(None)),
            allowlist: Arc::new(Mutex::new(HashMap::new())),
            module_limits: Arc::new(Mutex::new(HashMap::new())),
            module_caps: Arc::new(Mutex::new(HashMap::new())),
            module_usage: Arc::new(Mutex::new(HashMap::new())),
            denied_actions_log: Arc::new(Mutex::new(Vec::new())),
            enforcement_active: Arc::new(Mutex::new(true)),
            blocked_until: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allowlist_action(&self, action_type: ActionType, allowed: bool) {
        let mut allowlist = self.allowlist.lock();
        allowlist.insert(action_type, allowed);
    }

    pub async fn set_module_limits(&self, module: &str, cpu_ms: u64, ram_mb: u64) {
        let mut limits = self.module_limits.lock();
        limits.insert(
            module.into(),
            ModuleLimits {
                cpu_ms,
                ram_mb,
                io_ops: 256,
                window_ms: 1_000,
                breaker_threshold: 5,
                breaker_open_ms: 5_000,
            },
        );
    }

    pub async fn set_module_limits_full(
        &self,
        module: &str,
        cpu_ms: u64,
        ram_mb: u64,
        io_ops: u64,
        window_ms: u64,
        breaker_threshold: u32,
        breaker_open_ms: u64,
    ) {
        let mut limits = self.module_limits.lock();
        limits.insert(
            module.into(),
            ModuleLimits {
                cpu_ms,
                ram_mb,
                io_ops,
                window_ms: window_ms.max(1),
                breaker_threshold: breaker_threshold.max(1),
                breaker_open_ms,
            },
        );
    }

    pub async fn set_module_capabilities(&self, module: &str, caps: ModuleCapabilities) {
        let mut map = self.module_caps.lock();
        map.insert(module.into(), caps);
    }

    pub async fn get_abuse_count(&self, module: &str) -> u32 {
        self.module_usage
            .lock()
            .get(module)
            .map(|u| u.abuse_count)
            .unwrap_or(0)
    }

    pub async fn set_permission(
        &self,
        action_type: ActionType,
        level: PermissionLevel,
    ) -> Result<(), String> {
        let mut permissions = self.permissions.lock();
        permissions.insert(action_type, level);
        Ok(())
    }

    pub async fn is_quarantined(&self) -> bool {
        let now = Self::current_timestamp();
        if let Some(until) = *self.quarantine_until.lock() {
            if now >= until {
                *self.quarantine_mode.lock() = false;
                *self.quarantine_until.lock() = None;
            }
        }
        *self.quarantine_mode.lock()
    }

    pub async fn reset_counters(&self) {
        self.action_counter.lock().clear();
        self.denied_actions_log.lock().clear();
        self.blocked_until.lock().clear();
        self.module_usage.lock().clear();
        *self.last_critical_action.lock() = None;
    }
    
    /// Valide une action et l'ENFORCES (bloque si refusée)
    pub async fn validate_action(
        &self,
        action_type: ActionType,
        params: HashMap<String, String>,
    ) -> Result<bool, String> {
        let now = Self::current_timestamp();
        if let Some(until) = *self.quarantine_until.lock() {
            if now >= until {
                *self.quarantine_mode.lock() = false;
                *self.quarantine_until.lock() = None;
            }
        }
        if params.is_empty() {
        }
        // Vérification d'abord si enforcement est actif
        let enforcement = *self.enforcement_active.lock();
        if !enforcement {
            return Ok(true);
        }
        
        // Vérification mode quarantaine: bloque TOUT
        if *self.quarantine_mode.lock() {
            let reason = format!("Mode quarantaine actif - action {} bloquée", 
                format!("{:?}", action_type));
            self.log_denied_action(action_type.clone(), reason.clone()).await;
            return Err(format!("BLOCKED: {}", reason));
        }
        
        // Vérification timing de déblocage (cooling period)
        let blocked_until = self.blocked_until.lock();
        if let Some(&until_time) = blocked_until.get(&action_type) {
            let now = Self::current_timestamp();
            if now < until_time {
                let reason = format!("Action {} verrouillée jusqu'à {}", 
                    format!("{:?}", action_type), until_time);
                drop(blocked_until);
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
        }
        drop(blocked_until);
        
        // Récupération du niveau de permission
        let permissions = self.permissions.lock();
        let permission = permissions
            .get(&action_type)
            .cloned()
            .unwrap_or(PermissionLevel::Denied);
        drop(permissions);

        if self.is_critical_action(&action_type) {
            let allowlist = self.allowlist.lock();
            let allowed = allowlist.get(&action_type).copied().unwrap_or(false);
            if !allowed {
                let reason = format!("Action critique non allowlistée: {:?}", action_type);
                drop(allowlist);
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
            if params.get("context").is_none() {
                let reason = format!("Contexte manquant pour action critique: {:?}", action_type);
                drop(allowlist);
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
        }

        let module = match params.get("module") {
            Some(m) => m.clone(),
            None => {
                let reason = "Module non identifié".to_string();
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
        };

        if !self.check_capability(&module, &action_type).await {
            let reason = format!("Capability manquante pour {}", module);
            self.log_denied_action(action_type.clone(), reason.clone()).await;
            return Err(format!("BLOCKED: {}", reason));
        }

        if let Some(limit) = self.module_limits.lock().get(&module).copied() {
            let now = Self::current_timestamp();
            let cpu = Self::parse_u64(params.get("cpu_ms")).unwrap_or(0);
            let ram = Self::parse_u64(params.get("ram_mb")).unwrap_or(0);
            let io_ops = Self::parse_u64(params.get("io_ops")).unwrap_or(0);
            if self.is_module_blocked(&module, now).await {
                let reason = format!("Module {} bloqué (circuit breaker)", module);
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
            if !self.update_usage(&module, limit, cpu, ram, io_ops, now).await {
                let reason = format!("Module limits exceeded for {}", module);
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
        }
        
        // Enforcement: Denied = BLOQUE IMMÉDIATEMENT
        if permission == PermissionLevel::Denied {
            let reason = format!("Permission refusée pour: {:?}", action_type);
            self.log_denied_action(action_type.clone(), reason.clone()).await;
            return Err(format!("BLOCKED: {}", reason));
        }
        
        // ReadOnly: BLOQUE les écritures
        if permission == PermissionLevel::ReadOnly {
            if self.is_write_action(&action_type) {
                let reason = format!("Action d'écriture bloquée sur {:?} (mode lecture seule)", 
                    action_type);
                self.log_denied_action(action_type.clone(), reason.clone()).await;
                return Err(format!("BLOCKED: {}", reason));
            }
            return self.check_frequency_limit(&action_type).await;
        }
        
        // Restricted: Vérifie les fréquences et criticalité
        if permission == PermissionLevel::Restricted {
            return self.check_frequency_limit(&action_type).await;
        }
        
        // Full: Aucune restriction
        Ok(true)
    }
    
    /// Vérifie les limites de fréquence et les actions critiques
    async fn check_frequency_limit(&self, action_type: &ActionType) -> Result<bool, String> {
        let mut counter = self.action_counter.lock();
        let current_count = counter.entry(action_type.clone()).or_insert(0);
        *current_count += 1;
        let count = *current_count;
        drop(counter);
        
        // Vérification des politiques
        let policies = self.policies.lock();
        for policy in policies.iter() {
            if policy.action == *action_type {
                // ENFORCEMENT: Bloque si dépassement de fréquence
                if let Some(max_freq) = policy.max_frequency_per_minute {
                    if count > max_freq {
                        drop(policies);
                        let reason = format!(
                            "Limite de fréquence DÉPASSÉE ({}/min max {})",
                            count, max_freq
                        );
                        self.log_denied_action(action_type.clone(), reason.clone()).await;
                        
                        // Bloque pendant 60 secondes
                        let mut blocked = self.blocked_until.lock();
                        blocked.insert(action_type.clone(), Self::current_timestamp() + 60);
                        drop(blocked);
                        
                        return Err(format!("BLOCKED: {}", reason));
                    }
                }
                
                // Actions critiques: cooldown 5 secondes entre les appels
                if policy.critical_action {
                    let mut last_critical = self.last_critical_action.lock();
                    let now = Self::current_timestamp();
                    if let Some(last_time) = *last_critical {
                        if now - last_time < 5 {
                            drop(policies);
                            let reason = format!(
                                "Action critique en cooldown (5s minimum entre les appels)"
                            );
                            self.log_denied_action(action_type.clone(), reason.clone()).await;
                            return Err(format!("BLOCKED: {}", reason));
                        }
                    }
                    *last_critical = Some(now);
                }
                break;
            }
        }
        drop(policies);
        
        Ok(true)
    }

    fn is_critical_action(&self, action_type: &ActionType) -> bool {
        let policies = self.policies.lock();
        let critical = policies
            .iter()
            .any(|policy| policy.action == *action_type && policy.critical_action);
        drop(policies);
        critical
    }
    
    /// Enregistre une action refusée pour audit
    async fn log_denied_action(&self, action_type: ActionType, reason: String) {
        let mut log = self.denied_actions_log.lock();
        
        // Cherche si l'action est déjà dans le log
        if let Some(entry) = log.iter_mut().find(|e| e.action_type == action_type) {
            entry.blocked_count += 1;
        } else {
            log.push(DeniedAction {
                action_type,
                timestamp: Self::current_timestamp(),
                reason,
                blocked_count: 1,
            });
        }
        let code = error_code_for_reason(log.last().map(|e| e.reason.as_str()).unwrap_or(""));
        logger::warn("sandbox", code, "action denied");
        observability::inc_errors_total();
    }
    
    /// Active/désactive l'enforcement réel
    pub async fn set_enforcement(&self, active: bool) {
        *self.enforcement_active.lock() = active;
    }
    
    /// Récupère l'état actuel de l'enforcement
    pub async fn is_enforcement_active(&self) -> bool {
        *self.enforcement_active.lock()
    }
    
    /// Activate le mode quarantaine (bloque TOUT sauf PermissionLevel::Full sur certains)
    pub async fn enter_quarantine(&self) {
        *self.quarantine_mode.lock() = true;
        *self.quarantine_until.lock() = Some(Self::current_timestamp().saturating_add(30_000));
    }
    
    /// Désactive le mode quarantaine
    pub async fn exit_quarantine(&self) {
        *self.quarantine_mode.lock() = false;
        *self.quarantine_until.lock() = None;
    }
    
    /// Récupère le journal des actions bloquées
    pub async fn get_denied_actions_log(&self) -> Vec<(ActionType, u32, String)> {
        self.denied_actions_log
            .lock()
            .iter()
            .map(|d| (d.action_type.clone(), d.blocked_count, d.reason.clone()))
            .collect()
    }
    
    /// Réinitialise les compteurs et le journal
    pub async fn reset_enforcement(&self) {
        self.action_counter.lock().clear();
        self.denied_actions_log.lock().clear();
        self.blocked_until.lock().clear();
        *self.last_critical_action.lock() = None;
        *self.quarantine_until.lock() = None;
    }
    
    fn is_write_action(&self, action_type: &ActionType) -> bool {
        matches!(
            action_type,
            ActionType::StorageWrite
                | ActionType::StorageAllocate
                | ActionType::StorageDeallocate
                | ActionType::DeviceEnable
                | ActionType::DeviceDisable
                | ActionType::CommunicationSend
                | ActionType::CommunicationConfig
                | ActionType::KernelScheduler
                | ActionType::KernelCPU
                | ActionType::KernelMemory
                | ActionType::KernelPower
        )
    }
    
    fn current_timestamp() -> u64 {
        time::now_ms()
    }

    fn parse_u64(value: Option<&String>) -> Option<u64> {
        value.and_then(|v| v.parse::<u64>().ok())
    }

    async fn check_capability(&self, module: &str, action: &ActionType) -> bool {
        let caps = self.module_caps.lock();
        let caps = match caps.get(module) {
            Some(c) => *c,
            None => return false,
        };
        match action {
            ActionType::StorageRead
            | ActionType::StorageWrite
            | ActionType::StorageAllocate
            | ActionType::StorageDeallocate => caps.storage || caps.fs,
            ActionType::CommunicationSend
            | ActionType::CommunicationReceive
            | ActionType::CommunicationConfig => caps.network || caps.ipc,
            ActionType::KernelScheduler
            | ActionType::KernelCPU
            | ActionType::KernelMemory
            | ActionType::KernelThermal
            | ActionType::KernelPower
            | ActionType::KernelReboot => caps.kernel || caps.system,
            ActionType::DeviceControl
            | ActionType::DeviceEnable
            | ActionType::DeviceDisable => caps.device,
            ActionType::SystemIntegrity => caps.system,
        }
    }

    async fn is_module_blocked(&self, module: &str, now_ms: u64) -> bool {
        self.module_usage
            .lock()
            .get(module)
            .map(|u| now_ms < u.breaker_until_ms)
            .unwrap_or(false)
    }

    async fn update_usage(
        &self,
        module: &str,
        limit: ModuleLimits,
        cpu_ms: u64,
        ram_mb: u64,
        io_ops: u64,
        now_ms: u64,
    ) -> bool {
        let mut usage = self.module_usage.lock();
        let entry = usage.entry(module.into()).or_insert(ModuleUsage {
            window_start_ms: now_ms,
            cpu_ms: 0,
            ram_mb: 0,
            io_ops: 0,
            abuse_count: 0,
            breaker_until_ms: 0,
        });
        if now_ms.saturating_sub(entry.window_start_ms) >= limit.window_ms.max(1) {
            entry.window_start_ms = now_ms;
            entry.cpu_ms = 0;
            entry.ram_mb = 0;
            entry.io_ops = 0;
        }
        entry.cpu_ms = entry.cpu_ms.saturating_add(cpu_ms);
        entry.ram_mb = entry.ram_mb.saturating_add(ram_mb);
        entry.io_ops = entry.io_ops.saturating_add(io_ops);
        if entry.cpu_ms > limit.cpu_ms || entry.ram_mb > limit.ram_mb || entry.io_ops > limit.io_ops {
            entry.abuse_count = entry.abuse_count.saturating_add(1);
            if entry.abuse_count >= limit.breaker_threshold.saturating_mul(2) {
                *self.quarantine_mode.lock() = true;
                *self.quarantine_until.lock() = Some(now_ms.saturating_add(30_000));
            }
            if entry.abuse_count >= limit.breaker_threshold {
                entry.breaker_until_ms = now_ms.saturating_add(limit.breaker_open_ms);
                entry.abuse_count = 0;
            }
            return false;
        }
        true
    }
}

// Implémente Default pour faciliter les tests
impl Default for SandboxController {
    fn default() -> Self {
        Self::new()
    }
}

fn error_code_for_reason(reason: &str) -> ErrorCode {
    let r = reason.to_ascii_lowercase();
    if r.contains("quota") || r.contains("limit") {
        return ErrorCode::ErrQuotaExceeded;
    }
    if r.contains("auth") || r.contains("capability") || r.contains("allowlist") {
        return ErrorCode::ErrUnauthorized;
    }
    if r.contains("replay") {
        return ErrorCode::ErrIntegrity;
    }
    ErrorCode::ErrUnknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_runtime::block_on;
    
    #[test]
    fn test_denied_permission_blocks_action() {
        block_on(async {
        let controller = SandboxController::new();
        controller.allowlist_action(ActionType::KernelReboot, true).await;
        controller
            .set_module_capabilities(
                "kernel",
                ModuleCapabilities {
                    fs: false,
                    network: false,
                    ipc: false,
                    gpu: false,
                    kernel: true,
                    device: false,
                    storage: false,
                    system: true,
                    memory: true,
                    power: true,
                },
            )
            .await;
        let mut params = HashMap::new();
        params.insert("module".into(), "kernel".into());
        let result = controller
            .validate_action(ActionType::KernelReboot, params)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BLOCKED"));
        });
    }
    
    #[test]
    fn test_quarantine_blocks_all() {
        block_on(async {
        let controller = SandboxController::new();
        controller.enter_quarantine().await;
        
        let result = controller
            .validate_action(ActionType::StorageRead, HashMap::new())
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BLOCKED"));
        
        controller.exit_quarantine().await;
        });
    }
}
