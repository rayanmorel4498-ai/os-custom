#[cfg(feature = "std")]
use alloc::collections::BTreeMap as HashMap;
use crate::alloc::string::ToString;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
use crate::alloc::string::ToString;
use crate::prelude::{String, Vec};
use crate::alloc::string::ToString;

use alloc::sync::Arc;
use crate::alloc::string::ToString;

use spin::Mutex;
use crate::alloc::string::ToString;
use super::crypto_core::EncryptedVault;
use crate::alloc::string::ToString;

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
            denied_actions_log: Arc::new(Mutex::new(Vec::new())),
            enforcement_active: Arc::new(Mutex::new(true)),
            blocked_until: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Valide une action et l'ENFORCES (bloque si refusée)
    pub async fn validate_action(
        &self,
        action_type: ActionType,
        params: HashMap<String, String>,
    ) -> Result<bool, String> {
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
    }
    
    /// Désactive le mode quarantaine
    pub async fn exit_quarantine(&self) {
        *self.quarantine_mode.lock() = false;
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
        0 // no_std: No system time available
    }
}

// Implémente Default pour faciliter les tests
impl Default for SandboxController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_denied_permission_blocks_action() {
        let controller = SandboxController::new();
        let result = controller
            .validate_action(ActionType::KernelReboot, HashMap::new())
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BLOCKED"));
    }
    
    #[tokio::test]
    async fn test_quarantine_blocks_all() {
        let controller = SandboxController::new();
        controller.enter_quarantine().await;
        
        let result = controller
            .validate_action(ActionType::StorageRead, HashMap::new())
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BLOCKED"));
        
        controller.exit_quarantine().await;
    }
}
