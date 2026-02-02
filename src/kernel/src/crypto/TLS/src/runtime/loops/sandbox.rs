use alloc::sync::Arc;
use parking_lot::RwLock;
use crate::api::component_token::ComponentType;
use core::sync::atomic::{AtomicBool, Ordering};

static TLS_SANDBOX_ACTIVE: AtomicBool = AtomicBool::new(false);
static PRIMARY_LOOP_ACTIVE: AtomicBool = AtomicBool::new(false);
static SECONDARY_LOOP_ACTIVE: AtomicBool = AtomicBool::new(false);
static THIRD_LOOP_ACTIVE: AtomicBool = AtomicBool::new(false);
static FORTH_LOOP_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTERNAL_LOOP_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopKind {
    Primary,
    Secondary,
    Third,
    Forth,
    External,
}

pub fn set_tls_sandbox_active(active: bool) {
    TLS_SANDBOX_ACTIVE.store(active, Ordering::SeqCst);
}

pub fn is_tls_sandbox_active() -> bool {
    TLS_SANDBOX_ACTIVE.load(Ordering::SeqCst)
}

pub fn set_loop_sandbox_active(kind: LoopKind, active: bool) {
    match kind {
        LoopKind::Primary => PRIMARY_LOOP_ACTIVE.store(active, Ordering::SeqCst),
        LoopKind::Secondary => SECONDARY_LOOP_ACTIVE.store(active, Ordering::SeqCst),
        LoopKind::Third => THIRD_LOOP_ACTIVE.store(active, Ordering::SeqCst),
        LoopKind::Forth => FORTH_LOOP_ACTIVE.store(active, Ordering::SeqCst),
        LoopKind::External => EXTERNAL_LOOP_ACTIVE.store(active, Ordering::SeqCst),
    }
}

pub fn is_loop_sandbox_active(kind: LoopKind) -> bool {
    match kind {
        LoopKind::Primary => PRIMARY_LOOP_ACTIVE.load(Ordering::SeqCst),
        LoopKind::Secondary => SECONDARY_LOOP_ACTIVE.load(Ordering::SeqCst),
        LoopKind::Third => THIRD_LOOP_ACTIVE.load(Ordering::SeqCst),
        LoopKind::Forth => FORTH_LOOP_ACTIVE.load(Ordering::SeqCst),
        LoopKind::External => EXTERNAL_LOOP_ACTIVE.load(Ordering::SeqCst),
    }
}

#[derive(Clone, Debug)]
pub struct SandboxLimits {
    pub max_cpu_percent: u32,
    pub max_memory_mb: u64,
    pub max_file_descriptors: u32,
    pub allowed_syscalls: u32,
}

impl SandboxLimits {
    pub fn new_restricted() -> Self {
        Self {
            max_cpu_percent: 50,
            max_memory_mb: 512,
            max_file_descriptors: 32,
            allowed_syscalls: 128,
        }
    }

    pub fn new_moderate() -> Self {
        Self {
            max_cpu_percent: 75,
            max_memory_mb: 1024,
            max_file_descriptors: 64,
            allowed_syscalls: 256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SandboxHandle {
    pub sandbox_id: u64,
    pub component: ComponentType,
    pub limits: SandboxLimits,
    pub is_active: Arc<RwLock<bool>>,
}

impl SandboxHandle {
    pub fn new(sandbox_id: u64, component: ComponentType, limits: SandboxLimits) -> Self {
        Self {
            sandbox_id,
            component,
            limits,
            is_active: Arc::new(RwLock::new(true)),
        }
    }

    pub fn is_active(&self) -> bool {
        *self.is_active.read()
    }

    pub fn activate(&self) {
        *self.is_active.write() = true;
    }

    pub fn deactivate(&self) {
        *self.is_active.write() = false;
    }

    pub fn get_cpu_quota(&self) -> u32 {
        self.limits.max_cpu_percent
    }

    pub fn get_memory_quota(&self) -> u64 {
        self.limits.max_memory_mb * 1024 * 1024
    }

    pub fn get_fd_limit(&self) -> u32 {
        self.limits.max_file_descriptors
    }
}

pub struct SandboxPolicy {
    pub allow_network: bool,
    pub allow_filesystem: bool,
    pub allow_ipc: bool,
    pub allow_signals: bool,
}

impl SandboxPolicy {
    pub fn for_os() -> Self {
        Self {
            allow_network: false,
            allow_filesystem: true,
            allow_ipc: true,
            allow_signals: false,
        }
    }

    pub fn for_network_service() -> Self {
        Self {
            allow_network: true,
            allow_filesystem: false,
            allow_ipc: false,
            allow_signals: false,
        }
    }

    pub fn for_device_driver() -> Self {
        Self {
            allow_network: false,
            allow_filesystem: false,
            allow_ipc: true,
            allow_signals: true,
        }
    }
}

pub struct SandboxManager {
    next_id: Arc<RwLock<u64>>,
    sandboxes: Arc<RwLock<alloc::collections::BTreeMap<u64, SandboxHandle>>>,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self {
            next_id: Arc::new(RwLock::new(1)),
            sandboxes: Arc::new(RwLock::new(alloc::collections::BTreeMap::new())),
        }
    }

    pub fn create_sandbox(
        &self,
        component: ComponentType,
        _policy: SandboxPolicy,
        limits: SandboxLimits,
    ) -> SandboxHandle {
        let mut id_guard = self.next_id.write();
        let sandbox_id = *id_guard;
        *id_guard += 1;

        let handle = SandboxHandle::new(sandbox_id, component, limits);
        
        let mut sandboxes = self.sandboxes.write();
        sandboxes.insert(sandbox_id, handle.clone());

        handle
    }

    pub fn get_sandbox(&self, sandbox_id: u64) -> Option<SandboxHandle> {
        let sandboxes = self.sandboxes.read();
        sandboxes.get(&sandbox_id).cloned()
    }

    pub fn destroy_sandbox(&self, sandbox_id: u64) -> bool {
        let mut sandboxes = self.sandboxes.write();
        if let Some(sandbox) = sandboxes.remove(&sandbox_id) {
            sandbox.deactivate();
            true
        } else {
            false
        }
    }

    pub fn list_active_sandboxes(&self) -> alloc::vec::Vec<SandboxHandle> {
        let sandboxes = self.sandboxes.read();
        sandboxes
            .values()
            .filter(|s| s.is_active())
            .cloned()
            .collect()
    }

    pub fn sandbox_count(&self) -> usize {
        let sandboxes = self.sandboxes.read();
        sandboxes.iter().filter(|(_, s)| s.is_active()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_limits_creation() {
        let restricted = SandboxLimits::new_restricted();
        assert_eq!(restricted.max_cpu_percent, 50);
        assert_eq!(restricted.max_memory_mb, 512);

        let moderate = SandboxLimits::new_moderate();
        assert_eq!(moderate.max_cpu_percent, 75);
        assert_eq!(moderate.max_memory_mb, 1024);
    }

    #[test]
    fn test_sandbox_handle() {
        let limits = SandboxLimits::new_restricted();
        let handle = SandboxHandle::new(1, ComponentType::OS, limits);
        
        assert!(handle.is_active());
        assert_eq!(handle.get_cpu_quota(), 50);
        assert_eq!(handle.get_memory_quota(), 512 * 1024 * 1024);
        
        handle.deactivate();
        assert!(!handle.is_active());
    }

    #[test]
    fn test_sandbox_manager() {
        let manager = SandboxManager::new();
        
        let sandbox = manager.create_sandbox(
            ComponentType::OS,
            SandboxPolicy::for_os(),
            SandboxLimits::new_restricted(),
        );
        
        assert_eq!(manager.sandbox_count(), 1);
        
        let retrieved = manager.get_sandbox(sandbox.sandbox_id);
        assert!(retrieved.is_some());
        
        assert!(manager.destroy_sandbox(sandbox.sandbox_id));
        assert_eq!(manager.sandbox_count(), 0);
    }

    #[test]
    fn test_sandbox_policy_variants() {
        let os_policy = SandboxPolicy::for_os();
        assert!(!os_policy.allow_network);
        assert!(os_policy.allow_filesystem);

        let net_policy = SandboxPolicy::for_network_service();
        assert!(net_policy.allow_network);
        assert!(!net_policy.allow_filesystem);

        let dev_policy = SandboxPolicy::for_device_driver();
        assert!(!dev_policy.allow_network);
        assert!(dev_policy.allow_ipc);
    }
}
