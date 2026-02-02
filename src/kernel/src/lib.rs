#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::sync::Arc;
use crate::config::{HardwareApiPoolConfig, KernelConfig};
use crate::services::HardwareDriver;
use redmi_hardware::config::HardwareCommandPool;

pub mod run;
pub mod services;
pub mod config;

pub mod sync;
pub use sync::{Mutex, Priority, FairScheduler, InterruptController, AsyncTaskPool, RwLock};


pub mod scheduler;
pub use scheduler::{
    RtTask, RtEdfScheduler, SlaMetrics, DynamicPriorityManager, ConditionVariable,
    FastRtTask, FastEdfScheduler, FastSlaMetrics,
    PreemptionContext, ContextSwitchTracker,
    TimeBudget, PreemptionDeadline, AdvancedPreemptionContext, TaskSla
};

pub mod core;
pub use core::{
    IoFuture, AsyncExecutor, IoMultiplexer,
    CpuAffinity, LoadBalancer, WorkQueue,
    CpuCluster, CoreWorkQueue, LoadPredictor, WorkStealingScheduler,
    PreemptiveTimerController, TimerConfig, TimerMode, InterruptPriority, DeadlineMissDetector
};


pub const KERNEL_VERSION: &str = "15c";
pub const KERNEL_MAJOR: u32 = 1;
pub const KERNEL_MINOR: u32 = 0;
pub const KERNEL_PATCH: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootState {
    PreBoot,
    BootLoader,
    Initializing,
    SecurityInit,
    DriverInit,
    Running,
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct KernelStats {
    pub boot_state: BootState,
    pub uptime_ms: u64,
    pub syscalls: u64,
    pub interrupts: u64,
    pub exceptions: u64,
    pub context_switches: u64,
}

#[derive(Debug, Clone)]
pub struct KernelDiagnostics {
    pub boot_start_ms: u64,
    pub boot_duration_ms: u64,
    pub errors_total: u64,
    pub last_error_code: u32,
    pub subsystems_enabled: u32,
    pub subsystems_disabled: u32,
}

pub struct Kernel {
    stats: Arc<Mutex<KernelStats>>,
    boot_state: Arc<Mutex<BootState>>,
    interrupt_controller: Arc<core::InterruptController>,
    hardware_pool: Option<Arc<HardwareCommandPool>>,
    hardware_driver: Arc<HardwareDriver>,
    kernel_config: Arc<Mutex<KernelConfig>>,
    diagnostics: Arc<Mutex<KernelDiagnostics>>,
}

impl Kernel {
    pub fn new() -> Self {
        let hardware_config = HardwareApiPoolConfig::default();
        let hardware_pool = Arc::new(HardwareCommandPool::new(
            hardware_config.resources.max_pending_requests,
            hardware_config.resources.max_pending_responses,
        ));
        let hardware_driver = Arc::new(HardwareDriver::with_pool(hardware_pool.clone()));
        let kernel_config = KernelConfig::default();
        let diagnostics = KernelDiagnostics {
            boot_start_ms: 0,
            boot_duration_ms: 0,
            errors_total: 0,
            last_error_code: 0,
            subsystems_enabled: 0,
            subsystems_disabled: 0,
        };
        Kernel {
            stats: Arc::new(Mutex::new(KernelStats {
                boot_state: BootState::PreBoot,
                uptime_ms: 0,
                syscalls: 0,
                interrupts: 0,
                exceptions: 0,
                context_switches: 0,
            })),
            boot_state: Arc::new(Mutex::new(BootState::PreBoot)),
            interrupt_controller: Arc::new(core::InterruptController::new()),
            hardware_pool: Some(hardware_pool),
            hardware_driver,
            kernel_config: Arc::new(Mutex::new(kernel_config)),
            diagnostics: Arc::new(Mutex::new(diagnostics)),
        }
    }

    pub fn new_without_pool() -> Self {
        let hardware_driver = Arc::new(HardwareDriver::new());
        let kernel_config = KernelConfig::default();
        let diagnostics = KernelDiagnostics {
            boot_start_ms: 0,
            boot_duration_ms: 0,
            errors_total: 0,
            last_error_code: 0,
            subsystems_enabled: 0,
            subsystems_disabled: 0,
        };
        Kernel {
            stats: Arc::new(Mutex::new(KernelStats {
                boot_state: BootState::PreBoot,
                uptime_ms: 0,
                syscalls: 0,
                interrupts: 0,
                exceptions: 0,
                context_switches: 0,
            })),
            boot_state: Arc::new(Mutex::new(BootState::PreBoot)),
            interrupt_controller: Arc::new(core::InterruptController::new()),
            hardware_pool: None,
            hardware_driver,
            kernel_config: Arc::new(Mutex::new(kernel_config)),
            diagnostics: Arc::new(Mutex::new(diagnostics)),
        }
    }

    pub fn apply_kernel_config(&self, config: KernelConfig) {
        *self.kernel_config.lock() = config;
        self.apply_subsystems();
    }

    pub fn initialize_with_kernel_config(&self, config: KernelConfig) -> Result<(), alloc::string::String> {
        self.apply_kernel_config(config);
        self.initialize()
    }

    pub fn get_kernel_config(&self) -> KernelConfig {
        self.kernel_config.lock().clone()
    }

    pub fn get_diagnostics(&self) -> KernelDiagnostics {
        self.diagnostics.lock().clone()
    }

    pub fn initialize(&self) -> Result<(), alloc::string::String> {
        let mut state = self.boot_state.lock();
        *state = BootState::Initializing;
        
        let mut stats = self.stats.lock();
        stats.boot_state = BootState::Initializing;
        let mut diagnostics = self.diagnostics.lock();
        diagnostics.boot_start_ms = stats.uptime_ms;
        
        Ok(())
    }

    pub fn initialize_with_config(
        &self,
        security_level: &str,
        encryption: &str,
        master_key: &str,
        boot_token: &str,
    ) -> Result<(), alloc::string::String> {
        let mut state = self.boot_state.lock();
        *state = BootState::SecurityInit;
        
        let mut stats = self.stats.lock();
        stats.boot_state = BootState::SecurityInit;
        
        Ok(())
    }

    pub fn start_drivers(&self) -> Result<(), alloc::string::String> {
        let mut state = self.boot_state.lock();
        *state = BootState::DriverInit;
        self.apply_subsystems();
        Ok(())
    }

    pub fn start(&self) -> Result<(), alloc::string::String> {
        let mut state = self.boot_state.lock();
        *state = BootState::Running;
        
        let mut stats = self.stats.lock();
        stats.boot_state = BootState::Running;
        let mut diagnostics = self.diagnostics.lock();
        diagnostics.boot_duration_ms = stats.uptime_ms.saturating_sub(diagnostics.boot_start_ms);
        
        Ok(())
    }

    pub fn record_error(&self, code: u32) {
        let mut diagnostics = self.diagnostics.lock();
        diagnostics.errors_total = diagnostics.errors_total.saturating_add(1);
        diagnostics.last_error_code = code;
    }

    fn apply_subsystems(&self) {
        let config = self.kernel_config.lock();
        let mut enabled = 0u32;
        let mut disabled = 0u32;

        for subsystem in config.subsystems.iter() {
            if subsystem.enabled {
                enabled = enabled.saturating_add(1);
            } else {
                disabled = disabled.saturating_add(1);
            }
        }

        let mut diagnostics = self.diagnostics.lock();
        diagnostics.subsystems_enabled = enabled;
        diagnostics.subsystems_disabled = disabled;
    }

    pub fn get_boot_state(&self) -> BootState {
        *self.boot_state.lock()
    }

    pub fn get_stats(&self) -> KernelStats {
        self.stats.lock().clone()
    }

    pub fn get_interrupt_controller(&self) -> Arc<core::InterruptController> {
        self.interrupt_controller.clone()
    }

    pub fn syscall(&self, _syscall_id: u32) -> Result<(), alloc::string::String> {
        let mut stats = self.stats.lock();
        stats.syscalls += 1;
        Ok(())
    }

    pub fn handle_interrupt(&self) -> Result<(), alloc::string::String> {
        let mut stats = self.stats.lock();
        stats.interrupts += 1;
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), alloc::string::String> {
        let mut state = self.boot_state.lock();
        *state = BootState::Shutdown;
        
        let mut stats = self.stats.lock();
        stats.boot_state = BootState::Shutdown;
        
        Ok(())
    }
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_new_has_pool() {
        let kernel = Kernel::new();
        assert!(kernel.hardware_pool.is_some());
    }

    #[test]
    fn kernel_new_without_pool_has_none() {
        let kernel = Kernel::new_without_pool();
        assert!(kernel.hardware_pool.is_none());
    }

    #[test]
    fn kernel_new_has_driver() {
        let kernel = Kernel::new();
        let driver = kernel.hardware_driver.clone();
        let _ = driver.drain_and_process();
    }
}

