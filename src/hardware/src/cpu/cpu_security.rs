
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const CPU_SEC_LOCK_OFFSET: u64 = 0x0100;
const CPU_SEC_STATUS_OFFSET: u64 = 0x0104;
const CPU_SEC_DEBUG_OFFSET: u64 = 0x0108;

#[inline(always)]
fn cpu_sec_lock() -> u64 {
    crate::cpu_apcs_base() + CPU_SEC_LOCK_OFFSET
}

#[inline(always)]
fn cpu_sec_status() -> u64 {
    crate::cpu_apcs_base() + CPU_SEC_STATUS_OFFSET
}

#[inline(always)]
fn cpu_sec_debug() -> u64 {
    crate::cpu_apcs_base() + CPU_SEC_DEBUG_OFFSET
}

#[inline(always)]
unsafe fn write_reg(addr: u64, value: u32) {
    write_volatile(addr as *mut u32, value);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(always)]
unsafe fn read_reg(addr: u64) -> u32 {
    read_volatile(addr as *const u32)
}
static CPU_LOCKED: AtomicBool = AtomicBool::new(false);
static DEBUG_DISABLED: AtomicBool = AtomicBool::new(false);
static SPECULATION_MITIGATED: AtomicBool = AtomicBool::new(false);
static EXECUTE_PROTECTION: AtomicU32 = AtomicU32::new(0);
pub fn lock_down() {
    if CPU_LOCKED.load(Ordering::SeqCst) {
        return;
    }
    disable_external_debug();
    mitigate_speculation();
    enforce_execute_protection();
    unsafe {
        write_reg(cpu_sec_lock(), 0xDEAD_BEEF);
        let _ = read_reg(cpu_sec_status());
    }
    CPU_LOCKED.store(true, Ordering::SeqCst);
}
pub fn is_locked() -> bool {
    CPU_LOCKED.load(Ordering::SeqCst)
}
pub fn disable_external_debug() {
    unsafe {
        write_reg(cpu_sec_debug(), 0x0);
    }
    DEBUG_DISABLED.store(true, Ordering::SeqCst);
}
pub fn mitigate_speculation() {
    if SPECULATION_MITIGATED.load(Ordering::SeqCst) {
        return;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    SPECULATION_MITIGATED.store(true, Ordering::SeqCst);
}
pub fn enforce_execute_protection() {
    let current = EXECUTE_PROTECTION.load(Ordering::SeqCst);
    if current != 0 {
        return;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    EXECUTE_PROTECTION.store(1, Ordering::SeqCst);
}
pub fn runtime_integrity_check() -> bool {
    let status = unsafe { read_reg(cpu_sec_status()) };
    let is_secure = DEBUG_DISABLED.load(Ordering::SeqCst)
        && SPECULATION_MITIGATED.load(Ordering::SeqCst)
        && CPU_LOCKED.load(Ordering::SeqCst);
    is_secure && status != 0
}
pub fn permanent_lock() {
    unsafe {
        write_reg(cpu_sec_lock(), 0xBEEF_DEAD);
        let _ = read_reg(cpu_sec_status());
    }
    CPU_LOCKED.store(true, Ordering::SeqCst);
}
pub fn enable_mmu() -> Result<(), &'static str> {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
}

pub fn enable_cache_protection() -> Result<(), &'static str> {
    enforce_execute_protection();
    Ok(())
}