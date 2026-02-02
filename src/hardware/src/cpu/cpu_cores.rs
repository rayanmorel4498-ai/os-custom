use core::ptr::write_volatile;
use core::sync::atomic::{AtomicU32, Ordering};
pub const MAX_CPU_CORES: u32 = 8;
pub const PERFORMANCE_CORES: u32 = 2;
pub const EFFICIENCY_CORES: u32 = 6;
static ACTIVE_CORES: AtomicU32 = AtomicU32::new(0b0000_0001);
const CPU_CORE_STRIDE: usize = 0x100;
const CORE_PWR: usize = 0x00;
const CORE_RST: usize = 0x04;
#[allow(dead_code)]
const CORE_STATUS: usize = 0x08;
pub fn enable(core_id: u32) {
    if core_id == 0 || core_id >= MAX_CPU_CORES {
        return;
    }
    let mask = 1 << core_id;
    if ACTIVE_CORES.load(Ordering::SeqCst) & mask != 0 {
        return;
    }
    let base = crate::cpu_core_ctrl_base() as usize + (core_id as usize * CPU_CORE_STRIDE);
    unsafe {
        write_volatile((base + CORE_PWR) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        write_volatile((base + CORE_RST) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        for _ in 0..1000 {
            core::arch::asm!("nop");
        }
    }
    ACTIVE_CORES.fetch_or(mask, Ordering::SeqCst);
}
pub fn disable(core_id: u32) {
    if core_id == 0 || core_id >= MAX_CPU_CORES {
        return;
    }
    let mask = 1 << core_id;
    if ACTIVE_CORES.load(Ordering::SeqCst) & mask == 0 {
        return;
    }
    let base = crate::cpu_core_ctrl_base() as usize + (core_id as usize * CPU_CORE_STRIDE);
    unsafe {
        write_volatile((base + CORE_RST) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        for _ in 0..100 {
            core::arch::asm!("nop");
        }
        write_volatile((base + CORE_PWR) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    ACTIVE_CORES.fetch_and(!mask, Ordering::SeqCst);
}
pub fn is_active(core_id: u32) -> bool {
    if core_id >= MAX_CPU_CORES {
        return false;
    }
    (ACTIVE_CORES.load(Ordering::SeqCst) & (1 << core_id)) != 0
}
pub fn active_count() -> u32 {
    ACTIVE_CORES.load(Ordering::SeqCst).count_ones()
}
pub fn enable_all() {
    for id in 1..MAX_CPU_CORES {
        enable(id);
    }
}
pub fn disable_all_secondary() {
    for id in 1..MAX_CPU_CORES {
        disable(id);
    }
}
pub fn power_on(core_id: u32) -> Result<(), &'static str> {
    enable(core_id);
    Ok(())
}

pub fn power_off(core_id: u32) -> Result<(), &'static str> {
    disable(core_id);
    Ok(())
}