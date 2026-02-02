use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

const CPU_PWR_CTRL_OFFSET: u64 = 0x0000;
const CPU_PWR_STATUS_OFFSET: u64 = 0x0004;
const CPU_PWR_WAKE_OFFSET: u64 = 0x0008;

#[inline(always)]
fn cpu_power_ctrl() -> u64 {
    crate::cpu_apcs_base() + CPU_PWR_CTRL_OFFSET
}

#[inline(always)]
fn cpu_power_status() -> u64 {
    crate::cpu_apcs_base() + CPU_PWR_STATUS_OFFSET
}

#[inline(always)]
fn cpu_power_wake() -> u64 {
    crate::cpu_apcs_base() + CPU_PWR_WAKE_OFFSET
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
static CPU_POWERED: AtomicBool = AtomicBool::new(false);
pub fn enable() {
    if CPU_POWERED.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        write_reg(cpu_power_ctrl(), 0x1);
        let _ = read_reg(cpu_power_status());
    }
    CPU_POWERED.store(true, Ordering::SeqCst);
}
pub fn idle() {
    if !CPU_POWERED.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        write_reg(cpu_power_ctrl(), 0x2);
        let _ = read_reg(cpu_power_status());
    }
}
pub fn wake() {
    if !CPU_POWERED.load(Ordering::SeqCst) {
        enable();
        return;
    }
    unsafe {
        write_reg(cpu_power_wake(), 0x1);
        let _ = read_reg(cpu_power_status());
    }
}
pub fn halt() -> ! {
    if CPU_POWERED.load(Ordering::SeqCst) {
        unsafe {
            write_reg(cpu_power_ctrl(), 0x0);
        }
    }
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
pub fn is_powered() -> bool {
    CPU_POWERED.load(Ordering::SeqCst)
}
