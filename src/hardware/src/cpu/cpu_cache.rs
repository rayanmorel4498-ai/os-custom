
pub fn clean_dcache() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("dc cvac, {}", in(reg) 0u64);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
pub fn invalidate_dcache() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("dc ivac, {}", in(reg) 0u64);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
pub fn flush_dcache() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("dc civac, {}", in(reg) 0u64);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
pub fn invalidate_icache() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("ic iallu");
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
pub fn sync_all() {
    clean_dcache();
    invalidate_icache();
}
pub fn disable_all() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
pub fn enable_all() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
