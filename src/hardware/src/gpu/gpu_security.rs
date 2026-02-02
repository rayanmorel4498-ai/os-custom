use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
static GPU_LOCKED: AtomicBool = AtomicBool::new(false);
static INTEGRITY_CHECKSUM: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
fn gpu_lock_reg() -> u64 {
    crate::gpu_security_base() as u64 + 0x0
}

#[inline(always)]
fn gpu_integrity_reg() -> u64 {
    crate::gpu_security_base() as u64 + 0x4
}

#[inline(always)]
fn gpu_debug_reg() -> u64 {
    crate::gpu_security_base() as u64 + 0x8
}

#[inline(always)]
fn gpu_memory_prot_reg() -> u64 {
    crate::gpu_security_base() as u64 + 0xC
}

#[inline(always)]
fn gpu_reset_reg() -> u64 {
    crate::gpu_security_base() as u64 + 0x10
}
pub fn lock_down() {
    if GPU_LOCKED.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        let lock_ptr = gpu_lock_reg() as *mut u32;
        core::ptr::write_volatile(lock_ptr, 0xDEAD_BEEF);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let debug_ptr = gpu_debug_reg() as *mut u32;
        core::ptr::write_volatile(debug_ptr, 0);
        let mem_prot_ptr = gpu_memory_prot_reg() as *mut u32;
        core::ptr::write_volatile(mem_prot_ptr, 0xFFFFFFFF);
    }
    GPU_LOCKED.store(true, Ordering::SeqCst);
}
pub fn is_locked() -> bool {
    GPU_LOCKED.load(Ordering::SeqCst)
}
pub fn emergency_halt() {
    unsafe {
        let reset_ptr = gpu_reset_reg() as *mut u32;
        core::ptr::write_volatile(reset_ptr, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub fn enforce_memory_protection() {
    unsafe {
        let mem_prot_ptr = gpu_memory_prot_reg() as *mut u32;
        core::ptr::write_volatile(mem_prot_ptr, 0xFFFFFFFF);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub fn runtime_integrity_check() -> bool {
    unsafe {
        let integrity_ptr = gpu_integrity_reg() as *const u32;
        let value = core::ptr::read_volatile(integrity_ptr);
        let valid = value == 0 || value == 0xFFFFFFFF;
        if valid {
            INTEGRITY_CHECKSUM.store(value, Ordering::SeqCst);
        }
        valid
    }
}
pub fn disable_external_debug() {
    unsafe {
        let debug_ptr = gpu_debug_reg() as *mut u32;
        core::ptr::write_volatile(debug_ptr, 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub fn permanent_lock() {
    unsafe {
        let lock_ptr = gpu_lock_reg() as *mut u32;
        core::ptr::write_volatile(lock_ptr, 0xDEAD_BEEF);
        core::ptr::write_volatile(lock_ptr, 0xBEEF_DEAD);
        core::ptr::write_volatile(lock_ptr, 0xDEAD_BEEF);
        let mem_prot_ptr = gpu_memory_prot_reg() as *mut u32;
        core::ptr::write_volatile(mem_prot_ptr, 0xFFFFFFFF);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    GPU_LOCKED.store(true, Ordering::SeqCst);
}
pub fn get_integrity_checksum() -> u32 {
    INTEGRITY_CHECKSUM.load(Ordering::SeqCst)
}
pub fn verify_lock_status() -> bool {
    unsafe {
        let lock_ptr = gpu_lock_reg() as *const u32;
        let status = core::ptr::read_volatile(lock_ptr);
        status == 0xDEAD_BEEF
    }
}
