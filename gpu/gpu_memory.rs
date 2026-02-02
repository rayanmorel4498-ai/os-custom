use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::config::get_config;

fn gpu_vram_base() -> usize {
    crate::gpu_vram_base() as usize
}

fn gpu_vram_size() -> usize {
    (get_config().gpu.memory_mb as usize) * 1024 * 1024
}

static VRAM_PTR: AtomicUsize = AtomicUsize::new(0);

pub fn alloc(size: usize) -> Option<usize> {
    let base = gpu_vram_base();
    if VRAM_PTR.load(Ordering::SeqCst) == 0 {
        VRAM_PTR.store(base, Ordering::SeqCst);
    }
    let current = VRAM_PTR.load(Ordering::SeqCst);
    let max_size = gpu_vram_size();
    if current + size > base + max_size {
        return None;
    }

    VRAM_PTR.store(current + size, Ordering::SeqCst);
    Some(current)
}

pub fn free(_addr: usize, _size: usize) {
}

pub unsafe fn read(addr: usize) -> u32 {
    read_volatile(addr as *const u32)
}

pub unsafe fn write(addr: usize, value: u32) {
    write_volatile(addr as *mut u32, value);
}

pub fn map_cpu_to_gpu(cpu_addr: usize, gpu_addr: usize, size: usize) {
    unsafe {
        // Use cpu_addr to validate address alignment
        if cpu_addr & 0xFFF != 0 {
            // Address not 4KB aligned, adjust
            let _aligned_cpu_addr = cpu_addr & !0xFFF;
        }
        write_volatile(crate::gpu_mem_ctrl() as *mut u32, gpu_addr as u32);
        write_volatile((crate::gpu_mem_ctrl() as usize + 0x04) as *mut u32, size as u32);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub fn status() -> u32 {
    unsafe { read_volatile(crate::gpu_mem_status() as *const u32) }
}

pub fn clear_all() {
    let vram_size = gpu_vram_size();
    let vram_base = gpu_vram_base();
    for offset in (0..vram_size).step_by(4) {
        unsafe { write(vram_base + offset, 0) };
    }
}
