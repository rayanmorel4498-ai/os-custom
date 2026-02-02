pub fn init() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::depth_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::depth_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_range() as *mut u32, 0x1000);
        core::ptr::write_volatile(crate::depth_accuracy() as *mut u32, 0x64);
        core::ptr::write_volatile(crate::depth_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::depth_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::depth_data() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_result() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn stop() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::depth_ctrl() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_range() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_accuracy() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_data() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::depth_result() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
