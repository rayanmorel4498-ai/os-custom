pub fn enable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::stabilization_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::stabilization_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_x_offset() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_y_offset() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_gain() as *mut u32, 0x100);
        core::ptr::write_volatile(crate::stabilization_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::stabilization_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::stabilization_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::stabilization_ctrl() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_x_offset() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_y_offset() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_gain() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::stabilization_data() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
