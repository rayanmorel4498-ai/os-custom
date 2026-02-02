pub fn enable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::camera_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::camera_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_select() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_power() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::camera_reset() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::camera_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::camera_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::camera_power() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_reset() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::camera_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_select() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_data() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::camera_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
