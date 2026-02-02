pub fn set_zoom(level: u32) -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::zoom_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::zoom_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::zoom_level() as *mut u32, level);
        core::ptr::write_volatile(crate::zoom_max() as *mut u32, 10);
        core::ptr::write_volatile(crate::zoom_min() as *mut u32, 1);
        core::ptr::write_volatile(crate::zoom_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::zoom_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::zoom_data() as *mut u32, level);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
