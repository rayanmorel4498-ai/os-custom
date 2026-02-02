pub fn enable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::gnss_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::gnss_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_lat() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_lon() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_alt() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::gnss_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::gnss_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::gnss_ctrl() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_lat() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_lon() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_alt() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::gnss_data() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
