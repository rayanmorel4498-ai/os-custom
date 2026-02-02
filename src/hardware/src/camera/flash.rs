pub fn enable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::flash_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::flash_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_pwm() as *mut u32, 0xFF);
        core::ptr::write_volatile(crate::flash_brightness() as *mut u32, 0xFF);
        core::ptr::write_volatile(crate::flash_timing() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::flash_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::flash_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::flash_ctrl() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_pwm() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_brightness() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_timing() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::flash_data() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
