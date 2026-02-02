pub fn init() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::front_isp_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_resolution() as *mut u32, 0x0D00_0960);
        core::ptr::write_volatile(crate::front_isp_frame_rate() as *mut u32, 30);
        core::ptr::write_volatile(crate::front_isp_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_format() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn capture() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::front_isp_ctrl() as *mut u32, 0x2);
        core::ptr::write_volatile(crate::front_isp_status() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_resolution() as *mut u32, 0x0D00_0960);
        core::ptr::write_volatile(crate::front_isp_frame_rate() as *mut u32, 30);
        core::ptr::write_volatile(crate::front_isp_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_format() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::front_isp_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn stop() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::front_isp_ctrl() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_resolution() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_frame_rate() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_format() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::front_isp_data() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
