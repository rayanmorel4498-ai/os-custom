pub fn get_coordinates() -> Result<(f32, f32), &'static str> {
    unsafe {
        let lat = core::ptr::read_volatile(crate::loc_lat() as *const u32) as f32 / 1e7;
        let lon = core::ptr::read_volatile(crate::loc_lon() as *const u32) as f32 / 1e7;
        core::ptr::write_volatile(crate::loc_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::loc_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::loc_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::loc_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::loc_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok((lat, lon))
    }
}

pub fn get_altitude() -> Result<u32, &'static str> {
    unsafe {
        let alt = core::ptr::read_volatile(crate::loc_alt() as *const u32);
        core::ptr::write_volatile(crate::loc_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::loc_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::loc_lat() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::loc_lon() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::loc_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::loc_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::loc_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok(alt)
    }
}
