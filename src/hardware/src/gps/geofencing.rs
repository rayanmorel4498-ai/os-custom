pub fn set_geofence(lat: u32, lon: u32, radius: u32) -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::geo_ctrl() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::geo_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_lat() as *mut u32, lat);
        core::ptr::write_volatile(crate::geo_lon() as *mut u32, lon);
        core::ptr::write_volatile(crate::geo_radius() as *mut u32, radius);
        core::ptr::write_volatile(crate::geo_config() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::geo_mode() as *mut u32, 0x1);
        core::ptr::write_volatile(crate::geo_data() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn clear_geofence() -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_volatile(crate::geo_ctrl() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_status() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_lat() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_lon() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_radius() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_config() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_mode() as *mut u32, 0x0);
        core::ptr::write_volatile(crate::geo_data() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
