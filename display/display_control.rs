use core::ptr::{read_volatile, write_volatile};

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_ctrl_reg() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(crate::display_status_reg() as *const u32);
        if status & 0x1 == 0 {
            return Err("Display control initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_ctrl_reg() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_ctrl_reg() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(crate::display_status_reg() as *const u32) }
}

pub fn set_width(width: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_width_reg() as *mut u32, width);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_height(height: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_height_reg() as *mut u32, height);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_mode_reg() as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_refresh(refresh: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_refresh_reg() as *mut u32, refresh);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_config_reg() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::display_data_reg() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(crate::display_data_reg() as *const u32) }
}
