use core::ptr::{read_volatile, write_volatile};
use crate::config::get_config;

pub fn get_max_brightness() -> u8 {
    get_config().display.brightness_max
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(crate::brightness_status() as *const u32);
        if status & 0x1 == 0 {
            return Err("Brightness initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(crate::brightness_status() as *const u32) }
}

pub fn set_level(level: u32) -> Result<(), &'static str> {
    if level > 255 {
        return Err("Brightness level out of range");
    }
    unsafe {
        write_volatile(crate::brightness_level() as *mut u32, level);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_level() -> u32 {
    unsafe { read_volatile(crate::brightness_level() as *const u32) }
}

pub fn set_min(min: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_min() as *mut u32, min);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_max(max: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_max() as *mut u32, max);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_config() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_mode() as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::brightness_data() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(crate::brightness_data() as *const u32) }
}
