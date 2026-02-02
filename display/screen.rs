use core::ptr::{read_volatile, write_volatile};

pub const MAX_TOUCH_POINTS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TouchPoint {
    pub x: u16,
    pub y: u16,
    pub pressure: u8,
    pub id: u8,
    pub active: bool,
}

pub struct DisplayScreen;
pub struct TouchScreen;

pub fn init_display() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::screen_ctrl_reg() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        write_volatile(crate::screen_status_reg() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        write_volatile(crate::screen_width_reg() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable_display() -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::screen_ctrl_reg() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_brightness(level: u32) -> Result<(), &'static str> {
    if level > 255 {
        return Err("Brightness level out of range");
    }
    unsafe {
        write_volatile(crate::screen_brightness_reg() as *mut u32, level);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_refresh_rate(rate: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(crate::screen_refresh_reg() as *mut u32, rate);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

impl DisplayScreen {
    pub fn init() -> Result<(), &'static str> {
        init_display()
    }

    pub fn is_enabled() -> bool {
        unsafe { read_volatile(crate::screen_status_reg() as *const u32) & 0x1 != 0 }
    }

    pub fn get_brightness() -> u32 {
        unsafe { read_volatile(crate::screen_brightness_reg() as *const u32) }
    }

    pub fn set_resolution(width: u32, height: u32) -> Result<(), &'static str> {
        unsafe {
            write_volatile(crate::screen_width_reg() as *mut u32, width);
            write_volatile(crate::screen_height_reg() as *mut u32, height);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn get_refresh_rate() -> u32 {
        unsafe { read_volatile(crate::screen_refresh_reg() as *const u32) }
    }

    pub fn get_status() -> u32 {
        unsafe { read_volatile(crate::screen_status_reg() as *const u32) }
    }

    pub fn set_config(config: u32) -> Result<(), &'static str> {
        unsafe {
            write_volatile(crate::screen_config_reg() as *mut u32, config);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn write_data(data: u32) -> Result<(), &'static str> {
        unsafe {
            write_volatile(crate::screen_data_reg() as *mut u32, data);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn read_data() -> u32 {
        unsafe { read_volatile(crate::screen_data_reg() as *const u32) }
    }
}
pub fn enable() -> Result<(), &'static str> {
    init_display()
}

pub fn disable() -> Result<(), &'static str> {
    disable_display()
}