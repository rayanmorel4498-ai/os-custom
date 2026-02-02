use core::ptr::{read_volatile, write_volatile};

const REFRESH_BASE_OFFSET: u64 = 0x2000;

fn refresh_base() -> u64 {
    crate::display_ctrl_base() + REFRESH_BASE_OFFSET
}

fn refresh_ctrl() -> u64 { refresh_base() + 0x0000 }
fn refresh_status() -> u64 { refresh_base() + 0x0004 }
fn refresh_rate() -> u64 { refresh_base() + 0x0008 }
fn refresh_mode() -> u64 { refresh_base() + 0x000C }
fn refresh_config() -> u64 { refresh_base() + 0x0010 }
fn refresh_min() -> u64 { refresh_base() + 0x0014 }
fn refresh_max() -> u64 { refresh_base() + 0x0018 }
fn refresh_data() -> u64 { refresh_base() + 0x001C }

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(refresh_status() as *const u32);
        if status & 0x1 == 0 {
            return Err("Refresh initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(refresh_status() as *const u32) }
}

pub fn set_rate(rate: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_rate() as *mut u32, rate);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_rate() -> u32 {
    unsafe { read_volatile(refresh_rate() as *const u32) }
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_mode() as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_config() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_min(min: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_min() as *mut u32, min);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_max(max: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_max() as *mut u32, max);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(refresh_data() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(refresh_data() as *const u32) }
}
