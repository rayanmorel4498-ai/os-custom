use core::ptr::{read_volatile, write_volatile};

const DYNAMIC_BASE_OFFSET: u64 = 0x6000;

fn dynamic_base() -> u64 {
    crate::display_ctrl_base() + DYNAMIC_BASE_OFFSET
}

fn dynamic_ctrl() -> u64 { dynamic_base() + 0x0000 }
fn dynamic_status() -> u64 { dynamic_base() + 0x0004 }
fn dynamic_resolution() -> u64 { dynamic_base() + 0x0008 }
fn dynamic_power() -> u64 { dynamic_base() + 0x000C }
fn dynamic_refresh() -> u64 { dynamic_base() + 0x0010 }
fn dynamic_brightness() -> u64 { dynamic_base() + 0x0014 }
fn dynamic_config() -> u64 { dynamic_base() + 0x0018 }
fn dynamic_data() -> u64 { dynamic_base() + 0x001C }

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(dynamic_status() as *const u32);
        if status & 0x1 == 0 {
            return Err("Dynamic display initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(dynamic_status() as *const u32) }
}

pub fn set_resolution(resolution: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_resolution() as *mut u32, resolution);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_power(power: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_power() as *mut u32, power);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_refresh(refresh: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_refresh() as *mut u32, refresh);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_brightness(brightness: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_brightness() as *mut u32, brightness);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_config() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(dynamic_data() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(dynamic_data() as *const u32) }
}
