use core::ptr::{read_volatile, write_volatile};

const TOUCH_BASE_OFFSET: u64 = 0x4000;

fn touch_base() -> u64 {
    crate::display_ctrl_base() + TOUCH_BASE_OFFSET
}

fn touch_ctrl() -> u64 { touch_base() + 0x0000 }
fn touch_status() -> u64 { touch_base() + 0x0004 }
fn touch_points() -> u64 { touch_base() + 0x0008 }
fn touch_x() -> u64 { touch_base() + 0x000C }
fn touch_y() -> u64 { touch_base() + 0x0010 }
fn touch_pressure() -> u64 { touch_base() + 0x0014 }
fn touch_config() -> u64 { touch_base() + 0x0018 }
fn touch_data() -> u64 { touch_base() + 0x001C }

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(touch_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(touch_status() as *const u32);
        if status & 0x1 == 0 {
            return Err("Touch initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(touch_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(touch_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(touch_status() as *const u32) }
}

pub fn get_point_count() -> u32 {
    unsafe { read_volatile(touch_points() as *const u32) }
}

pub fn get_x() -> u32 {
    unsafe { read_volatile(touch_x() as *const u32) }
}

pub fn get_y() -> u32 {
    unsafe { read_volatile(touch_y() as *const u32) }
}

pub fn get_pressure() -> u32 {
    unsafe { read_volatile(touch_pressure() as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(touch_config() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(touch_data() as *const u32) }
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(touch_data() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
