use core::ptr::{read_volatile, write_volatile};

const STYLUS_BASE_OFFSET: u64 = 0x3000;

fn stylus_base() -> u64 {
    crate::display_ctrl_base() + STYLUS_BASE_OFFSET
}

fn stylus_ctrl() -> u64 { stylus_base() + 0x0000 }
fn stylus_status() -> u64 { stylus_base() + 0x0004 }
fn stylus_x() -> u64 { stylus_base() + 0x0008 }
fn stylus_y() -> u64 { stylus_base() + 0x000C }
fn stylus_pressure() -> u64 { stylus_base() + 0x0010 }
fn stylus_buttons() -> u64 { stylus_base() + 0x0014 }
fn stylus_config() -> u64 { stylus_base() + 0x0018 }
fn stylus_data() -> u64 { stylus_base() + 0x001C }

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(stylus_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(stylus_status() as *const u32);
        if status & 0x1 == 0 {
            return Err("Stylus initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(stylus_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(stylus_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(stylus_status() as *const u32) }
}

pub fn get_x() -> u32 {
    unsafe { read_volatile(stylus_x() as *const u32) }
}

pub fn get_y() -> u32 {
    unsafe { read_volatile(stylus_y() as *const u32) }
}

pub fn get_pressure() -> u32 {
    unsafe { read_volatile(stylus_pressure() as *const u32) }
}

pub fn get_buttons() -> u32 {
    unsafe { read_volatile(stylus_buttons() as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(stylus_config() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn is_active() -> bool {
    let status = get_status();
    status & 0x1 != 0
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(stylus_data() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(stylus_data() as *const u32) }
}
