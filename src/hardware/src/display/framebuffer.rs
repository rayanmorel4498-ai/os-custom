use core::ptr::{read_volatile, write_volatile};

const FB_BASE_OFFSET: u64 = 0x5000;

fn fb_base() -> u64 {
    crate::display_ctrl_base() + FB_BASE_OFFSET
}

fn fb_ctrl() -> u64 { fb_base() + 0x0000 }
fn fb_status() -> u64 { fb_base() + 0x0004 }
fn fb_addr() -> u64 { fb_base() + 0x0008 }
fn fb_size() -> u64 { fb_base() + 0x000C }
fn fb_width() -> u64 { fb_base() + 0x0010 }
fn fb_height() -> u64 { fb_base() + 0x0014 }
fn fb_config() -> u64 { fb_base() + 0x0018 }
fn fb_data() -> u64 { fb_base() + 0x001C }

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(fb_status() as *const u32);
        if status & 0x1 == 0 {
            return Err("Framebuffer initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_ctrl() as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_ctrl() as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(fb_status() as *const u32) }
}

pub fn set_address(addr: u64) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_addr() as *mut u64, addr);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_size(size: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_size() as *mut u32, size);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_width(width: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_width() as *mut u32, width);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_height(height: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_height() as *mut u32, height);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_config() as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fb_data() as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(fb_data() as *const u32) }
}
