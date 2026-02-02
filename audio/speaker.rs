use core::ptr::{read_volatile, write_volatile};

const SPEAKER_CTRL_OFFSET: u64 = 0x0000;
const SPEAKER_STATUS_OFFSET: u64 = 0x0004;
const SPEAKER_VOLUME_OFFSET: u64 = 0x0008;
const SPEAKER_PLAY_OFFSET: u64 = 0x000C;
const SPEAKER_STOP_OFFSET: u64 = 0x0010;
const SPEAKER_DATA_OFFSET: u64 = 0x0014;
const SPEAKER_CONFIG_OFFSET: u64 = 0x0018;
const SPEAKER_MODE_OFFSET: u64 = 0x001C;

fn speaker_reg(offset: u64) -> u64 {
    crate::speaker_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(speaker_reg(SPEAKER_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Speaker initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(speaker_reg(SPEAKER_STATUS_OFFSET) as *const u32) }
}

pub fn set_volume(volume: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_VOLUME_OFFSET) as *mut u32, volume);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_volume() -> u32 {
    unsafe { read_volatile(speaker_reg(SPEAKER_VOLUME_OFFSET) as *const u32) }
}

pub fn play() -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_PLAY_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn stop() -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_STOP_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_DATA_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(speaker_reg(SPEAKER_DATA_OFFSET) as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(speaker_reg(SPEAKER_MODE_OFFSET) as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
