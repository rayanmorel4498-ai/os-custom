use core::ptr::{read_volatile, write_volatile};

const ANC_CTRL_OFFSET: u64 = 0x0000;
const ANC_STATUS_OFFSET: u64 = 0x0004;
const ANC_MODE_OFFSET: u64 = 0x0008;
const ANC_LEVEL_OFFSET: u64 = 0x000C;
const ANC_CONFIG_OFFSET: u64 = 0x0010;
const ANC_DATA_OFFSET: u64 = 0x0014;
const ANC_FILTER_OFFSET: u64 = 0x0018;
const ANC_GAIN_OFFSET: u64 = 0x001C;

fn anc_reg(offset: u64) -> u64 {
    crate::noise_cancellation_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(anc_reg(ANC_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("ANC initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(anc_reg(ANC_STATUS_OFFSET) as *const u32) }
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_MODE_OFFSET) as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_mode() -> u32 {
    unsafe { read_volatile(anc_reg(ANC_MODE_OFFSET) as *const u32) }
}

pub fn set_level(level: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_LEVEL_OFFSET) as *mut u32, level);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_level() -> u32 {
    unsafe { read_volatile(anc_reg(ANC_LEVEL_OFFSET) as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(anc_reg(ANC_DATA_OFFSET) as *const u32) }
}

pub fn set_filter(filter: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_FILTER_OFFSET) as *mut u32, filter);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_gain(gain: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(anc_reg(ANC_GAIN_OFFSET) as *mut u32, gain);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
