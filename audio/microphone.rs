use core::ptr::{read_volatile, write_volatile};

const MIC_CTRL_OFFSET: u64 = 0x0000;
const MIC_STATUS_OFFSET: u64 = 0x0004;
const MIC_DATA_OFFSET: u64 = 0x0008;
const MIC_GAIN_OFFSET: u64 = 0x000C;
const MIC_CONFIG_OFFSET: u64 = 0x0010;
const MIC_MODE_OFFSET: u64 = 0x0014;
const MIC_BUFFER_OFFSET: u64 = 0x0018;
const MIC_COUNT_OFFSET: u64 = 0x001C;

fn mic_reg(offset: u64) -> u64 {
    crate::microphone_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(mic_reg(MIC_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(mic_reg(MIC_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Microphone initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(mic_reg(MIC_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(mic_reg(MIC_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(mic_reg(MIC_STATUS_OFFSET) as *const u32) }
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(mic_reg(MIC_DATA_OFFSET) as *const u32) }
}

pub fn set_gain(gain: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(mic_reg(MIC_GAIN_OFFSET) as *mut u32, gain);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_gain() -> u32 {
    unsafe { read_volatile(mic_reg(MIC_GAIN_OFFSET) as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(mic_reg(MIC_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(mic_reg(MIC_MODE_OFFSET) as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_buffer_addr() -> u64 {
    unsafe { read_volatile(mic_reg(MIC_BUFFER_OFFSET) as *const u64) }
}

pub fn get_sample_count() -> u32 {
    unsafe { read_volatile(mic_reg(MIC_COUNT_OFFSET) as *const u32) }
}
