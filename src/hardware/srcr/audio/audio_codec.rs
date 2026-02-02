use core::ptr::{read_volatile, write_volatile};

const CODEC_CTRL_OFFSET: u64 = 0x0000;
const CODEC_STATUS_OFFSET: u64 = 0x0004;
const CODEC_VOLUME_OFFSET: u64 = 0x0008;
const CODEC_MIC_GAIN_OFFSET: u64 = 0x000C;
const CODEC_HP_GAIN_OFFSET: u64 = 0x0010;
const CODEC_DATA_OFFSET: u64 = 0x0014;
const CODEC_CONFIG_OFFSET: u64 = 0x0018;
const CODEC_MODE_OFFSET: u64 = 0x001C;

fn codec_reg(offset: u64) -> u64 {
    crate::audio_codec_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(codec_reg(CODEC_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Codec initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(codec_reg(CODEC_STATUS_OFFSET) as *const u32) }
}

pub fn set_volume(volume: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_VOLUME_OFFSET) as *mut u32, volume);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_volume() -> u32 {
    unsafe { read_volatile(codec_reg(CODEC_VOLUME_OFFSET) as *const u32) }
}

pub fn set_mic_gain(gain: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_MIC_GAIN_OFFSET) as *mut u32, gain);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_mic_gain() -> u32 {
    unsafe { read_volatile(codec_reg(CODEC_MIC_GAIN_OFFSET) as *const u32) }
}

pub fn set_hp_gain(gain: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_HP_GAIN_OFFSET) as *mut u32, gain);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_hp_gain() -> u32 {
    unsafe { read_volatile(codec_reg(CODEC_HP_GAIN_OFFSET) as *const u32) }
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(codec_reg(CODEC_DATA_OFFSET) as *const u32) }
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_DATA_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(codec_reg(CODEC_MODE_OFFSET) as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
