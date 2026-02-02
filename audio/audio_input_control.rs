use core::ptr::{read_volatile, write_volatile};

const AUDIO_IN_CTRL_OFFSET: u64 = 0x0000;
const AUDIO_IN_STATUS_OFFSET: u64 = 0x0004;
const AUDIO_IN_DATA_OFFSET: u64 = 0x0008;
const AUDIO_IN_CONFIG_OFFSET: u64 = 0x000C;
const AUDIO_IN_GAIN_OFFSET: u64 = 0x0010;
const AUDIO_IN_MUX_OFFSET: u64 = 0x0014;
const AUDIO_IN_FILTER_OFFSET: u64 = 0x0018;
const AUDIO_IN_IRQ_OFFSET: u64 = 0x001C;

fn audio_in_reg(offset: u64) -> u64 {
    crate::audio_input_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(audio_in_reg(AUDIO_IN_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Audio input initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(audio_in_reg(AUDIO_IN_STATUS_OFFSET) as *const u32) }
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(audio_in_reg(AUDIO_IN_DATA_OFFSET) as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_gain(gain: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_GAIN_OFFSET) as *mut u32, gain);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mux(mux: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_MUX_OFFSET) as *mut u32, mux);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_filter(filter: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(audio_in_reg(AUDIO_IN_FILTER_OFFSET) as *mut u32, filter);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_irq_status() -> u32 {
    unsafe { read_volatile(audio_in_reg(AUDIO_IN_IRQ_OFFSET) as *const u32) }
}
