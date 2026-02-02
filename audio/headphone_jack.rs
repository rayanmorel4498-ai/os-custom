use core::ptr::{read_volatile, write_volatile};

const JACK_CTRL_OFFSET: u64 = 0x0000;
const JACK_STATUS_OFFSET: u64 = 0x0004;
const JACK_TYPE_OFFSET: u64 = 0x0008;
const JACK_VOLUME_OFFSET: u64 = 0x000C;
const JACK_CONFIG_OFFSET: u64 = 0x0010;
const JACK_MODE_OFFSET: u64 = 0x0014;
const JACK_DATA_OFFSET: u64 = 0x0018;
const JACK_IRQ_OFFSET: u64 = 0x001C;

fn jack_reg(offset: u64) -> u64 {
    crate::headphone_jack_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(jack_reg(JACK_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(jack_reg(JACK_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Headphone jack initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(jack_reg(JACK_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(jack_reg(JACK_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(jack_reg(JACK_STATUS_OFFSET) as *const u32) }
}

pub fn is_inserted() -> bool {
    let status = get_status();
    status & 0x1 != 0
}

pub fn get_type() -> u32 {
    unsafe { read_volatile(jack_reg(JACK_TYPE_OFFSET) as *const u32) }
}

pub fn set_volume(volume: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(jack_reg(JACK_VOLUME_OFFSET) as *mut u32, volume);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_volume() -> u32 {
    unsafe { read_volatile(jack_reg(JACK_VOLUME_OFFSET) as *const u32) }
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(jack_reg(JACK_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_mode(mode: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(jack_reg(JACK_MODE_OFFSET) as *mut u32, mode);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(jack_reg(JACK_DATA_OFFSET) as *const u32) }
}

pub fn get_irq_status() -> u32 {
    unsafe { read_volatile(jack_reg(JACK_IRQ_OFFSET) as *const u32) }
}
