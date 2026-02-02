use core::ptr::{read_volatile, write_volatile};

const VOICE_CTRL_OFFSET: u64 = 0x0000;
const VOICE_STATUS_OFFSET: u64 = 0x0004;
const VOICE_ENROLL_OFFSET: u64 = 0x0008;
const VOICE_VERIFY_OFFSET: u64 = 0x000C;
const VOICE_PROFILE_OFFSET: u64 = 0x0010;
const VOICE_CONF_OFFSET: u64 = 0x0014;
const VOICE_DATA_OFFSET: u64 = 0x0018;
const VOICE_CONFIG_OFFSET: u64 = 0x001C;

fn voice_reg(offset: u64) -> u64 {
    crate::voice_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(voice_reg(VOICE_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Voice biometrics initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(voice_reg(VOICE_STATUS_OFFSET) as *const u32) }
}

pub fn enroll_voice(profile_id: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_ENROLL_OFFSET) as *mut u32, profile_id);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn verify_voice(profile_id: u32) -> Result<u32, &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_VERIFY_OFFSET) as *mut u32, profile_id);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok(read_volatile(voice_reg(VOICE_VERIFY_OFFSET) as *const u32))
    }
}

pub fn get_profile_count() -> u32 {
    unsafe { read_volatile(voice_reg(VOICE_PROFILE_OFFSET) as *const u32) }
}

pub fn set_confidence(conf: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_CONF_OFFSET) as *mut u32, conf);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_confidence() -> u32 {
    unsafe { read_volatile(voice_reg(VOICE_CONF_OFFSET) as *const u32) }
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(voice_reg(VOICE_DATA_OFFSET) as *const u32) }
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_DATA_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn set_config(config: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(voice_reg(VOICE_CONFIG_OFFSET) as *mut u32, config);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_config() -> u32 {
    unsafe { read_volatile(voice_reg(VOICE_CONFIG_OFFSET) as *const u32) }
}
pub fn enroll(profile_id: u32) -> Result<(), &'static str> {
    enroll_voice(profile_id)
}