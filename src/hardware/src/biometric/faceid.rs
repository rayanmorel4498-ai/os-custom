use core::ptr::{read_volatile, write_volatile};

const FACEID_CTRL_OFFSET: u64 = 0x0000;
const FACEID_STATUS_OFFSET: u64 = 0x0004;
const FACEID_ENROLL_OFFSET: u64 = 0x0008;
const FACEID_VERIFY_OFFSET: u64 = 0x000C;
const FACEID_CONF_OFFSET: u64 = 0x0010;
const FACEID_ATTEMPTS_OFFSET: u64 = 0x0014;
const FACEID_LOCK_OFFSET: u64 = 0x0018;
const FACEID_DATA_OFFSET: u64 = 0x001C;

fn faceid_reg(offset: u64) -> u64 {
    crate::faceid_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(faceid_reg(FACEID_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("FaceID initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(faceid_reg(FACEID_STATUS_OFFSET) as *const u32) }
}

pub fn enroll_face(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_ENROLL_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn verify_face(data: u32) -> Result<u32, &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_VERIFY_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok(read_volatile(faceid_reg(FACEID_VERIFY_OFFSET) as *const u32))
    }
}

pub fn set_confidence_threshold(threshold: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_CONF_OFFSET) as *mut u32, threshold);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_confidence_threshold() -> u32 {
    unsafe { read_volatile(faceid_reg(FACEID_CONF_OFFSET) as *const u32) }
}

pub fn get_attempts() -> u32 {
    unsafe { read_volatile(faceid_reg(FACEID_ATTEMPTS_OFFSET) as *const u32) }
}

pub fn get_lock_status() -> u32 {
    unsafe { read_volatile(faceid_reg(FACEID_LOCK_OFFSET) as *const u32) }
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(faceid_reg(FACEID_DATA_OFFSET) as *const u32) }
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(faceid_reg(FACEID_DATA_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
pub fn enroll(data: u32) -> Result<(), &'static str> {
    enroll_face(data)
}

pub fn verify(data: u32) -> Result<u32, &'static str> {
    verify_face(data)
}