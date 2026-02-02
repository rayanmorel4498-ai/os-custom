use core::ptr::{read_volatile, write_volatile};

const FP_CTRL_OFFSET: u64 = 0x0000;
const FP_STATUS_OFFSET: u64 = 0x0004;
const FP_ENROLL_OFFSET: u64 = 0x0008;
const FP_VERIFY_OFFSET: u64 = 0x000C;
const FP_TEMPLATE_OFFSET: u64 = 0x0010;
const FP_ATTEMPTS_OFFSET: u64 = 0x0014;
const FP_LOCK_OFFSET: u64 = 0x0018;
const FP_DATA_OFFSET: u64 = 0x001C;

fn fp_reg(offset: u64) -> u64 {
    crate::fingerprint_base() + offset
}

pub fn init() -> Result<(), &'static str> {
    unsafe {
        read_volatile(fp_reg(FP_STATUS_OFFSET) as *const u32);
        write_volatile(fp_reg(FP_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let status = read_volatile(fp_reg(FP_STATUS_OFFSET) as *const u32);
        if status & 0x1 == 0 {
            return Err("Fingerprint initialization failed");
        }
    }
    Ok(())
}

pub fn enable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(fp_reg(FP_CTRL_OFFSET) as *mut u32, 0x1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn disable() -> Result<(), &'static str> {
    unsafe {
        write_volatile(fp_reg(FP_CTRL_OFFSET) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_status() -> u32 {
    unsafe { read_volatile(fp_reg(FP_STATUS_OFFSET) as *const u32) }
}

pub fn enroll(template_id: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fp_reg(FP_ENROLL_OFFSET) as *mut u32, template_id);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn verify(template_id: u32) -> Result<u32, &'static str> {
    unsafe {
        write_volatile(fp_reg(FP_VERIFY_OFFSET) as *mut u32, template_id);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok(read_volatile(fp_reg(FP_VERIFY_OFFSET) as *const u32))
    }
}

pub fn get_template_count() -> u32 {
    unsafe { read_volatile(fp_reg(FP_TEMPLATE_OFFSET) as *const u32) }
}

pub fn get_attempts() -> u32 {
    unsafe { read_volatile(fp_reg(FP_ATTEMPTS_OFFSET) as *const u32) }
}

pub fn get_lock_status() -> u32 {
    unsafe { read_volatile(fp_reg(FP_LOCK_OFFSET) as *const u32) }
}

pub fn read_data() -> u32 {
    unsafe { read_volatile(fp_reg(FP_DATA_OFFSET) as *const u32) }
}

pub fn write_data(data: u32) -> Result<(), &'static str> {
    unsafe {
        write_volatile(fp_reg(FP_DATA_OFFSET) as *mut u32, data);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}
