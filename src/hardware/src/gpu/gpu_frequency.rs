use core::ptr::{read_volatile, write_volatile};
use crate::config::get_config;

pub fn get_max_frequency() -> u32 {
    get_config().gpu.max_frequency
}

pub fn get_throttle_temperature() -> i8 {
    get_config().gpu.throttle_temperature
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GpuFreqLevel {
    Low,
    Medium,
    High,
    Turbo,
}
const FREQ_LOW: u32 = 0x01;
const FREQ_MED: u32 = 0x02;
const FREQ_HIGH: u32 = 0x03;
const FREQ_TURBO: u32 = 0x04;
#[inline(always)]
unsafe fn write_freq(val: u32) {
    write_volatile(crate::gpu_freq_ctrl() as *mut u32, val);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
#[inline(always)]
unsafe fn read_freq() -> u32 {
    read_volatile(crate::gpu_freq_status() as *const u32)
}
pub fn set(level: GpuFreqLevel) {
    unsafe {
        match level {
            GpuFreqLevel::Low => write_freq(FREQ_LOW),
            GpuFreqLevel::Medium => write_freq(FREQ_MED),
            GpuFreqLevel::High => write_freq(FREQ_HIGH),
            GpuFreqLevel::Turbo => write_freq(FREQ_TURBO),
        }
    }
}
pub fn current() -> GpuFreqLevel {
    unsafe {
        match read_freq() {
            FREQ_LOW => GpuFreqLevel::Low,
            FREQ_MED => GpuFreqLevel::Medium,
            FREQ_HIGH => GpuFreqLevel::High,
            FREQ_TURBO => GpuFreqLevel::Turbo,
            _ => GpuFreqLevel::Low,
        }
    }
}
pub fn force_low_power() {
    set(GpuFreqLevel::Low);
}
pub fn boost() {
    set(GpuFreqLevel::Turbo);
}

pub fn set_frequency(freq: u32) -> Result<(), &'static str> {
    let level = match freq {
        300..=400 => GpuFreqLevel::Low,
        401..=600 => GpuFreqLevel::Medium,
        601..=800 => GpuFreqLevel::High,
        801..=1000 => GpuFreqLevel::Turbo,
        _ => return Err("Frequency out of range"),
    };
    set(level);
    Ok(())
}
