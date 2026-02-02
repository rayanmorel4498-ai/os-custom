extern crate alloc;
use core::sync::atomic::{AtomicU32, Ordering};
use core::ptr::{read_volatile, write_volatile};
const DISPLAY_CTRL_BASE: usize = 0x1400_0000;
const DISP_PWR: usize = 0x00;
const DISP_CLK: usize = 0x04;
const DISP_RST: usize = 0x08;
const DISP_STATUS: usize = 0x0C;
const DISP_RES_WIDTH: usize = 0x10;
const DISP_RES_HEIGHT: usize = 0x14;
const DISP_REFRESH_RATE: usize = 0x18;
const DISP_BRIGHTNESS: usize = 0x1C;
static DISPLAY_ENABLED: AtomicU32 = AtomicU32::new(0);
static CURRENT_BRIGHTNESS: AtomicU32 = AtomicU32::new(255);
#[derive(Debug, Clone, Copy)]
pub enum TouchError {
    I2c,
    Timeout,
    Invalid,
}
impl TouchError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TouchError::I2c => "I2C communication error",
            TouchError::Timeout => "Touch timeout",
            TouchError::Invalid => "Invalid touch data",
        }
    }
}
pub struct DisplaySpec;
impl DisplaySpec {
    pub const RESOLUTION_WIDTH: u32 = 2520;
    pub const RESOLUTION_HEIGHT: u32 = 1080;
    pub const ASPECT_RATIO: f32 = 20.7 / 9.0;
    pub const MAX_REFRESH_RATE_HZ: u32 = 120;
    pub const STANDARD_REFRESH_RATE_HZ: u32 = 60;
    pub const PPI: u32 = 450;
    pub const DPI: u32 = 450;
    pub const HDR_SUPPORT: bool = true;
    pub const ADAPTIVE_REFRESH_SUPPORT: bool = true;
}
pub fn init_display() {
    unsafe {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        write_volatile((DISPLAY_CTRL_BASE + DISP_PWR) as *mut u32, 0x1);
        write_volatile((DISPLAY_CTRL_BASE + DISP_CLK) as *mut u32, 0x1);
        write_volatile((DISPLAY_CTRL_BASE + DISP_RST) as *mut u32, 0x0);
        write_volatile((DISPLAY_CTRL_BASE + DISP_STATUS) as *mut u32, 0x0);
        write_volatile((DISPLAY_CTRL_BASE + DISP_RES_WIDTH) as *mut u32, DisplaySpec::RESOLUTION_WIDTH);
        write_volatile((DISPLAY_CTRL_BASE + DISP_RES_HEIGHT) as *mut u32, DisplaySpec::RESOLUTION_HEIGHT);
        write_volatile((DISPLAY_CTRL_BASE + DISP_REFRESH_RATE) as *mut u32, 60);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        for _ in 0..1000 {
            core::arch::asm!("nop");
        }
    }
    DISPLAY_ENABLED.store(1, Ordering::SeqCst);
}
pub fn enable_display() {
    if DISPLAY_ENABLED.load(Ordering::SeqCst) != 0 {
        return;
    }
    init_display();
}
pub fn disable_display() {
    if DISPLAY_ENABLED.load(Ordering::SeqCst) == 0 {
        return;
    }
    unsafe {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        write_volatile((DISPLAY_CTRL_BASE + DISP_RST) as *mut u32, 0x1);
        write_volatile((DISPLAY_CTRL_BASE + DISP_CLK) as *mut u32, 0x0);
        write_volatile((DISPLAY_CTRL_BASE + DISP_PWR) as *mut u32, 0x0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    DISPLAY_ENABLED.store(0, Ordering::SeqCst);
}
pub fn set_brightness(level: u8) {
    if DISPLAY_ENABLED.load(Ordering::SeqCst) == 0 {
        return;
    }
    unsafe {
        write_volatile((DISPLAY_CTRL_BASE + DISP_BRIGHTNESS) as *mut u32, level as u32);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    CURRENT_BRIGHTNESS.store(level as u32, Ordering::SeqCst);
}
pub fn get_brightness() -> u8 {
    CURRENT_BRIGHTNESS.load(Ordering::SeqCst) as u8
}
pub fn set_refresh_rate(hz: u32) {
    if DISPLAY_ENABLED.load(Ordering::SeqCst) == 0 {
        return;
    }
    let rate = if hz > DisplaySpec::MAX_REFRESH_RATE_HZ {
        DisplaySpec::MAX_REFRESH_RATE_HZ
    } else if hz < 30 {
        30
    } else {
        hz
    };
    unsafe {
        write_volatile((DISPLAY_CTRL_BASE + DISP_REFRESH_RATE) as *mut u32, rate);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub fn get_refresh_rate() -> u32 {
    unsafe {
        read_volatile((DISPLAY_CTRL_BASE + DISP_REFRESH_RATE) as *const u32)
    }
}
pub fn is_display_enabled() -> bool {
    DISPLAY_ENABLED.load(Ordering::SeqCst) != 0
}
pub fn enable_adaptive_refresh() {
    set_refresh_rate(120);
}
pub fn disable_adaptive_refresh() {
    set_refresh_rate(60);
}
