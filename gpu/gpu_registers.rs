
pub struct GPURegisters;
impl GPURegisters {
    pub fn read_frequency() -> u32 {
        unsafe {
            core::ptr::read_volatile(crate::gpu_freq_status() as *const u32)
        }
    }
    pub fn write_frequency(freq: u32) {
        unsafe {
            core::ptr::write_volatile(crate::gpu_freq_ctrl() as *mut u32, freq);
        }
    }
    pub fn get_clock_divider() -> u32 {
        unsafe {
            let val = core::ptr::read_volatile((crate::gpu_freq_ctrl() + 0x04) as *const u32);
            val & 0xFF
        }
    }
    pub fn set_clock_divider(divider: u32) {
        unsafe {
            let current = core::ptr::read_volatile(crate::gpu_freq_ctrl() as *const u32);
            let new_val = (current & !0xFF) | (divider & 0xFF);
            core::ptr::write_volatile(crate::gpu_freq_ctrl() as *mut u32, new_val);
        }
    }
    pub fn enable_clock() {
        unsafe {
            let current = core::ptr::read_volatile(crate::gpu_freq_ctrl() as *const u32);
            core::ptr::write_volatile(crate::gpu_freq_ctrl() as *mut u32, current | 0x01);
        }
    }
    pub fn disable_clock() {
        unsafe {
            let current = core::ptr::read_volatile(crate::gpu_freq_ctrl() as *const u32);
            core::ptr::write_volatile(crate::gpu_freq_ctrl() as *mut u32, current & !0x01);
        }
    }
}
