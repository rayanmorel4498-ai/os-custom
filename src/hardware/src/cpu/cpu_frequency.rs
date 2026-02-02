use crate::config::get_config;

pub fn get_max_frequency() -> u32 {
    get_config().cpu.max_frequency
}

pub fn get_min_frequency() -> u32 {
    get_config().cpu.min_frequency
}

pub fn is_turbo_enabled() -> bool {
    get_config().cpu.turbo_enabled
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CpuFrequency {
    pub big_mhz: u16,
    pub little_mhz: u16,
}

impl CpuFrequency {
    pub fn new(big: u16, little: u16) -> Self {
        CpuFrequency { big_mhz: big, little_mhz: little }
    }

    pub fn validate(&self) -> bool {
        let max = get_max_frequency() as u16;
        let min = get_min_frequency() as u16;
        self.big_mhz >= min && self.big_mhz <= max &&
        self.little_mhz >= min && self.little_mhz <= max
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CpuFreqLevel {
    Low,
    Medium,
    High,
    Turbo,
}

impl CpuFreqLevel {
    pub fn to_freq(self) -> CpuFrequency {
        let max_freq = get_max_frequency() as u16;
        match self {
            CpuFreqLevel::Low => CpuFrequency::new(400, 400),
            CpuFreqLevel::Medium => CpuFrequency::new(1113, 1113),
            CpuFreqLevel::High => CpuFrequency::new(1728, 1708),
            CpuFreqLevel::Turbo => CpuFrequency::new(max_freq, max_freq),
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn dmb_sy() {
    unsafe {
        asm!("dmb sy", options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn dmb_sy() {
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn dsb_sy() {
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn dsb_sy() {
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn isb() {
    unsafe {
        asm!("isb", options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn isb() {
}

#[inline(always)]
unsafe fn write_mmio(addr: u64, value: u32) {
    (addr as *mut u32).write_volatile(value);
    dmb_sy();
}

#[inline(always)]
unsafe fn read_mmio(addr: u64) -> u32 {
    dmb_sy();
    (addr as *const u32).read_volatile()
}

#[inline(always)]
unsafe fn write_big_freq(mhz: u16) {
    write_mmio(crate::cpu_big_freq_reg(), mhz as u32);
}

#[inline(always)]
unsafe fn write_little_freq(mhz: u16) {
    write_mmio(crate::cpu_little_freq_reg(), mhz as u32);
}

#[inline(always)]
unsafe fn read_big_freq() -> u16 {
    read_mmio(crate::cpu_big_freq_reg()) as u16
}

#[inline(always)]
unsafe fn read_little_freq() -> u16 {
    read_mmio(crate::cpu_little_freq_reg()) as u16
}

#[inline(always)]
unsafe fn write_big_voltage(mv: u16) {
    write_mmio(crate::cpu_big_volt_reg(), mv as u32);
}

#[inline(always)]
unsafe fn write_little_voltage(mv: u16) {
    write_mmio(crate::cpu_little_volt_reg(), mv as u32);
}
pub fn set(level: CpuFreqLevel) {
    let freq = level.to_freq();
    unsafe {
        write_big_freq(freq.big_mhz);
        write_little_freq(freq.little_mhz);
        dsb_sy();
        isb();
    }
}

pub fn current() -> CpuFrequency {
    unsafe {
        let big = read_big_freq();
        let little = read_little_freq();
        CpuFrequency::new(big, little)
    }
}

pub fn force_low_power() {
    set(CpuFreqLevel::Low);
}

pub fn boost() {
    set(CpuFreqLevel::Turbo);
}

pub fn current_level() -> CpuFreqLevel {
    let freq = current();
    match (freq.big_mhz, freq.little_mhz) {
        (576, 576) => CpuFreqLevel::Low,
        (1113, 1113) => CpuFreqLevel::Medium,
        (1728, 1708) => CpuFreqLevel::High,
        (2400, 2000) => CpuFreqLevel::Turbo,
        _ => CpuFreqLevel::Medium,
    }
}

pub fn set_raw(big_mhz: u16, little_mhz: u16) -> Result<(), &'static str> {
    let freq = CpuFrequency::new(big_mhz, little_mhz);
    if !freq.validate() {
        return Err("frequency_out_of_range");
    }
    unsafe {
        write_big_freq(freq.big_mhz);
        write_little_freq(freq.little_mhz);
        dsb_sy();
    }
    Ok(())
}

pub fn set_voltage(big_mv: u16, little_mv: u16) -> Result<(), &'static str> {
    if big_mv < 700 || big_mv > 1200 || little_mv < 700 || little_mv > 1200 {
        return Err("voltage_out_of_range");
    }
    unsafe {
        write_big_voltage(big_mv);
        write_little_voltage(little_mv);
        dsb_sy();
    }
    Ok(())
}
pub fn set_frequency(core_id: u32, mhz: u16) -> Result<(), &'static str> {
    if mhz < 300 || mhz > 2400 {
        return Err("frequency_out_of_range");
    }
    unsafe {
        if core_id < 2 {
            write_big_freq(mhz);
        } else {
            write_little_freq(mhz);
        }
        dsb_sy();
    }
    Ok(())
}