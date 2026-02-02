use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CpuState {
    Reset,
    Init,
    Running,
    Idle,
    Halted,
}

pub struct CpuControl {
    state: CpuState,
    initialized: AtomicBool,
}

impl CpuControl {
    pub const fn new() -> Self {
        Self {
            state: CpuState::Reset,
            initialized: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    fn big_cluster_ctrl() -> u64 {
        crate::cpu_apcs_base() + 0x0000
    }

    #[inline(always)]
    fn little_cluster_ctrl() -> u64 {
        crate::cpu_apcs_base() + 0x0004
    }

    #[inline(always)]
    fn big_cluster_status() -> u64 {
        crate::cpu_apcs_base() + 0x0008
    }

    #[inline(always)]
    fn little_cluster_status() -> u64 {
        crate::cpu_apcs_base() + 0x000C
    }

    #[inline(always)]
    unsafe fn write_reg(addr: u64, value: u32) {
        write_volatile(addr as *mut u32, value);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    #[inline(always)]
    unsafe fn read_reg(addr: u64) -> u32 {
        read_volatile(addr as *const u32)
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.state = CpuState::Init;
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), &'static str> {
        if !self.initialized.load(Ordering::SeqCst) {
            self.init()?;
        }
        self.state = CpuState::Running;
        Ok(())
    }

    pub fn idle(&mut self) {
        self.state = CpuState::Idle;
        
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }

    pub fn halt(&mut self) -> ! {
        self.state = CpuState::Halted;
        
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("msr DAIF, #15", options(nomem, nostack));
        }
        
        loop {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                core::arch::asm!("wfi", options(nomem, nostack));
            }
            
            #[cfg(not(target_arch = "aarch64"))]
            {
                core::hint::spin_loop();
            }
        }
    }

    pub fn state(&self) -> CpuState {
        self.state
    }

    pub fn enable_big_cluster(&self) -> Result<(), &'static str> {
        unsafe {
            Self::write_reg(Self::big_cluster_ctrl(), 0x1);
            let _ = Self::read_reg(Self::big_cluster_status());
        }
        Ok(())
    }

    pub fn enable_little_cluster(&self) -> Result<(), &'static str> {
        unsafe {
            Self::write_reg(Self::little_cluster_ctrl(), 0x1);
            let _ = Self::read_reg(Self::little_cluster_status());
        }
        Ok(())
    }

    pub fn disable_big_cluster(&self) {
        unsafe {
            Self::write_reg(Self::big_cluster_ctrl(), 0x0);
        }
    }

    pub fn disable_little_cluster(&self) {
        unsafe {
            Self::write_reg(Self::little_cluster_ctrl(), 0x0);
        }
    }

    pub fn set_big_frequency(&self, freq_mhz: u16) -> Result<(), &'static str> {
        if freq_mhz < 300 || freq_mhz > 2400 {
            return Err("invalid_frequency");
        }
        unsafe {
            Self::write_reg(crate::cpu_big_freq_reg(), freq_mhz as u32);
        }
        Ok(())
    }

    pub fn set_little_frequency(&self, freq_mhz: u16) -> Result<(), &'static str> {
        if freq_mhz < 300 || freq_mhz > 2000 {
            return Err("invalid_frequency");
        }
        unsafe {
            Self::write_reg(crate::cpu_little_freq_reg(), freq_mhz as u32);
        }
        Ok(())
    }

    pub fn set_big_voltage(&self, mv: u16) -> Result<(), &'static str> {
        if mv < 700 || mv > 1200 {
            return Err("invalid_voltage");
        }
        unsafe {
            Self::write_reg(crate::cpu_big_volt_reg(), mv as u32);
        }
        Ok(())
    }

    pub fn set_little_voltage(&self, mv: u16) -> Result<(), &'static str> {
        if mv < 700 || mv > 1200 {
            return Err("invalid_voltage");
        }
        unsafe {
            Self::write_reg(crate::cpu_little_volt_reg(), mv as u32);
        }
        Ok(())
    }
}
