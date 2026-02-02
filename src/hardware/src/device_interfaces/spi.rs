extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU8, AtomicBool, Ordering};
pub struct SPIInterface {
    clock_mhz: AtomicU32,
    mode: AtomicU8,
    enabled: AtomicBool,
}
impl SPIInterface {
    pub fn new() -> Self {
        SPIInterface {
            clock_mhz: AtomicU32::new(10),
            mode: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
        }
    }
    pub fn enable(&self) -> Result<(), String> {
        unsafe {
            write_volatile(crate::spi_ctrl() as *mut u32, SPI_CTRL_ENABLE);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn transfer(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(String::from("SPI not enabled"));
        }
        let mut out = Vec::with_capacity(data.len());
        for byte in data {
            self.wait_tx_ready()?;
            unsafe {
                write_volatile(crate::spi_tx() as *mut u32, *byte as u32);
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
            self.wait_rx_ready()?;
            let value = unsafe { read_volatile(crate::spi_rx() as *const u32) };
            out.push(value as u8);
        }
        Ok(out)
    }
    pub fn set_clock(&self, mhz: u32) -> Result<(), String> {
        if mhz > 50 {
            return Err(String::from("Clock too high"));
        }
        unsafe {
            write_volatile(crate::spi_clk() as *mut u32, mhz);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.clock_mhz.store(mhz, Ordering::SeqCst);
        Ok(())
    }
    pub fn set_mode(&self, mode: u8) -> Result<(), String> {
        if mode > 3 {
            return Err(String::from("Invalid SPI mode"));
        }
        unsafe {
            let mut ctrl = read_volatile(crate::spi_ctrl() as *const u32);
            ctrl &= !SPI_CTRL_MODE_MASK;
            ctrl |= (mode as u32) << SPI_CTRL_MODE_SHIFT;
            write_volatile(crate::spi_ctrl() as *mut u32, ctrl);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.mode.store(mode, Ordering::SeqCst);
        Ok(())
    }
    pub fn get_clock(&self) -> u32 {
        self.clock_mhz.load(Ordering::SeqCst)
    }
    pub fn get_mode(&self) -> u8 {
        self.mode.load(Ordering::SeqCst)
    }

    fn wait_tx_ready(&self) -> Result<(), String> {
        for _ in 0..SPI_POLL_LIMIT {
            let status = unsafe { read_volatile(crate::spi_status() as *const u32) };
            if status & SPI_STATUS_TX_READY != 0 {
                return Ok(());
            }
        }
        Err(String::from("spi_tx_timeout"))
    }

    fn wait_rx_ready(&self) -> Result<(), String> {
        for _ in 0..SPI_POLL_LIMIT {
            let status = unsafe { read_volatile(crate::spi_status() as *const u32) };
            if status & SPI_STATUS_RX_READY != 0 {
                return Ok(());
            }
        }
        Err(String::from("spi_rx_timeout"))
    }
}
impl Default for SPIInterface {
    fn default() -> Self {
        Self::new()
    }
}

const SPI_CTRL_ENABLE: u32 = 0x0001;
const SPI_CTRL_MODE_SHIFT: u32 = 1;
const SPI_CTRL_MODE_MASK: u32 = 0x0006;

const SPI_STATUS_TX_READY: u32 = 0x0001;
const SPI_STATUS_RX_READY: u32 = 0x0002;

const SPI_POLL_LIMIT: u32 = 100_000;
