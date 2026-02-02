/// UART (Serial Communication) Driver

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Parity {
    None,
    Even,
    Odd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataBits {
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
}

#[derive(Copy, Clone, Debug)]
pub struct UartConfig {
    pub baudrate: u32,
    pub parity: Parity,
    pub data_bits: DataBits,
}

impl Default for UartConfig {
    fn default() -> Self {
        UartConfig {
            baudrate: 115200,
            parity: Parity::None,
            data_bits: DataBits::Eight,
        }
    }
}

pub struct Uart {
    config: UartConfig,
    tx_buffer: Vec<u8>,
    controller_index: usize,
}

impl Uart {
    /// Create UART instance for controller index
    pub fn new(_controller_index: usize, config: UartConfig) -> Result<Self, &'static str> {
        Ok(Uart {
            config,
            tx_buffer: Vec::new(),
            controller_index: _controller_index,
        })
    }

    fn base(&self) -> u64 {
        crate::uart_base() + (self.controller_index as u64 * UART_CTRL_STRIDE)
    }

    fn reg(&self, offset: u64) -> u64 {
        self.base() + offset
    }

    fn status(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.reg(UART_STATUS_OFFSET) as *const u32) }
    }


    pub fn set_baudrate(&mut self, baudrate: u32) -> Result<(), &'static str> {
        if baudrate == 0 {
            return Err("invalid_baudrate");
        }
        self.config.baudrate = baudrate;
        let divisor = (UART_REF_CLOCK_HZ / (baudrate * 16)).max(1);
        unsafe {
            core::ptr::write_volatile(self.reg(UART_BAUD_OFFSET) as *mut u32, divisor);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }


    pub fn write_byte(&mut self, _byte: u8) -> Result<(), &'static str> {
        for _ in 0..UART_POLL_LIMIT {
            if self.status() & UART_STATUS_TX_READY != 0 {
                unsafe {
                    core::ptr::write_volatile(self.reg(UART_TX_OFFSET) as *mut u32, _byte as u32);
                    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                }
                return Ok(());
            }
        }
        return Err("tx_timeout");
    }


    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), &'static str> {
        for &byte in buf {
            self.tx_buffer.push(byte);
        }
        Ok(())
    }

    pub fn read_byte(&self) -> Result<u8, &'static str> {
        for _ in 0..UART_POLL_LIMIT {
            if self.status() & UART_STATUS_RX_READY != 0 {
                let value = unsafe { core::ptr::read_volatile(self.reg(UART_RX_OFFSET) as *const u32) };
                return Ok(value as u8);
            }
        }
        Err("rx_timeout")
    }

    pub fn try_read_byte(&self) -> Option<u8> {
        if self.status() & UART_STATUS_RX_READY == 0 {
            return None;
        }
        let value = unsafe { core::ptr::read_volatile(self.reg(UART_RX_OFFSET) as *const u32) };
        Some(value as u8)
    }

    /// Wait for TX to be complete
    pub fn flush(&self) -> Result<(), &'static str> {
        for _ in 0..UART_POLL_LIMIT {
            if self.status() & UART_STATUS_TX_BUSY == 0 {
                return Ok(());
            }
        }
        return Err("tx_busy");
    }
}

/// Legacy UART Interface for compatibility
pub struct UARTInterface {
    uart: Uart,
}

impl UARTInterface {
    pub fn new() -> Self {
        let config = UartConfig::default();
        let uart = Uart::new(0, config).expect("failed to init uart0");
        UARTInterface { uart }
    }

    pub fn enable(&self) -> Result<(), &'static str> {
        unsafe {
            core::ptr::write_volatile(self.uart.reg(UART_CTRL_OFFSET) as *mut u32, UART_CTRL_ENABLE);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), &'static str> {
        self.uart.write_all(data)
    }

    pub fn receive(&self) -> Result<u8, &'static str> {
        self.uart.read_byte()
    }

    pub fn set_baud_rate(&mut self, baud: u32) -> Result<(), &'static str> {
        self.uart.set_baudrate(baud)
    }
}

impl Default for UARTInterface {
    fn default() -> Self {
        Self::new()
    }
}

const UART_CTRL_STRIDE: u64 = 0x1000;
const UART_CTRL_OFFSET: u64 = 0x0000;
const UART_STATUS_OFFSET: u64 = 0x0004;
const UART_BAUD_OFFSET: u64 = 0x0008;
const UART_TX_OFFSET: u64 = 0x000C;
const UART_RX_OFFSET: u64 = 0x0010;

const UART_CTRL_ENABLE: u32 = 0x0001;

const UART_STATUS_TX_READY: u32 = 0x0001;
const UART_STATUS_RX_READY: u32 = 0x0002;
const UART_STATUS_TX_BUSY: u32 = 0x0004;

const UART_REF_CLOCK_HZ: u32 = 26_000_000;
const UART_POLL_LIMIT: u32 = 100_000;
