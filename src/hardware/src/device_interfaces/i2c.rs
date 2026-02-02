#[repr(u8)]
pub enum I2CCommand {
    Start = 0x01,
    Stop = 0x02,
    Read = 0x04,
    Write = 0x08,
}

#[derive(Copy, Clone)]
pub enum I2CSpeed {
    Standard = 100,
    Fast = 400,
    FastPlus = 1000,
    HighSpeed = 3400,
}

pub trait I2CBus {
    fn write(&mut self, address: u8, data: &[u8]) -> Result<(), &'static str>;
    fn read(&mut self, address: u8, buf: &mut [u8]) -> Result<(), &'static str>;
}

pub struct I2CInterface {
    controller_id: u8,
}

impl I2CInterface {
    pub fn new(controller_id: u8) -> Result<Self, &'static str> {
        if controller_id >= 16 {
            return Err("invalid_i2c_controller");
        }
        Ok(I2CInterface { controller_id })
    }

    fn base(&self) -> u64 {
        crate::i2c_base() + (self.controller_id as u64 * I2C_CTRL_STRIDE)
    }

    fn reg(&self, offset: u64) -> u64 {
        self.base() + offset
    }

    fn status(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.reg(I2C_STATUS_OFFSET) as *const u32) }
    }

    fn wait_tx_ready(&self) -> Result<(), &'static str> {
        for _ in 0..I2C_POLL_LIMIT {
            let status = self.status();
            if status & I2C_STATUS_ARB_LOST != 0 {
                return Err("arb_lost");
            }
            if status & I2C_STATUS_TX_READY != 0 {
                return Ok(());
            }
        }
        Err("tx_timeout")
    }

    fn wait_rx_ready(&self) -> Result<(), &'static str> {
        for _ in 0..I2C_POLL_LIMIT {
            let status = self.status();
            if status & I2C_STATUS_ARB_LOST != 0 {
                return Err("arb_lost");
            }
            if status & I2C_STATUS_RX_READY != 0 {
                return Ok(());
            }
        }
        Err("rx_timeout")
    }

    fn wait_idle(&self) -> Result<(), &'static str> {
        for _ in 0..I2C_POLL_LIMIT {
            if self.status() & I2C_STATUS_BUSY == 0 {
                return Ok(());
            }
        }
        Err("bus_busy")
    }

    fn issue_cmd(&self, cmd: I2CCommand) {
        unsafe {
            core::ptr::write_volatile(self.reg(I2C_CMD_OFFSET) as *mut u32, cmd as u32);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

    fn write_byte(&self, byte: u8) -> Result<(), &'static str> {
        self.wait_tx_ready()?;
        unsafe {
            core::ptr::write_volatile(self.reg(I2C_TX_OFFSET) as *mut u32, byte as u32);
        }
        self.issue_cmd(I2CCommand::Write);
        if self.status() & I2C_STATUS_NACK != 0 {
            return Err("nack");
        }
        Ok(())
    }

    fn read_byte(&self) -> Result<u8, &'static str> {
        self.issue_cmd(I2CCommand::Read);
        self.wait_rx_ready()?;
        let value = unsafe { core::ptr::read_volatile(self.reg(I2C_RX_OFFSET) as *const u32) };
        Ok(value as u8)
    }

    pub fn enable(&self) -> Result<(), &'static str> {
        unsafe {
            core::ptr::write_volatile(self.reg(I2C_CTRL_OFFSET) as *mut u32, I2C_CTRL_ENABLE);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn set_frequency(&self, freq_khz: u32) -> Result<(), &'static str> {
        if freq_khz > 3400 {
            return Err("frequency_too_high");
        }
        let divider = (I2C_REF_CLOCK_KHZ / (freq_khz * 2)).max(1);
        unsafe {
            core::ptr::write_volatile(self.reg(I2C_CLKDIV_OFFSET) as *mut u32, divider);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn write(&self, address: u8, data: &[u8]) -> Result<(), &'static str> {
        if data.is_empty() {
            return Ok(());
        }
        self.wait_idle()?;
        self.issue_cmd(I2CCommand::Start);
        self.write_byte(address << 1)?;
        for byte in data {
            self.write_byte(*byte)?;
        }
        self.issue_cmd(I2CCommand::Stop);
        Ok(())
    }

    pub fn read(&self, address: u8, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.is_empty() {
            return Ok(());
        }
        self.wait_idle()?;
        self.issue_cmd(I2CCommand::Start);
        self.write_byte((address << 1) | 0x1)?;
        for slot in buf.iter_mut() {
            *slot = self.read_byte()?;
        }
        self.issue_cmd(I2CCommand::Stop);
        Ok(())
    }
}

impl I2CBus for I2CInterface {
    fn write(&mut self, address: u8, data: &[u8]) -> Result<(), &'static str> {
        I2CInterface::write(self, address, data)
    }

    fn read(&mut self, address: u8, buf: &mut [u8]) -> Result<(), &'static str> {
        I2CInterface::read(self, address, buf)
    }
}

impl Default for I2CInterface {
    fn default() -> Self {
        Self::new(0).expect("failed to init i2c0")
    }
}

const I2C_CTRL_STRIDE: u64 = 0x1000;
const I2C_CTRL_OFFSET: u64 = 0x0000;
const I2C_STATUS_OFFSET: u64 = 0x0004;
const I2C_CLKDIV_OFFSET: u64 = 0x0008;
const I2C_CMD_OFFSET: u64 = 0x000C;
const I2C_TX_OFFSET: u64 = 0x0010;
const I2C_RX_OFFSET: u64 = 0x0014;

const I2C_CTRL_ENABLE: u32 = 0x0001;

const I2C_STATUS_BUSY: u32 = 0x0001;
const I2C_STATUS_TX_READY: u32 = 0x0002;
const I2C_STATUS_RX_READY: u32 = 0x0004;
const I2C_STATUS_NACK: u32 = 0x0008;
const I2C_STATUS_ARB_LOST: u32 = 0x0010;

const I2C_REF_CLOCK_KHZ: u32 = 26_000;
const I2C_POLL_LIMIT: u32 = 100_000;
