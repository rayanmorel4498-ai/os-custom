/// GPIO (General Purpose Input/Output) Interface

use core::ptr::{read_volatile, write_volatile};

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum GPIOMode {
    Input = 0,
    Output = 1,
    PWM = 2,
    Analog = 3,
}

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum GPIOPermission {
    None = 0,
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}


pub struct GPIO {
    pin: u8,
}

impl GPIO {
    pub const fn new(pin: u8) -> Self {
        GPIO { pin }
    }

    fn dir_reg(&self) -> u64 {
        gpio_bank_reg(crate::gpio_dir(), self.pin)
    }

    fn out_reg(&self) -> u64 {
        gpio_bank_reg(crate::gpio_out(), self.pin)
    }

    fn in_reg(&self) -> u64 {
        gpio_bank_reg(crate::gpio_in(), self.pin)
    }

    fn drive_reg(&self) -> u64 {
        gpio_mode_reg(crate::gpio_drive(), self.pin)
    }

    fn mode_reg(&self) -> u64 {
        gpio_mode_reg(crate::gpio_mode(), self.pin)
    }

    pub fn set_direction(&self, mode: GPIOMode) -> Result<(), &'static str> {
        match mode {
            GPIOMode::Input => {
                write_bit(self.dir_reg(), self.pin, false);
                write_mode(self.mode_reg(), self.pin, GPIOMode::Input);
            }
            GPIOMode::Output => {
                write_bit(self.dir_reg(), self.pin, true);
                write_mode(self.mode_reg(), self.pin, GPIOMode::Output);
            }
            GPIOMode::PWM => {
                write_bit(self.dir_reg(), self.pin, true);
                write_mode(self.mode_reg(), self.pin, GPIOMode::PWM);
            }
            GPIOMode::Analog => {
                write_bit(self.dir_reg(), self.pin, false);
                write_mode(self.mode_reg(), self.pin, GPIOMode::Analog);
            }
        }
        Ok(())
    }

    pub fn write(&self, value: bool) -> Result<(), &'static str> {
        write_bit(self.out_reg(), self.pin, value);
        Ok(())
    }

    pub fn read(&self) -> Result<bool, &'static str> {
        Ok(read_bit(self.in_reg(), self.pin))
    }

    pub fn set_drive_strength(&self, ma: u8) -> Result<(), &'static str> {
        let level = match ma {
            0..=4 => 0,
            5..=8 => 1,
            9..=12 => 2,
            _ => 3,
        };
        write_mode_bits(self.drive_reg(), self.pin, level);
        Ok(())
    }

    pub fn get_mode(&self) -> GPIOMode {
        read_mode(self.mode_reg(), self.pin)
    }
}

pub struct GPIOInterface {
    num_pins: u8,
}

impl GPIOInterface {
    pub const fn new(num_pins: u8) -> Self {
        GPIOInterface { num_pins }
    }

    pub fn set_mode(&self, pin: u8, mode: GPIOMode) -> Result<(), &'static str> {
        if pin >= self.num_pins {
            return Err("invalid_pin");
        }
        GPIO::new(pin).set_direction(mode)
    }

    pub fn write(&self, pin: u8, value: bool) -> Result<(), &'static str> {
        if pin >= self.num_pins {
            return Err("invalid_pin");
        }
        GPIO::new(pin).write(value)
    }

    pub fn read(&self, pin: u8) -> Result<bool, &'static str> {
        if pin >= self.num_pins {
            return Err("invalid_pin");
        }
        GPIO::new(pin).read()
    }
}

impl Default for GPIOInterface {
    fn default() -> Self {
        Self::new(150)
    }
}

const GPIO_BANK_STRIDE: u64 = 0x20;

fn gpio_bank_reg(base: u64, pin: u8) -> u64 {
    let bank = (pin as u64) / 32;
    base + bank * GPIO_BANK_STRIDE
}

fn gpio_mode_reg(base: u64, pin: u8) -> u64 {
    let bank = (pin as u64) / 16;
    base + bank * GPIO_BANK_STRIDE
}

fn write_bit(reg: u64, pin: u8, value: bool) {
    let bit = 1u32 << (pin as u32 % 32);
    unsafe {
        let mut current = read_volatile(reg as *const u32);
        if value {
            current |= bit;
        } else {
            current &= !bit;
        }
        write_volatile(reg as *mut u32, current);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

fn read_bit(reg: u64, pin: u8) -> bool {
    let bit = 1u32 << (pin as u32 % 32);
    unsafe { (read_volatile(reg as *const u32) & bit) != 0 }
}

fn write_mode(reg: u64, pin: u8, mode: GPIOMode) {
    write_mode_bits(reg, pin, mode as u32);
}

fn write_mode_bits(reg: u64, pin: u8, value: u32) {
    let shift = ((pin as u32) % 16) * 2;
    let mask = 0x3u32 << shift;
    unsafe {
        let mut current = read_volatile(reg as *const u32);
        current &= !mask;
        current |= (value << shift) & mask;
        write_volatile(reg as *mut u32, current);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

fn read_mode(reg: u64, pin: u8) -> GPIOMode {
    let shift = ((pin as u32) % 16) * 2;
    let mask = 0x3u32 << shift;
    let value = unsafe { (read_volatile(reg as *const u32) & mask) >> shift };
    match value {
        0 => GPIOMode::Input,
        1 => GPIOMode::Output,
        2 => GPIOMode::PWM,
        _ => GPIOMode::Analog,
    }
}
