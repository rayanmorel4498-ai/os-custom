extern crate alloc;
use alloc::string::String;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum USBSpeed {
    FullSpeed = 0,
    HighSpeed = 1,
    SuperSpeed = 2,
    SuperSpeedPlus = 3,
}
impl USBSpeed {
    fn from_u32(val: u32) -> Self {
        match val {
            0 => USBSpeed::FullSpeed,
            1 => USBSpeed::HighSpeed,
            2 => USBSpeed::SuperSpeed,
            3 => USBSpeed::SuperSpeedPlus,
            _ => USBSpeed::HighSpeed,
        }
    }
    fn to_u32(&self) -> u32 {
        *self as u32
    }
}
pub struct USBInterface {
    connected: AtomicBool,
    speed: AtomicU32,
    power_m_a: AtomicU32,
}
impl USBInterface {
    pub fn new() -> Self {
        USBInterface {
            connected: AtomicBool::new(false),
            speed: AtomicU32::new(USBSpeed::HighSpeed.to_u32()),
            power_m_a: AtomicU32::new(0),
        }
    }
    pub fn connect(&self) -> Result<(), String> {
        unsafe {
            write_volatile(crate::usb_ctrl() as *mut u32, USB_CTRL_ENABLE);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            let status = read_volatile(crate::usb_status() as *const u32);
            if status & USB_STATUS_PRESENT == 0 {
                return Err(String::from("usb_not_present"));
            }
        }
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn disconnect(&self) -> Result<(), String> {
        unsafe {
            write_volatile(crate::usb_ctrl() as *mut u32, 0x0);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.connected.store(false, Ordering::SeqCst);
        self.power_m_a.store(0, Ordering::SeqCst);
        Ok(())
    }
    pub fn set_speed(&self, speed: USBSpeed) -> Result<(), String> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(String::from("USB not connected"));
        }
        unsafe {
            write_volatile(crate::usb_speed() as *mut u32, speed.to_u32());
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.speed.store(speed.to_u32(), Ordering::SeqCst);
        Ok(())
    }
    pub fn get_speed(&self) -> USBSpeed {
        let speed_val = unsafe { read_volatile(crate::usb_speed() as *const u32) };
        USBSpeed::from_u32(speed_val)
    }
    pub fn is_connected(&self) -> bool {
        let status = unsafe { read_volatile(crate::usb_status() as *const u32) };
        let present = (status & USB_STATUS_PRESENT) != 0;
        if present {
            self.connected.store(true, Ordering::SeqCst);
        } else {
            self.connected.store(false, Ordering::SeqCst);
        }
        present
    }
    pub fn set_power(&self, power_m_a: u32) {
        unsafe {
            write_volatile(crate::usb_power() as *mut u32, power_m_a);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.power_m_a.store(power_m_a, Ordering::SeqCst);
    }
    pub fn get_power(&self) -> u32 {
        unsafe { read_volatile(crate::usb_power() as *const u32) }
    }
}
impl Default for USBInterface {
    fn default() -> Self {
        Self::new()
    }
}

const USB_CTRL_ENABLE: u32 = 0x0001;
const USB_STATUS_PRESENT: u32 = 0x0001;
