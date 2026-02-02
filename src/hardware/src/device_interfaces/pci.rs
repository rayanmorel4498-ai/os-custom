extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
pub struct PCIInterface {
    enabled: AtomicBool,
    device_count: AtomicU32,
}
impl PCIInterface {
    pub fn new() -> Self {
        PCIInterface {
            enabled: AtomicBool::new(false),
            device_count: AtomicU32::new(0),
        }
    }
    pub fn enable(&self) -> Result<(), String> {
        unsafe {
            write_volatile(crate::pci_ctrl() as *mut u32, PCI_CTRL_ENABLE);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn enumerate_devices(&self) -> Result<Vec<u16>, String> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(String::from("PCI not enabled"));
        }
        let mut devices = Vec::new();
        for bus in 0..=PCI_MAX_BUS {
            for dev in 0..=PCI_MAX_DEVICE {
                for func in 0..=PCI_MAX_FUNCTION {
                    let vendor_id = self.read_config16(bus, dev, func, PCI_VENDOR_ID_OFFSET)?;
                    if vendor_id != 0xFFFF {
                        devices.push(vendor_id);
                    }
                }
            }
        }
        Ok(devices)
    }
    pub fn probe_device(&self, vendor_id: u16) -> Result<bool, String> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(String::from("PCI not enabled"));
        }
        let devices = self.enumerate_devices()?;
        Ok(devices.iter().any(|id| *id == vendor_id))
    }
    pub fn add_device(&self) {
        self.device_count.fetch_add(1, Ordering::SeqCst);
    }

    fn read_config16(&self, bus: u8, device: u8, function: u8, offset: u8) -> Result<u16, String> {
        let aligned = (offset & 0xFC) as u32;
        let address = 0x8000_0000
            | ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | aligned;

        unsafe {
            write_volatile(crate::pci_cfg_addr() as *mut u32, address);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            let data = read_volatile(crate::pci_cfg_data() as *const u32);
            let shift = ((offset & 0x2) * 8) as u32;
            Ok(((data >> shift) & 0xFFFF) as u16)
        }
    }
}
impl Default for PCIInterface {
    fn default() -> Self {
        Self::new()
    }
}

const PCI_VENDOR_ID_OFFSET: u8 = 0x00;
const PCI_CTRL_ENABLE: u32 = 0x1;

const PCI_MAX_BUS: u8 = 0;
const PCI_MAX_DEVICE: u8 = 31;
const PCI_MAX_FUNCTION: u8 = 7;
