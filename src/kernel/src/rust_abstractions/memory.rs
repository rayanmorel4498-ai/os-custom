#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::device_drivers::memory::{MEMORY_DRIVER, MemoryRegion, DriverError};


pub struct MemoryManager {
    supply_queue: heapless::Vec<MemoryRegion, 128>,
}

impl MemoryManager {
    pub fn init() -> Result<Self, DriverError> {
        MEMORY_DRIVER.init()?;
        Ok(MemoryManager {
            supply_queue: heapless::Vec::new(),
        })
    }

    pub fn allocate(&mut self, size: usize, critical: bool) -> Option<&mut [u8]> {
        let protected = critical;

        let region = MEMORY_DRIVER.alloc(size, protected).ok()?;

        if !critical {
            self.supply_queue.push(region).ok()?;
        }

        Some(unsafe { core::slice::from_raw_parts_mut(region.start as *mut u8, region.size) })
    }

    pub fn free(&mut self, ptr: *mut u8) {
        if let Some(pos) = self.supply_queue.iter().position(|r| r.start as *mut u8 == ptr) {
            let region = self.supply_queue.remove(pos);
            MEMORY_DRIVER.free(&region);
        } else {
        }
    }

    pub fn protect(&self, region: &mut MemoryRegion) {
        MEMORY_DRIVER.protect(region);
    }

    pub fn unprotect(&self, region: &mut MemoryRegion) {
        MEMORY_DRIVER.unprotect(region);
    }

    pub fn enqueue_dynamic(&mut self, region: MemoryRegion) -> bool {
        self.supply_queue.push(region).is_ok()
    }

    pub fn dequeue_dynamic(&mut self) -> Option<&mut [u8]> {
        let region = self.supply_queue.pop()?;
        Some(unsafe { core::slice::from_raw_parts_mut(region.start as *mut u8, region.size) })
    }

    pub fn used(&self) -> usize {
        MEMORY_DRIVER.used()
    }

    pub fn free(&self) -> usize {
        MEMORY_DRIVER.total() - MEMORY_DRIVER.used()
    }
}