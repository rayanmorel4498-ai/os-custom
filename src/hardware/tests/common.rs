use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref MMIO_MEMORY: Mutex<[u32; 16384]> = Mutex::new([0u32; 16384]);
}

pub fn mmio_write(address: u64, value: u32) {
    let offset = (address >> 2) & 0x3FFF;
    if let Ok(mut mem) = MMIO_MEMORY.lock() {
        mem[offset as usize] = value;
    }
}

pub fn mmio_read(address: u64) -> u32 {
    let offset = (address >> 2) & 0x3FFF;
    if let Ok(mem) = MMIO_MEMORY.lock() {
        mem[offset as usize]
    } else {
        0
    }
}

pub fn mmio_reset() {
    if let Ok(mut mem) = MMIO_MEMORY.lock() {
        for v in mem.iter_mut() {
            *v = 0;
        }
    }
}
