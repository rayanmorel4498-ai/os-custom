use std::sync::Mutex;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref MMIO_SIMULATOR: Mutex<MMIOSimulator> = Mutex::new(MMIOSimulator::new());
}

pub struct MMIOSimulator {
    memory: HashMap<u64, u32>,
}

impl MMIOSimulator {
    pub fn new() -> Self {
        MMIOSimulator {
            memory: HashMap::new(),
        }
    }

    fn reset(&mut self) {
        self.memory.clear();
    }
}

pub fn sim_reset() {
    if let Ok(mut sim) = MMIO_SIMULATOR.lock() {
        sim.reset();
    }
}
