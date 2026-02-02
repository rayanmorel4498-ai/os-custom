pub struct MemoryAnalyzer {
    peak_usage: usize,
    current_usage: usize,
}

impl MemoryAnalyzer {
    pub fn new() -> Self {
        MemoryAnalyzer {
            peak_usage: 0,
            current_usage: 0,
        }
    }

    pub fn record_allocation(&mut self, size: usize) {
        self.current_usage += size;
        if self.current_usage > self.peak_usage {
            self.peak_usage = self.current_usage;
        }
    }

    pub fn record_deallocation(&mut self, size: usize) {
        if self.current_usage >= size {
            self.current_usage -= size;
        }
    }

    pub fn get_peak(&self) -> usize {
        self.peak_usage
    }

    pub fn get_current(&self) -> usize {
        self.current_usage
    }

    pub fn utilization_percent(&self) -> u8 {
        if self.peak_usage == 0 {
            0
        } else {
            ((self.current_usage * 100) / self.peak_usage) as u8
        }
    }
}
