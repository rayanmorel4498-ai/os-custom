use alloc::vec::Vec;
use alloc::vec;
use parking_lot::Mutex;
use alloc::sync::Arc;

#[derive(Clone, Debug, Copy)]
pub struct CpuAffinity {
    pub mask: u64, 
}

impl CpuAffinity {
    pub fn single_cpu(cpu_id: u32) -> Self {
        Self {
            mask: 1u64 << cpu_id,
        }
    }

    pub fn any_cpu() -> Self {
        Self { mask: u64::MAX }
    }

    pub fn from_mask(mask: u64) -> Self {
        Self { mask }
    }

    pub fn has_cpu(&self, cpu_id: u32) -> bool {
        (self.mask & (1u64 << cpu_id)) != 0
    }

    pub fn cpu_count(&self) -> u32 {
        self.mask.count_ones()
    }

    pub fn first_cpu(&self) -> Option<u32> {
        if self.mask == 0 {
            None
        } else {
            Some(self.mask.trailing_zeros())
        }
    }
}

pub struct LoadBalancer {
    cpu_loads: Arc<Mutex<Vec<u32>>>,
    total_tasks: Arc<Mutex<u32>>,
    rebalance_threshold: u32,
}

impl LoadBalancer {
    pub fn new(cpu_count: usize, rebalance_threshold: u32) -> Self {
        Self {
            cpu_loads: Arc::new(Mutex::new(vec![0; cpu_count])),
            total_tasks: Arc::new(Mutex::new(0)),
            rebalance_threshold,
        }
    }

    pub fn add_task(&self, cpu_id: usize) -> Result<(), &'static str> {
        let mut loads = self.cpu_loads.lock();
        if cpu_id >= loads.len() {
            return Err("Invalid CPU ID");
        }
        loads[cpu_id] += 1;
        *self.total_tasks.lock() += 1;
        Ok(())
    }

    pub fn remove_task(&self, cpu_id: usize) -> Result<(), &'static str> {
        let mut loads = self.cpu_loads.lock();
        if cpu_id >= loads.len() {
            return Err("Invalid CPU ID");
        }
        if loads[cpu_id] > 0 {
            loads[cpu_id] -= 1;
            let mut total = self.total_tasks.lock();
            if *total > 0 {
                *total -= 1;
            }
        }
        Ok(())
    }

    pub fn get_load(&self, cpu_id: usize) -> Result<u32, &'static str> {
        let loads = self.cpu_loads.lock();
        if cpu_id >= loads.len() {
            return Err("Invalid CPU ID");
        }
        Ok(loads[cpu_id])
    }

    pub fn find_least_loaded_cpu(&self) -> Option<usize> {
        let loads = self.cpu_loads.lock();
        loads
            .iter()
            .enumerate()
            .min_by_key(|(_, &load)| load)
            .map(|(idx, _)| idx)
    }

    pub fn needs_rebalance(&self) -> bool {
        let loads = self.cpu_loads.lock();
        if loads.is_empty() {
            return false;
        }

        let min_load = *loads.iter().min().unwrap_or(&0);
        let max_load = *loads.iter().max().unwrap_or(&0);
        (max_load - min_load) > self.rebalance_threshold
    }

    pub fn average_load(&self) -> f32 {
        let total = *self.total_tasks.lock();
        let loads = self.cpu_loads.lock();
        if loads.is_empty() {
            0.0
        } else {
            total as f32 / loads.len() as f32
        }
    }
}

pub struct WorkQueue {
    queues: Arc<Mutex<Vec<Vec<u64>>>>,
    queue_depths: Arc<Mutex<Vec<usize>>>,
}

impl WorkQueue {
    pub fn new(cpu_count: usize, max_depth: usize) -> Self {
        let mut queues = Vec::with_capacity(cpu_count);
        let mut depths = Vec::with_capacity(cpu_count);
        for _ in 0..cpu_count {
            queues.push(Vec::with_capacity(max_depth));
            depths.push(0);
        }

        Self {
            queues: Arc::new(Mutex::new(queues)),
            queue_depths: Arc::new(Mutex::new(depths)),
        }
    }

    pub fn enqueue(&self, cpu_id: usize, task_id: u64) -> Result<(), &'static str> {
        let mut queues = self.queues.lock();
        if cpu_id >= queues.len() {
            return Err("Invalid CPU ID");
        }

        let mut depths = self.queue_depths.lock();
        if queues[cpu_id].len() >= 1000 {
            return Err("Queue full");
        }

        queues[cpu_id].push(task_id);
        depths[cpu_id] = queues[cpu_id].len();
        Ok(())
    }

    pub fn dequeue(&self, cpu_id: usize) -> Result<Option<u64>, &'static str> {
        let mut queues = self.queues.lock();
        if cpu_id >= queues.len() {
            return Err("Invalid CPU ID");
        }

        let result = if queues[cpu_id].is_empty() {
            None
        } else {
            Some(queues[cpu_id].remove(0))
        };

        let mut depths = self.queue_depths.lock();
        depths[cpu_id] = queues[cpu_id].len();

        Ok(result)
    }

    pub fn queue_depth(&self, cpu_id: usize) -> Result<usize, &'static str> {
        let depths = self.queue_depths.lock();
        if cpu_id >= depths.len() {
            return Err("Invalid CPU ID");
        }
        Ok(depths[cpu_id])
    }

    pub fn total_depth(&self) -> usize {
        self.queue_depths.lock().iter().sum()
    }
}