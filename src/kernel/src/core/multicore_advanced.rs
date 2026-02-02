use alloc::vec::Vec;
use alloc::collections::VecDeque;
use parking_lot::Mutex;
use alloc::sync::Arc;

pub struct CpuCluster {
    cluster_id: u32,
    core_count: u32,
    frequencies: Arc<Mutex<Vec<u32>>>,
    active_cores: Arc<Mutex<u32>>,
}

impl CpuCluster {
    pub fn new(cluster_id: u32, core_count: u32, base_freq_mhz: u32) -> Self {
        let mut freqs = Vec::with_capacity(core_count as usize);
        for _ in 0..core_count {
            freqs.push(base_freq_mhz);
        }

        Self {
            cluster_id,
            core_count,
            frequencies: Arc::new(Mutex::new(freqs)),
            active_cores: Arc::new(Mutex::new(core_count)),
        }
    }

    pub fn set_core_frequency(&self, core_id: u32, freq_mhz: u32) -> Result<(), &'static str> {
        let mut freqs = self.frequencies.lock();
        if core_id as usize >= freqs.len() {
            return Err("Invalid core ID");
        }
        freqs[core_id as usize] = freq_mhz;
        Ok(())
    }

    pub fn get_core_frequency(&self, core_id: u32) -> Result<u32, &'static str> {
        let freqs = self.frequencies.lock();
        if core_id as usize >= freqs.len() {
            return Err("Invalid core ID");
        }
        Ok(freqs[core_id as usize])
    }

    pub fn average_frequency(&self) -> u32 {
        let freqs = self.frequencies.lock();
        if freqs.is_empty() {
            0
        } else {
            freqs.iter().sum::<u32>() / freqs.len() as u32
        }
    }

    pub fn set_active_cores(&self, count: u32) -> Result<(), &'static str> {
        if count > self.core_count {
            return Err("Cannot activate more cores than available");
        }
        *self.active_cores.lock() = count;
        Ok(())
    }

    pub fn get_active_cores(&self) -> u32 {
        *self.active_cores.lock()
    }

    pub fn cluster_id(&self) -> u32 {
        self.cluster_id
    }

    pub fn core_count(&self) -> u32 {
        self.core_count
    }
}

pub struct CoreWorkQueue {
    queues: Arc<Mutex<Vec<VecDeque<WorkItem>>>>,
    priorities: Arc<Mutex<Vec<u8>>>,
}

#[derive(Clone, Debug)]
pub struct WorkItem {
    pub task_id: u64,
    pub priority: u8,
    pub deadline: u64,
}

impl CoreWorkQueue {
    pub fn new(core_count: usize) -> Self {
        let mut queues = Vec::with_capacity(core_count);
        let mut priorities = Vec::with_capacity(core_count);

        for _ in 0..core_count {
            queues.push(VecDeque::new());
            priorities.push(0);
        }

        Self {
            queues: Arc::new(Mutex::new(queues)),
            priorities: Arc::new(Mutex::new(priorities)),
        }
    }

    pub fn enqueue_with_priority(
        &self,
        core_id: usize,
        work: WorkItem,
    ) -> Result<(), &'static str> {
        let mut queues = self.queues.lock();
        if core_id >= queues.len() {
            return Err("Invalid core ID");
        }

        queues[core_id].push_back(work);
        Ok(())
    }

    pub fn dequeue(&self, core_id: usize) -> Result<Option<WorkItem>, &'static str> {
        let mut queues = self.queues.lock();
        if core_id >= queues.len() {
            return Err("Invalid core ID");
        }

        Ok(queues[core_id].pop_front())
    }

    pub fn queue_depth(&self, core_id: usize) -> Result<usize, &'static str> {
        let queues = self.queues.lock();
        if core_id >= queues.len() {
            return Err("Invalid core ID");
        }
        Ok(queues[core_id].len())
    }

    pub fn total_pending(&self) -> usize {
        self.queues.lock().iter().map(|q| q.len()).sum()
    }
}

pub struct LoadPredictor {
    history: Arc<Mutex<Vec<u32>>>,
    window_size: usize,
}

impl LoadPredictor {
    pub fn new(window_size: usize) -> Self {
        Self {
            history: Arc::new(Mutex::new(Vec::with_capacity(window_size))),
            window_size,
        }
    }

    pub fn record_load(&self, load: u32) {
        let mut hist = self.history.lock();
        hist.push(load);
        if hist.len() > self.window_size {
            hist.remove(0);
        }
    }

    pub fn predict_load(&self) -> u32 {
        let hist = self.history.lock();
        if hist.is_empty() {
            0
        } else {
            hist.iter().sum::<u32>() / hist.len() as u32
        }
    }

    pub fn trend(&self) -> i32 {
        let hist = self.history.lock();
        if hist.len() < 2 {
            return 0;
        }

        let recent_avg = hist.iter().rev().take(hist.len() / 2).sum::<u32>() / (hist.len() / 2) as u32;
        let older_avg = hist.iter().take(hist.len() / 2).sum::<u32>() / (hist.len() / 2) as u32;

        (recent_avg as i32) - (older_avg as i32)
    }

    pub fn variance(&self) -> u32 {
        let hist = self.history.lock();
        if hist.is_empty() {
            return 0;
        }

        let avg = hist.iter().sum::<u32>() / hist.len() as u32;
        let sum_sq_diff: u32 = hist.iter().map(|x| ((*x as i32 - avg as i32).pow(2)) as u32).sum();
        sum_sq_diff / hist.len() as u32
    }
}

pub struct WorkStealingScheduler {
    work_queues: Arc<Mutex<Vec<VecDeque<u64>>>>,
    steal_attempts: Arc<Mutex<u32>>,
    successful_steals: Arc<Mutex<u32>>,
}

impl WorkStealingScheduler {
    pub fn new(core_count: usize) -> Self {
        let mut queues = Vec::with_capacity(core_count);
        for _ in 0..core_count {
            queues.push(VecDeque::new());
        }

        Self {
            work_queues: Arc::new(Mutex::new(queues)),
            steal_attempts: Arc::new(Mutex::new(0)),
            successful_steals: Arc::new(Mutex::new(0)),
        }
    }

    pub fn enqueue(&self, core_id: usize, task_id: u64) -> Result<(), &'static str> {
        let mut queues = self.work_queues.lock();
        if core_id >= queues.len() {
            return Err("Invalid core ID");
        }
        queues[core_id].push_back(task_id);
        Ok(())
    }

    pub fn dequeue_local(&self, core_id: usize) -> Result<Option<u64>, &'static str> {
        let mut queues = self.work_queues.lock();
        if core_id >= queues.len() {
            return Err("Invalid core ID");
        }
        Ok(queues[core_id].pop_front())
    }

    pub fn steal_work(&self, victim_core: usize, thief_core: usize) -> Result<Option<u64>, &'static str> {
        let mut queues = self.work_queues.lock();
        if victim_core >= queues.len() || thief_core >= queues.len() {
            return Err("Invalid core ID");
        }

        *self.steal_attempts.lock() += 1;

        if !queues[victim_core].is_empty() {
            if let Some(task) = queues[victim_core].pop_back() {
                *self.successful_steals.lock() += 1;
                return Ok(Some(task));
            }
        }

        Ok(None)
    }

    pub fn steal_statistics(&self) -> (u32, u32, f32) {
        let attempts = *self.steal_attempts.lock();
        let successes = *self.successful_steals.lock();
        let success_rate = if attempts > 0 {
            (successes as f32 / attempts as f32) * 100.0
        } else {
            0.0
        };
        (attempts, successes, success_rate)
    }

    pub fn total_work(&self) -> usize {
        self.work_queues.lock().iter().map(|q| q.len()).sum()
    }
}