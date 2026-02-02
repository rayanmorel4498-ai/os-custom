use alloc::collections::BinaryHeap;
use core::cmp::Reverse;
use core::sync::atomic::AtomicU32;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug)]
pub struct RtTask {
    pub id: u32,
    pub deadline_us: u64,
    pub created_at: u64,
    pub priority: u32,
    pub deadline_us_custom: u64,
}

impl RtTask {
    pub fn new(id: u32, deadline_us: u64, created_at: u64, priority: u32, deadline_us_custom: u64) -> Self {
        RtTask {
            id,
            deadline_us,
            created_at,
            priority,
            deadline_us_custom,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SlaMetrics {
    pub deadline_met: u32,
    pub deadline_missed: u32,
    pub total_scheduled: u32,
}

impl SlaMetrics {
    pub fn new() -> Self {
        SlaMetrics {
            deadline_met: 0,
            deadline_missed: 0,
            total_scheduled: 0,
        }
    }

    pub fn deadline_met_percentage(&self) -> f32 {
        if self.total_scheduled == 0 {
            return 0.0;
        }
        (self.deadline_met as f32 / self.total_scheduled as f32) * 100.0
    }
}

pub struct RtEdfScheduler {
    tasks: Mutex<BinaryHeap<Reverse<(u64, u32)>>>,
    metrics: Mutex<SlaMetrics>,
    deadline_misses: AtomicU32,
}

impl RtEdfScheduler {
    pub fn new() -> Self {
        RtEdfScheduler {
            tasks: Mutex::new(BinaryHeap::new()),
            metrics: Mutex::new(SlaMetrics::new()),
            deadline_misses: AtomicU32::new(0),
        }
    }

    pub fn add_task(&self, task: RtTask) {
        let mut tasks = self.tasks.lock();
        tasks.push(Reverse((task.deadline_us, task.id)));
    }

    pub fn get_task_count(&self) -> usize {
        self.tasks.lock().len()
    }

    pub fn get_sla_metrics(&self) -> SlaMetrics {
        *self.metrics.lock()
    }
}

pub struct DynamicPriorityManager;
pub struct ConditionVariable;