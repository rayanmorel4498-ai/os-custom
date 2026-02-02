use alloc::vec::Vec;
use parking_lot::Mutex;
use alloc::sync::Arc;
use alloc::boxed::Box;

#[derive(Clone, Debug)]
pub struct TimerConfig {
    pub period_us: u64,
    pub enabled: bool,
    pub priority: InterruptPriority,
}

impl TimerConfig {
    pub fn new(period_us: u64, priority: InterruptPriority) -> Self {
        Self {
            period_us,
            enabled: true,
            priority,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TimerMode {
    OneShot,
    Periodic,
    Continuous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterruptPriority {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
}

pub struct DeadlineMissDetector {
    deadline_violations: Arc<Mutex<u32>>,
    max_allowed_violations: u32,
}

impl DeadlineMissDetector {
    pub fn new(max_allowed_violations: u32) -> Self {
        Self {
            deadline_violations: Arc::new(Mutex::new(0)),
            max_allowed_violations,
        }
    }

    pub fn record_deadline_miss(&self) -> Result<(), &'static str> {
        let mut violations = self.deadline_violations.lock();
        *violations += 1;

        if *violations > self.max_allowed_violations {
            return Err("Max deadline violations exceeded");
        }
        Ok(())
    }

    pub fn reset(&self) {
        *self.deadline_violations.lock() = 0;
    }

    pub fn violation_count(&self) -> u32 {
        *self.deadline_violations.lock()
    }
}

pub struct PreemptiveTimerController {
    config: Arc<Mutex<TimerConfig>>,
    mode: Arc<Mutex<TimerMode>>,
    current_tick: Arc<Mutex<u64>>,
    callbacks: Arc<Mutex<Vec<Box<dyn Fn() + Send + Sync>>>>,
    deadline_detector: DeadlineMissDetector,
}

impl PreemptiveTimerController {
    pub fn new(config: TimerConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            mode: Arc::new(Mutex::new(TimerMode::Periodic)),
            current_tick: Arc::new(Mutex::new(0)),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            deadline_detector: DeadlineMissDetector::new(5),
        }
    }

    pub fn configure(&self, config: TimerConfig) -> Result<(), &'static str> {
        *self.config.lock() = config;
        Ok(())
    }

    pub fn set_mode(&self, mode: TimerMode) {
        *self.mode.lock() = mode;
    }

    pub fn get_mode(&self) -> TimerMode {
        self.mode.lock().clone()
    }

    pub fn register_callback(&self, callback: Box<dyn Fn() + Send + Sync>) {
        self.callbacks.lock().push(callback);
    }

    pub fn tick(&self) -> Result<(), &'static str> {
        let mut current = self.current_tick.lock();
        *current += 1;

        let config = self.config.lock();
        let mode = self.mode.lock();

        if *current % 10 == 0 {
            self.deadline_detector.record_deadline_miss().ok();
        }

        drop(config);
        drop(mode);
        
        for callback in self.callbacks.lock().iter() {
            callback();
        }

        Ok(())
    }

    pub fn current_tick(&self) -> u64 {
        *self.current_tick.lock()
    }

    pub fn reset(&self) {
        *self.current_tick.lock() = 0;
        self.deadline_detector.reset();
    }

    pub fn stop(&self) -> Result<(), &'static str> {
        let mut config = self.config.lock();
        config.enabled = false;
        Ok(())
    }

    pub fn start(&self) -> Result<(), &'static str> {
        let mut config = self.config.lock();
        config.enabled = true;
        Ok(())
    }

    pub fn get_deadline_violations(&self) -> u32 {
        self.deadline_detector.violation_count()
    }
}