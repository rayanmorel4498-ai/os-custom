
use core::sync::atomic::{AtomicU32, Ordering};
use alloc::vec::Vec;
use alloc::boxed::Box;
pub use parking_lot::{Mutex, RwLock, Once, Condvar};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

pub struct Task {
    pub id: u32,
    pub priority: Priority,
    pub counter: AtomicU32,
}

impl Task {
    pub fn new(id: u32, priority: Priority) -> Self {
        Task {
            id,
            priority,
            counter: AtomicU32::new(0),
        }
    }

    pub fn increment_counter(&self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_counter(&self) -> u32 {
        self.counter.load(Ordering::Relaxed)
    }

    pub fn reset_counter(&self) {
        self.counter.store(0, Ordering::Relaxed);
    }
}

pub struct FairScheduler {
    tasks: parking_lot::Mutex<Vec<Task>>,
    current_task: AtomicU32,
}

impl FairScheduler {
    pub fn new() -> Self {
        FairScheduler {
            tasks: parking_lot::Mutex::new(Vec::new()),
            current_task: AtomicU32::new(0),
        }
    }

    pub fn add_task(&self, task: Task) {
        let mut tasks = self.tasks.lock();
        tasks.push(task);
        tasks.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn schedule_next(&self) -> Option<u32> {
        let tasks = self.tasks.lock();
        if tasks.is_empty() {
            return None;
        }

        let current = self.current_task.load(Ordering::Relaxed) as usize;
        let next_idx = (current + 1) % tasks.len();
        let task_id = tasks[next_idx].id;

        self.current_task.store(next_idx as u32, Ordering::Relaxed);
        Some(task_id)
    }

    pub fn get_task_count(&self) -> usize {
        self.tasks.lock().len()
    }
}

pub trait InterruptHandler: Send + Sync {
    fn handle(&self, irq: u32) -> bool;
    fn priority(&self) -> u32;
}

pub struct InterruptController {
    handlers: parking_lot::Mutex<Vec<Box<dyn InterruptHandler>>>,
    irq_counter: AtomicU32,
}

impl InterruptController {
    pub fn new() -> Self {
        InterruptController {
            handlers: parking_lot::Mutex::new(Vec::new()),
            irq_counter: AtomicU32::new(0),
        }
    }

    pub fn register_handler(&self, handler: Box<dyn InterruptHandler>) {
        let mut handlers = self.handlers.lock();
        handlers.push(handler);
        handlers.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    pub fn handle_interrupt(&self, irq: u32) -> bool {
        self.irq_counter.fetch_add(1, Ordering::Relaxed);
        
        let handlers = self.handlers.lock();
        for handler in handlers.iter() {
            if handler.handle(irq) {
                return true;
            }
        }
        false
    }

    pub fn get_irq_count(&self) -> u32 {
        self.irq_counter.load(Ordering::Relaxed)
    }
}

pub struct AsyncTaskPool {
    tasks: parking_lot::Mutex<Vec<Box<dyn Fn() + Send + Sync>>>,
}

impl AsyncTaskPool {
    pub fn new() -> Self {
        AsyncTaskPool {
            tasks: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn spawn<F>(&self, task: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let mut tasks = self.tasks.lock();
        tasks.push(Box::new(task));
    }

    pub fn run_all(&self) {
        let mut tasks = self.tasks.lock();
        for task in tasks.drain(..) {
            task();
        }
    }

    pub fn pending_count(&self) -> usize {
        self.tasks.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fair_scheduler() {
        let scheduler = FairScheduler::new();
        scheduler.add_task(Task::new(1, Priority::Low));
        scheduler.add_task(Task::new(2, Priority::High));
        scheduler.add_task(Task::new(3, Priority::Normal));

        assert_eq!(scheduler.get_task_count(), 3);
        let next = scheduler.schedule_next();
        assert_eq!(next, Some(3));
    }

    #[test]
    fn test_interrupt_controller() {
        let controller = InterruptController::new();
        
        struct SimpleHandler;
        impl InterruptHandler for SimpleHandler {
            fn handle(&self, _irq: u32) -> bool {
                true
            }
            fn priority(&self) -> u32 {
                10
            }
        }

        controller.register_handler(Box::new(SimpleHandler));
        let handled = controller.handle_interrupt(5);
        assert!(handled);
        assert_eq!(controller.get_irq_count(), 1);
    }

    #[test]
    fn test_async_pool() {
        let pool = AsyncTaskPool::new();
        let counter = core::sync::atomic::AtomicU32::new(0);

        pool.spawn(|| {
        });

        assert_eq!(pool.pending_count(), 1);
    }
}
