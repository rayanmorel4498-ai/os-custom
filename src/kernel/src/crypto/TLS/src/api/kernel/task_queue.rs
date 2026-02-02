
use alloc::collections::VecDeque;
use super::spinlock::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};

pub type TaskCallback = fn(*mut u8);

pub struct Task {
    callback: TaskCallback,
    context: *mut u8,
}

unsafe impl Send for Task {}

static TASK_QUEUE: SpinLock<VecDeque<Task>> = SpinLock::new(VecDeque::new());
static TASK_DISPATCHER: AtomicUsize = AtomicUsize::new(0);

pub type TaskDispatcherCallback = fn(&Task);

pub fn init_task_dispatcher(dispatcher: TaskDispatcherCallback) {
    TASK_DISPATCHER.store(dispatcher as usize, Ordering::Release);
}

pub fn enqueue_task(callback: TaskCallback, context: *mut u8) -> Result<(), &'static str> {
    let task = Task { callback, context };
    let mut queue = TASK_QUEUE.lock();
    
    if queue.len() >= 1024 {
        return Err("task_queue_full");
    }
    
    queue.push_back(task);
    Ok(())
}

pub fn dequeue_task() -> Option<Task> {
    let mut queue = TASK_QUEUE.lock();
    queue.pop_front()
}

pub fn execute_task(task: &Task) {
    (task.callback)(task.context);
}

pub fn task_queue_depth() -> usize {
    let queue = TASK_QUEUE.lock();
    queue.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_dequeue() {
        while dequeue_task().is_some() {}
        
        let test_val: u32 = 42;
        let ctx = &test_val as *const u32 as *mut u8;
        
        enqueue_task(|_| {}, ctx).unwrap();
        assert_eq!(task_queue_depth(), 1);
        
        let task = dequeue_task();
        assert!(task.is_some());
        assert_eq!(task_queue_depth(), 0);
    }

    #[test]
    fn test_task_overflow() {
        while dequeue_task().is_some() {}
        
        for _ in 0..1024 {
            let _ = enqueue_task(|_| {}, core::ptr::null_mut());
        }
        let result = enqueue_task(|_| {}, core::ptr::null_mut());
        assert!(result.is_err());
        
        while dequeue_task().is_some() {}
    }
}
