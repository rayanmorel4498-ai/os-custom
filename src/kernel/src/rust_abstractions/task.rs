#![no_std]

use crate::rust_abstractions::concurrency::{Mutex, SpinLock, Semaphore};
use crate::rust_abstractions::threads::{ThreadManager, ThreadState};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Critical,
    Normal,
    Supply,
}

pub struct Task {
    pub id: usize,
    pub priority: TaskPriority,
    pub runnable: fn(),
}

pub struct TaskQueue {
    queue: [Option<Task>; 128],
    mutex: Mutex,
    spinlock: SpinLock,
    semaphore: Semaphore,
}

impl TaskQueue {
    pub const fn new() -> Self {
        TaskQueue {
            queue: [None; 128],
            mutex: Mutex::new(),
            spinlock: SpinLock::new(),
            semaphore: Semaphore::new(128),
        }
    }

    pub fn enqueue(&mut self, task: Task) -> bool {
        match task.priority {
            TaskPriority::Critical => self.enqueue_critical(task),
            TaskPriority::Normal | TaskPriority::Supply => self.enqueue_normal(task),
        }
    }

    pub fn dequeue(&mut self) -> Option<Task> {
        self.mutex.lock();
        let mut idx = None;
        let mut highest = TaskPriority::Supply;
        for (i, slot) in self.queue.iter().enumerate() {
            if let Some(t) = slot {
                if t.priority < highest {
                    highest = t.priority;
                    idx = Some(i);
                }
            }
        }
        if let Some(i) = idx {
            let task = self.queue[i].take();
            self.semaphore.release();
            self.mutex.unlock();
            task
        } else {
            self.mutex.unlock();
            None
        }
    }

    pub fn dispatch(&mut self, threads: &mut ThreadManager, load_percent_0_5: usize) {
        if load_percent_0_5 > 70 {
            for id in 6..8 {
                if let Some(thread) = &mut threads.threads[id] {
                    if thread.state == ThreadState::Suspended {
                        thread.state = ThreadState::Ready;
                    }
                }
            }
        } else {
            for id in 6..8 {
                if let Some(thread) = &mut threads.threads[id] {
                    thread.state = ThreadState::Suspended;
                }
            }
        }

        for id in 0..8 {
            if let Some(thread) = &threads.threads[id] {
                if thread.state == ThreadState::Ready {
                    if let Some(task) = self.dequeue() {
                        (task.runnable)();
                    }
                }
            }
        }
    }


    fn enqueue_critical(&mut self, task: Task) -> bool {
        self.spinlock.lock();
        let mut added = false;
        for slot in self.queue.iter_mut() {
            if slot.is_none() {
                *slot = Some(task);
                self.semaphore.acquire();
                added = true;
                break;
            }
        }
        self.spinlock.unlock();
        added
    }

    fn enqueue_normal(&mut self, task: Task) -> bool {
        self.mutex.lock();
        let mut added = false;
        for slot in self.queue.iter_mut() {
            if slot.is_none() {
                *slot = Some(task);
                self.semaphore.acquire();
                added = true;
                break;
            }
        }
        self.mutex.unlock();
        added
    }
}