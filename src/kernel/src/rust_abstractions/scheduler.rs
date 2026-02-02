#![no_std]

use crate::rust_abstractions::task::{TaskQueue};
use crate::rust_abstractions::threads::{ThreadManager, ThreadState};
use crate::rust_abstractions::ipc::IpcManager;
use crate::rust_abstractions::concurrency::{AtomicCounter, ThreadSupplyFlags};

pub struct Scheduler {
    pub threads: ThreadManager,
    pub task_queue: TaskQueue,
    pub supply_flags: ThreadSupplyFlags,
    pub load_0_5: AtomicCounter,
    pub ipc: IpcManager,
}

impl Scheduler {
    pub const fn new(task_queue: TaskQueue, ipc: IpcManager) -> Self {
        Scheduler {
            threads: ThreadManager::new(),
            task_queue,
            supply_flags: ThreadSupplyFlags::new(),
            load_0_5: AtomicCounter::new(0),
            ipc,
        }
    }

    pub fn tick(&mut self) {
        self.update_load();
        self.manage_supply_threads();
        self.dispatch_tasks();
        self.check_ipc();
    }

    fn update_load(&mut self) {
        let mut load = 0;
        for id in 0..6 {
            if let Some(thread) = &self.threads.threads[id] {
                if thread.state == ThreadState::Running {
                    load += 1;
                }
            }
        }
        let percent_load = (load * 100) / 6;
        self.load_0_5.set(percent_load);
    }

    fn manage_supply_threads(&mut self) {
        let percent_load = self.load_0_5.get();
        if percent_load > 70 {
            self.supply_flags.activate_supply();
            for id in 6..8 {
                if let Some(thread) = &mut self.threads.threads[id] {
                    if thread.state == ThreadState::Suspended {
                        thread.state = ThreadState::Ready;
                    }
                }
            }
        } else {
            self.supply_flags.deactivate_supply();
            for id in 6..8 {
                if let Some(thread) = &mut self.threads.threads[id] {
                    thread.state = ThreadState::Suspended;
                }
            }
        }
    }

    fn dispatch_tasks(&mut self) {
        self.task_queue.dispatch(&mut self.threads, self.load_0_5.get());
    }

    fn check_ipc(&mut self) {
        for id in 0..8 {
            if self.ipc.has_messages(id) {
                if let Some(thread) = &mut self.threads.threads[id] {
                    if thread.state != ThreadState::Running {
                        thread.state = ThreadState::Ready;
                    }
                }
            }
        }
    }

    pub fn add_task(&mut self, task: crate::task::Task) -> bool {
        self.task_queue.enqueue(task)
    }

    pub fn run(&mut self) {
        for id in 0..8 {
            if let Some(thread) = &mut self.threads.threads[id] {
                if thread.state == ThreadState::Ready {
                    thread.state = ThreadState::Running;

                    thread.run_real();

                    thread.state = ThreadState::Ready;
                }
            }
        }
    }
}