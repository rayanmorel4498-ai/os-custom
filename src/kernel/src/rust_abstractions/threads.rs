#![no_std]

use crate::memory::MemoryManager;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Suspended,
    Terminated,
}

pub struct Thread {
    pub id: usize,
    pub state: ThreadState,
    pub priority: u8,
    pub stack: *mut u8,
    pub stack_size: usize,
    pub critical: bool,
}

pub struct ThreadManager {
    pub threads: [Option<Thread>; 8],
    memory_manager: MemoryManager,
}

impl ThreadManager {
    pub fn init(memory_manager: MemoryManager) -> Self {
        ThreadManager {
            threads: [None, None, None, None, None, None, None, None],
            memory_manager,
        }
    }

    pub fn create_thread(&mut self, id: usize, stack_size: usize, priority: u8, critical: bool) -> Result<(), &'static str> {
        if id >= self.threads.len() { return Err("ID invalide"); }

        let stack = if critical {
            self.memory_manager.allocate(stack_size, true).ok_or("Pas de mémoire pour thread critique")?
        } else {
            self.memory_manager.allocate(stack_size, false).ok_or("Pas de mémoire pour thread normal/supply")?
        };

        let thread = Thread {
            id,
            state: if critical || (id >= 2 && id <= 5) { ThreadState::Ready } else { ThreadState::Suspended },
            priority,
            stack: stack.as_mut_ptr(),
            stack_size,
            critical,
        };

        self.threads[id] = Some(thread);
        Ok(())
    }

    pub fn suspend(&mut self, id: usize) {
        if let Some(thread) = &mut self.threads[id] {
            if thread.critical { return; }
            thread.state = ThreadState::Suspended;
        }
    }

    pub fn resume(&mut self, id: usize) {
        if let Some(thread) = &mut self.threads[id] {
            thread.state = ThreadState::Ready;
        }
    }

    pub fn manage_supply_threads(&mut self, usage_percent_0_5: usize) {
        if usage_percent_0_5 > 70 {
            for id in 6..8 {
                if let Some(thread) = &mut self.threads[id] {
                    if thread.state == ThreadState::Suspended {
                        thread.state = ThreadState::Ready;
                        self.memory_manager.allocate(thread.stack_size, false);
                    }
                }
            }
        } else {
            for id in 6..8 {
                if let Some(thread) = &mut self.threads[id] {
                    thread.state = ThreadState::Suspended;
                }
            }
        }
    }

    pub fn destroy_thread(&mut self, id: usize) {
        if let Some(thread) = self.threads[id].take() {
            if !thread.critical {
                self.memory_manager.free(thread.stack);
            }
        }
    }

    pub fn thread_state(&self, id: usize) -> Option<ThreadState> {
        self.threads[id].as_ref().map(|t| t.state)
    }
}