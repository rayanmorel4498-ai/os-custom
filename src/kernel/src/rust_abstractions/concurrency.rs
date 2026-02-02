#![no_std]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::hint::spin_loop;

pub struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    pub const fn new() -> Self {
        SpinLock { locked: AtomicBool::new(false) }
    }

    pub fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    pub fn try_lock(&self) -> bool {
        !self.locked.swap(true, Ordering::Acquire)
    }
}

pub struct Mutex {
    locked: AtomicBool,
}

impl Mutex {
    pub const fn new() -> Self {
        Mutex { locked: AtomicBool::new(false) }
    }

    pub fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    pub fn try_lock(&self) -> bool {
        !self.locked.swap(true, Ordering::Acquire)
    }
}

pub struct Semaphore {
    count: AtomicUsize,
    max: usize,
}

impl Semaphore {
    pub const fn new(max: usize) -> Self {
        Semaphore { count: AtomicUsize::new(max), max }
    }

    pub fn acquire(&self) -> bool {
        let mut current = self.count.load(Ordering::Acquire);
        while current > 0 {
            if self.count.compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return true;
            }
            current = self.count.load(Ordering::Acquire);
        }
        false
    }

    pub fn release(&self) {
        let mut current = self.count.load(Ordering::Acquire);
        while current < self.max {
            if self.count.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return;
            }
            current = self.count.load(Ordering::Acquire);
        }
    }

    pub fn available(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

pub struct AtomicCounter {
    count: AtomicUsize,
}

impl AtomicCounter {
    pub const fn new(initial: usize) -> Self {
        AtomicCounter { count: AtomicUsize::new(initial) }
    }

    pub fn increment(&self) -> usize {
        self.count.fetch_add(1, Ordering::AcqRel)
    }

    pub fn decrement(&self) -> usize {
        self.count.fetch_sub(1, Ordering::AcqRel)
    }

    pub fn get(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    pub fn set(&self, value: usize) {
        self.count.store(value, Ordering::Release)
    }
}

pub struct ThreadSupplyFlags {
    pub active: AtomicBool,
    pub cpu_load_percent: AtomicUsize,
}

impl ThreadSupplyFlags {
    pub const fn new() -> Self {
        ThreadSupplyFlags {
            active: AtomicBool::new(false),
            cpu_load_percent: AtomicUsize::new(0),
        }
    }

    pub fn check_activation(&self) -> bool {
        self.cpu_load_percent.load(Ordering::Acquire) > 70
    }

    pub fn set_cpu_load(&self, load: usize) {
        self.cpu_load_percent.store(load, Ordering::Release);
    }

    pub fn activate_supply(&self) {
        self.active.store(true, Ordering::Release);
    }

    pub fn deactivate_supply(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}