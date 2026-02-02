
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Mutex<T: ?Sized> {
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub fn new(data: T) -> Self {
        Mutex {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            match self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => break,
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
        MutexGuard { mutex: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => Some(MutexGuard { mutex: self }),
            Err(_) => None,
        }
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        self.mutex.lock.store(false, Ordering::Release);
    }
}
