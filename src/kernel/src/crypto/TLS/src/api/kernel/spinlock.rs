
use core::sync::atomic::{AtomicBool, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    #[inline]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            match self.locked.compare_exchange_weak(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
        SpinLockGuard { lock: self }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        match self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => Some(SpinLockGuard { lock: self }),
            Err(_) => None,
        }
    }

    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

pub struct SpinLockGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
}

impl<'a, T: ?Sized> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spinlock_acquire() {
        let lock = SpinLock::new(42);
        {
            let mut guard = lock.lock();
            assert_eq!(*guard, 42);
            *guard = 100;
        }
        {
            let guard = lock.lock();
            assert_eq!(*guard, 100);
        }
    }

    #[test]
    fn test_spinlock_try_lock() {
        let lock = SpinLock::new(42);
        {
            let _guard1 = lock.lock();
            assert!(lock.try_lock().is_none());
        }
        assert!(lock.try_lock().is_some());
    }
}
