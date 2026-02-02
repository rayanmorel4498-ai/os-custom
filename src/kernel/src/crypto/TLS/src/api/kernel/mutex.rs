
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "kernel_bare_metal")]
use super::spinlock::SpinLock;

#[cfg(not(feature = "kernel_bare_metal"))]
use parking_lot::Mutex as ParkingLotMutex;

#[cfg(feature = "kernel_bare_metal")]
pub struct KernelMutex<T>(SpinLock<T>);

#[cfg(not(feature = "kernel_bare_metal"))]
pub struct KernelMutex<T>(ParkingLotMutex<T>);

impl<T> KernelMutex<T> {
    #[cfg(feature = "kernel_bare_metal")]
    pub const fn new(data: T) -> Self {
        KernelMutex(SpinLock::new(data))
    }

    #[cfg(not(feature = "kernel_bare_metal"))]
    pub const fn new(data: T) -> Self {
        KernelMutex(ParkingLotMutex::new(data))
    }

    #[cfg(feature = "kernel_bare_metal")]
    pub fn lock(&self) -> KernelMutexGuard<'_, T> {
        KernelMutexGuard(self.0.lock())
    }

    #[cfg(not(feature = "kernel_bare_metal"))]
    pub fn lock(&self) -> KernelMutexGuard<'_, T> {
        KernelMutexGuard(self.0.lock())
    }

    #[cfg(feature = "kernel_bare_metal")]
    pub fn try_lock(&self) -> Option<KernelMutexGuard<'_, T>> {
        self.0.try_lock().map(KernelMutexGuard)
    }

    #[cfg(not(feature = "kernel_bare_metal"))]
    pub fn try_lock(&self) -> Option<KernelMutexGuard<'_, T>> {
        self.0.try_lock().map(KernelMutexGuard)
    }

    pub fn get_mut(&mut self) -> &mut T {
        #[cfg(feature = "kernel_bare_metal")]
        {
            self.0.get_mut()
        }
        #[cfg(not(feature = "kernel_bare_metal"))]
        {
            self.0.get_mut()
        }
    }

    pub fn into_inner(self) -> T {
        #[cfg(feature = "kernel_bare_metal")]
        {
            self.0.into_inner()
        }
        #[cfg(not(feature = "kernel_bare_metal"))]
        {
            self.0.into_inner()
        }
    }
}

pub struct KernelMutexGuard<'a, T: ?Sized>(
    #[cfg(feature = "kernel_bare_metal")] super::spinlock::SpinLockGuard<'a, T>,
    #[cfg(not(feature = "kernel_bare_metal"))] parking_lot::MutexGuard<'a, T>,
);

impl<'a, T: ?Sized> Deref for KernelMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        #[cfg(feature = "kernel_bare_metal")]
        {
            &*self.0
        }
        #[cfg(not(feature = "kernel_bare_metal"))]
        {
            &*self.0
        }
    }
}

impl<'a, T: ?Sized> DerefMut for KernelMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        #[cfg(feature = "kernel_bare_metal")]
        {
            &mut *self.0
        }
        #[cfg(not(feature = "kernel_bare_metal"))]
        {
            &mut *self.0
        }
    }
}

pub type KernelMutexArc<T> = Arc<KernelMutex<T>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_mutex_basic() {
        let mutex = KernelMutex::new(42);
        {
            let mut guard = mutex.lock();
            *guard = 100;
        }
        {
            let guard = mutex.lock();
            assert_eq!(*guard, 100);
        }
    }

    #[test]
    fn test_kernel_mutex_try_lock() {
        let mutex = KernelMutex::new(42);
        assert!(mutex.try_lock().is_some());
    }
}
