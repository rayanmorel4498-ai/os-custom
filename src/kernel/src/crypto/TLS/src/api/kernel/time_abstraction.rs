
use core::sync::atomic::{AtomicU64, Ordering};

static KERNEL_TIME_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn kernel_time_secs() -> u64 {
    KERNEL_TIME_COUNTER.load(Ordering::Relaxed)
}

#[inline]
pub fn kernel_time_secs_i64() -> i64 {
    KERNEL_TIME_COUNTER.load(Ordering::Relaxed) as i64
}

#[inline]
pub fn kernel_time_advance(seconds: u64) {
    KERNEL_TIME_COUNTER.fetch_add(seconds, Ordering::Relaxed);
}

#[inline]
pub fn kernel_time_reset() {
    KERNEL_TIME_COUNTER.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_time() {
        kernel_time_reset();
        assert_eq!(kernel_time_secs(), 0);
        kernel_time_advance(10);
        assert_eq!(kernel_time_secs(), 10);
        assert_eq!(kernel_time_secs_i64(), 10);
    }
}
