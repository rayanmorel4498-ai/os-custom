
use core::sync::atomic::{AtomicUsize, Ordering};

pub type SleepCallback = fn(millis: u64);

pub type TimeCallback = fn() -> u64;
pub type SandboxCreatedCallback = fn(sandbox_id: u64);

static SLEEP_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static TIME_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static SANDBOX_CREATED_CALLBACK: AtomicUsize = AtomicUsize::new(0);

pub fn init_callbacks(sleep_fn: SleepCallback, time_fn: TimeCallback) {
    SLEEP_CALLBACK.store(sleep_fn as usize, Ordering::Release);
    TIME_CALLBACK.store(time_fn as usize, Ordering::Release);
}

pub fn init_sandbox_created_callback(callback: SandboxCreatedCallback) {
    SANDBOX_CREATED_CALLBACK.store(callback as usize, Ordering::Release);
}

#[inline]
pub fn kernel_sleep_ms(millis: u64) {
    let callback_addr = SLEEP_CALLBACK.load(Ordering::Acquire);
    if callback_addr != 0 {
        let callback: SleepCallback = unsafe { core::mem::transmute(callback_addr) };
        callback(millis);
    }
}

#[inline]
pub fn kernel_sleep_secs(secs: u64) {
    kernel_sleep_ms(secs.saturating_mul(1000));
}

#[inline]
pub fn kernel_get_time_ms() -> u64 {
    let callback_addr = TIME_CALLBACK.load(Ordering::Acquire);
    if callback_addr != 0 {
        let callback: TimeCallback = unsafe { core::mem::transmute(callback_addr) };
        callback()
    } else {
        crate::api::kernel::time_abstraction::kernel_time_secs() * 1000
    }
}

#[inline]
pub fn kernel_sandbox_created(sandbox_id: u64) {
    let callback_addr = SANDBOX_CREATED_CALLBACK.load(Ordering::Acquire);
    if callback_addr != 0 {
        let callback: SandboxCreatedCallback = unsafe { core::mem::transmute(callback_addr) };
        callback(sandbox_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_callbacks_init() {
        fn test_sleep(_millis: u64) {}

        fn test_time() -> u64 {
            12345
        }

        init_callbacks(test_sleep, test_time);
        assert_eq!(kernel_get_time_ms(), 12345);
    }
}
