extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use parking_lot::RwLock;

pub struct RateLimiter {
    max_requests_per_sec: u32,
    window_seconds: u64,
    buckets: Arc<RwLock<BTreeMap<u64, (f64, u64)>>>,
    total_requests: Arc<AtomicU64>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_limit(100, 1)
    }

    pub fn with_limit(max_requests_per_sec: u32, window_seconds: u64) -> Self {
        Self {
            max_requests_per_sec,
            window_seconds,
            buckets: Arc::new(RwLock::new(BTreeMap::new())),
            total_requests: Arc::new(AtomicU64::new(0)),
        }
    }

    fn current_time() -> u64 {
        crate::time_abstraction::kernel_time_secs()
    }

    pub fn check_rate_limit(&self, component_id: u64) -> bool {
        let now = Self::current_time();
        let mut buckets = self.buckets.write();

        let (mut tokens, last_refill) = buckets
            .get(&component_id)
            .copied()
            .unwrap_or((self.max_requests_per_sec as f64, now));

        let elapsed = now.saturating_sub(last_refill);
        let refill_rate = self.max_requests_per_sec as f64 / self.window_seconds as f64;
        tokens = (tokens + elapsed as f64 * refill_rate)
            .min(self.max_requests_per_sec as f64);

        let allowed = tokens >= 1.0;
        if allowed {
            tokens -= 1.0;
            self.total_requests.fetch_add(1, Ordering::SeqCst);
        }

        buckets.insert(component_id, (tokens, now));
        allowed
    }

    pub fn get_remaining_tokens(&self, component_id: u64) -> u32 {
        let now = Self::current_time();
        let buckets = self.buckets.read();

        let (tokens, last_refill) = buckets
            .get(&component_id)
            .copied()
            .unwrap_or((self.max_requests_per_sec as f64, now));

        let elapsed = now.saturating_sub(last_refill);
        let refill_rate = self.max_requests_per_sec as f64 / self.window_seconds as f64;
        let current_tokens = (tokens + elapsed as f64 * refill_rate)
            .min(self.max_requests_per_sec as f64);

        current_tokens as u32
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::SeqCst)
    }

    pub fn reset_component(&self, component_id: u64) {
        let mut buckets = self.buckets.write();
        buckets.remove(&component_id);
    }

    pub fn reset_all(&self) {
        let mut buckets = self.buckets.write();
        buckets.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = RateLimiter::with_limit(5, 1);
        let component_id = 123;

        for _ in 0..5 {
            assert!(limiter.check_rate_limit(component_id));
        }

        assert!(!limiter.check_rate_limit(component_id));
    }

    #[test]
    fn test_rate_limiter_independent_per_component() {
        let limiter = RateLimiter::with_limit(2, 1);

        let comp1 = 100;
        let comp2 = 200;

        assert!(limiter.check_rate_limit(comp1));
        assert!(limiter.check_rate_limit(comp2));
        assert!(limiter.check_rate_limit(comp1));
        assert!(limiter.check_rate_limit(comp2));

        assert!(!limiter.check_rate_limit(comp1));
        assert!(!limiter.check_rate_limit(comp2));
    }

    #[test]
    fn test_total_requests_counter() {
        let limiter = RateLimiter::with_limit(10, 1);
        let component_id = 456;

        for _ in 0..5 {
            let _ = limiter.check_rate_limit(component_id);
        }

        assert_eq!(limiter.total_requests(), 5);
    }

    #[test]
    fn test_reset_component() {
        let limiter = RateLimiter::with_limit(2, 1);
        let component_id = 789;

        assert!(limiter.check_rate_limit(component_id));
        assert!(limiter.check_rate_limit(component_id));
        assert!(!limiter.check_rate_limit(component_id));

        limiter.reset_component(component_id);

        assert!(limiter.check_rate_limit(component_id));
    }
}
