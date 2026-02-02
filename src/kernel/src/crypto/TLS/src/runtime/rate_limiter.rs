use alloc::collections::BTreeMap;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentType {
    Kernel,
    IA,
    API,
    Security,
    Optimization,
    HSM,
}

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

impl RateLimitConfig {
    pub fn default_for(component: ComponentType) -> Self {
        match component {
            ComponentType::Kernel => Self {
                requests_per_second: 1000,
                burst_size: 100,
            },
            ComponentType::IA => Self {
                requests_per_second: 500,
                burst_size: 50,
            },
            ComponentType::API => Self {
                requests_per_second: 100,
                burst_size: 20,
            },
            ComponentType::Security => Self {
                requests_per_second: 50,
                burst_size: 10,
            },
            ComponentType::Optimization => Self {
                requests_per_second: 200,
                burst_size: 30,
            },
            ComponentType::HSM => Self {
                requests_per_second: 10,
                burst_size: 3,
            },
        }
    }
}

#[derive(Clone, Debug)]
struct TokenBucket {
    tokens: u32,
    max_tokens: u32,
    refill_rate: u32,
    last_refill: u64,
}

impl TokenBucket {
    fn new(config: &RateLimitConfig) -> Self {
        Self {
            tokens: config.burst_size,
            max_tokens: config.burst_size,
            refill_rate: config.requests_per_second,
            last_refill: Self::now(),
        }
    }

    fn refill(&mut self) {
        let now = Self::now();
        let elapsed = now.saturating_sub(self.last_refill);
        
        if elapsed > 0 {
            let new_tokens = (elapsed as u32).saturating_mul(self.refill_rate);
            self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn now() -> u64 {
        0u64
    }
}

pub struct RateLimiter {
    buckets: Mutex<BTreeMap<ComponentType, TokenBucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn initialize_component(&self, component: ComponentType) {
        let config = RateLimitConfig::default_for(component);
        let bucket = TokenBucket::new(&config);
        self.buckets.lock().insert(component, bucket);
    }

    pub fn is_allowed(&self, component: ComponentType, tokens: u32) -> bool {
        let mut buckets = self.buckets.lock();

        if !buckets.contains_key(&component) {
            let config = RateLimitConfig::default_for(component);
            buckets.insert(component, TokenBucket::new(&config));
        }

        if let Some(bucket) = buckets.get_mut(&component) {
            bucket.try_consume(tokens)
        } else {
            false
        }
    }

    pub fn get_tokens(&self, component: ComponentType) -> u32 {
        let buckets = self.buckets.lock();
        buckets
            .get(&component)
            .map(|b| b.tokens)
            .unwrap_or(0)
    }

    pub fn reset_component(&self, component: ComponentType) {
        let config = RateLimitConfig::default_for(component);
        let bucket = TokenBucket::new(&config);
        self.buckets.lock().insert(component, bucket);
    }

    pub fn is_throttled(&self, component: ComponentType) -> bool {
        self.get_tokens(component) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig::default_for(ComponentType::Kernel);
        assert_eq!(config.requests_per_second, 1000);
        assert_eq!(config.burst_size, 100);
    }

    #[test]
    fn test_rate_limiter_initialization() {
        let limiter = RateLimiter::new();
        limiter.initialize_component(ComponentType::API);
        assert!(limiter.get_tokens(ComponentType::API) > 0);
    }

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = RateLimiter::new();
        limiter.initialize_component(ComponentType::API);
        
        assert!(limiter.is_allowed(ComponentType::API, 1));
        assert!(limiter.is_allowed(ComponentType::API, 1));
    }

    #[test]
    fn test_rate_limiter_throttling() {
        let limiter = RateLimiter::new();
        limiter.initialize_component(ComponentType::HSM);
        assert!(limiter.is_allowed(ComponentType::HSM, 1));
        assert!(limiter.is_allowed(ComponentType::HSM, 1));
        assert!(limiter.is_allowed(ComponentType::HSM, 1));
        assert!(!limiter.is_allowed(ComponentType::HSM, 1));
    }

    #[test]
    fn test_different_components_independent() {
        let limiter = RateLimiter::new();
        limiter.initialize_component(ComponentType::Kernel);
        limiter.initialize_component(ComponentType::HSM);
        assert!(limiter.get_tokens(ComponentType::Kernel) >= limiter.get_tokens(ComponentType::HSM));
    }
}
