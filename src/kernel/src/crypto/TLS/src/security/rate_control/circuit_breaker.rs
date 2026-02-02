extern crate alloc;
use alloc::sync::Arc;
use parking_lot::Mutex;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

#[derive(Clone)]
pub struct CircuitBreaker {
    state: Arc<Mutex<CircuitState>>,
    failure_count: Arc<AtomicU32>,
    success_count: Arc<AtomicU32>,
    transitions: Arc<AtomicU64>,
    
    failure_threshold: u32,
    success_threshold: u32,
    timeout_secs: u64,
    last_failure_time: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self::with_config(5, 3, 30)
    }

    pub fn with_config(failure_threshold: u32, success_threshold: u32, timeout_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(CircuitState::Closed)),
            failure_count: Arc::new(AtomicU32::new(0)),
            success_count: Arc::new(AtomicU32::new(0)),
            transitions: Arc::new(AtomicU64::new(0)),
            failure_threshold,
            success_threshold,
            timeout_secs,
            last_failure_time: Arc::new(Mutex::new(0)),
        }
    }

    pub fn record_success(&self) {
        let mut state = self.state.lock();
        
        match *state {
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let succ = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if succ >= self.success_threshold {
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                    self.transitions.fetch_add(1, Ordering::SeqCst);
                }
            }
            CircuitState::Open => {
            }
        }
    }

    pub fn record_failure(&self, current_time: u64) {
        let mut state = self.state.lock();
        *self.last_failure_time.lock() = current_time;
        
        match *state {
            CircuitState::Closed => {
                let fails = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                if fails >= self.failure_threshold {
                    *state = CircuitState::Open;
                    self.success_count.store(0, Ordering::SeqCst);
                    self.transitions.fetch_add(1, Ordering::SeqCst);
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open;
                self.success_count.store(0, Ordering::SeqCst);
                self.transitions.fetch_add(1, Ordering::SeqCst);
            }
            CircuitState::Open => {
            }
        }
    }

    pub fn allow_request(&self, current_time: u64) -> bool {
        let mut state = self.state.lock();
        
        match *state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last_failure = *self.last_failure_time.lock();
                if current_time - last_failure >= self.timeout_secs * 1000 {
                    *state = CircuitState::HalfOpen;
                    self.success_count.store(0, Ordering::SeqCst);
                    self.transitions.fetch_add(1, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    pub fn state(&self) -> CircuitState {
        *self.state.lock()
    }

    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::SeqCst)
    }

    pub fn success_count(&self) -> u32 {
        self.success_count.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        let mut state = self.state.lock();
        *state = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.transitions.fetch_add(1, Ordering::SeqCst);
    }

    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            state: self.state(),
            failure_count: self.failure_count.load(Ordering::SeqCst),
            success_count: self.success_count.load(Ordering::SeqCst),
            transitions: self.transitions.load(Ordering::SeqCst),
            failure_threshold: self.failure_threshold,
            success_threshold: self.success_threshold,
            timeout_secs: self.timeout_secs,
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub transitions: u64,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed_to_open() {
        let cb = CircuitBreaker::with_config(3, 2, 1);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request(0));
        
        cb.record_failure(0);
        cb.record_failure(1);
        cb.record_failure(2);
        
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request(2));
    }

    #[test]
    fn test_circuit_breaker_open_to_half_open() {
        let cb = CircuitBreaker::with_config(3, 2, 1);
        
        cb.record_failure(0);
        cb.record_failure(1);
        cb.record_failure(2);
        assert_eq!(cb.state(), CircuitState::Open);
        
        assert!(cb.allow_request(2000));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_breaker_half_open_to_closed() {
        let cb = CircuitBreaker::with_config(3, 2, 1);
        
        cb.record_failure(0);
        cb.record_failure(1);
        cb.record_failure(2);
        assert!(cb.allow_request(2000));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let cb = CircuitBreaker::new();
        cb.record_failure(0);
        cb.record_failure(1);
        cb.reset();
        
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_circuit_breaker_stats() {
        let cb = CircuitBreaker::with_config(5, 3, 30);
        let stats = cb.stats();
        assert_eq!(stats.state, CircuitState::Closed);
        assert_eq!(stats.failure_threshold, 5);
        assert_eq!(stats.success_threshold, 3);
    }
}
