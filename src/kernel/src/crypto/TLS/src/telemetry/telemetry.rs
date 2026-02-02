extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::format;

#[derive(Clone)]
pub struct TelemetryCollector {
    total_requests: Arc<AtomicU64>,
    successful_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
    
    total_latency_ms: Arc<AtomicU64>,
    min_latency_ms: Arc<RwLock<u64>>,
    max_latency_ms: Arc<RwLock<u64>>,
    latency_samples: Arc<RwLock<Vec<u64>>>,
    
    peak_memory_usage: Arc<RwLock<u64>>,
    current_connections: Arc<AtomicU64>,
    total_connections_created: Arc<AtomicU64>,
    
    handshake_failures: Arc<AtomicU64>,
    authentication_failures: Arc<AtomicU64>,
    timeout_errors: Arc<AtomicU64>,
    
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    cache_evictions: Arc<AtomicU64>,
}

impl TelemetryCollector {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_latency_ms: Arc::new(AtomicU64::new(0)),
            min_latency_ms: Arc::new(RwLock::new(u64::MAX)),
            max_latency_ms: Arc::new(RwLock::new(0)),
            latency_samples: Arc::new(RwLock::new(Vec::new())),
            peak_memory_usage: Arc::new(RwLock::new(0)),
            current_connections: Arc::new(AtomicU64::new(0)),
            total_connections_created: Arc::new(AtomicU64::new(0)),
            handshake_failures: Arc::new(AtomicU64::new(0)),
            authentication_failures: Arc::new(AtomicU64::new(0)),
            timeout_errors: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            cache_evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_success(&self, latency_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
        self.successful_requests.fetch_add(1, Ordering::SeqCst);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::SeqCst);
        self.record_latency_sample(latency_ms);
        
        let mut min = self.min_latency_ms.write();
        if latency_ms < *min {
            *min = latency_ms;
        }
        drop(min);
        
        let mut max = self.max_latency_ms.write();
        if latency_ms > *max {
            *max = latency_ms;
        }
    }

    pub fn record_failure(&self, latency_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
        self.failed_requests.fetch_add(1, Ordering::SeqCst);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::SeqCst);
        self.record_latency_sample(latency_ms);
    }

    pub fn record_handshake_failure(&self) {
        self.handshake_failures.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_auth_failure(&self) {
        self.authentication_failures.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_timeout(&self) {
        self.timeout_errors.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_cache_eviction(&self) {
        self.cache_evictions.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_connection_created(&self) {
        self.total_connections_created.fetch_add(1, Ordering::SeqCst);
        self.current_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_connection_closed(&self) {
        let mut current = self.current_connections.load(Ordering::SeqCst);
        while current > 0 {
            match self.current_connections.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn record_memory_usage(&self, bytes: u64) {
        let mut peak = self.peak_memory_usage.write();
        if bytes > *peak {
            *peak = bytes;
        }
    }

    fn record_latency_sample(&self, latency_ms: u64) {
        let mut samples = self.latency_samples.write();
        samples.push(latency_ms);
        if samples.len() > 2048 {
            samples.remove(0);
        }
    }

    fn percentile_from_sorted(sorted: &[u64], percentile: u64) -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        let idx = ((sorted.len() - 1) as u64 * percentile) / 100;
        sorted[idx as usize]
    }

    pub fn average_latency_ms(&self) -> u64 {
        let total_reqs = self.total_requests.load(Ordering::SeqCst);
        if total_reqs == 0 {
            return 0;
        }
        self.total_latency_ms.load(Ordering::SeqCst) / total_reqs
    }

    pub fn success_rate_percent(&self) -> u64 {
        let total = self.total_requests.load(Ordering::SeqCst);
        if total == 0 {
            return 100;
        }
        (self.successful_requests.load(Ordering::SeqCst) * 100) / total
    }

    pub fn cache_hit_rate_percent(&self) -> u64 {
        let total_accesses = self.cache_hits.load(Ordering::SeqCst) + 
                            self.cache_misses.load(Ordering::SeqCst);
        if total_accesses == 0 {
            return 0;
        }
        (self.cache_hits.load(Ordering::SeqCst) * 100) / total_accesses
    }

    pub fn stats(&self) -> TelemetryStats {
        let (p95, p99) = {
            let samples = self.latency_samples.read();
            if samples.is_empty() {
                (0, 0)
            } else {
                let mut sorted = samples.clone();
                sorted.sort_unstable();
                (
                    Self::percentile_from_sorted(&sorted, 95),
                    Self::percentile_from_sorted(&sorted, 99),
                )
            }
        };
        TelemetryStats {
            total_requests: self.total_requests.load(Ordering::SeqCst),
            successful_requests: self.successful_requests.load(Ordering::SeqCst),
            failed_requests: self.failed_requests.load(Ordering::SeqCst),
            success_rate_percent: self.success_rate_percent(),
            avg_latency_ms: self.average_latency_ms(),
            min_latency_ms: *self.min_latency_ms.read(),
            max_latency_ms: *self.max_latency_ms.read(),
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            peak_memory_usage_bytes: *self.peak_memory_usage.read(),
            current_connections: self.current_connections.load(Ordering::SeqCst),
            total_connections_created: self.total_connections_created.load(Ordering::SeqCst),
            handshake_failures: self.handshake_failures.load(Ordering::SeqCst),
            auth_failures: self.authentication_failures.load(Ordering::SeqCst),
            timeout_errors: self.timeout_errors.load(Ordering::SeqCst),
            cache_hits: self.cache_hits.load(Ordering::SeqCst),
            cache_misses: self.cache_misses.load(Ordering::SeqCst),
            cache_hit_rate_percent: self.cache_hit_rate_percent(),
            cache_evictions: self.cache_evictions.load(Ordering::SeqCst),
        }
    }

    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::SeqCst);
        self.successful_requests.store(0, Ordering::SeqCst);
        self.failed_requests.store(0, Ordering::SeqCst);
        self.total_latency_ms.store(0, Ordering::SeqCst);
        *self.min_latency_ms.write() = u64::MAX;
        *self.max_latency_ms.write() = 0;
        self.latency_samples.write().clear();
        self.handshake_failures.store(0, Ordering::SeqCst);
        self.authentication_failures.store(0, Ordering::SeqCst);
        self.timeout_errors.store(0, Ordering::SeqCst);
        self.cache_hits.store(0, Ordering::SeqCst);
        self.cache_misses.store(0, Ordering::SeqCst);
        self.cache_evictions.store(0, Ordering::SeqCst);
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct TelemetryStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub success_rate_percent: u64,
    pub avg_latency_ms: u64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub peak_memory_usage_bytes: u64,
    pub current_connections: u64,
    pub total_connections_created: u64,
    pub handshake_failures: u64,
    pub auth_failures: u64,
    pub timeout_errors: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate_percent: u64,
    pub cache_evictions: u64,
}

impl TelemetryStats {
    pub fn summary(&self) -> alloc::string::String {
        format!(
            "📊 TLS Telemetry Summary:\n\
            Requests: {} (Success: {}%, Failures: {})\n\
            Latency: avg={:?}ms, min={:?}ms, p95={:?}ms, p99={:?}ms, max={:?}ms\n\
            Connections: {} active, {} total created\n\
            Errors: {} handshake, {} auth, {} timeout\n\
            Cache: {}% hit rate ({} hits, {} misses, {} evictions)\n\
            Memory: {}KB peak usage",
            self.total_requests,
            self.success_rate_percent,
            self.failed_requests,
            self.avg_latency_ms,
            self.min_latency_ms,
            self.p95_latency_ms,
            self.p99_latency_ms,
            self.max_latency_ms,
            self.current_connections,
            self.total_connections_created,
            self.handshake_failures,
            self.auth_failures,
            self.timeout_errors,
            self.cache_hit_rate_percent,
            self.cache_hits,
            self.cache_misses,
            self.cache_evictions,
            self.peak_memory_usage_bytes / 1024
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_creation() {
        let telemetry = TelemetryCollector::new();
        let stats = telemetry.stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.success_rate_percent, 100);
    }

    #[test]
    fn test_telemetry_success_recording() {
        let telemetry = TelemetryCollector::new();
        telemetry.record_success(100);
        telemetry.record_success(200);
        
        let stats = telemetry.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.successful_requests, 2);
        assert_eq!(stats.avg_latency_ms, 150);
        assert_eq!(stats.p95_latency_ms, 200);
        assert_eq!(stats.p99_latency_ms, 200);
    }

    #[test]
    fn test_telemetry_failure_recording() {
        let telemetry = TelemetryCollector::new();
        telemetry.record_success(100);
        telemetry.record_failure(50);
        
        let stats = telemetry.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.successful_requests, 1);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.success_rate_percent, 50);
    }

    #[test]
    fn test_telemetry_cache_metrics() {
        let telemetry = TelemetryCollector::new();
        telemetry.record_cache_hit();
        telemetry.record_cache_hit();
        telemetry.record_cache_miss();
        
        let stats = telemetry.stats();
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hit_rate_percent, 66);
    }

    #[test]
    fn test_telemetry_reset() {
        let telemetry = TelemetryCollector::new();
        telemetry.record_success(100);
        telemetry.reset();
        
        let stats = telemetry.stats();
        assert_eq!(stats.total_requests, 0);
    }
}
