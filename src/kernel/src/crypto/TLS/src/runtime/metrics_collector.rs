use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug)]
pub struct LatencyMetrics {
    pub handshake_ms: u64,
    pub message_processing_ms: u64,
    pub record_layer_ms: u64,
    pub e2e_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ThroughputMetrics {
    pub messages_per_sec: u64,
    pub bytes_per_sec: u64,
    pub encryptions_per_sec: u64,
    pub decryptions_per_sec: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HealthMetrics {
    pub active_sessions: u64,
    pub failed_handshakes: u64,
    pub timeout_errors: u64,
    pub memory_usage: u64,
}

pub struct MetricsCollector {
    latency: Mutex<Vec<u64>>,
    throughput: Mutex<ThroughputMetrics>,
    health: Mutex<HealthMetrics>,
    timeline: Mutex<BTreeMap<u64, MetricsSnapshot>>,
}

#[derive(Clone, Copy, Debug)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub avg_latency_ms: u64,
    pub throughput_msg_per_sec: u64,
    pub active_sessions: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            latency: Mutex::new(Vec::new()),
            throughput: Mutex::new(ThroughputMetrics {
                messages_per_sec: 0,
                bytes_per_sec: 0,
                encryptions_per_sec: 0,
                decryptions_per_sec: 0,
            }),
            health: Mutex::new(HealthMetrics {
                active_sessions: 0,
                failed_handshakes: 0,
                timeout_errors: 0,
                memory_usage: 0,
            }),
            timeline: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn record_latency(&self, latency_ms: u64) {
        self.latency.lock().push(latency_ms);
    }

    pub fn record_message(&self, bytes: u64) {
        let mut throughput = self.throughput.lock();
        throughput.messages_per_sec += 1;
        throughput.bytes_per_sec += bytes;
    }

    pub fn record_encryption(&self) {
        self.throughput.lock().encryptions_per_sec += 1;
    }

    pub fn record_decryption(&self) {
        self.throughput.lock().decryptions_per_sec += 1;
    }

    pub fn update_active_sessions(&self, count: u64) {
        self.health.lock().active_sessions = count;
    }

    pub fn record_failed_handshake(&self) {
        self.health.lock().failed_handshakes += 1;
    }

    pub fn record_timeout(&self) {
        self.health.lock().timeout_errors += 1;
    }

    pub fn update_memory_usage(&self, bytes: u64) {
        self.health.lock().memory_usage = bytes;
    }

    pub fn get_avg_latency(&self) -> u64 {
        let latencies = self.latency.lock();
        if latencies.is_empty() {
            return 0;
        }
        latencies.iter().sum::<u64>() / latencies.len() as u64
    }

    pub fn get_latency_metrics(&self) -> LatencyMetrics {
        let avg = self.get_avg_latency();
        LatencyMetrics {
            handshake_ms: avg,
            message_processing_ms: avg / 3,
            record_layer_ms: avg / 4,
            e2e_ms: avg,
        }
    }

    pub fn get_throughput_metrics(&self) -> ThroughputMetrics {
        *self.throughput.lock()
    }

    pub fn get_health_metrics(&self) -> HealthMetrics {
        *self.health.lock()
    }

    pub fn create_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: Self::now(),
            avg_latency_ms: self.get_avg_latency(),
            throughput_msg_per_sec: self.throughput.lock().messages_per_sec,
            active_sessions: self.health.lock().active_sessions,
        }
    }

    pub fn store_snapshot(&self) {
        let snapshot = self.create_snapshot();
        self.timeline.lock().insert(snapshot.timestamp, snapshot);
    }

    pub fn get_health_score(&self) -> u8 {
        let health = self.health.lock();
        let mut score = 100u32;
        score = score.saturating_sub(health.failed_handshakes.min(50) as u32);
        score = score.saturating_sub(health.timeout_errors.min(30) as u32);

        (score.min(100)) as u8
    }

    pub fn reset(&self) {
        self.latency.lock().clear();
        self.throughput.lock().messages_per_sec = 0;
        self.health.lock().failed_handshakes = 0;
        self.health.lock().timeout_errors = 0;
    }

    fn now() -> u64 {
        0u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.get_avg_latency(), 0);
    }

    #[test]
    fn test_record_latency() {
        let collector = MetricsCollector::new();
        collector.record_latency(10);
        collector.record_latency(20);
        collector.record_latency(30);
        assert_eq!(collector.get_avg_latency(), 20);
    }

    #[test]
    fn test_record_message() {
        let collector = MetricsCollector::new();
        collector.record_message(100);
        collector.record_message(200);
        let throughput = collector.get_throughput_metrics();
        assert_eq!(throughput.messages_per_sec, 2);
        assert_eq!(throughput.bytes_per_sec, 300);
    }

    #[test]
    fn test_health_metrics() {
        let collector = MetricsCollector::new();
        collector.update_active_sessions(5);
        collector.record_failed_handshake();
        collector.record_timeout();

        let health = collector.get_health_metrics();
        assert_eq!(health.active_sessions, 5);
        assert_eq!(health.failed_handshakes, 1);
        assert_eq!(health.timeout_errors, 1);
    }

    #[test]
    fn test_health_score() {
        let collector = MetricsCollector::new();
        let score1 = collector.get_health_score();
        assert_eq!(score1, 100);

        collector.record_failed_handshake();
        let score2 = collector.get_health_score();
        assert!(score2 < 100);
    }

    #[test]
    fn test_snapshot() {
        let collector = MetricsCollector::new();
        collector.record_latency(50);
        collector.record_message(512);
        collector.update_active_sessions(3);

        let snapshot = collector.create_snapshot();
        assert_eq!(snapshot.avg_latency_ms, 50);
        assert_eq!(snapshot.throughput_msg_per_sec, 1);
        assert_eq!(snapshot.active_sessions, 3);
    }

    #[test]
    fn test_reset() {
        let collector = MetricsCollector::new();
        collector.record_latency(100);
        collector.record_failed_handshake();

        collector.reset();
        assert_eq!(collector.get_avg_latency(), 0);
        assert_eq!(collector.get_health_metrics().failed_handshakes, 0);
    }
}
