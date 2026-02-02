/// Dynamic Adaptability System
/// - Runtime parameter tuning
/// - Self-healing mechanisms
/// - Anomaly detection
/// - Performance auto-scaling
/// - Load prediction

use alloc::sync::Arc;
use parking_lot::Mutex;
use alloc::collections::VecDeque;
use crate::prelude::{String, ToString, Vec};

/// System metrics for adaptation
#[derive(Clone, Debug)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub queue_depth: usize,
    pub error_rate: f64,
    pub latency_ms: f64,
    pub timestamp: u64,
}

impl SystemMetrics {
    pub fn is_healthy(&self) -> bool {
        self.cpu_usage < 80.0
            && self.memory_usage < 85.0
            && self.error_rate < 0.01
            && self.latency_ms < 1000.0
    }

    pub fn stress_level(&self) -> f64 {
        (self.cpu_usage + self.memory_usage) / 200.0
    }
}

/// Anomaly detector using statistical methods
pub struct AnomalyDetector {
    history: Arc<Mutex<VecDeque<f64>>>,
    window_size: usize,
    sensitivity: f64,
}

impl AnomalyDetector {
    pub fn new(window_size: usize, sensitivity: f64) -> Self {
        AnomalyDetector {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(window_size))),
            window_size,
            sensitivity,
        }
    }

    pub fn record_value(&self, value: f64) -> bool {
        let mut history = self.history.lock();

        if history.len() < self.window_size {
            history.push_back(value);
            return false;
        }

        let mean = history.iter().sum::<f64>() / history.len() as f64;
        let variance = history
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / history.len() as f64;
        let std_dev = variance.sqrt();

        let z_score = (value - mean).abs() / (std_dev + 1e-10);
        let is_anomaly = z_score > self.sensitivity;

        history.pop_front();
        history.push_back(value);

        is_anomaly
    }

    pub fn clear(&self) {
        self.history.lock().clear();
    }
}

/// Load predictor
pub struct LoadPredictor {
    history: Arc<Mutex<VecDeque<usize>>>,
    window_size: usize,
}

impl LoadPredictor {
    pub fn new(window_size: usize) -> Self {
        LoadPredictor {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(window_size))),
            window_size,
        }
    }

    pub fn record_load(&self, load: usize) {
        let mut history = self.history.lock();
        history.push_back(load);

        if history.len() > self.window_size {
            history.pop_front();
        }
    }

    pub fn predict_next_load(&self) -> Option<f64> {
        let history = self.history.lock();
        if history.len() < 3 {
            return None;
        }

        let h: Vec<usize> = history.iter().copied().collect();

        // Simple exponential smoothing
        let alpha = 0.3;
        let mut smoothed = h[0] as f64;

        for &val in &h[1..] {
            smoothed = alpha * val as f64 + (1.0 - alpha) * smoothed;
        }

        Some(smoothed)
    }

    pub fn get_trend(&self) -> Option<String> {
        let history = self.history.lock();
        if history.len() < 2 {
            return None;
        }

        let h: Vec<usize> = history.iter().copied().collect();
        let first_half_avg: f64 = h[..h.len() / 2].iter().sum::<usize>() as f64
            / (h.len() / 2) as f64;
        let second_half_avg: f64 = h[h.len() / 2..].iter().sum::<usize>() as f64
            / (h.len() - h.len() / 2) as f64;

        if second_half_avg > first_half_avg * 1.1 {
            Some("increasing")
        } else if second_half_avg < first_half_avg * 0.9 {
            Some("decreasing")
        } else {
            Some("stable")
        }
    }
}

/// Adaptive parameter controller
pub struct AdaptiveController {
    target_cpu: f64,
    target_memory: f64,
    batch_size: Arc<Mutex<usize>>,
    thread_count: Arc<Mutex<usize>>,
    cache_size: Arc<Mutex<usize>>,
}

impl AdaptiveController {
    pub fn new(initial_batch_size: usize, initial_threads: usize, initial_cache: usize) -> Self {
        AdaptiveController {
            target_cpu: 70.0,
            target_memory: 70.0,
            batch_size: Arc::new(Mutex::new(initial_batch_size)),
            thread_count: Arc::new(Mutex::new(initial_threads)),
            cache_size: Arc::new(Mutex::new(initial_cache)),
        }
    }

    pub fn adapt(&self, metrics: &SystemMetrics) {
        if metrics.cpu_usage > self.target_cpu {
            // Reduce batch size
            let mut batch = self.batch_size.lock();
            if *batch > 1 {
                *batch = (*batch * 9) / 10;
            }
        } else if metrics.cpu_usage < self.target_cpu * 0.8 {
            // Increase batch size
            let mut batch = self.batch_size.lock();
            *batch = (*batch * 11) / 10;
        }

        if metrics.memory_usage > self.target_memory {
            // Reduce cache size
            let mut cache = self.cache_size.lock();
            if *cache > 100 {
                *cache = (*cache * 9) / 10;
            }
        }

        if metrics.queue_depth > 1000 {
            // Add threads
            let mut threads = self.thread_count.lock();
            if *threads < 64 {
                *threads += 1;
            }
        } else if metrics.queue_depth < 10 {
            // Remove threads
            let mut threads = self.thread_count.lock();
            if *threads > 1 {
                *threads -= 1;
            }
        }
    }

    pub fn get_batch_size(&self) -> usize {
        *self.batch_size.lock()
    }

    pub fn get_thread_count(&self) -> usize {
        *self.thread_count.lock()
    }

    pub fn get_cache_size(&self) -> usize {
        *self.cache_size.lock()
    }
}

/// Self-healing mechanism
pub struct SelfHealer {
    failure_count: Arc<Mutex<usize>>,
    recovery_threshold: usize,
    last_recovery: Arc<Mutex<u64>>,
}

impl SelfHealer {
    pub fn new(recovery_threshold: usize) -> Self {
        SelfHealer {
            failure_count: Arc::new(Mutex::new(0)),
            recovery_threshold,
            last_recovery: Arc::new(Mutex::new(0)),
        }
    }

    pub fn record_failure(&self) -> bool {
        let mut failures = self.failure_count.lock();
        *failures += 1;

        if *failures >= self.recovery_threshold {
            *failures = 0;
            drop(failures); // Release lock
            self.trigger_recovery();
            true
        } else {
            false
        }
    }

    pub fn trigger_recovery(&self) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut last = self.last_recovery.lock();
        *last = now;

        // In production: restart components, clear caches, etc
    }

    pub fn get_failure_count(&self) -> usize {
        *self.failure_count.lock()
    }

    pub fn get_last_recovery(&self) -> u64 {
        *self.last_recovery.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_metrics() {
        let metrics = SystemMetrics {
            cpu_usage: 50.0,
            memory_usage: 60.0,
            queue_depth: 100,
            error_rate: 0.001,
            latency_ms: 100.0,
            timestamp: 0,
        };

        assert!(metrics.is_healthy());
        assert!(metrics.stress_level() < 1.0);
    }

    #[test]
    fn test_anomaly_detector() {
        let detector = AnomalyDetector::new(10, 2.0);

        for i in 0..10 {
            detector.record_value(100.0 + i as f64);
        }

        let is_anomaly = detector.record_value(1000.0); // Large spike
        assert!(is_anomaly);
    }

    #[test]
    fn test_load_predictor() {
        let predictor = LoadPredictor::new(10);

        for load in [100, 110, 120, 130].iter() {
            predictor.record_load(*load);
        }

        let predicted = predictor.predict_next_load();
        assert!(predicted.is_some());

        let trend = predictor.get_trend();
        assert_eq!(trend, Some("increasing"));
    }

    #[test]
    fn test_adaptive_controller() {
        let controller = AdaptiveController::new(32, 4, 1000);

        let high_load = SystemMetrics {
            cpu_usage: 85.0,
            memory_usage: 80.0,
            queue_depth: 2000,
            error_rate: 0.005,
            latency_ms: 500.0,
            timestamp: 0,
        };

        controller.adapt(&high_load);

        let new_batch = controller.get_batch_size();
        assert!(new_batch < 32);
    }

    #[test]
    fn test_self_healer() {
        let healer = SelfHealer::new(5);

        for _ in 0..4 {
            assert!(!healer.record_failure());
        }

        assert!(healer.record_failure()); // 5th failure triggers recovery
        assert_eq!(healer.get_failure_count(), 0);
    }
}
