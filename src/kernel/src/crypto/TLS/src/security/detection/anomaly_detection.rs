extern crate alloc;

use anyhow::Result;
use alloc::sync::Arc;
use alloc::{format, string::{String, ToString}};
use alloc::vec::Vec;
use parking_lot::RwLock;

#[derive(Clone)]
pub struct AnomalyDetection {
	thresholds: Arc<RwLock<AnomalyThresholds>>,
	anomalies: Arc<RwLock<Vec<DetectedAnomaly>>>,
	stats: Arc<RwLock<AnomalyStats>>,
	auto_remediation: Arc<RwLock<bool>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AnomalyThresholds {
	pub high_error_rate: f64,
	pub low_success_rate: f64,
	pub high_latency_ms: u64,
	pub connection_spike: u32,
	pub cache_miss_threshold: f64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DetectedAnomaly {
	pub anomaly_type: String,
	pub severity: AnomalySeverity,
	pub timestamp: i64,
	pub details: String,
	pub remediation_applied: bool,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum AnomalySeverity {
	Low,
	Medium,
	High,
	Critical,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AnomalyStats {
	pub total_anomalies_detected: u64,
	pub critical_anomalies: u64,
	pub auto_remediations_triggered: u64,
	pub false_positives: u64,
}

impl AnomalyDetection {
	pub fn new() -> Self {
		Self {
			thresholds: Arc::new(RwLock::new(AnomalyThresholds {
				high_error_rate: 0.25,
				low_success_rate: 0.70,
				high_latency_ms: 500,
				connection_spike: 50,
				cache_miss_threshold: 0.30,
			})),
			anomalies: Arc::new(RwLock::new(Vec::new())),
			stats: Arc::new(RwLock::new(AnomalyStats {
				total_anomalies_detected: 0,
				critical_anomalies: 0,
				auto_remediations_triggered: 0,
				false_positives: 0,
			})),
			auto_remediation: Arc::new(RwLock::new(true)),
		}
	}

	pub fn check_metrics(
		&self,
		error_rate: f64,
		success_rate: f64,
		avg_latency_ms: u64,
		connection_count: u32,
		cache_hit_rate: f64,
	) -> Result<Vec<DetectedAnomaly>> {
		let mut detected = Vec::new();
		let thresholds = self.thresholds.read().clone();
		let now = crate::time_abstraction::kernel_time_secs_i64();

		if error_rate > thresholds.high_error_rate {
			detected.push(DetectedAnomaly {
				anomaly_type: "HIGH_ERROR_RATE".to_string(),
				severity: AnomalySeverity::Critical,
				timestamp: now,
				details: format!("Error rate: {:.2}% (seuil: {:.2}%)", error_rate * 100.0, thresholds.high_error_rate * 100.0),
				remediation_applied: false,
			});
		}

		if success_rate < thresholds.low_success_rate {
			detected.push(DetectedAnomaly {
				anomaly_type: "LOW_SUCCESS_RATE".to_string(),
				severity: AnomalySeverity::High,
				timestamp: now,
				details: format!("Success rate: {:.2}% (seuil: {:.2}%)", success_rate * 100.0, thresholds.low_success_rate * 100.0),
				remediation_applied: false,
			});
		}

		if avg_latency_ms > thresholds.high_latency_ms {
			detected.push(DetectedAnomaly {
				anomaly_type: "HIGH_LATENCY".to_string(),
				severity: AnomalySeverity::Medium,
				timestamp: now,
				details: format!("Latency: {}ms (seuil: {}ms)", avg_latency_ms, thresholds.high_latency_ms),
				remediation_applied: false,
			});
		}

		if connection_count > thresholds.connection_spike {
			detected.push(DetectedAnomaly {
				anomaly_type: "CONNECTION_SPIKE".to_string(),
				severity: AnomalySeverity::High,
				timestamp: now,
				details: format!("Connections: {} (seuil: {})", connection_count, thresholds.connection_spike),
				remediation_applied: false,
			});
		}

		let miss_rate = 1.0 - cache_hit_rate;
		let miss_threshold = thresholds.cache_miss_threshold + 1e-12;
		if miss_rate > miss_threshold {
			detected.push(DetectedAnomaly {
				anomaly_type: "CACHE_MISS_SPIKE".to_string(),
				severity: AnomalySeverity::Medium,
				timestamp: now,
				details: format!("Cache miss rate: {:.2}% (seuil: {:.2}%)", miss_rate * 100.0, thresholds.cache_miss_threshold * 100.0),
				remediation_applied: false,
			});
		}

		let mut anomalies = self.anomalies.write();
		let mut stats = self.stats.write();

		if !detected.is_empty() {
			stats.total_anomalies_detected = stats.total_anomalies_detected.saturating_add(1);
		}

		for anomaly in &detected {
			anomalies.push(anomaly.clone());

			if anomaly.severity == AnomalySeverity::Critical {
				stats.critical_anomalies = stats.critical_anomalies.saturating_add(1);
			}
		}

		Ok(detected)
	}

	pub fn apply_auto_remediation(&self, anomaly: &DetectedAnomaly) -> Result<RemediationAction> {
		let mut stats = self.stats.write();
		stats.auto_remediations_triggered = stats.auto_remediations_triggered.saturating_add(1);

		let action = match anomaly.anomaly_type.as_str() {
			"HIGH_ERROR_RATE" => RemediationAction::ClearCache,
			"LOW_SUCCESS_RATE" => RemediationAction::IncreaseCircuitBreakerThreshold,
			"HIGH_LATENCY" => RemediationAction::ReduceMaxConcurrency,
			"CONNECTION_SPIKE" => RemediationAction::EnableRateLimiting,
			"CACHE_MISS_SPIKE" => RemediationAction::RebuildCache,
			_ => RemediationAction::LogAndAlert,
		};

		Ok(action)
	}

	pub fn mark_remediated(&self, index: usize) -> Result<()> {
		let mut anomalies = self.anomalies.write();
		if index < anomalies.len() {
			anomalies[index].remediation_applied = true;
		}
		Ok(())
	}

	pub fn get_recent_anomalies(&self, limit: usize) -> Result<Vec<DetectedAnomaly>> {
		let anomalies = self.anomalies.read();
		let count = anomalies.len();
		let start = if count > limit { count - limit } else { 0 };
		Ok(anomalies[start..count].to_vec())
	}

	pub fn set_thresholds(&self, thresholds: AnomalyThresholds) {
		*self.thresholds.write() = thresholds;
	}

	pub fn set_auto_remediation(&self, enabled: bool) {
		*self.auto_remediation.write() = enabled;
	}

	pub fn is_auto_remediation_enabled(&self) -> bool {
		*self.auto_remediation.read()
	}

	pub fn get_stats(&self) -> AnomalyStats {
		self.stats.read().clone()
	}

	pub fn get_anomaly_count(&self) -> usize {
		self.anomalies.read().len()
	}

	pub fn cleanup_old_anomalies(&self) -> Result<()> {
		let mut anomalies = self.anomalies.write();
		let now = crate::time_abstraction::kernel_time_secs_i64();
		anomalies.retain(|a| (now - a.timestamp) < 3600);
		Ok(())
	}
}

#[derive(Clone, Debug, serde::Serialize)]
pub enum RemediationAction {
	ClearCache,
	IncreaseCircuitBreakerThreshold,
	ReduceMaxConcurrency,
	EnableRateLimiting,
	RebuildCache,
	LogAndAlert,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_high_error_detection() {
		let detector = AnomalyDetection::new();

		let anomalies = detector.check_metrics(
			0.30,
			0.70, 100, 10, 0.95
		).unwrap();

		assert!(!anomalies.is_empty());
		assert_eq!(anomalies[0].anomaly_type, "HIGH_ERROR_RATE");
		assert_eq!(anomalies[0].severity, AnomalySeverity::Critical);
	}

	#[test]
	fn test_multiple_anomalies() {
		let detector = AnomalyDetection::new();

		let anomalies = detector.check_metrics(
			0.30,
			0.60,
			600,
			100,
			0.70,
		).unwrap();

		assert_eq!(anomalies.len(), 4);
	}

	#[test]
	fn test_no_anomalies() {
		let detector = AnomalyDetection::new();

		let anomalies = detector.check_metrics(
			0.10, 0.90, 100, 20, 0.95
		).unwrap();

		assert!(anomalies.is_empty());
	}

	#[test]
	fn test_remediation_action() {
		let detector = AnomalyDetection::new();

		let anomaly = DetectedAnomaly {
			anomaly_type: "HIGH_ERROR_RATE".to_string(),
			severity: AnomalySeverity::Critical,
			timestamp: crate::time_abstraction::kernel_time_secs_i64(),
			details: "Test".to_string(),
			remediation_applied: false,
		};

		let action = detector.apply_auto_remediation(&anomaly).unwrap();
		assert!(matches!(action, RemediationAction::ClearCache));
	}

	#[test]
	fn test_stats_tracking() {
		let detector = AnomalyDetection::new();

		detector.check_metrics(0.30, 0.70, 100, 10, 0.95).ok();
		detector.check_metrics(0.35, 0.60, 100, 10, 0.95).ok();

		let stats = detector.get_stats();
		assert_eq!(stats.total_anomalies_detected, 2);
	}

	#[test]
	fn test_mark_remediated() {
		let detector = AnomalyDetection::new();

		detector.check_metrics(0.30, 0.70, 100, 10, 0.95).ok();

		let recent = detector.get_recent_anomalies(1).unwrap();
		assert!(!recent[0].remediation_applied);

		detector.mark_remediated(0).ok();

		let recent2 = detector.get_recent_anomalies(1).unwrap();
		assert!(recent2[0].remediation_applied);
	}

	#[test]
	fn test_enable_disable_auto_remediation() {
		let detector = AnomalyDetection::new();

		detector.set_auto_remediation(false);
		assert!(!detector.is_auto_remediation_enabled());

		detector.set_auto_remediation(true);
		assert!(detector.is_auto_remediation_enabled());
	}
}
