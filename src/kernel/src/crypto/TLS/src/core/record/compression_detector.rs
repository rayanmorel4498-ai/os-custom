extern crate alloc;

use anyhow::Result;
use alloc::sync::Arc;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct CompressionDetector {
	enabled: Arc<RwLock<bool>>,
	compression_banned: Arc<RwLock<bool>>,
	attempted_compressions: Arc<AtomicU64>,
	stats: Arc<RwLock<CompressionStats>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CompressionStats {
	pub total_checks: u64,
	pub compression_detected: u64,
	pub compression_blocked: u64,
	pub fallback_count: u64,
}

impl CompressionDetector {
	pub fn new() -> Self {
		Self {
			enabled: Arc::new(RwLock::new(true)),
			compression_banned: Arc::new(RwLock::new(false)),
			attempted_compressions: Arc::new(AtomicU64::new(0)),
			stats: Arc::new(RwLock::new(CompressionStats {
				total_checks: 0,
				compression_detected: 0,
				compression_blocked: 0,
				fallback_count: 0,
			})),
		}
	}

	pub fn check_compression(&self, content_encoding: Option<&str>) -> Result<bool> {
		let mut stats = self.stats.write();
		stats.total_checks = stats.total_checks.saturating_add(1);

		let is_enabled = *self.enabled.read();
		if !is_enabled {
			return Ok(false);
		}

		let is_compressed = content_encoding
			.map(|enc| enc.contains("gzip") || enc.contains("deflate") || enc.contains("br"))
			.unwrap_or(false);

		if is_compressed {
			self.attempted_compressions.fetch_add(1, Ordering::SeqCst);
			stats.compression_detected = stats.compression_detected.saturating_add(1);
		}

		Ok(is_compressed)
	}

	pub fn enforce_no_compression(&self, content_encoding: Option<&str>) -> Result<()> {
		let is_compressed = self.check_compression(content_encoding)?;

		if is_compressed && *self.compression_banned.read() {
			let mut stats = self.stats.write();
			stats.compression_blocked = stats.compression_blocked.saturating_add(1);
			return Err(anyhow::anyhow!("Compression interdite (CRIME/BREACH prevention)"));
		}

		Ok(())
	}

	pub fn set_enabled(&self, enabled: bool) {
		*self.enabled.write() = enabled;
	}

	pub fn set_compression_banned(&self, banned: bool) {
		*self.compression_banned.write() = banned;
	}

	pub fn get_safe_encoding(&self) -> Result<&'static str> {
		let mut stats = self.stats.write();
		stats.fallback_count = stats.fallback_count.saturating_add(1);
		Ok("identity")
	}

	pub fn get_stats(&self) -> CompressionStats {
		self.stats.read().clone()
	}

	pub fn check_breach_vulnerability(&self, uncompressed_size: usize, compressed_size: usize) -> Result<bool> {
		let ratio = if uncompressed_size > 0 {
			(uncompressed_size - compressed_size) as f64 / uncompressed_size as f64
		} else {
			0.0
		};

		Ok(ratio > 0.1)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_compression_detection() {
		let detector = CompressionDetector::new();
		
		let is_gzip = detector.check_compression(Some("gzip")).unwrap();
		assert!(is_gzip);

		let is_none = detector.check_compression(Some("identity")).unwrap();
		assert!(!is_none);

		let is_none2 = detector.check_compression(None).unwrap();
		assert!(!is_none2);
	}

	#[test]
	fn test_compression_blocking() {
		let detector = CompressionDetector::new();
		detector.set_compression_banned(true);

		let result = detector.enforce_no_compression(Some("gzip"));
		assert!(result.is_err());

		let result2 = detector.enforce_no_compression(Some("identity"));
		assert!(result2.is_ok());
	}

	#[test]
	fn test_stats_tracking() {
		let detector = CompressionDetector::new();
		
		detector.check_compression(Some("gzip")).ok();
		detector.check_compression(Some("identity")).ok();
		detector.check_compression(Some("br")).ok();

		let stats = detector.get_stats();
		assert_eq!(stats.total_checks, 3);
		assert_eq!(stats.compression_detected, 2);
	}

	#[test]
	fn test_breach_vulnerability() {
		let detector = CompressionDetector::new();
		
		let vulnerable = detector.check_breach_vulnerability(100, 50).unwrap();
		assert!(vulnerable);

		let safe = detector.check_breach_vulnerability(100, 95).unwrap();
		assert!(!safe);
	}

	#[test]
	fn test_safe_encoding_fallback() {
		let detector = CompressionDetector::new();
		detector.set_compression_banned(true);

		let encoding = detector.get_safe_encoding().unwrap();
		assert_eq!(encoding, "identity");

		let stats = detector.get_stats();
		assert_eq!(stats.fallback_count, 1);
	}

	#[test]
	fn test_enable_disable() {
		let detector = CompressionDetector::new();
		
		detector.set_enabled(false);
		let is_compressed = detector.check_compression(Some("gzip")).unwrap();
		assert!(!is_compressed);

		detector.set_enabled(true);
		let is_compressed2 = detector.check_compression(Some("gzip")).unwrap();
		assert!(is_compressed2);
	}
}
