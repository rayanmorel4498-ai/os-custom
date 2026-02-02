extern crate alloc;

use anyhow::Result;
use alloc::sync::Arc;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct AutomaticRekeying {
	time_based_interval: Arc<RwLock<u64>>,
	volume_based_threshold: Arc<RwLock<u64>>,
	last_rekey_time: Arc<RwLock<i64>>,
	bytes_since_rekey: Arc<AtomicU64>,
	stats: Arc<RwLock<RekeyingStats>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RekeyingStats {
	pub total_rekeys: u64,
	pub time_based_rekeys: u64,
	pub volume_based_rekeys: u64,
	pub forced_rekeys: u64,
	pub rekey_failures: u64,
}

impl AutomaticRekeying {
	pub fn new(time_interval_secs: u64, volume_threshold_bytes: u64) -> Self {
		Self {
			time_based_interval: Arc::new(RwLock::new(time_interval_secs)),
			volume_based_threshold: Arc::new(RwLock::new(volume_threshold_bytes)),
			last_rekey_time: Arc::new(RwLock::new(crate::time_abstraction::kernel_time_secs_i64())),
			bytes_since_rekey: Arc::new(AtomicU64::new(0)),
			stats: Arc::new(RwLock::new(RekeyingStats {
				total_rekeys: 0,
				time_based_rekeys: 0,
				volume_based_rekeys: 0,
				forced_rekeys: 0,
				rekey_failures: 0,
			})),
		}
	}

	pub fn record_bytes_processed(&self, bytes: u64) {
		self.bytes_since_rekey.fetch_add(bytes, Ordering::SeqCst);
	}

	pub fn check_time_based_rekey(&self) -> Result<bool> {
		let interval = *self.time_based_interval.read();
		let last_rekey = *self.last_rekey_time.read();
		let now = crate::time_abstraction::kernel_time_secs_i64();

		Ok((now - last_rekey) as u64 >= interval)
	}

	pub fn check_volume_based_rekey(&self) -> Result<bool> {
		let threshold = *self.volume_based_threshold.read();
		let bytes = self.bytes_since_rekey.load(Ordering::SeqCst);

		Ok(bytes >= threshold)
	}

	pub fn should_rekey(&self) -> Result<bool> {
		let time_based = self.check_time_based_rekey()?;
		let volume_based = self.check_volume_based_rekey()?;
		Ok(time_based || volume_based)
	}

	pub fn get_rekey_reason(&self) -> Result<Option<RekeyReason>> {
		let time_based = self.check_time_based_rekey()?;
		let volume_based = self.check_volume_based_rekey()?;

		if time_based && volume_based {
			Ok(Some(RekeyReason::Both))
		} else if time_based {
			Ok(Some(RekeyReason::TimeBased))
		} else if volume_based {
			Ok(Some(RekeyReason::VolumeBased))
		} else {
			Ok(None)
		}
	}

	pub fn perform_rekey(&self, reason: RekeyReason) -> Result<()> {
		let mut last_time = self.last_rekey_time.write();
		let mut stats = self.stats.write();

		let now = crate::time_abstraction::kernel_time_secs_i64();
		*last_time = now;
		self.bytes_since_rekey.store(0, Ordering::SeqCst);

		stats.total_rekeys = stats.total_rekeys.saturating_add(1);

		match reason {
			RekeyReason::TimeBased => {
				stats.time_based_rekeys = stats.time_based_rekeys.saturating_add(1);
			}
			RekeyReason::VolumeBased => {
				stats.volume_based_rekeys = stats.volume_based_rekeys.saturating_add(1);
			}
			RekeyReason::Both => {
				stats.time_based_rekeys = stats.time_based_rekeys.saturating_add(1);
				stats.volume_based_rekeys = stats.volume_based_rekeys.saturating_add(1);
			}
			RekeyReason::Forced => {
				stats.forced_rekeys = stats.forced_rekeys.saturating_add(1);
			}
		}

		Ok(())
	}

	pub fn force_rekey(&self) -> Result<()> {
		self.perform_rekey(RekeyReason::Forced)
	}

	pub fn set_time_interval(&self, seconds: u64) {
		*self.time_based_interval.write() = seconds;
	}

	pub fn set_volume_threshold(&self, bytes: u64) {
		*self.volume_based_threshold.write() = bytes;
	}

	pub fn get_stats(&self) -> RekeyingStats {
		self.stats.read().clone()
	}

	pub fn time_since_last_rekey(&self) -> Result<u64> {
		let last_rekey = *self.last_rekey_time.read();
		let now = crate::time_abstraction::kernel_time_secs_i64();
		Ok((now - last_rekey) as u64)
	}

	pub fn bytes_since_last_rekey(&self) -> u64 {
		self.bytes_since_rekey.load(Ordering::SeqCst)
	}

	pub fn get_status(&self) -> Result<RekeyStatus> {
		Ok(RekeyStatus {
			time_since_last_rekey: self.time_since_last_rekey()?,
			bytes_since_last_rekey: self.bytes_since_last_rekey(),
			time_interval: *self.time_based_interval.read(),
			volume_threshold: *self.volume_based_threshold.read(),
			needs_rekey: self.should_rekey()?,
		})
	}
}

#[derive(Clone, Debug)]
pub enum RekeyReason {
	TimeBased,
	VolumeBased,
	Both,
	Forced,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RekeyStatus {
	pub time_since_last_rekey: u64,
	pub bytes_since_last_rekey: u64,
	pub time_interval: u64,
	pub volume_threshold: u64,
	pub needs_rekey: bool,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_volume_based_rekey() {
		let rekeyer = AutomaticRekeying::new(3600, 1000);

		rekeyer.record_bytes_processed(500);
		assert!(!rekeyer.check_volume_based_rekey().unwrap());

		rekeyer.record_bytes_processed(600);
		assert!(rekeyer.check_volume_based_rekey().unwrap());
	}

	#[test]
	fn test_force_rekey() {
		let rekeyer = AutomaticRekeying::new(3600, 10000);

		let initial_stats = rekeyer.get_stats();
		assert_eq!(initial_stats.total_rekeys, 0);

		rekeyer.force_rekey().unwrap();

		let stats = rekeyer.get_stats();
		assert_eq!(stats.total_rekeys, 1);
		assert_eq!(stats.forced_rekeys, 1);
	}

	#[test]
	fn test_rekey_reason_detection() {
		let rekeyer = AutomaticRekeying::new(1, 100);
		
		rekeyer.record_bytes_processed(150);
		let reason = rekeyer.get_rekey_reason().unwrap();
		assert!(matches!(reason, Some(RekeyReason::VolumeBased)));
	}

	#[test]
	fn test_stats_tracking() {
		let rekeyer = AutomaticRekeying::new(3600, 1000);

		rekeyer.record_bytes_processed(500);
		rekeyer.force_rekey().unwrap();

		let stats = rekeyer.get_stats();
		assert_eq!(stats.total_rekeys, 1);
		assert_eq!(stats.forced_rekeys, 1);
	}

	#[test]
	fn test_bytes_reset_after_rekey() {
		let rekeyer = AutomaticRekeying::new(3600, 1000);

		rekeyer.record_bytes_processed(500);
		rekeyer.perform_rekey(RekeyReason::Forced).unwrap();

		assert_eq!(rekeyer.bytes_since_last_rekey(), 0);
	}

	#[test]
	fn test_rekey_status() {
		let rekeyer = AutomaticRekeying::new(3600, 10000);
		rekeyer.record_bytes_processed(5000);

		let status = rekeyer.get_status().unwrap();
		assert_eq!(status.bytes_since_last_rekey, 5000);
		assert!(!status.needs_rekey);
	}
}
