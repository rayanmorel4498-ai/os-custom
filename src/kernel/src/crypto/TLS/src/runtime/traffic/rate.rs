extern crate alloc;

use anyhow::Result;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use parking_lot::RwLock;

#[derive(Clone)]
pub struct RateLimiter {
	max_handshakes_per_minute: Arc<RwLock<u32>>,
	max_failures_per_ip: Arc<RwLock<u32>>,
	failure_window_secs: Arc<RwLock<u64>>,
	client_attempts: Arc<RwLock<BTreeMap<String, ClientAttempts>>>,
	stats: Arc<RwLock<RateLimiterStats>>,
}

#[derive(Clone, Debug)]
struct ClientAttempts {
	handshake_count: u32,
	failure_count: u32,
	last_attempt_time: i64,
	last_failure_time: i64,
	blocked_until: Option<i64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RateLimiterStats {
	pub total_attempts: u64,
	pub blocked_requests: u64,
	pub ip_blocks: u64,
	pub reset_windows: u64,
}

impl RateLimiter {
	pub fn new(max_handshakes_per_minute: u32, max_failures_per_ip: u32) -> Self {
		Self {
			max_handshakes_per_minute: Arc::new(RwLock::new(max_handshakes_per_minute)),
			max_failures_per_ip: Arc::new(RwLock::new(max_failures_per_ip)),
			failure_window_secs: Arc::new(RwLock::new(300)),
			client_attempts: Arc::new(RwLock::new(BTreeMap::new())),
			stats: Arc::new(RwLock::new(RateLimiterStats {
				total_attempts: 0,
				blocked_requests: 0,
				ip_blocks: 0,
				reset_windows: 0,
			})),
		}
	}

	pub fn check_request(&self, client_ip: &str) -> Result<bool> {
		let mut stats = self.stats.write();
		stats.total_attempts = stats.total_attempts.saturating_add(1);

		let mut clients = self.client_attempts.write();
		let now = crate::time_abstraction::kernel_time_secs_i64();

		let max_handshakes = *self.max_handshakes_per_minute.read();
		let max_failures = *self.max_failures_per_ip.read();

		let client = clients.entry(client_ip.to_string())
			.or_insert_with(|| ClientAttempts {
				handshake_count: 0,
				failure_count: 0,
				last_attempt_time: now,
				last_failure_time: now,
				blocked_until: None,
			});

		if (now - client.last_attempt_time) as u64 >= 60 {
			client.handshake_count = 0;
			stats.reset_windows = stats.reset_windows.saturating_add(1);
		}

		let window = *self.failure_window_secs.read();
		if (now - client.last_failure_time) as u64 >= window {
			client.failure_count = 0;
		}

		if let Some(blocked_until) = client.blocked_until {
			if now < blocked_until {
				stats.blocked_requests = stats.blocked_requests.saturating_add(1);
				return Ok(false);
			} else {
				client.blocked_until = None;
			}
		}

		if client.handshake_count >= max_handshakes {
			client.blocked_until = Some(now + 60);
			stats.blocked_requests = stats.blocked_requests.saturating_add(1);
			stats.ip_blocks = stats.ip_blocks.saturating_add(1);
			return Ok(false);
		}

		if client.failure_count >= max_failures {
			client.blocked_until = Some(now + (window as i64));
			stats.blocked_requests = stats.blocked_requests.saturating_add(1);
			stats.ip_blocks = stats.ip_blocks.saturating_add(1);
			return Ok(false);
		}

		client.handshake_count += 1;
		client.last_attempt_time = now;

		Ok(true)
	}

	pub fn record_failure(&self, client_ip: &str) -> Result<()> {
		let mut clients = self.client_attempts.write();
		let now = crate::time_abstraction::kernel_time_secs_i64();

		let client = clients.entry(client_ip.to_string())
			.or_insert_with(|| ClientAttempts {
				handshake_count: 0,
				failure_count: 0,
				last_attempt_time: now,
				last_failure_time: now,
				blocked_until: None,
			});

		client.failure_count += 1;
		client.last_failure_time = now;

		Ok(())
	}

	pub fn record_success(&self, client_ip: &str) -> Result<()> {
		let mut clients = self.client_attempts.write();

		if let Some(client) = clients.get_mut(client_ip) {
			client.failure_count = client.failure_count.saturating_sub(1);
		}

		Ok(())
	}

	pub fn unblock_ip(&self, client_ip: &str) -> Result<()> {
		let mut clients = self.client_attempts.write();

		if let Some(client) = clients.get_mut(client_ip) {
			client.blocked_until = None;
			client.failure_count = 0;
			client.handshake_count = 0;
		}

		Ok(())
	}

	pub fn set_max_handshakes(&self, limit: u32) {
		*self.max_handshakes_per_minute.write() = limit;
	}

	pub fn set_max_failures(&self, limit: u32) {
		*self.max_failures_per_ip.write() = limit;
	}

	pub fn get_stats(&self) -> RateLimiterStats {
		self.stats.read().clone()
	}

	pub fn clear_all(&self) {
		self.client_attempts.write().clear();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_rate_limiting() {
		let limiter = RateLimiter::new(3, 5);

		assert!(limiter.check_request("192.168.1.1").unwrap());
		assert!(limiter.check_request("192.168.1.1").unwrap());
		assert!(limiter.check_request("192.168.1.1").unwrap());

		assert!(!limiter.check_request("192.168.1.1").unwrap());
	}

	#[test]
	fn test_failure_tracking() {
		let limiter = RateLimiter::new(10, 3);

		limiter.record_failure("10.0.0.1").ok();
		limiter.record_failure("10.0.0.1").ok();
		limiter.record_failure("10.0.0.1").ok();

		assert!(!limiter.check_request("10.0.0.1").unwrap());
	}

	#[test]
	fn test_success_reduces_failure_count() {
		let limiter = RateLimiter::new(10, 5);

		limiter.record_failure("10.0.0.1").ok();
		limiter.record_failure("10.0.0.1").ok();

		limiter.record_success("10.0.0.1").ok();
		limiter.record_success("10.0.0.1").ok();

		assert!(limiter.check_request("10.0.0.1").unwrap());
	}

	#[test]
	fn test_unblock_ip() {
		let limiter = RateLimiter::new(2, 10);

		limiter.check_request("10.0.0.2").unwrap();
		limiter.check_request("10.0.0.2").unwrap();
		assert!(!limiter.check_request("10.0.0.2").unwrap());

		limiter.unblock_ip("10.0.0.2").ok();
		assert!(limiter.check_request("10.0.0.2").unwrap());
	}

	#[test]
	fn test_multiple_ips() {
		let limiter = RateLimiter::new(2, 10);

		assert!(limiter.check_request("192.168.1.1").unwrap());
		assert!(limiter.check_request("192.168.1.2").unwrap());
		assert!(limiter.check_request("192.168.1.1").unwrap());
		assert!(limiter.check_request("192.168.1.2").unwrap());

		assert!(!limiter.check_request("192.168.1.1").unwrap());
		assert!(!limiter.check_request("192.168.1.2").unwrap());
	}

	#[test]
	fn test_stats() {
		let limiter = RateLimiter::new(10, 10);

		limiter.check_request("192.168.1.1").unwrap();
		limiter.check_request("192.168.1.1").unwrap();

		let stats = limiter.get_stats();
		assert_eq!(stats.total_attempts, 2);
	}
}
