extern crate alloc;

use anyhow::Result;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use parking_lot::RwLock;
use sha2::{Sha256, Digest};


#[derive(Clone)]
pub struct SessionBinding {
	bindings: Arc<RwLock<BTreeMap<String, SessionBindingInfo>>>,
	stats: Arc<RwLock<SessionBindingStats>>,
}

#[derive(Clone, Debug)]
struct SessionBindingInfo {
	session_id: String,
	channel_binding: Vec<u8>,
	certificate_fingerprint: Vec<u8>,
	client_ip: String,
	created_time: i64,
	last_verified: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionBindingStats {
	pub sessions_bound: u64,
	pub binding_verifications: u64,
	pub verification_failures: u64,
	pub migration_attempts: u64,
}

impl SessionBinding {
	pub fn new() -> Self {
		Self {
			bindings: Arc::new(RwLock::new(BTreeMap::new())),
			stats: Arc::new(RwLock::new(SessionBindingStats {
				sessions_bound: 0,
				binding_verifications: 0,
				verification_failures: 0,
				migration_attempts: 0,
			})),
		}
	}

	pub fn create_binding(
		&self,
		session_id: &str,
		certificate_data: &[u8],
		client_ip: &str,
	) -> Result<ChannelBinding> {
		let mut bindings = self.bindings.write();
		let mut stats = self.stats.write();

		let channel_binding = Self::compute_tls_unique(certificate_data);

		let cert_fingerprint = Self::compute_fingerprint(certificate_data);

		bindings.insert(
			session_id.to_string(),
			SessionBindingInfo {
				session_id: session_id.to_string(),
				channel_binding: channel_binding.clone(),
				certificate_fingerprint: cert_fingerprint.clone(),
				client_ip: client_ip.to_string(),
			created_time: crate::time_abstraction::kernel_time_secs_i64(),
			last_verified: crate::time_abstraction::kernel_time_secs_i64(),
			},
		);

		stats.sessions_bound = stats.sessions_bound.saturating_add(1);

		Ok(ChannelBinding {
			binding_data: channel_binding,
			fingerprint: cert_fingerprint,
		})
	}

	pub fn verify_binding(
		&self,
		session_id: &str,
		certificate_data: &[u8],
		client_ip: &str,
	) -> Result<bool> {
		let mut bindings = self.bindings.write();
		let mut stats = self.stats.write();

		stats.binding_verifications = stats.binding_verifications.saturating_add(1);

		let binding = bindings.get(session_id)
			.ok_or_else(|| anyhow::anyhow!("Session not bound: {}", session_id))?;

		if binding.client_ip != client_ip {
			stats.verification_failures = stats.verification_failures.saturating_add(1);
			return Err(anyhow::anyhow!("Client IP mismatch for session: {}", session_id));
		}

		let expected_fingerprint = Self::compute_fingerprint(certificate_data);
		if binding.certificate_fingerprint != expected_fingerprint {
			stats.verification_failures = stats.verification_failures.saturating_add(1);
			return Err(anyhow::anyhow!("Certificate fingerprint mismatch for session: {}", session_id));
		}

		let expected_channel_binding = Self::compute_tls_unique(certificate_data);
		if binding.channel_binding != expected_channel_binding {
			stats.verification_failures = stats.verification_failures.saturating_add(1);
			return Err(anyhow::anyhow!("Channel binding mismatch for session: {}", session_id));
		}

		if let Some(entry) = bindings.get_mut(session_id) {
			entry.last_verified = crate::time_abstraction::kernel_time_secs_i64();
		}

		Ok(true)
	}

	pub fn detect_session_migration(&self, session_id: &str, new_client_ip: &str) -> Result<bool> {
		let bindings = self.bindings.read();
		let mut stats = self.stats.write();

		stats.migration_attempts = stats.migration_attempts.saturating_add(1);

		let binding = bindings.get(session_id)
			.ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

		Ok(binding.client_ip != new_client_ip)
	}

	pub fn release_binding(&self, session_id: &str) -> Result<()> {
		self.bindings.write().remove(session_id)
			.ok_or_else(|| anyhow::anyhow!("Session not bound: {}", session_id))?;
		Ok(())
	}

	fn compute_tls_unique(certificate_data: &[u8]) -> Vec<u8> {
		let mut hasher = Sha256::new();
		hasher.update(certificate_data);
		hasher.finalize().to_vec()
	}

	fn compute_fingerprint(certificate_data: &[u8]) -> Vec<u8> {
		let mut hasher = Sha256::new();
		hasher.update(certificate_data);
		hasher.finalize().to_vec()
	}

	pub fn get_stats(&self) -> SessionBindingStats {
		self.stats.read().clone()
	}

	pub fn binding_count(&self) -> usize {
		self.bindings.read().len()
	}

	pub fn get_binding_context(&self, session_id: &str) -> Result<Option<BindingContext>> {
		let bindings = self.bindings.read();
		
		Ok(bindings.get(session_id).map(|b| BindingContext {
			session_id: b.session_id.clone(),
			client_ip: b.client_ip.clone(),
			created_time: b.created_time,
			last_verified: b.last_verified,
		}))
	}
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ChannelBinding {
	pub binding_data: Vec<u8>,
	pub fingerprint: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct BindingContext {
	pub session_id: String,
	pub client_ip: String,
	pub created_time: i64,
	pub last_verified: i64,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_binding_creation() {
		let binder = SessionBinding::new();
		let cert_data = b"certificate_data_sample";

		let binding = binder.create_binding("sess_1", cert_data, "192.168.1.1").unwrap();
		assert!(!binding.binding_data.is_empty());
		assert!(!binding.fingerprint.is_empty());

		let stats = binder.get_stats();
		assert_eq!(stats.sessions_bound, 1);
	}

	#[test]
	fn test_binding_verification() {
		let binder = SessionBinding::new();
		let cert_data = b"certificate_data_sample";

		binder.create_binding("sess_1", cert_data, "192.168.1.1").unwrap();

		let verified = binder.verify_binding("sess_1", cert_data, "192.168.1.1").unwrap();
		assert!(verified);

		let stats = binder.get_stats();
		assert_eq!(stats.binding_verifications, 1);
	}

	#[test]
	fn test_ip_mismatch_detection() {
		let binder = SessionBinding::new();
		let cert_data = b"certificate_data_sample";

		binder.create_binding("sess_1", cert_data, "192.168.1.1").unwrap();

		let result = binder.verify_binding("sess_1", cert_data, "192.168.1.2");
		assert!(result.is_err());

		let stats = binder.get_stats();
		assert_eq!(stats.verification_failures, 1);
	}

	#[test]
	fn test_session_migration_detection() {
		let binder = SessionBinding::new();
		let cert_data = b"certificate_data_sample";

		binder.create_binding("sess_1", cert_data, "192.168.1.1").unwrap();

		let migrated = binder.detect_session_migration("sess_1", "192.168.1.2").unwrap();
		assert!(migrated);

		let not_migrated = binder.detect_session_migration("sess_1", "192.168.1.1").unwrap();
		assert!(!not_migrated);
	}

	#[test]
	fn test_binding_release() {
		let binder = SessionBinding::new();
		let cert_data = b"certificate_data_sample";

		binder.create_binding("sess_1", cert_data, "192.168.1.1").unwrap();
		assert_eq!(binder.binding_count(), 1);

		binder.release_binding("sess_1").unwrap();
		assert_eq!(binder.binding_count(), 0);
	}

	#[test]
	fn test_binding_context() {
		let binder = SessionBinding::new();
		let cert_data = b"certificate_data_sample";

		binder.create_binding("sess_1", cert_data, "10.0.0.1").unwrap();

		let context = binder.get_binding_context("sess_1").unwrap();
		assert!(context.is_some());

		let ctx = context.unwrap();
		assert_eq!(ctx.client_ip, "10.0.0.1");
	}
}
