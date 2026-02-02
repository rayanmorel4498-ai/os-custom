extern crate alloc;
use alloc::string::ToString;

use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use parking_lot::Mutex;
use crate::api::token::{encrypt_with_master, decrypt_with_master};
use crate::utils::SecureBuffer;
use anyhow::Result;

pub struct CommonTlsHandler {
	pub early_data_nonces: Arc<Mutex<Vec<Vec<u8>>>>,
	pub key_update_interval_secs: u64,
	pub last_key_update: AtomicU64,
	pub rate_limit_map: Arc<Mutex<BTreeMap<String, (u64, u64)>>>,
	pub pinned_clients: Vec<String>,
	pub compression_detected: AtomicBool,
	pub post_handshake_challenges: Arc<Mutex<Vec<Vec<u8>>>>,
	pub ticket_encryption_key: Vec<u8>,
	pub handshake_timeout_secs: u64,
	pub handshake_start: AtomicU64,
	pub entropy_samples: Arc<Mutex<Vec<Vec<u8>>>>,
	pub ech_enabled: AtomicBool,
}

impl CommonTlsHandler {
	pub fn check_early_data_nonce(&self, nonce: &[u8]) -> Result<()> {
		let mut nonces = self.early_data_nonces.lock();
		
		for existing in nonces.iter() {
			if constant_time_eq(existing, nonce) {
				return Err(anyhow::anyhow!("early data nonce replay detected"));
			}
		}
		
		nonces.push(nonce.to_vec());
		
		if nonces.len() > 10000 {
			nonces.remove(0);
		}
		
		Ok(())
	}

	pub fn verify_mtls_client(&self, fingerprint: &str) -> Result<()> {
		if self.pinned_clients.is_empty() {
			return Ok(());
		}

		for pin in &self.pinned_clients {
			if constant_time_eq(pin.as_bytes(), fingerprint.as_bytes()) {
				return Ok(());
			}
		}

		Err(anyhow::anyhow!("client certificate not in trusted list"))
	}

	pub fn should_update_key(&self) -> bool {
		let last_update = self.last_key_update.load(Ordering::Relaxed);
		let now = crate::time_abstraction::kernel_time_secs_i64() as u64;
		now.saturating_sub(last_update) >= self.key_update_interval_secs
	}

	pub fn encrypt_session_ticket(&self, ticket_data: &[u8]) -> Vec<u8> {
		match encrypt_with_master(
			core::str::from_utf8(&self.ticket_encryption_key)
				.unwrap_or("default-master-key"),
			ticket_data
		) {
			Ok(encrypted) => encrypted,
			Err(_) => {
				let mut fallback = Vec::new();
				for (i, byte) in ticket_data.iter().enumerate() {
					fallback.push(byte ^ self.ticket_encryption_key[i % self.ticket_encryption_key.len()]);
				}
				fallback
			}
		}
	}

	pub fn decrypt_session_ticket(&self, ticket_data: &[u8]) -> Vec<u8> {
		match decrypt_with_master(
			core::str::from_utf8(&self.ticket_encryption_key)
				.unwrap_or("default-master-key"),
			ticket_data
		) {
			Ok(decrypted) => decrypted,
			Err(_) => {
				let mut fallback = Vec::new();
				for (i, byte) in ticket_data.iter().enumerate() {
					fallback.push(byte ^ self.ticket_encryption_key[i % self.ticket_encryption_key.len()]);
				}
				fallback
			}
		}
	}

	pub fn check_rate_limit(&self, key: &str, window_secs: u64, max_requests: u64) -> Result<()> {
		let now = crate::time_abstraction::kernel_time_secs_i64() as u64;
		let mut map = self.rate_limit_map.lock();

		match map.get_mut(key) {
			Some((timestamp, count)) => {
				if now - *timestamp > window_secs {
					*timestamp = now;
					*count = 1;
				} else if *count >= max_requests {
					return Err(anyhow::anyhow!("rate limit exceeded"));
				} else {
					*count += 1;
				}
			}
			None => {
				map.insert(key.to_string(), (now, 1));
			}
		}

		Ok(())
	}

	pub fn validate_no_compression(&self, data: &[u8]) -> Result<()> {
		if data.len() > 4 && data[0] == 0x1f && data[1] == 0x8b {
			self.compression_detected.store(true, Ordering::Relaxed);
			return Err(anyhow::anyhow!("compression detected - CRIME attack prevention"));
		}
		Ok(())
	}

	pub fn check_handshake_timeout(&self) -> Result<()> {
		let start = self.handshake_start.load(Ordering::Relaxed);
		if start == 0 {
			return Ok(());
		}

		let now = crate::time_abstraction::kernel_time_secs() as u64;
		if now - start > self.handshake_timeout_secs {
			return Err(anyhow::anyhow!("handshake timeout exceeded"));
		}

		Ok(())
	}

	pub fn collect_entropy_sample(&self, data: &[u8]) {
		let mut samples = self.entropy_samples.lock();
		if samples.len() < 10000 {
			samples.push(data.to_vec());
		}
	}

	pub fn add_post_handshake_challenge(&self, challenge: &[u8]) {
		let mut challenges = self.post_handshake_challenges.lock();
		challenges.push(challenge.to_vec());
	}

	pub fn verify_post_handshake_challenge(&self, response: &[u8]) -> Result<bool> {
		let mut challenges = self.post_handshake_challenges.lock();
		if let Some(expected) = challenges.first() {
			if constant_time_eq(expected, response) {
				challenges.remove(0);
				return Ok(true);
			}
		}
		Ok(false)
	}

	pub fn use_secure_buffer(&self, data: &[u8]) -> SecureBuffer {
		SecureBuffer::new(data.len())
	}
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut result = 0u8;
	for i in 0..a.len() {
		result |= a[i] ^ b[i];
	}
	result == 0
}
