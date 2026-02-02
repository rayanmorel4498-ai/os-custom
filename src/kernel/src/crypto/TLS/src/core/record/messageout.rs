extern crate alloc;
use alloc::string::ToString;

use anyhow::Result;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use crate::runtime::loops::primary_loop::PrimaryChannel;
use alloc::sync::Arc;
use crate::api::token::{TokenManager, encrypt_with_master};
use sha2::{Digest, Sha256};
use crate::utils::hex_encode;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use zeroize::Zeroize;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;

type HmacSha256 = Hmac<Sha256>;

pub struct MessageOut {
	channel: PrimaryChannel,
	max_len: usize,
	tokens: Arc<TokenManager>,
	sent_count: AtomicU64,
	error_count: AtomicU64,
	circuit_breaker_open: AtomicBool,
	error_threshold: u64,
	sequence_counter: AtomicU64,
	rate_limit_map: Arc<Mutex<BTreeMap<String, (u64, u64)>>>,
	pinned_clients: Vec<String>,
	ticket_encryption_key: Vec<u8>,
	early_data_nonces: Arc<Mutex<Vec<Vec<u8>>>>,
	last_key_update: AtomicU64,
	key_update_interval_secs: u64,
	entropy_samples: Arc<Mutex<Vec<u8>>>,
	compression_detected: AtomicBool,
}

impl MessageOut {
	pub fn new(channel: PrimaryChannel, max_len: usize, tokens: Arc<TokenManager>) -> Self {
		let master = tokens.master_key().to_string();
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		Self {
			channel,
			max_len,
			tokens,
			sent_count: AtomicU64::new(0),
			error_count: AtomicU64::new(0),
			circuit_breaker_open: AtomicBool::new(false),
			error_threshold: 10,
			sequence_counter: AtomicU64::new(1),
			rate_limit_map: Arc::new(Mutex::new(BTreeMap::new())),
			pinned_clients: Vec::new(),
			ticket_encryption_key: master.as_bytes().to_vec(),
			early_data_nonces: Arc::new(Mutex::new(Vec::with_capacity(1000))),
			last_key_update: AtomicU64::new(now),
			key_update_interval_secs: 30,
			entropy_samples: Arc::new(Mutex::new(Vec::with_capacity(10000))),
			compression_detected: AtomicBool::new(false),
		}
	}

	fn compute_fingerprint(&self, data: &[u8]) -> String {
		let mut hasher = Sha256::new();
		hasher.update(data);
		hex_encode(&hasher.finalize())
	}

	fn compute_hmac(&self, payload: &[u8]) -> Result<Vec<u8>> {
		let master = self.tokens.master_key();
		let mut mac = HmacSha256::new_from_slice(master.as_bytes())
			.map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
		mac.update(payload);
		Ok(mac.finalize().into_bytes().to_vec())
	}

	fn generate_sequence(&self) -> u64 {
		self.sequence_counter.fetch_add(1, Ordering::Relaxed)
	}

	fn check_rate_limit(&self, dest: &str) -> Result<()> {
		let mut map = self.rate_limit_map.lock();
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		if let Some((count, timestamp)) = map.get_mut(dest) {
			if now - *timestamp < 60 {
				if *count >= 100 {
					return Err(anyhow::anyhow!("rate limit exceeded to destination: {}", dest));
				}
				*count += 1;
			} else {
				*count = 1;
				*timestamp = now;
			}
		} else {
			map.insert(dest.to_string(), (1, now));
		}
		Ok(())
	}

	fn should_update_key(&self) -> bool {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		let last = self.last_key_update.load(Ordering::Relaxed);
		now - last >= self.key_update_interval_secs
	}

	fn check_early_data_nonce(&self, nonce: &[u8]) -> Result<()> {
		let mut nonces = self.early_data_nonces.lock();
		
		if nonces.iter().any(|n| n == nonce) {
			return Err(anyhow::anyhow!("early data nonce replay detected"));
		}
		
		nonces.push(nonce.to_vec());
		if nonces.len() > 1000 {
			nonces.remove(0);
		}
		Ok(())
	}

	#[allow(dead_code)]
	fn verify_mtls_client(&self, client_cert_fp: &str) -> Result<()> {
		if self.pinned_clients.is_empty() {
			return Ok(());
		}

		if self.pinned_clients.iter().any(|fp| fp == client_cert_fp) {
			Ok(())
		} else {
			Err(anyhow::anyhow!("client certificate not in trusted list"))
		}
	}

	fn encrypt_session_ticket(&self, ticket_data: &[u8]) -> Vec<u8> {
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

	fn validate_no_compression(&self, data: &[u8]) -> Result<()> {
		if data.len() > 4 && data[0] == 0x1f && data[1] == 0x8b {
			self.compression_detected.store(true, Ordering::Relaxed);
			return Err(anyhow::anyhow!("compression detected - CRIME attack prevention"));
		}
		Ok(())
	}

	pub fn send(&self, data: Vec<u8>, dest: &str) -> Result<()> {
		if self.circuit_breaker_open.load(Ordering::Relaxed) {
			return Err(anyhow::anyhow!("circuit breaker open: service temporarily unavailable"));
		}

		let count = self.sent_count.fetch_add(1, Ordering::Relaxed);

		if data.is_empty() || data.len() > self.max_len {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(anyhow::anyhow!("message size invalid: {} (msg #{})", data.len(), count));
		}

		if let Err(e) = self.validate_no_compression(&data) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		let fingerprint = self.compute_fingerprint(&data);

		if let Err(e) = self.check_rate_limit(dest) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if self.should_update_key() {
			self.last_key_update.store(
				crate::time_abstraction::kernel_time_secs_i64().max(0) as u64,
				Ordering::Relaxed
			);
		}

		let sequence = self.generate_sequence();

		if let Err(e) = self.check_early_data_nonce(&sequence.to_le_bytes()) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		let hmac_tag = match self.compute_hmac(&data) {
			Ok(tag) => tag,
			Err(e) => {
				self.error_count.fetch_add(1, Ordering::Relaxed);
				return Err(e);
			}
		};

		let mut combined = sequence.to_le_bytes().to_vec();
		combined.extend_from_slice(&hmac_tag);
		combined.extend_from_slice(&data);

		if !self.pinned_clients.is_empty() {
		}

		let _session_ticket = self.encrypt_session_ticket(&combined);

		let master = self.tokens.master_key();
		let ciphertext = match encrypt_with_master(master, &combined) {
			Ok(ct) => ct,
			Err(e) => {
				self.error_count.fetch_add(1, Ordering::Relaxed);
				let mut combined_zero = combined;
				combined_zero.zeroize();
				return Err(anyhow::anyhow!("encryption failed (msg #{}, fp: {}): {}", count, &fingerprint[..16], e));
			}
		};

		if ciphertext.is_empty() {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(anyhow::anyhow!("ciphertext empty (msg #{})", count));
		}

		{
			let mut samples = self.entropy_samples.lock();
			if samples.len() < 10000 {
				samples.extend_from_slice(&sequence.to_le_bytes());
			}
		}

		let mut combined_zero = combined;
		combined_zero.zeroize();

		if self.channel.send(dest, ciphertext, "") {
			Ok(())
		} else {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			
			let err_count = self.error_count.load(Ordering::Relaxed);
			if err_count >= self.error_threshold {
				self.circuit_breaker_open.store(true, Ordering::Relaxed);
				return Err(anyhow::anyhow!("circuit breaker triggered (error #{})", err_count));
			}
			Err(anyhow::anyhow!("channel send failed (msg #{})", count))
		}
	}

	pub fn sent_stats(&self) -> (u64, u64) {
		(
			self.sent_count.load(Ordering::Relaxed),
			self.error_count.load(Ordering::Relaxed),
		)
	}

	pub fn reset_circuit_breaker(&self) {
		self.circuit_breaker_open.store(false, Ordering::Relaxed);
		self.error_count.store(0, Ordering::Relaxed);
	}

	pub fn is_circuit_open(&self) -> bool {
		self.circuit_breaker_open.load(Ordering::Relaxed)
	}
}

