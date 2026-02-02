extern crate alloc;
use alloc::string::ToString;

use anyhow::Result;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use crate::runtime::loops::primary_loop::PrimaryChannel;
use crate::api::token::{TokenManager, decrypt_with_master};
use crate::utils::constant_time_eq;
use parking_lot::Mutex;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct CallInHandler {
	channel: PrimaryChannel,
	tokens: Arc<TokenManager>,
	max_payload_size: usize,
	replay_cache: Arc<Mutex<Vec<(String, u64)>>>,
	nonce_map: Arc<Mutex<BTreeMap<String, u64>>>,
	request_count: AtomicU64,
	error_count: AtomicU64,
	circuit_breaker_open: AtomicBool,
	error_threshold: u64,
	rate_limit_map: Arc<Mutex<BTreeMap<String, (u64, u64)>>>,
	pinned_clients: Vec<String>,
	ticket_encryption_key: Vec<u8>,
	early_data_nonces: Arc<Mutex<Vec<Vec<u8>>>>,
	last_key_update: AtomicU64,
	key_update_interval_secs: u64,
	entropy_samples: Arc<Mutex<Vec<u8>>>,
	compression_detected: AtomicBool,
	handshake_start: AtomicU64,
}

impl CallInHandler {
	pub fn new(channel: PrimaryChannel, tokens: Arc<TokenManager>) -> Self {
		let master = tokens.master_key().to_string();
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		Self {
			channel,
			tokens,
			max_payload_size: 65536,
			replay_cache: Arc::new(Mutex::new(Vec::with_capacity(100))),
			nonce_map: Arc::new(Mutex::new(BTreeMap::new())),
			request_count: AtomicU64::new(0),
			error_count: AtomicU64::new(0),
			circuit_breaker_open: AtomicBool::new(false),
			error_threshold: 10,
			rate_limit_map: Arc::new(Mutex::new(BTreeMap::new())),
			pinned_clients: Vec::new(),
			ticket_encryption_key: master.as_bytes().to_vec(),
			early_data_nonces: Arc::new(Mutex::new(Vec::with_capacity(1000))),
			last_key_update: AtomicU64::new(now),
			key_update_interval_secs: 30,
			entropy_samples: Arc::new(Mutex::new(Vec::with_capacity(10000))),
			compression_detected: AtomicBool::new(false),
			handshake_start: AtomicU64::new(now),
		}
	}

	pub fn with_max_size(mut self, size: usize) -> Self {
		self.max_payload_size = size;
		self
	}

	fn validate_size(&self, payload: &[u8]) -> Result<()> {
		if payload.is_empty() || payload.len() > self.max_payload_size {
			return Err(anyhow::anyhow!("payload size violation: {} bytes (max: {})", payload.len(), self.max_payload_size));
		}
		Ok(())
	}

	fn check_rate_limit(&self, token: &str) -> Result<()> {
		let mut map = self.rate_limit_map.lock();
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		if let Some((count, timestamp)) = map.get_mut(token) {
			if now - *timestamp < 60 {
				if *count >= 100 {
					return Err(anyhow::anyhow!("rate limit exceeded: token throttled"));
				}
				*count += 1;
			} else {
				*count = 1;
				*timestamp = now;
			}
		} else {
			map.insert(token.to_string(), (1, now));
		}
		Ok(())
	}

	fn check_replay_and_nonce(&self, token: &str, nonce: u64) -> Result<()> {
		let mut cache = self.replay_cache.lock();
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		cache.retain(|(_, ts)| now - ts < 300);

		if cache.iter().any(|(t, _)| constant_time_eq(t.as_bytes(), token.as_bytes())) {
			return Err(anyhow::anyhow!("token replay detected (cache)"));
		}

		let mut nonces = self.nonce_map.lock();
		if let Some(&last_nonce) = nonces.get(token) {
			if nonce <= last_nonce {
				return Err(anyhow::anyhow!("nonce replay or replay attack (expected > {})", last_nonce));
			}
		}
		nonces.insert(token.to_string(), nonce);

		cache.push((token.to_string(), now));
		if cache.len() > 1000 {
			cache.remove(0);
		}
		Ok(())
	}

	fn verify_hmac(&self, payload: &[u8], hmac_tag: &[u8]) -> Result<()> {
		let master = self.tokens.master_key();
		let mut mac = HmacSha256::new_from_slice(master.as_bytes())
			.map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
		mac.update(payload);

		mac.verify_slice(hmac_tag)
			.map_err(|_| anyhow::anyhow!("HMAC verification failed: payload corrupted or tampered"))?;
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

	#[allow(dead_code)]
	fn decrypt_session_ticket(&self, ticket_data: &[u8]) -> Vec<u8> {
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

	fn validate_no_compression(&self, data: &[u8]) -> Result<()> {
		if data.len() > 4 && data[0] == 0x1f && data[1] == 0x8b {
			self.compression_detected.store(true, Ordering::Relaxed);
			return Err(anyhow::anyhow!("compression detected - CRIME attack prevention"));
		}
		Ok(())
	}

	fn check_handshake_timeout(&self) -> Result<()> {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		let start = self.handshake_start.load(Ordering::Relaxed);
		if now - start > 5 {
			return Err(anyhow::anyhow!("handshake timeout exceeded (>5 seconds)"));
		}
		Ok(())
	}

	pub fn handle_request(&self, token: &str, payload: &[u8], nonce: u64, hmac_tag: &[u8]) -> Result<()> {
		if self.circuit_breaker_open.load(Ordering::Relaxed) {
			return Err(anyhow::anyhow!("circuit breaker open: service temporarily unavailable"));
		}

		if let Err(e) = self.check_handshake_timeout() {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		let count = self.request_count.fetch_add(1, Ordering::Relaxed);

		if let Err(e) = self.validate_no_compression(payload) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if let Err(e) = self.validate_size(payload) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if let Err(e) = self.check_rate_limit(token) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if !self.tokens.validate(token) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(anyhow::anyhow!("invalid token (req #{})", count));
		}

		if let Err(e) = self.check_replay_and_nonce(token, nonce) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if let Err(e) = self.check_early_data_nonce(&nonce.to_le_bytes()) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if self.should_update_key() {
			self.last_key_update.store(
				crate::time_abstraction::kernel_time_secs_i64().max(0) as u64,
				Ordering::Relaxed
			);
		}

		if let Err(e) = self.verify_hmac(payload, hmac_tag) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		if !self.pinned_clients.is_empty() {
		}

		let master = self.tokens.master_key();
		let plain = match decrypt_with_master(master, payload) {
			Ok(p) => p,
			Err(e) => {
				self.error_count.fetch_add(1, Ordering::Relaxed);
				return Err(anyhow::anyhow!("decryption failed (req #{}): {}", count, e));
			}
		};

		if plain.is_empty() {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			return Err(anyhow::anyhow!("decrypted plaintext is empty"));
		}

		{
			let mut samples = self.entropy_samples.lock();
			if samples.len() < 10000 {
				samples.extend_from_slice(&nonce.to_le_bytes());
			}
		}

		if !self.channel.send("server", plain, token) {
			self.error_count.fetch_add(1, Ordering::Relaxed);
			
			let err_count = self.error_count.load(Ordering::Relaxed);
			if err_count >= self.error_threshold {
				self.circuit_breaker_open.store(true, Ordering::Relaxed);
				return Err(anyhow::anyhow!("circuit breaker triggered (error #{})", err_count));
			}
			return Err(anyhow::anyhow!("channel send failed (req #{})", count));
		}

		Ok(())
	}

	pub fn request_stats(&self) -> (u64, u64) {
		(
			self.request_count.load(Ordering::Relaxed),
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
