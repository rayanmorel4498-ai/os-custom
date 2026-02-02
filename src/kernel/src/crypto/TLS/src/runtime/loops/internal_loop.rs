extern crate alloc;
use alloc::string::String;

use anyhow::Result;
use alloc::sync::Arc;
use alloc::vec::Vec;
use parking_lot::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::api::token::TokenManager;
use crate::runtime::loops::primary_loop::PrimaryChannel;
use crate::runtime::loops::sandbox::{SandboxLimits, SandboxManager, SandboxPolicy};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopType {
	CallIn,
	CallOut,
	MessageIn,
	MessageOut,
	KeyRotation,
	EntropyAudit,
	CompressionCheck,
}

#[derive(Clone, Debug)]
pub struct LoopStatus {
	pub loop_type: LoopType,
	pub is_running: bool,
	pub message_count: u64,
	pub error_count: u64,
	pub last_update: u64,
	pub key_last_rotated: u64,
	pub sandbox_id: u64,
}

pub struct InternalLoopController {
	loops: Arc<Mutex<Vec<LoopStatus>>>,
	master_shutdown: AtomicBool,
	loop_counter: AtomicU64,

	pub sync_barrier: Arc<Mutex<u32>>,
	last_global_sync: AtomicU64,

	pinned_clients: Arc<Mutex<Vec<String>>>,

	ticket_master_key: Arc<Mutex<Vec<u8>>>,

	global_early_data_nonces: Arc<Mutex<Vec<Vec<u8>>>>,

	ech_enabled: AtomicBool,

	key_update_interval_secs: u64,
	last_global_key_update: AtomicU64,

	memory_locked: AtomicBool,

	global_entropy_samples: Arc<Mutex<Vec<u8>>>,

	post_handshake_challenges: Arc<Mutex<Vec<Vec<u8>>>>,

	compression_detected: AtomicBool,

	handshake_timeout_secs: u64,
	global_handshake_start: AtomicU64,

	tokens: Arc<TokenManager>,
	pub channel: PrimaryChannel,
	sandbox_manager: SandboxManager,
}

impl InternalLoopController {
	pub fn new(tokens: Arc<TokenManager>, channel: PrimaryChannel) -> Self {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		let master_key = tokens.master_key();
		Self {
			loops: Arc::new(Mutex::new(Vec::new())),
			master_shutdown: AtomicBool::new(false),
			loop_counter: AtomicU64::new(0),
			sync_barrier: Arc::new(Mutex::new(0)),
			last_global_sync: AtomicU64::new(now),
			pinned_clients: Arc::new(Mutex::new(Vec::new())),
			ticket_master_key: Arc::new(Mutex::new(master_key.as_bytes().to_vec())),
			global_early_data_nonces: Arc::new(Mutex::new(Vec::with_capacity(10000))),
			ech_enabled: AtomicBool::new(false),
			key_update_interval_secs: 30,
			last_global_key_update: AtomicU64::new(now),
			memory_locked: AtomicBool::new(false),
			global_entropy_samples: Arc::new(Mutex::new(Vec::with_capacity(100000))),
			post_handshake_challenges: Arc::new(Mutex::new(Vec::new())),
			compression_detected: AtomicBool::new(false),
			handshake_timeout_secs: 5,
			global_handshake_start: AtomicU64::new(now),
			tokens,
			channel,
			sandbox_manager: SandboxManager::new(),
		}
	}

	fn sandbox_policy_for(loop_type: LoopType) -> SandboxPolicy {
		match loop_type {
			LoopType::CallIn
			| LoopType::CallOut
			| LoopType::MessageIn
			| LoopType::MessageOut => SandboxPolicy::for_network_service(),
			LoopType::KeyRotation
			| LoopType::EntropyAudit
			| LoopType::CompressionCheck => SandboxPolicy::for_os(),
		}
	}

	fn sandbox_limits_for(loop_type: LoopType) -> SandboxLimits {
		match loop_type {
			LoopType::CallIn
			| LoopType::CallOut
			| LoopType::MessageIn
			| LoopType::MessageOut => SandboxLimits::new_moderate(),
			LoopType::KeyRotation
			| LoopType::EntropyAudit
			| LoopType::CompressionCheck => SandboxLimits::new_restricted(),
		}
	}

	fn component_for(loop_type: LoopType) -> crate::api::component_token::ComponentType {
		use crate::api::component_token::ComponentType;
		match loop_type {
			LoopType::CallIn | LoopType::CallOut => ComponentType::Calling,
			LoopType::MessageIn | LoopType::MessageOut => ComponentType::Messaging,
			LoopType::KeyRotation | LoopType::EntropyAudit => ComponentType::SecurityDriver,
			LoopType::CompressionCheck => ComponentType::Kernel,
		}
	}

	pub fn register_loop(&self, loop_type: LoopType) -> Result<()> {
		if self.master_shutdown.load(Ordering::Relaxed) {
			return Err(anyhow::anyhow!("internal loop controller is shutting down"));
		}

		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		let policy = Self::sandbox_policy_for(loop_type);
		let limits = Self::sandbox_limits_for(loop_type);
		let component = Self::component_for(loop_type);
		let sandbox = self.sandbox_manager.create_sandbox(component, policy, limits);

		let status = LoopStatus {
			loop_type,
			is_running: true,
			message_count: 0,
			error_count: 0,
			last_update: now,
			key_last_rotated: now,
			sandbox_id: sandbox.sandbox_id,
		};

		let mut loops = self.loops.lock();
		loops.push(status);
		self.loop_counter.fetch_add(1, Ordering::Relaxed);
		Ok(())
	}

	pub fn should_rotate_global_keys(&self) -> bool {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		let last = self.last_global_key_update.load(Ordering::Relaxed);
		now - last >= self.key_update_interval_secs
	}

	pub fn rotate_global_keys(&self) -> Result<()> {
		let new_key = self.tokens.master_key();
		let mut master = self.ticket_master_key.lock();
		master.clear();
		master.extend_from_slice(new_key.as_bytes());
		
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		self.last_global_key_update.store(now, Ordering::Relaxed);
		Ok(())
	}

	pub fn validate_early_data_nonce(&self, nonce: &[u8]) -> Result<()> {
		let mut nonces = self.global_early_data_nonces.lock();
		
		if nonces.iter().any(|n| n == nonce) {
			return Err(anyhow::anyhow!("early data nonce replay detected (global)"));
		}
		
		nonces.push(nonce.to_vec());
		if nonces.len() > 10000 {
			nonces.remove(0);
		}
		Ok(())
	}

	pub fn add_pinned_client(&self, fingerprint: String) -> Result<()> {
		let mut clients = self.pinned_clients.lock();
		if !clients.contains(&fingerprint) {
			clients.push(fingerprint);
		}
		Ok(())
	}

	pub fn verify_pinned_client(&self, fingerprint: &str) -> Result<()> {
		let clients = self.pinned_clients.lock();
		if clients.is_empty() {
			return Ok(());
		}
		
		if clients.iter().any(|c| c == fingerprint) {
			Ok(())
		} else {
			Err(anyhow::anyhow!("client not in pinned list (global mTLS)"))
		}
	}

	pub fn add_entropy_sample(&self, sample: &[u8]) -> Result<()> {
		let mut samples = self.global_entropy_samples.lock();
		if samples.len() < 100000 {
			samples.extend_from_slice(sample);
		}
		Ok(())
	}

	pub fn audit_entropy_quality(&self) -> Result<(u64, f64)> {
		let samples = self.global_entropy_samples.lock();
		let count = samples.len() as u64;
		
		let mut freq = [0u32; 256];
		for &byte in samples.iter() {
			freq[byte as usize] += 1;
		}
		
		let unique_bytes = freq.iter().filter(|&&f| f > 0).count();
		let entropy = (unique_bytes as f64 / 256.0) * 100.0;
		
		Ok((count, entropy))
	}

	pub fn start_handshake(&self) -> Result<()> {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		self.global_handshake_start.store(now, Ordering::Relaxed);
		Ok(())
	}

	pub fn check_handshake_timeout(&self) -> Result<()> {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		let start = self.global_handshake_start.load(Ordering::Relaxed);
		
		if now - start > self.handshake_timeout_secs {
			return Err(anyhow::anyhow!("global handshake timeout exceeded (>{} seconds)", self.handshake_timeout_secs));
		}
		Ok(())
	}

	pub fn detect_compression(&self, data: &[u8]) -> Result<()> {
		if data.len() > 4 && data[0] == 0x1f && data[1] == 0x8b {
			self.compression_detected.store(true, Ordering::Relaxed);
			return Err(anyhow::anyhow!("compression detected in global scope - CRIME prevention"));
		}
		Ok(())
	}

	pub fn add_post_handshake_challenge(&self, challenge: Vec<u8>) -> Result<()> {
		let mut challenges = self.post_handshake_challenges.lock();
		challenges.push(challenge);
		if challenges.len() > 1000 {
			challenges.remove(0);
		}
		Ok(())
	}

	pub fn verify_post_handshake_response(&self, response: &[u8]) -> Result<()> {
		let mut challenges = self.post_handshake_challenges.lock();
		
		if challenges.is_empty() {
			return Err(anyhow::anyhow!("no post-handshake challenge pending"));
		}
		
		if response == &challenges[0] {
			challenges.remove(0);
			Ok(())
		} else {
			Err(anyhow::anyhow!("post-handshake response verification failed"))
		}
	}

	pub fn enable_ech(&self) -> Result<()> {
		self.ech_enabled.store(true, Ordering::Relaxed);
		Ok(())
	}

	pub fn is_ech_enabled(&self) -> bool {
		self.ech_enabled.load(Ordering::Relaxed)
	}

	pub fn lock_memory(&self) -> Result<()> {
		self.memory_locked.store(true, Ordering::Relaxed);
		Ok(())
	}

	pub fn is_memory_locked(&self) -> bool {
		self.memory_locked.load(Ordering::Relaxed)
	}

	pub fn sync_all_loops(&self) -> Result<()> {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;
		self.last_global_sync.store(now, Ordering::Relaxed);

		self.validate_loop_sandboxes()?;

		if self.should_rotate_global_keys() {
			self.rotate_global_keys()?;
		}

		self.check_handshake_timeout()?;

		Ok(())
	}

	fn validate_loop_sandboxes(&self) -> Result<()> {
		let loops = self.loops.lock();
		for status in loops.iter() {
			let Some(sandbox) = self.sandbox_manager.get_sandbox(status.sandbox_id) else {
				return Err(anyhow::anyhow!("sandbox missing for loop"));
			};
			if !sandbox.is_active() {
				return Err(anyhow::anyhow!("sandbox inactive for loop"));
			}
		}
		Ok(())
	}

	pub fn get_loop_statuses(&self) -> Vec<LoopStatus> {
		let loops = self.loops.lock();
		loops.clone()
	}

	pub fn shutdown(&self) -> Result<()> {
		self.master_shutdown.store(true, Ordering::Relaxed);
		let mut loops = self.loops.lock();
		for loop_status in loops.iter_mut() {
			loop_status.is_running = false;
		}
		Ok(())
	}

	pub fn is_shutting_down(&self) -> bool {
		self.master_shutdown.load(Ordering::Relaxed)
	}
}

