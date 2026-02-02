extern crate alloc;
use alloc::string::String;

use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};
use alloc::sync::Arc;
use parking_lot::Mutex;

#[derive(Clone)]
pub struct SecretVec<T: Zeroize> {
	inner: Vec<T>,
}

impl<T: Zeroize> SecretVec<T> {
	pub fn new() -> Self {
		Self { inner: Vec::new() }
	}

	pub fn with_capacity(capacity: usize) -> Self {
		Self {
			inner: Vec::with_capacity(capacity),
		}
	}

	pub fn push(&mut self, item: T) {
		self.inner.push(item);
	}

	pub fn as_slice(&self) -> &[T] {
		&self.inner
	}

	pub fn as_mut_slice(&mut self) -> &mut [T] {
		&mut self.inner
	}

	pub fn len(&self) -> usize {
		self.inner.len()
	}

	pub fn is_empty(&self) -> bool {
		self.inner.is_empty()
	}

	pub fn clear(&mut self) {
		self.inner.clear();
	}
}

impl<T: Zeroize> Drop for SecretVec<T> {
	fn drop(&mut self) {
		self.inner.zeroize();
	}
}

impl<T: Zeroize + Clone> From<Vec<T>> for SecretVec<T> {
	fn from(v: Vec<T>) -> Self {
		Self { inner: v }
	}
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey {
	bytes: Vec<u8>,
}

impl SecretKey {
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.bytes
	}

	pub fn len(&self) -> usize {
		self.bytes.len()
	}

	pub fn is_empty(&self) -> bool {
		self.bytes.is_empty()
	}
}

pub type SecretBytes = SecretKey;

pub struct SecureBuffer {
	data: Arc<Mutex<Vec<u8>>>,
	locked: bool,
}

impl SecureBuffer {
	pub fn new(capacity: usize) -> Self {
		Self {
			data: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
			locked: false,
		}
	}

	pub fn lock_memory(&mut self) -> Result<(), &'static str> {
		#[cfg(feature = "real_tls")]
		{
			unsafe {
				let data = self.data.lock();
				let ptr = data.as_ptr() as *mut libc::c_void;
				let len = data.len();
				if ptr.is_null() || len == 0 {
					return Ok(());
				}
				if libc::mlock(ptr, len) == 0 {
					self.locked = true;
					Ok(())
				} else {
					Err("mlockall failed")
				}
			}
		}
		#[cfg(not(feature = "real_tls"))]
		{
			self.locked = true;
			Ok(())
		}
	}

	pub fn is_locked(&self) -> bool {
		self.locked
	}

	pub fn push_byte(&self, byte: u8) {
		let mut data = self.data.lock();
		data.push(byte);
	}

	pub fn as_slice(&self) -> Vec<u8> {
		let data = self.data.lock();
		data.clone()
	}

	pub fn clear(&self) {
		let mut data = self.data.lock();
		data.zeroize();
		data.clear();
	}
}

impl Drop for SecureBuffer {
	fn drop(&mut self) {
		let mut data = self.data.lock();
		data.zeroize();
	}
}

pub struct TlsSessionTicket {
	ticket_data: Vec<u8>,
	issued_at: u64,
	lifetime_secs: u64,
}

impl TlsSessionTicket {
	pub fn new(ticket_data: Vec<u8>, lifetime_secs: u64) -> Self {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		Self {
			ticket_data,
			issued_at: now,
			lifetime_secs,
		}
	}

	pub fn is_valid(&self) -> bool {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		now - self.issued_at < self.lifetime_secs
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.ticket_data
	}

	pub fn age_secs(&self) -> u64 {
		let now = crate::time_abstraction::kernel_time_secs_i64().max(0) as u64;

		now - self.issued_at
	}
}

impl Drop for TlsSessionTicket {
	fn drop(&mut self) {
		self.ticket_data.zeroize();
	}
}

pub struct ClientCertificateFingerprint {
	fingerprint: String,
	algorithm: String,
	trusted: bool,
}

impl ClientCertificateFingerprint {
	pub fn new(fingerprint: String, algorithm: String) -> Self {
		Self {
			fingerprint,
			algorithm,
			trusted: false,
		}
	}

	pub fn mark_trusted(&mut self) {
		self.trusted = true;
	}

	pub fn is_trusted(&self) -> bool {
		self.trusted
	}

	pub fn matches(&self, other: &str) -> bool {
		self.fingerprint == other
	}

	pub fn fingerprint(&self) -> &str {
		&self.fingerprint
	}

	pub fn algorithm(&self) -> &str {
		&self.algorithm
	}
}

pub struct EntropyPool {
	samples: Arc<Mutex<Vec<u8>>>,
	max_samples: usize,
}

impl EntropyPool {
	pub fn new(max_samples: usize) -> Self {
		Self {
			samples: Arc::new(Mutex::new(Vec::with_capacity(max_samples))),
			max_samples,
		}
	}

	pub fn add_sample(&self, sample: &[u8]) {
		let mut samples = self.samples.lock();
		if samples.len() < self.max_samples {
			samples.extend_from_slice(sample);
		}
	}

	pub fn entropy_quality(&self) -> f64 {
		let samples = self.samples.lock();
		if samples.is_empty() {
			return 0.0;
		}

		let mut freq = [0u32; 256];
		for &byte in samples.iter() {
			freq[byte as usize] += 1;
		}

		let unique = freq.iter().filter(|&&f| f > 0).count();
		(unique as f64 / 256.0) * 100.0
	}

	pub fn clear(&self) {
		let mut samples = self.samples.lock();
		samples.zeroize();
		samples.clear();
	}
}
