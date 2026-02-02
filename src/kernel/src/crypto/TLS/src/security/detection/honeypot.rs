extern crate alloc;

use anyhow::Result;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use parking_lot::Mutex;

use crate::api::token::TokenManager;

const BASE_BATCH: usize = 100;

struct Inner {
	honeypots: BTreeMap<String, String>,
	attempts: u64,
	next_id: usize,
	token_manager: Arc<TokenManager>,
}

#[derive(Clone)]
pub struct HoneypotSystem {
	inner: Arc<Mutex<Inner>>,
}

impl HoneypotSystem {
	pub fn new(token_manager: Arc<TokenManager>) -> Result<Self> {
		let mut map = BTreeMap::new();

		let initial_tokens = token_manager.generate_acces(BASE_BATCH);

		for (i, tok) in initial_tokens.into_iter().enumerate() {
			let id = format!("hp_{:08}", i + 1);
			map.insert(id, tok);
		}

		let mut honeypots = BTreeMap::new();
		for (k, v) in map {
			honeypots.insert(k, v);
		}

		Ok(Self {
			inner: Arc::new(Mutex::new(Inner {
				honeypots,
				attempts: 0,
				next_id: BASE_BATCH + 1,
				token_manager,
			})),
		})
	}

	pub(crate) fn signal_attempt(&self) {
		let mut inner = self.inner.lock();
		inner.attempts = inner.attempts.saturating_add(1);

		let target_total = (inner.attempts as usize) * BASE_BATCH;
		let existing = inner.honeypots.len();

		if target_total > existing {
			let to_create = target_total - existing;

			let new_tokens = inner.token_manager.generate_acces(to_create);

			for tok in new_tokens.into_iter() {
				let id = format!("hp_{:08}", inner.next_id);
				inner.next_id += 1;
				inner.honeypots.insert(id, tok);
			}
		}
	}

	pub fn shuffle_tokens(&self) {
		let inner = self.inner.lock();
		let keys: Vec<_> = inner.honeypots.keys().cloned().collect();
		#[cfg(feature = "real_tls")]
		{
			let mut _shuffled = keys.clone();
			for i in (1.._shuffled.len()).rev() {
				let mut buf = [0u8; 8];
				crate::rng::kernel_rng_fill(&mut buf);
				let j = (u64::from_le_bytes(buf) as usize) % (i + 1);
				_shuffled.swap(i, j);
			}
		}
		#[cfg(not(feature = "real_tls"))]
		{
			let _ = keys.len(); 
		}
	}

	pub fn add_honeypots_batch(&self, n: usize) {
		let mut inner = self.inner.lock();
		let new_tokens = inner.token_manager.generate_acces(n);
		for tok in new_tokens.into_iter() {
			let id = format!("hp_{:08}", inner.next_id);
			inner.next_id += 1;
			inner.honeypots.insert(id, tok);
		}
	}

    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        let inner = self.inner.lock();
        inner.honeypots.len()
    }
}

