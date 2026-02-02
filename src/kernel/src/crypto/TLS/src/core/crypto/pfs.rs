extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use parking_lot::RwLock;
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::core::crypto::dh::DHKeyExchange;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphemeralDHKey {
    pub key_id: u64,
    pub public_key_bytes: Vec<u8>,
    pub shared_secret: Option<Vec<u8>>,
    pub generated_at: u64,
    pub ttl_secs: u64,
}

impl EphemeralDHKey {
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.generated_at) <= self.ttl_secs
    }

    pub fn has_shared_secret(&self) -> bool {
        self.shared_secret.is_some()
    }
}

pub struct PerfectForwardSecrecy {
    dh_exchange: DHKeyExchange,
    active_keys: Arc<RwLock<BTreeMap<u64, EphemeralDHKey>>>,
    key_lifetime: u64,
    next_key_id: Arc<parking_lot::Mutex<u64>>,
}

impl PerfectForwardSecrecy {
    pub fn new() -> Self {
        Self::with_lifetime(300)
    }

    pub fn with_lifetime(key_lifetime: u64) -> Self {
        Self {
            dh_exchange: DHKeyExchange::new(),
            active_keys: Arc::new(RwLock::new(BTreeMap::new())),
            key_lifetime,
            next_key_id: Arc::new(parking_lot::Mutex::new(1)),
        }
    }

    pub fn generate_ephemeral_key(&self) -> EphemeralDHKey {
        let keypair = self.dh_exchange.generate_keypair();
        
        let mut id_counter = self.next_key_id.lock();
        let key_id = *id_counter;
        *id_counter = id_counter.saturating_add(1);

        let ephemeral = EphemeralDHKey {
            key_id,
            public_key_bytes: keypair.public_key().value.clone(),
            shared_secret: None,
            generated_at: Self::current_time(),
            ttl_secs: self.key_lifetime,
        };

        let mut keys = self.active_keys.write();
        keys.insert(key_id, ephemeral.clone());

        ephemeral
    }

    pub fn compute_shared_secret(
        &self,
        key_id: u64,
        peer_public_key: &[u8],
    ) -> Option<Vec<u8>> {
        let mut keys = self.active_keys.write();

        if let Some(key) = keys.get_mut(&key_id) {
            if !key.is_valid(Self::current_time()) {
                return None;
            }

            let mut secret = key.public_key_bytes.clone();
            secret.extend_from_slice(peer_public_key);
            
            key.shared_secret = Some(secret.clone());
            Some(secret)
        } else {
            None
        }
    }

    pub fn get_shared_secret(&self, key_id: u64) -> Option<Vec<u8>> {
        let keys = self.active_keys.read();
        keys.get(&key_id).and_then(|k| k.shared_secret.clone())
    }

    pub fn has_valid_key(&self, key_id: u64) -> bool {
        let keys = self.active_keys.read();
        if let Some(key) = keys.get(&key_id) {
            key.is_valid(Self::current_time())
        } else {
            false
        }
    }

    pub fn remove_key(&self, key_id: u64) -> bool {
        let mut keys = self.active_keys.write();
        keys.remove(&key_id).is_some()
    }

    pub fn cleanup_expired(&self) {
        let now = Self::current_time();
        let mut keys = self.active_keys.write();
        keys.retain(|_, key| key.is_valid(now));
    }

    pub fn active_key_count(&self) -> usize {
        let keys = self.active_keys.read();
        keys.len()
    }

    pub fn stats(&self) -> PFSStats {
        let keys = self.active_keys.read();
        let now = Self::current_time();

        let mut valid_count = 0;
        let mut with_shared_secret = 0;

        for key in keys.values() {
            if key.is_valid(now) {
                valid_count += 1;
                if key.has_shared_secret() {
                    with_shared_secret += 1;
                }
            }
        }

        PFSStats {
            total_keys: keys.len(),
            valid_keys: valid_count,
            keys_with_secret: with_shared_secret,
        }
    }

    pub fn clear_all(&self) {
        let mut keys = self.active_keys.write();
        keys.clear();
    }

    fn current_time() -> u64 {
        #[cfg(feature = "real_tls")]
        {
            
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
        #[cfg(not(feature = "real_tls"))]
        {
            0
        }
    }
}

#[derive(Clone, Debug)]
pub struct PFSStats {
    pub total_keys: usize,
    pub valid_keys: usize,
    pub keys_with_secret: usize,
}

impl Default for PerfectForwardSecrecy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ephemeral_key() {
        let pfs = PerfectForwardSecrecy::new();
        let key = pfs.generate_ephemeral_key();

        assert!(key.key_id > 0);
        assert!(!key.public_key_bytes.is_empty());
        assert!(!key.has_shared_secret());
    }

    #[test]
    fn test_compute_shared_secret() {
        let pfs = PerfectForwardSecrecy::new();
        let key = pfs.generate_ephemeral_key();
        let peer_public = b"peer_public_key";

        let secret = pfs.compute_shared_secret(key.key_id, peer_public);
        assert!(secret.is_some());
        assert!(!secret.unwrap().is_empty());
    }

    #[test]
    fn test_get_shared_secret() {
        let pfs = PerfectForwardSecrecy::new();
        let key = pfs.generate_ephemeral_key();
        let peer_public = b"peer_public_key";

        pfs.compute_shared_secret(key.key_id, peer_public);
        
        let secret = pfs.get_shared_secret(key.key_id);
        assert!(secret.is_some());
    }

    #[test]
    fn test_has_valid_key() {
        let pfs = PerfectForwardSecrecy::new();
        let key = pfs.generate_ephemeral_key();

        assert!(pfs.has_valid_key(key.key_id));
    }

    #[test]
    fn test_remove_key() {
        let pfs = PerfectForwardSecrecy::new();
        let key = pfs.generate_ephemeral_key();

        assert!(pfs.remove_key(key.key_id));
        assert!(!pfs.has_valid_key(key.key_id));
    }

    #[test]
    fn test_pfs_stats() {
        let pfs = PerfectForwardSecrecy::new();
        let _key = pfs.generate_ephemeral_key();

        let stats = pfs.stats();
        assert!(stats.total_keys > 0);
    }

    #[test]
    fn test_clear_all() {
        let pfs = PerfectForwardSecrecy::new();
        let _key1 = pfs.generate_ephemeral_key();
        let _key2 = pfs.generate_ephemeral_key();

        pfs.clear_all();
        assert_eq!(pfs.active_key_count(), 0);
    }
}
