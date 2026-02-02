extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Debug)]
pub struct PreSharedKey {
    pub identity: Vec<u8>,
    pub key: Vec<u8>,
    pub obfuscated_ticket_age: u32,
    pub added_time: u64,
    pub ttl_secs: u64,
    pub resumption_count: u32,
}

impl PreSharedKey {
    pub fn is_valid(&self, current_time: u64) -> bool {
        current_time < (self.added_time + self.ttl_secs)
    }

    pub fn age_secs(&self, current_time: u64) -> u64 {
        if current_time > self.added_time {
            current_time - self.added_time
        } else {
            0
        }
    }
}

#[derive(Clone)]
pub struct PSKManager {
    psks: Arc<RwLock<alloc::collections::BTreeMap<Vec<u8>, PreSharedKey>>>,
    
    max_psks: usize,
    
    default_ttl_secs: u64,
    
    psks_created: Arc<AtomicU64>,
    psks_used: Arc<AtomicU64>,
    psks_expired: Arc<AtomicU64>,
}

impl PSKManager {
    pub fn new(max_psks: usize, default_ttl_secs: u64) -> Self {
        Self {
            psks: Arc::new(RwLock::new(alloc::collections::BTreeMap::new())),
            max_psks,
            default_ttl_secs,
            psks_created: Arc::new(AtomicU64::new(0)),
            psks_used: Arc::new(AtomicU64::new(0)),
            psks_expired: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn store_psk(
        &self,
        identity: Vec<u8>,
        key: Vec<u8>,
        current_time: u64,
    ) -> bool {
        let psk = PreSharedKey {
            identity: identity.clone(),
            key,
            obfuscated_ticket_age: 0,
            added_time: current_time,
            ttl_secs: self.default_ttl_secs,
            resumption_count: 0,
        };

        let mut psks = self.psks.write();

        if psks.len() >= self.max_psks && !psks.contains_key(&identity) {
            if let Some(oldest_key) = psks.keys().next().cloned() {
                psks.remove(&oldest_key);
                self.psks_expired.fetch_add(1, Ordering::SeqCst);
            }
        }

        psks.insert(identity, psk);
        self.psks_created.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn get_psk(&self, identity: &[u8], current_time: u64) -> Option<PreSharedKey> {
        let mut psks = self.psks.write();

        match psks.get(identity) {
            Some(psk) if psk.is_valid(current_time) => {
                let mut psk = psk.clone();
                psk.resumption_count += 1;
                psks.insert(psk.identity.clone(), psk.clone());
                self.psks_used.fetch_add(1, Ordering::SeqCst);
                Some(psk)
            }
            Some(_) => {
                psks.remove(identity);
                self.psks_expired.fetch_add(1, Ordering::SeqCst);
                None
            }
            None => None,
        }
    }

    pub fn has_psk(&self, identity: &[u8], current_time: u64) -> bool {
        let psks = self.psks.read();
        psks.get(identity)
            .map(|psk| psk.is_valid(current_time))
            .unwrap_or(false)
    }

    pub fn delete_psk(&self, identity: &[u8]) -> bool {
        self.psks.write().remove(identity).is_some()
    }

    pub fn cleanup_expired(&self, current_time: u64) -> u64 {
        let mut psks = self.psks.write();
        let initial_count = psks.len() as u64;

        psks.retain(|_, psk| psk.is_valid(current_time));

        let removed_count = initial_count - psks.len() as u64;
        self.psks_expired.fetch_add(removed_count, Ordering::SeqCst);
        removed_count
    }

    pub fn active_psks(&self) -> usize {
        self.psks.read().len()
    }

    pub fn stats(&self) -> PSKManagerStats {
        PSKManagerStats {
            psks_created: self.psks_created.load(Ordering::SeqCst),
            psks_used: self.psks_used.load(Ordering::SeqCst),
            psks_expired: self.psks_expired.load(Ordering::SeqCst),
            active_psks: self.active_psks() as u64,
            max_psks: self.max_psks as u64,
            default_ttl_secs: self.default_ttl_secs,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PSKManagerStats {
    pub psks_created: u64,
    pub psks_used: u64,
    pub psks_expired: u64,
    pub active_psks: u64,
    pub max_psks: u64,
    pub default_ttl_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_manager_creation() {
        let manager = PSKManager::new(100, 3600);
        assert_eq!(manager.active_psks(), 0);
    }

    #[test]
    fn test_psk_store_and_retrieve() {
        let manager = PSKManager::new(100, 3600);
        let identity = b"client1".to_vec();
        let key = b"secret_key_material".to_vec();

        manager.store_psk(identity.clone(), key.clone(), 0);
        assert_eq!(manager.active_psks(), 1);

        let retrieved = manager.get_psk(&identity, 100);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_psk_expiration() {
        let manager = PSKManager::new(100, 100);
        let identity = b"client2".to_vec();
        let key = b"key".to_vec();

        manager.store_psk(identity.clone(), key, 0);
        
        assert!(manager.has_psk(&identity, 50));
        
        assert!(!manager.has_psk(&identity, 150));
    }

    #[test]
    fn test_psk_resumption_count() {
        let manager = PSKManager::new(100, 3600);
        let identity = b"client3".to_vec();
        let key = b"key".to_vec();

        manager.store_psk(identity.clone(), key, 0);

        let psk1 = manager.get_psk(&identity, 100).unwrap();
        assert_eq!(psk1.resumption_count, 1);

        let psk2 = manager.get_psk(&identity, 200).unwrap();
        assert_eq!(psk2.resumption_count, 2);
    }

    #[test]
    fn test_psk_cleanup() {
        let manager = PSKManager::new(100, 100);
        manager.store_psk(b"id1".to_vec(), b"key1".to_vec(), 0);
        manager.store_psk(b"id2".to_vec(), b"key2".to_vec(), 50);

        let removed = manager.cleanup_expired(150);
        assert_eq!(removed, 2);
        assert_eq!(manager.active_psks(), 0);
    }

    #[test]
    fn test_psk_stats() {
        let manager = PSKManager::new(100, 3600);
        manager.store_psk(b"id1".to_vec(), b"key1".to_vec(), 0);
        
        let stats = manager.stats();
        assert_eq!(stats.psks_created, 1);
        assert_eq!(stats.active_psks, 1);
        assert_eq!(stats.max_psks, 100);
    }
}
