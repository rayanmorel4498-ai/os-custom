extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use alloc::sync::Arc;

#[derive(Clone, Debug)]
pub struct EarlyDataInfo {
    pub identity: Vec<u8>,
    pub data: Vec<u8>,
    pub max_early_data_size: u32,
    pub is_valid: bool,
    pub created_at: u64,
}

pub struct EarlyDataManager {
    early_data: Arc<RwLock<BTreeMap<Vec<u8>, EarlyDataInfo>>>,
    max_early_size: u32,
    ttl_secs: u64,
    accepted: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
}

impl EarlyDataManager {
    pub fn new(max_early_size: u32, ttl_secs: u64) -> Self {
        Self {
            early_data: Arc::new(RwLock::new(BTreeMap::new())),
            max_early_size,
            ttl_secs,
            accepted: Arc::new(AtomicU64::new(0)),
            rejected: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn store_early_data(&self, identity: Vec<u8>, data: Vec<u8>) -> bool {
        if data.len() > self.max_early_size as usize {
            self.rejected.fetch_add(1, Ordering::SeqCst);
            return false;
        }

        let info = EarlyDataInfo {
            identity: identity.clone(),
            data,
            max_early_data_size: self.max_early_size,
            is_valid: true,
            created_at: Self::current_time(),
        };

        let mut store = self.early_data.write();
        store.insert(identity, info);
        self.accepted.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn get_early_data(&self, identity: &[u8]) -> Option<EarlyDataInfo> {
        let store = self.early_data.read();
        let info = store.get(identity)?;

        let now = Self::current_time();
        if now.saturating_sub(info.created_at) > self.ttl_secs {
            return None;
        }

        Some(info.clone())
    }

    pub fn accept_early_data(&self, identity: &[u8]) -> bool {
        let mut store = self.early_data.write();
        if let Some(info) = store.get_mut(identity) {
            info.is_valid = false;
            return true;
        }
        false
    }

    pub fn remove_early_data(&self, identity: &[u8]) -> bool {
        let mut store = self.early_data.write();
        store.remove(identity).is_some()
    }

    pub fn has_early_data(&self, identity: &[u8]) -> bool {
        let store = self.early_data.read();
        if let Some(info) = store.get(identity) {
            let now = Self::current_time();
            return info.is_valid && now.saturating_sub(info.created_at) <= self.ttl_secs;
        }
        false
    }

    pub fn stats(&self) -> EarlyDataStats {
        let store = self.early_data.read();
        EarlyDataStats {
            stored_identities: store.len(),
            accepted_count: self.accepted.load(Ordering::SeqCst),
            rejected_count: self.rejected.load(Ordering::SeqCst),
            max_early_data_size: self.max_early_size,
        }
    }

    pub fn cleanup_expired(&self) {
        let mut store = self.early_data.write();
        let now = Self::current_time();
        
        store.retain(|_, info| {
            now.saturating_sub(info.created_at) <= self.ttl_secs
        });
    }

    pub fn clear_all(&self) {
        self.early_data.write().clear();
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
pub struct EarlyDataStats {
    pub stored_identities: usize,
    pub accepted_count: u64,
    pub rejected_count: u64,
    pub max_early_data_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_early_data() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        assert!(mgr.store_early_data(identity, data));
    }

    #[test]
    fn test_get_early_data() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        mgr.store_early_data(identity.clone(), data.clone());
        let retrieved = mgr.get_early_data(&identity);
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, data);
    }

    #[test]
    fn test_accept_early_data() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        mgr.store_early_data(identity.clone(), data);
        assert!(mgr.accept_early_data(&identity));
    }

    #[test]
    fn test_remove_early_data() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        mgr.store_early_data(identity.clone(), data);
        assert!(mgr.remove_early_data(&identity));
        assert!(!mgr.has_early_data(&identity));
    }

    #[test]
    fn test_has_early_data() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        assert!(!mgr.has_early_data(&identity));
        mgr.store_early_data(identity.clone(), data);
        assert!(mgr.has_early_data(&identity));
    }

    #[test]
    fn test_stats() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        mgr.store_early_data(identity, data);
        let stats = mgr.stats();
        
        assert_eq!(stats.stored_identities, 1);
        assert_eq!(stats.accepted_count, 1);
    }

    #[test]
    fn test_clear_all() {
        let mgr = EarlyDataManager::new(1024, 3600);
        let identity = b"test_id".to_vec();
        let data = b"early_data".to_vec();
        
        mgr.store_early_data(identity, data);
        mgr.clear_all();
        
        assert_eq!(mgr.stats().stored_identities, 0);
    }
}
