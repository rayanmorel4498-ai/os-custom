extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use alloc::sync::Arc;

#[derive(Clone, Debug)]
pub struct HandshakeParams {
    pub peer_id: Vec<u8>,
    pub dh_params: Vec<u8>,
    pub ecdh_curve: Vec<u8>,
    pub cipher_suite: Vec<u8>,
    pub created_at: u64,
    pub ttl_secs: u64,
    pub reuse_count: u64,
}

impl HandshakeParams {
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) < self.ttl_secs
    }
}

pub struct HandshakeOptimizer {
    params_cache: Arc<RwLock<BTreeMap<Vec<u8>, HandshakeParams>>>,
    default_ttl: u64,
    max_cache_size: usize,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    evictions: Arc<AtomicU64>,
}

impl HandshakeOptimizer {
    pub fn new(default_ttl: u64, max_cache_size: usize) -> Self {
        Self {
            params_cache: Arc::new(RwLock::new(BTreeMap::new())),
            default_ttl,
            max_cache_size,
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn cache_params(&self, peer_id: Vec<u8>, dh_params: Vec<u8>, ecdh_curve: Vec<u8>, cipher_suite: Vec<u8>) {
        let params = HandshakeParams {
            peer_id: peer_id.clone(),
            dh_params,
            ecdh_curve,
            cipher_suite,
            created_at: Self::current_time(),
            ttl_secs: self.default_ttl,
            reuse_count: 0,
        };

        let mut cache = self.params_cache.write();
        cache.insert(peer_id, params);

        if cache.len() > self.max_cache_size {
            if let Some(first_key) = cache.keys().next().cloned() {
                cache.remove(&first_key);
                self.evictions.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    pub fn get_params(&self, peer_id: &[u8]) -> Option<HandshakeParams> {
        let mut cache = self.params_cache.write();
        let params = cache.get_mut(peer_id)?;

        let now = Self::current_time();
        if !params.is_valid(now) {
            cache.remove(peer_id);
            self.misses.fetch_add(1, Ordering::SeqCst);
            return None;
        }

        params.reuse_count += 1;
        self.hits.fetch_add(1, Ordering::SeqCst);
        Some(params.clone())
    }

    pub fn has_cached_params(&self, peer_id: &[u8]) -> bool {
        let cache = self.params_cache.read();
        if let Some(params) = cache.get(peer_id) {
            params.is_valid(Self::current_time())
        } else {
            false
        }
    }

    pub fn invalidate(&self, peer_id: &[u8]) -> bool {
        self.params_cache.write().remove(peer_id).is_some()
    }

    pub fn update_ttl(&self, peer_id: &[u8], new_ttl: u64) -> bool {
        let mut cache = self.params_cache.write();
        if let Some(params) = cache.get_mut(peer_id) {
            params.ttl_secs = new_ttl;
            return true;
        }
        false
    }

    pub fn stats(&self) -> HandshakeOptimizationStats {
        let cache = self.params_cache.read();
        let total_requests = self.hits.load(Ordering::SeqCst) + self.misses.load(Ordering::SeqCst);
        let hit_rate = if total_requests > 0 {
            (self.hits.load(Ordering::SeqCst) * 100) / total_requests
        } else {
            0
        };

        HandshakeOptimizationStats {
            cached_params: cache.len(),
            cache_hits: self.hits.load(Ordering::SeqCst),
            cache_misses: self.misses.load(Ordering::SeqCst),
            evictions: self.evictions.load(Ordering::SeqCst),
            hit_rate_percent: hit_rate,
        }
    }

    pub fn cleanup_expired(&self) {
        let mut cache = self.params_cache.write();
        let now = Self::current_time();
        
        cache.retain(|_, params| params.is_valid(now));
    }

    pub fn clear_all(&self) {
        self.params_cache.write().clear();
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
pub struct HandshakeOptimizationStats {
    pub cached_params: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
    pub hit_rate_percent: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_params() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        let dh = b"dh_params".to_vec();
        let ecdh = b"ecdh_curve".to_vec();
        let cipher = b"cipher_suite".to_vec();
        
        opt.cache_params(peer, dh, ecdh, cipher);
        assert_eq!(opt.stats().cached_params, 1);
    }

    #[test]
    fn test_get_params() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        let dh = b"dh_params".to_vec();
        let ecdh = b"ecdh_curve".to_vec();
        let cipher = b"cipher_suite".to_vec();
        
        opt.cache_params(peer.clone(), dh.clone(), ecdh, cipher);
        let retrieved = opt.get_params(&peer);
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().dh_params, dh);
    }

    #[test]
    fn test_has_cached_params() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        
        assert!(!opt.has_cached_params(&peer));
        opt.cache_params(peer.clone(), b"dh".to_vec(), b"ecdh".to_vec(), b"cipher".to_vec());
        assert!(opt.has_cached_params(&peer));
    }

    #[test]
    fn test_invalidate() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        
        opt.cache_params(peer.clone(), b"dh".to_vec(), b"ecdh".to_vec(), b"cipher".to_vec());
        assert!(opt.invalidate(&peer));
        assert!(!opt.has_cached_params(&peer));
    }

    #[test]
    fn test_update_ttl() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        
        opt.cache_params(peer.clone(), b"dh".to_vec(), b"ecdh".to_vec(), b"cipher".to_vec());
        assert!(opt.update_ttl(&peer, 7200));
    }

    #[test]
    fn test_stats() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        
        opt.cache_params(peer.clone(), b"dh".to_vec(), b"ecdh".to_vec(), b"cipher".to_vec());
        opt.get_params(&peer);
        
        let stats = opt.stats();
        assert_eq!(stats.cached_params, 1);
        assert_eq!(stats.cache_hits, 1);
    }

    #[test]
    fn test_clear_all() {
        let opt = HandshakeOptimizer::new(3600, 100);
        let peer = b"peer1".to_vec();
        
        opt.cache_params(peer, b"dh".to_vec(), b"ecdh".to_vec(), b"cipher".to_vec());
        opt.clear_all();
        
        assert_eq!(opt.stats().cached_params, 0);
    }
}
