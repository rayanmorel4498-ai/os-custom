extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::format;
use parking_lot::RwLock;
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedSession {
    pub session_id: Vec<u8>,
    pub ticket: Option<Vec<u8>>,
    pub master_secret: Vec<u8>,
    pub cipher_suite: u16,
    pub created_at: u64,
    pub ttl_secs: u64,
    pub resume_count: u32,
}

impl CachedSession {
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) <= self.ttl_secs
    }

    pub fn mark_resumed(&mut self) {
        self.resume_count = self.resume_count.saturating_add(1);
    }
}

pub struct SessionCache {
    cache: Arc<RwLock<BTreeMap<String, CachedSession>>>,
    default_ttl: u64,
    max_sessions: usize,
}

impl SessionCache {
    pub fn new() -> Self {
        Self::with_ttl(3600)
    }

    pub fn with_ttl(default_ttl: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(BTreeMap::new())),
            default_ttl,
            max_sessions: 1000,
        }
    }

    pub fn cache_session(
        &self,
        hostname: &str,
        session_id: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: u16,
    ) {
        let key = format!("{}:{}", hostname, alloc::string::String::from_utf8_lossy(&session_id));
        let session = CachedSession {
            session_id,
            ticket: None,
            master_secret,
            cipher_suite,
            created_at: Self::current_time(),
            ttl_secs: self.default_ttl,
            resume_count: 0,
        };

        let mut cache = self.cache.write();
        
        if cache.len() >= self.max_sessions {
            if let Some(first_key) = cache.keys().next().cloned() {
                cache.remove(&first_key);
            }
        }

        cache.insert(key, session);
    }

    pub fn get_session(&self, hostname: &str, session_id: &[u8]) -> Option<CachedSession> {
        let key = format!("{}:{}", hostname, alloc::string::String::from_utf8_lossy(session_id));
        let mut cache = self.cache.write();

        if let Some(session) = cache.get_mut(&key) {
            let now = Self::current_time();
            if session.is_valid(now) {
                session.mark_resumed();
                return Some(session.clone());
            } else {
                cache.remove(&key);
            }
        }
        None
    }

    pub fn has_valid_session(&self, hostname: &str, session_id: &[u8]) -> bool {
        let key = format!("{}:{}", hostname, alloc::string::String::from_utf8_lossy(session_id));
        let cache = self.cache.read();

        if let Some(session) = cache.get(&key) {
            session.is_valid(Self::current_time())
        } else {
            false
        }
    }

    pub fn remove_session(&self, hostname: &str, session_id: &[u8]) -> bool {
        let key = format!("{}:{}", hostname, alloc::string::String::from_utf8_lossy(session_id));
        let mut cache = self.cache.write();
        cache.remove(&key).is_some()
    }

    pub fn cleanup_expired(&self) {
        let now = Self::current_time();
        let mut cache = self.cache.write();
        cache.retain(|_, session| session.is_valid(now));
    }

    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        let now = Self::current_time();

        let mut valid_count = 0;
        let mut total_resumes = 0u64;

        for session in cache.values() {
            if session.is_valid(now) {
                valid_count += 1;
                total_resumes += session.resume_count as u64;
            }
        }

        CacheStats {
            total_sessions: cache.len(),
            valid_sessions: valid_count,
            total_resumptions: total_resumes,
        }
    }

    pub fn clear_all(&self) {
        let mut cache = self.cache.write();
        cache.clear();
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
pub struct CacheStats {
    pub total_sessions: usize,
    pub valid_sessions: usize,
    pub total_resumptions: u64,
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_session() {
        let cache = SessionCache::new();
        let session_id = b"test_session_id".to_vec();
        let master_secret = b"test_secret".to_vec();

        cache.cache_session("example.com", session_id, master_secret, 0x002F);
        assert_eq!(cache.stats().total_sessions, 1);
    }

    #[test]
    fn test_retrieve_cached_session() {
        let cache = SessionCache::new();
        let session_id = b"test_session_id".to_vec();
        let master_secret = b"test_secret".to_vec();

        cache.cache_session("example.com", session_id.clone(), master_secret.clone(), 0x002F);
        
        let retrieved = cache.get_session("example.com", &session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().master_secret, master_secret);
    }

    #[test]
    fn test_session_not_found() {
        let cache = SessionCache::new();
        let missing_id = b"missing".to_vec();

        let retrieved = cache.get_session("example.com", &missing_id);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_remove_session() {
        let cache = SessionCache::new();
        let session_id = b"test_session_id".to_vec();
        let master_secret = b"test_secret".to_vec();

        cache.cache_session("example.com", session_id.clone(), master_secret, 0x002F);
        assert!(cache.remove_session("example.com", &session_id));
        assert_eq!(cache.stats().total_sessions, 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = SessionCache::new();
        let session_id = b"test_session_id".to_vec();
        let master_secret = b"test_secret".to_vec();

        cache.cache_session("example.com", session_id.clone(), master_secret, 0x002F);
        
        let stats = cache.stats();
        assert!(stats.total_sessions > 0);
    }

    #[test]
    fn test_clear_all() {
        let cache = SessionCache::new();
        let session_id = b"test_session_id".to_vec();
        let master_secret = b"test_secret".to_vec();

        cache.cache_session("example.com", session_id, master_secret, 0x002F);
        cache.clear_all();
        assert_eq!(cache.stats().total_sessions, 0);
    }
}
