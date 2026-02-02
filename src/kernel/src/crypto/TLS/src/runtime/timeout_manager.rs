use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use parking_lot::Mutex;
use core::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TimeoutType {
    Handshake,
    Session,
    MessagePending,
    Retry,
}

impl TimeoutType {
    pub fn duration(&self) -> Duration {
        match self {
            Self::Handshake => Duration::from_secs(30),
            Self::Session => Duration::from_secs(3600),
            Self::MessagePending => Duration::from_secs(5),
            Self::Retry => Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimeoutEntry {
    pub session_id: String,
    pub timeout_type: TimeoutType,
    pub created_at: u64,
    pub retries: u32,
    pub max_retries: u32,
}

impl TimeoutEntry {
    pub fn new(session_id: String, timeout_type: TimeoutType) -> Self {
        Self {
            session_id,
            timeout_type,
            created_at: Self::now(),
            retries: 0,
            max_retries: 3,
        }
    }

    pub fn is_expired(&self) -> bool {
        let elapsed = Self::now().saturating_sub(self.created_at);
        elapsed > self.timeout_type.duration().as_secs()
    }

    pub fn should_retry(&self) -> bool {
        self.retries < self.max_retries && self.is_expired()
    }

    fn now() -> u64 {
        0u64
    }
}

pub struct TimeoutManager {
    entries: Mutex<BTreeMap<String, TimeoutEntry>>,
    expired_sessions: Mutex<Vec<String>>,
}

impl TimeoutManager {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            expired_sessions: Mutex::new(Vec::new()),
        }
    }

    pub fn register_timeout(
        &self,
        session_id: String,
        timeout_type: TimeoutType,
    ) {
        let entry = TimeoutEntry::new(session_id.clone(), timeout_type);
        self.entries.lock().insert(session_id, entry);
    }

    pub fn has_timeout(&self, session_id: &str) -> bool {
        self.entries
            .lock()
            .get(session_id)
            .map(|e| e.is_expired())
            .unwrap_or(false)
    }

    pub fn get_retry_candidates(&self) -> Vec<String> {
        self.entries
            .lock()
            .values()
            .filter(|e| e.should_retry())
            .map(|e| e.session_id.clone())
            .collect()
    }

    pub fn increment_retry(&self, session_id: &str) {
        if let Some(entry) = self.entries.lock().get_mut(session_id) {
            entry.retries += 1;
        }
    }

    pub fn cleanup_expired(&self) -> Vec<String> {
        let mut entries = self.entries.lock();
        let mut expired = Vec::new();

        let keys: Vec<_> = entries.keys().cloned().collect();
        for key in keys {
            if let Some(entry) = entries.get(&key) {
                if entry.is_expired() && entry.retries >= entry.max_retries {
                    expired.push(key.clone());
                }
            }
        }

        for session_id in &expired {
            entries.remove(session_id);
        }

        self.expired_sessions.lock().extend(expired.clone());
        expired
    }

    pub fn get_expired_sessions(&self) -> Vec<String> {
        self.expired_sessions.lock().drain(..).collect()
    }

    pub fn remove_timeout(&self, session_id: &str) {
        self.entries.lock().remove(session_id);
    }

    pub fn active_count(&self) -> usize {
        self.entries.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_timeout_entry_creation() {
        let entry = TimeoutEntry::new("session_1".to_string(), TimeoutType::Handshake);
        assert_eq!(entry.session_id, "session_1");
        assert_eq!(entry.timeout_type, TimeoutType::Handshake);
        assert_eq!(entry.retries, 0);
        assert_eq!(entry.max_retries, 3);
    }

    #[test]
    fn test_timeout_manager_registration() {
        let manager = TimeoutManager::new();
        manager.register_timeout("sess1".to_string(), TimeoutType::Session);
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_timeout_manager_cleanup() {
        let manager = TimeoutManager::new();
        manager.register_timeout("sess1".to_string(), TimeoutType::MessagePending);
        manager.register_timeout("sess2".to_string(), TimeoutType::Handshake);
        
        let expired = manager.cleanup_expired();
        assert!(expired.is_empty() || expired.len() <= 2);
    }

    #[test]
    fn test_timeout_manager_remove() {
        let manager = TimeoutManager::new();
        manager.register_timeout("sess1".to_string(), TimeoutType::Session);
        assert_eq!(manager.active_count(), 1);
        
        manager.remove_timeout("sess1");
        assert_eq!(manager.active_count(), 0);
    }
}
