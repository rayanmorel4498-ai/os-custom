extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::{RwLock, Mutex};
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRotationPolicy {
    TimeBasedRotation(u64),
    OperationBasedRotation(u64),
    HybridRotation(u64, u64),
}

#[derive(Clone, Debug)]
pub struct RotationKey {
    pub key_id: u64,
    pub key_material: Vec<u8>,
    pub created_at: u64,
    pub operation_count: u64,
    pub is_active: bool,
}

impl RotationKey {
    pub fn needs_rotation(&self, now: u64, policy: KeyRotationPolicy) -> bool {
        match policy {
            KeyRotationPolicy::TimeBasedRotation(interval) => {
                now.saturating_sub(self.created_at) >= interval
            }
            KeyRotationPolicy::OperationBasedRotation(limit) => {
                self.operation_count >= limit
            }
            KeyRotationPolicy::HybridRotation(time_interval, op_limit) => {
                let time_expired = now.saturating_sub(self.created_at) >= time_interval;
                let ops_exceeded = self.operation_count >= op_limit;
                time_expired || ops_exceeded
            }
        }
    }
}

pub struct KeyRotationManager {
    active_key: Arc<Mutex<RotationKey>>,
    historical_keys: Arc<RwLock<BTreeMap<u64, RotationKey>>>,
    policy: KeyRotationPolicy,
    next_key_id: Arc<AtomicU64>,
    max_historical: usize,
}

impl KeyRotationManager {
    pub fn new(initial_key: Vec<u8>, policy: KeyRotationPolicy) -> Self {
        let key = RotationKey {
            key_id: 1,
            key_material: initial_key,
            created_at: Self::current_time(),
            operation_count: 0,
            is_active: true,
        };

        Self {
            active_key: Arc::new(Mutex::new(key)),
            historical_keys: Arc::new(RwLock::new(BTreeMap::new())),
            policy,
            next_key_id: Arc::new(AtomicU64::new(2)),
            max_historical: 10,
        }
    }

    pub fn get_active_key(&self) -> RotationKey {
        self.active_key.lock().clone()
    }

    pub fn record_operation(&self) {
        let mut key = self.active_key.lock();
        key.operation_count = key.operation_count.saturating_add(1);
    }

    pub fn rotate_if_needed(&self) -> bool {
        let now = Self::current_time();
        let active = self.active_key.lock();

        if !active.needs_rotation(now, self.policy) {
            return false;
        }

        let old_key_id = active.key_id;
        let old_key = active.clone();
        drop(active);

        let mut history = self.historical_keys.write();
        history.insert(old_key_id, old_key);

        if history.len() > self.max_historical {
            if let Some(first_key) = history.keys().next().cloned() {
                history.remove(&first_key);
            }
        }
        drop(history);

        let new_key_id = self.next_key_id.fetch_add(1, Ordering::SeqCst);
        let new_key = RotationKey {
            key_id: new_key_id,
            key_material: Self::generate_key(),
            created_at: now,
            operation_count: 0,
            is_active: true,
        };

        *self.active_key.lock() = new_key;
        true
    }

    pub fn get_key_by_id(&self, key_id: u64) -> Option<RotationKey> {
        let active = self.active_key.lock();
        if active.key_id == key_id {
            return Some(active.clone());
        }
        drop(active);

        let history = self.historical_keys.read();
        history.get(&key_id).cloned()
    }

    pub fn force_rotation(&self) -> u64 {
        let now = Self::current_time();
        let active = self.active_key.lock();

        let old_key = active.clone();
        drop(active);

        let mut history = self.historical_keys.write();
        history.insert(old_key.key_id, old_key);
        drop(history);

        let new_key_id = self.next_key_id.fetch_add(1, Ordering::SeqCst);
        let new_key = RotationKey {
            key_id: new_key_id,
            key_material: Self::generate_key(),
            created_at: now,
            operation_count: 0,
            is_active: true,
        };

        *self.active_key.lock() = new_key;
        new_key_id
    }

    pub fn stats(&self) -> KeyRotationStats {
        let active = self.active_key.lock();
        let history = self.historical_keys.read();
        let now = Self::current_time();

        KeyRotationStats {
            active_key_id: active.key_id,
            operations_with_current_key: active.operation_count,
            time_since_rotation_secs: now.saturating_sub(active.created_at),
            total_historical_keys: history.len(),
            needs_rotation: active.needs_rotation(now, self.policy),
        }
    }

    pub fn clear_historical(&self) {
        let mut history = self.historical_keys.write();
        history.clear();
    }

    fn generate_key() -> Vec<u8> {
        let id = Self::current_time();
        alloc::format!("key_{:016x}", id).into_bytes()
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
pub struct KeyRotationStats {
    pub active_key_id: u64,
    pub operations_with_current_key: u64,
    pub time_since_rotation_secs: u64,
    pub total_historical_keys: usize,
    pub needs_rotation: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_key_rotation_manager() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::TimeBasedRotation(3600);
        let manager = KeyRotationManager::new(key, policy);

        let active = manager.get_active_key();
        assert_eq!(active.key_id, 1);
    }

    #[test]
    fn test_record_operation() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::OperationBasedRotation(100);
        let manager = KeyRotationManager::new(key, policy);

        manager.record_operation();
        manager.record_operation();

        let active = manager.get_active_key();
        assert_eq!(active.operation_count, 2);
    }

    #[test]
    fn test_rotation_not_needed() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::TimeBasedRotation(3600);
        let manager = KeyRotationManager::new(key, policy);

        let rotated = manager.rotate_if_needed();
        assert!(!rotated);
    }

    #[test]
    fn test_force_rotation() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::TimeBasedRotation(3600);
        let manager = KeyRotationManager::new(key, policy);

        let old_id = manager.get_active_key().key_id;
        let new_id = manager.force_rotation();

        assert_ne!(old_id, new_id);
        assert_eq!(manager.get_active_key().key_id, new_id);
    }

    #[test]
    fn test_get_key_by_id() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::TimeBasedRotation(3600);
        let manager = KeyRotationManager::new(key, policy);

        let retrieved = manager.get_key_by_id(1);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().key_id, 1);
    }

    #[test]
    fn test_stats() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::TimeBasedRotation(3600);
        let manager = KeyRotationManager::new(key, policy);

        manager.record_operation();
        let stats = manager.stats();

        assert_eq!(stats.active_key_id, 1);
        assert_eq!(stats.operations_with_current_key, 1);
    }

    #[test]
    fn test_clear_historical() {
        let key = b"initial_key".to_vec();
        let policy = KeyRotationPolicy::TimeBasedRotation(3600);
        let manager = KeyRotationManager::new(key, policy);

        manager.force_rotation();
        manager.clear_historical();

        assert_eq!(manager.stats().total_historical_keys, 0);
    }
}
