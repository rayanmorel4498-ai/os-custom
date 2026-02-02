extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum KeyUpdateType {
    Update = 0,
    UpdateRequested = 1,
}

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum KeyUpdateState {
    Idle,
    Pending,
    Complete,
}

#[derive(Clone, Debug)]
pub struct KeyUpdateRecord {
    pub sequence: u64,
    pub update_type: KeyUpdateType,
    pub timestamp: u64,
    pub previous_key: Vec<u8>,
    pub new_key: Vec<u8>,
}

#[derive(Clone)]
pub struct KeyUpdateManager {
    current_key: Arc<RwLock<Vec<u8>>>,
    
    update_sequence: Arc<AtomicU64>,
    
    state: Arc<RwLock<KeyUpdateState>>,
    
    update_history: Arc<RwLock<Vec<KeyUpdateRecord>>>,
    
    max_history: usize,
    
    last_update_time: Arc<RwLock<u64>>,
    
    min_interval_secs: u64,
    
    total_updates: Arc<AtomicU64>,
    pending_updates: Arc<AtomicU32>,
}

impl KeyUpdateManager {
    pub fn new(initial_key: Vec<u8>) -> Self {
        Self {
            current_key: Arc::new(RwLock::new(initial_key)),
            update_sequence: Arc::new(AtomicU64::new(0)),
            state: Arc::new(RwLock::new(KeyUpdateState::Idle)),
            update_history: Arc::new(RwLock::new(Vec::new())),
            max_history: 100,
            last_update_time: Arc::new(RwLock::new(u64::MAX)),
               min_interval_secs: 1,
            total_updates: Arc::new(AtomicU64::new(0)),
            pending_updates: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn with_interval(initial_key: Vec<u8>, min_interval_secs: u64) -> Self {
           Self {
               current_key: Arc::new(RwLock::new(initial_key)),
               update_sequence: Arc::new(AtomicU64::new(0)),
               state: Arc::new(RwLock::new(KeyUpdateState::Idle)),
               update_history: Arc::new(RwLock::new(Vec::new())),
               max_history: 100,
               last_update_time: Arc::new(RwLock::new(u64::MAX)),
               min_interval_secs,
               total_updates: Arc::new(AtomicU64::new(0)),
               pending_updates: Arc::new(AtomicU32::new(0)),
           }
    }

    pub fn initiate_update(
        &self,
        new_key: Vec<u8>,
        update_type: KeyUpdateType,
        current_time: u64,
    ) -> Result<u64, &'static str> {
        let last_update = *self.last_update_time.read();
        if last_update != u64::MAX && current_time < last_update + (self.min_interval_secs * 1000) {
            return Err("Key update interval too short");
        }

        let mut state = self.state.write();
        if *state == KeyUpdateState::Pending {
            return Err("Key update already pending");
        }

        let mut current = self.current_key.write();
        let previous_key = current.clone();
        *current = new_key.clone();
        drop(current);

        let sequence = self.update_sequence.fetch_add(1, Ordering::SeqCst);

        let record = KeyUpdateRecord {
            sequence,
            update_type,
            timestamp: current_time,
            previous_key,
            new_key,
        };

        let mut history = self.update_history.write();
        history.push(record);
        if history.len() > self.max_history {
            history.remove(0);
        }

        *state = if update_type == KeyUpdateType::UpdateRequested {
            KeyUpdateState::Pending
        } else {
            KeyUpdateState::Complete
        };

        *self.last_update_time.write() = current_time;
        self.total_updates.fetch_add(1, Ordering::SeqCst);

        if update_type == KeyUpdateType::UpdateRequested {
            self.pending_updates.fetch_add(1, Ordering::SeqCst);
        }

        Ok(sequence)
    }

    pub fn acknowledge_update(&self) -> Result<(), &'static str> {
        let mut state = self.state.write();
        
        if *state == KeyUpdateState::Pending {
            *state = KeyUpdateState::Complete;
            self.pending_updates.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        } else if *state == KeyUpdateState::Complete {
            Ok(())
        } else {
            Err("No update pending")
        }
    }

    pub fn get_current_key(&self) -> Vec<u8> {
        self.current_key.read().clone()
    }

    pub fn state(&self) -> KeyUpdateState {
        *self.state.read()
    }

    pub fn sequence(&self) -> u64 {
        self.update_sequence.load(Ordering::SeqCst)
    }

    pub fn get_history(&self, limit: usize) -> Vec<KeyUpdateRecord> {
        let history = self.update_history.read();
        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> KeyUpdateStats {
        KeyUpdateStats {
            total_updates: self.total_updates.load(Ordering::SeqCst),
            current_sequence: self.update_sequence.load(Ordering::SeqCst),
            pending_updates: self.pending_updates.load(Ordering::SeqCst) as u64,
            current_state: self.state(),
            history_size: self.update_history.read().len() as u64,
        }
    }

    pub fn clear_history(&self) {
        self.update_history.write().clear();
    }

    pub fn reset(&self) {
        *self.state.write() = KeyUpdateState::Idle;
        self.pending_updates.store(0, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct KeyUpdateStats {
    pub total_updates: u64,
    pub current_sequence: u64,
    pub pending_updates: u64,
    pub current_state: KeyUpdateState,
    pub history_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_update_creation() {
        let manager = KeyUpdateManager::new(b"initial_key".to_vec());
        assert_eq!(manager.state(), KeyUpdateState::Idle);
    }

    #[test]
    fn test_key_update_simple() {
        let manager = KeyUpdateManager::new(b"key1".to_vec());
        let new_key = b"key2".to_vec();

        let result = manager.initiate_update(new_key.clone(), KeyUpdateType::Update, 0);
        assert!(result.is_ok());
        assert_eq!(manager.get_current_key(), new_key);
        assert_eq!(manager.state(), KeyUpdateState::Complete);
    }

    #[test]
    fn test_key_update_requested() {
        let manager = KeyUpdateManager::new(b"key1".to_vec());

        let result = manager.initiate_update(
            b"key2".to_vec(),
            KeyUpdateType::UpdateRequested,
            0,
        );
        assert!(result.is_ok());
        assert_eq!(manager.state(), KeyUpdateState::Pending);
    }

    #[test]
    fn test_key_update_acknowledge() {
        let manager = KeyUpdateManager::new(b"key1".to_vec());
        manager.initiate_update(b"key2".to_vec(), KeyUpdateType::UpdateRequested, 0).ok();
        
        assert!(manager.acknowledge_update().is_ok());
        assert_eq!(manager.state(), KeyUpdateState::Complete);
    }

    #[test]
    fn test_key_update_interval() {
        let manager = KeyUpdateManager::with_interval(b"key1".to_vec(), 10);

        assert!(manager.initiate_update(b"key2".to_vec(), KeyUpdateType::Update, 0).is_ok());

        assert!(manager.initiate_update(b"key3".to_vec(), KeyUpdateType::Update, 5000).is_err());

        assert!(manager.initiate_update(b"key3".to_vec(), KeyUpdateType::Update, 11000).is_ok());
    }

    #[test]
    fn test_key_update_stats() {
        let manager = KeyUpdateManager::new(b"key".to_vec());
        manager.initiate_update(b"key2".to_vec(), KeyUpdateType::Update, 0).ok();

        let stats = manager.stats();
        assert_eq!(stats.total_updates, 1);
        assert_eq!(stats.current_sequence, 1);
    }
}
