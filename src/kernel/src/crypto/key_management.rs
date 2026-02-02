
extern crate alloc;
use alloc::vec::Vec;
use rand_core::{RngCore, OsRng};
use crate::crypto::storage_crypto::StorageCrypto;

pub const KEY_SIZE: usize = 32;

pub struct KeyManager {
    master_key: [u8; KEY_SIZE],
    session_keys: Vec<[u8; KEY_SIZE]>,
}

impl KeyManager {
    pub fn new(master_key: [u8; KEY_SIZE]) -> Self {
        KeyManager {
            master_key,
            session_keys: Vec::new(),
        }
    }

    pub fn generate_session_key(&mut self) -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        self.session_keys.push(key);
        key
    }

    pub fn derive_session_key(&mut self, tls_token: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
        let mut derived = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            derived[i] = self.master_key[i].wrapping_add(tls_token[i]);
        }
        self.session_keys.push(derived);
        derived
    }

    pub fn revoke_session_key(&mut self, index: usize) {
        if index < self.session_keys.len() {
            StorageCrypto::zeroize(&mut self.session_keys[index]);
            self.session_keys.remove(index);
        }
    }

    pub fn get_session_key(&self, index: usize) -> Option<&[u8; KEY_SIZE]> {
        self.session_keys.get(index)
    }

    pub fn zeroize_all_sessions(&mut self) {
        for key in self.session_keys.iter_mut() {
            StorageCrypto::zeroize(key);
        }
        self.session_keys.clear();
    }

    pub fn get_master_key(&self) -> &[u8; KEY_SIZE] {
        &self.master_key
    }
}