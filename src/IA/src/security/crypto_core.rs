use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::{String, Vec};
use aes::Aes256;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

pub struct EncryptedVault {
    internal_state: Arc<Mutex<Vec<u8>>>,
}

impl EncryptedVault {
    pub fn new() -> Self {
        EncryptedVault {
            internal_state: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn store_opaque(&self, data: &[u8]) -> Result<(), String> {
        let mut state = self.internal_state.lock();
        state.extend_from_slice(data);
        Ok(())
    }

    pub async fn retrieve_opaque(&self, offset: usize, size: usize) -> Result<Vec<u8>, String> {
        let state = self.internal_state.lock();
        if offset + size > state.len() {
            return Err("Out of bounds".into());
        }
        Ok(state[offset..offset + size].to_vec())
    }

    pub async fn wipe(&self) {
        let mut state = self.internal_state.lock();
        state.iter_mut().for_each(|b| *b = 0);
        state.clear();
    }
}

pub struct CryptoCore {
    vault: Arc<EncryptedVault>,
}

impl CryptoCore {
    pub fn new() -> Self {
        CryptoCore {
            vault: Arc::new(EncryptedVault::new()),
        }
    }

    pub fn get_vault(&self) -> Arc<EncryptedVault> {
        self.vault.clone()
    }

    pub fn encrypt_chacha20(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let mut data = plaintext.to_vec();
        let mut cipher = ChaCha20::new(key.into(), nonce.into());
        cipher.apply_keystream(&mut data);
        data
    }

    pub fn decrypt_chacha20(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let mut data = ciphertext.to_vec();
        let mut cipher = ChaCha20::new(key.into(), nonce.into());
        cipher.apply_keystream(&mut data);
        data
    }

    pub fn encrypt_aes_ctr(&self, key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        type Aes256Ctr = Ctr128BE<Aes256>;
        let mut data = plaintext.to_vec();
        let mut cipher = Aes256Ctr::new(key.into(), iv.into());
        cipher.apply_keystream(&mut data);
        data
    }

    pub fn decrypt_aes_ctr(&self, key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        type Aes256Ctr = Ctr128BE<Aes256>;
        let mut data = ciphertext.to_vec();
        let mut cipher = Aes256Ctr::new(key.into(), iv.into());
        cipher.apply_keystream(&mut data);
        data
    }
}
