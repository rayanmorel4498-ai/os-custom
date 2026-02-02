extern crate alloc;
use alloc::vec::Vec;
use rand_core::{RngCore};
use aes_gcm::Nonce;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::sync::Mutex;

static STORAGE_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static KEY_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct StorageCrypto;

impl StorageCrypto {
    pub fn init_key(key: [u8; 32]) {
        let mut guard = STORAGE_KEY.lock();
        *guard = Some(key);
        KEY_INITIALIZED.store(true, Ordering::Release);
    }

    fn get_key() -> Result<[u8; 32], &'static str> {
        if !KEY_INITIALIZED.load(Ordering::Acquire) {
            return Err("Storage key not initialized");
        }
        let guard = STORAGE_KEY.lock();
        guard.ok_or("Storage key not available")
    }

    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), &'static str> {
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*key);
        let cipher = aes_gcm::Aes256Gcm::new(&key);

        let mut nonce_bytes = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data).map_err(|_| "Encryption failed")?;

        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*key);
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed")
    }

    pub fn zeroize(buffer: &mut [u8]) {
        for byte in buffer.iter_mut() {
            *byte = 0;
        }
    }

    pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>, crate::device_drivers::DriverError> {
        let key = Self::get_key()
            .map_err(|_| crate::device_drivers::DriverError::NotInitialized)?;
        
        let key_obj = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(key);
        let cipher = aes_gcm::Aes256Gcm::new(&key_obj);
        
        let mut nonce_bytes = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut sealed = nonce_bytes.to_vec();
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| crate::device_drivers::DriverError::InitFailed)?;
        sealed.extend_from_slice(&ciphertext);
        
        Ok(sealed)
    }

    pub fn unseal(sealed_data: &[u8]) -> Result<Vec<u8>, crate::device_drivers::DriverError> {
        if sealed_data.len() < 12 + 16 {
            return Err(crate::device_drivers::DriverError::InitFailed);
        }
        
        let key = Self::get_key()
            .map_err(|_| crate::device_drivers::DriverError::NotInitialized)?;
        
        let (nonce_bytes, ciphertext) = sealed_data.split_at(12);
        
        let key_obj = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(key);
        let cipher = aes_gcm::Aes256Gcm::new(&key_obj);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| crate::device_drivers::DriverError::InitFailed)
    }

    pub fn destroy_key() {
        let mut guard = STORAGE_KEY.lock();
        if let Some(ref mut key) = *guard {
            for byte in key.iter_mut() {
                *byte = 0;
            }
        }
        *guard = None;
        KEY_INITIALIZED.store(false, Ordering::Release);
    }
}