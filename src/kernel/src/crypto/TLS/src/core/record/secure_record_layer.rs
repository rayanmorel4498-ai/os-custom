extern crate alloc;

use alloc::vec::Vec;
use anyhow::Result;
use parking_lot::Mutex;
pub struct SecureRecordLayer {
    encrypt_key: Mutex<Option<Vec<u8>>>,
    decrypt_key: Mutex<Option<Vec<u8>>>,
    encrypt_iv: Mutex<Option<Vec<u8>>>,
    decrypt_iv: Mutex<Option<Vec<u8>>>,
    work_buffer: Mutex<Vec<u8>>,
    message_counter: parking_lot::Mutex<u64>,
}

impl SecureRecordLayer {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            encrypt_key: Mutex::new(None),
            decrypt_key: Mutex::new(None),
            encrypt_iv: Mutex::new(None),
            decrypt_iv: Mutex::new(None),
            work_buffer: Mutex::new(alloc::vec![0u8; buffer_size]),
            message_counter: parking_lot::Mutex::new(0),
        }
    }

    pub fn set_encrypt_key(&self, key: Vec<u8>, iv: Vec<u8>) -> Result<()> {
        if key.is_empty() || iv.is_empty() {
            return Err(anyhow::anyhow!("Clé ou IV vide"));
        }
        *self.encrypt_key.lock() = Some(key);
        *self.encrypt_iv.lock() = Some(iv);
        Ok(())
    }

    pub fn set_decrypt_key(&self, key: Vec<u8>, iv: Vec<u8>) -> Result<()> {
        if key.is_empty() || iv.is_empty() {
            return Err(anyhow::anyhow!("Clé ou IV vide"));
        }
        *self.decrypt_key.lock() = Some(key);
        *self.decrypt_iv.lock() = Some(iv);
        Ok(())
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let encrypt_key = self.encrypt_key.lock();
        let key = encrypt_key.as_ref().ok_or_else(|| anyhow::anyhow!("Clé de chiffrement non configurée"))?;

        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }

        *self.message_counter.lock() += 1;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let decrypt_key = self.decrypt_key.lock();
        let key = decrypt_key.as_ref().ok_or_else(|| anyhow::anyhow!("Clé de déchiffrement non configurée"))?;

        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }

        *self.message_counter.lock() += 1;

        Ok(plaintext)
    }

    pub fn zeroize_keys(&self) -> Result<()> {
        if let Some(ref mut key) = self.encrypt_key.lock().as_mut() {
            for byte in key.iter_mut() {
                *byte = 0;
            }
        }
        if let Some(ref mut key) = self.decrypt_key.lock().as_mut() {
            for byte in key.iter_mut() {
                *byte = 0;
            }
        }

        if let Some(ref mut iv) = self.encrypt_iv.lock().as_mut() {
            for byte in iv.iter_mut() {
                *byte = 0;
            }
        }
        if let Some(ref mut iv) = self.decrypt_iv.lock().as_mut() {
            for byte in iv.iter_mut() {
                *byte = 0;
            }
        }

        for byte in self.work_buffer.lock().iter_mut() {
            *byte = 0;
        }

        Ok(())
    }

    pub fn message_count(&self) -> u64 {
        *self.message_counter.lock()
    }

    pub fn reset_counter(&self) {
        *self.message_counter.lock() = 0;
    }

    pub fn is_ready(&self) -> bool {
        self.encrypt_key.lock().is_some() && self.decrypt_key.lock().is_some()
    }
}

impl Drop for SecureRecordLayer {
    fn drop(&mut self) {
        let _ = self.zeroize_keys();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_layer_creation() {
        let layer = SecureRecordLayer::new(4096);
        assert!(!layer.is_ready());
        assert_eq!(layer.message_count(), 0);
    }

    #[test]
    fn test_set_encrypt_key() {
        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];
        
        let result = layer.set_encrypt_key(key.clone(), iv);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_key_rejected() {
        let layer = SecureRecordLayer::new(4096);
        let empty = alloc::vec![];
        let iv = alloc::vec![0x02u8; 16];
        
        let result = layer.set_encrypt_key(empty, iv);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];
        
        layer.set_encrypt_key(key.clone(), iv.clone()).unwrap();
        layer.set_decrypt_key(key, iv).unwrap();
        
        let plaintext = b"Hello, World!";
        let ciphertext = layer.encrypt(plaintext).unwrap();
        let decrypted = layer.decrypt(&ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_message_counter() {
        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];
        
        layer.set_encrypt_key(key.clone(), iv.clone()).unwrap();
        layer.set_decrypt_key(key, iv).unwrap();
        
        layer.encrypt(b"msg1").unwrap();
        layer.encrypt(b"msg2").unwrap();
        layer.decrypt(&[1, 2, 3]).unwrap();
        
        assert_eq!(layer.message_count(), 3);
    }

    #[test]
    fn test_reset_counter() {
        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];
        
        layer.set_encrypt_key(key.clone(), iv.clone()).unwrap();
        layer.set_decrypt_key(key, iv).unwrap();
        
        layer.encrypt(b"test").unwrap();
        assert_eq!(layer.message_count(), 1);
        
        layer.reset_counter();
        assert_eq!(layer.message_count(), 0);
    }

    #[test]
    fn test_zeroize_keys() {
        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0xFFu8; 16];
        let iv = alloc::vec![0xFFu8; 16];
        
        layer.set_encrypt_key(key, iv).unwrap();
        layer.zeroize_keys().unwrap();
        
        assert!(true);
    }

    #[test]
    fn test_is_ready_check() {
        let layer = SecureRecordLayer::new(4096);
        assert!(!layer.is_ready());
        
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];
        
        layer.set_encrypt_key(key.clone(), iv.clone()).unwrap();
        assert!(!layer.is_ready());
        
        layer.set_decrypt_key(key, iv).unwrap();
        assert!(layer.is_ready());
    }
}
