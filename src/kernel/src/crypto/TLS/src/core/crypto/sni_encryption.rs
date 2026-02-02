extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Sha256, Digest};
use crate::validation;


static NONCE_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct EncryptedSNI {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub length_tag: u16,
}

#[derive(Clone, Debug)]
pub struct MaskedFingerprint {
    pub original: Vec<u8>,
    pub masked: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ObfuscationState {
    pub enabled: bool,
    pub padding_block_size: usize,
    pub nonce_rotation_ms: u64,
}

impl Default for ObfuscationState {
    fn default() -> Self {
        Self {
            enabled: true,
            padding_block_size: 256,
            nonce_rotation_ms: 5000,
        }
    }
}

pub struct SNIEncryptionManager {
    obfuscation_state: Arc<RwLock<ObfuscationState>>,
    
    sni_encryption_key: Arc<RwLock<Vec<u8>>>,
    
    fingerprint_nonce: Arc<RwLock<Vec<u8>>>,
    
    last_nonce_rotation: Arc<RwLock<u64>>,
    
    total_sni_encryptions: Arc<AtomicU64>,
    total_sni_decryptions: Arc<AtomicU64>,
    total_fingerprint_masks: Arc<AtomicU64>,
    metadata_bytes_obfuscated: Arc<AtomicU64>,
}

impl SNIEncryptionManager {
    pub fn new() -> Self {
        let key = Self::generate_key();
        let nonce = Self::generate_nonce();
        
        Self {
            obfuscation_state: Arc::new(RwLock::new(ObfuscationState::default())),
            sni_encryption_key: Arc::new(RwLock::new(key)),
            fingerprint_nonce: Arc::new(RwLock::new(nonce)),
            last_nonce_rotation: Arc::new(RwLock::new(0)),
            total_sni_encryptions: Arc::new(AtomicU64::new(0)),
            total_sni_decryptions: Arc::new(AtomicU64::new(0)),
            total_fingerprint_masks: Arc::new(AtomicU64::new(0)),
            metadata_bytes_obfuscated: Arc::new(AtomicU64::new(0)),
        }
    }

    fn generate_key() -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sni_encryption_key_seed");
        hasher.finalize().to_vec()
    }

    fn generate_nonce() -> Vec<u8> {
        let counter = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        
        let mut hasher = Sha256::new();
        hasher.update(b"sni_nonce_seed");
        hasher.update(counter.to_le_bytes());
        hasher.finalize()[..16].to_vec()
    }

    pub fn encrypt_sni(&self, hostname: &str) -> Result<EncryptedSNI, &'static str> {
        if let Err(_) = validation::validate_hostname(hostname) {
            return Err("Invalid hostname format");
        }

        let state = self.obfuscation_state.read();
        if !state.enabled {
            return Err("SNI encryption disabled");
        }

        let key = self.sni_encryption_key.read();
        let nonce = Self::generate_nonce();
        
        let padded = self.pad_metadata(hostname.as_bytes(), state.padding_block_size);
        
        let ciphertext: Vec<u8> = padded.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ key[i % key.len()] ^ nonce[i % nonce.len()])
            .collect();

        self.metadata_bytes_obfuscated.fetch_add(ciphertext.len() as u64, Ordering::SeqCst);
        self.total_sni_encryptions.fetch_add(1, Ordering::SeqCst);

        Ok(EncryptedSNI {
            ciphertext,
            nonce,
            length_tag: hostname.len() as u16,
        })
    }

    pub fn decrypt_sni(&self, encrypted: &EncryptedSNI) -> Result<String, &'static str> {
        let key = self.sni_encryption_key.read();
        
        let decrypted: Vec<u8> = encrypted.ciphertext.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ key[i % key.len()] ^ encrypted.nonce[i % encrypted.nonce.len()])
            .collect();

        let hostname_bytes = &decrypted[..encrypted.length_tag as usize];
        let hostname = String::from_utf8(hostname_bytes.to_vec())
            .map_err(|_| "Invalid UTF-8 in SNI")?;

        self.total_sni_decryptions.fetch_add(1, Ordering::SeqCst);

        Ok(hostname)
    }

    pub fn mask_fingerprint(&self, fingerprint: &[u8]) -> Result<MaskedFingerprint, &'static str> {
        let nonce = Self::generate_nonce();
        
        let masked: Vec<u8> = fingerprint.iter()
            .enumerate()
            .map(|(i, f)| f ^ nonce[i % nonce.len()])
            .collect();

        self.metadata_bytes_obfuscated.fetch_add(masked.len() as u64, Ordering::SeqCst);
        self.total_fingerprint_masks.fetch_add(1, Ordering::SeqCst);

        Ok(MaskedFingerprint {
            original: fingerprint.to_vec(),
            masked: masked.clone(),
            nonce,
        })
    }

    pub fn unmask_fingerprint(&self, masked: &MaskedFingerprint) -> Result<Vec<u8>, &'static str> {
        let unmasked: Vec<u8> = masked.masked.iter()
            .enumerate()
            .map(|(i, m)| m ^ masked.nonce[i % masked.nonce.len()])
            .collect();

        Ok(unmasked)
    }

    fn pad_metadata(&self, data: &[u8], block_size: usize) -> Vec<u8> {
        let remainder = data.len() % block_size;
        let padding_len = if remainder == 0 {
            block_size
        } else {
            block_size - remainder
        };

        let mut padded = data.to_vec();
        padded.extend_from_slice(&alloc::vec![0xAAu8; padding_len]);
        padded
    }

    pub fn set_obfuscation_enabled(&self, enabled: bool) {
        self.obfuscation_state.write().enabled = enabled;
    }

    pub fn set_padding_block_size(&self, size: usize) {
        self.obfuscation_state.write().padding_block_size = size;
    }

    pub fn rotate_fingerprint_nonce(&self) {
        let new_nonce = Self::generate_nonce();
        *self.fingerprint_nonce.write() = new_nonce;
        *self.last_nonce_rotation.write() = crate::time_abstraction::kernel_time_secs() * 1000;
    }

    pub fn should_rotate_nonce(&self) -> bool {
        let state = self.obfuscation_state.read();
        let last = *self.last_nonce_rotation.read();
        let now = crate::time_abstraction::kernel_time_secs() * 1000;
        
        now - last > state.nonce_rotation_ms
    }

    pub fn stats(&self) -> SNIEncryptionStats {
        SNIEncryptionStats {
            total_sni_encryptions: self.total_sni_encryptions.load(Ordering::SeqCst),
            total_sni_decryptions: self.total_sni_decryptions.load(Ordering::SeqCst),
            total_fingerprint_masks: self.total_fingerprint_masks.load(Ordering::SeqCst),
            metadata_bytes_obfuscated: self.metadata_bytes_obfuscated.load(Ordering::SeqCst),
            obfuscation_enabled: self.obfuscation_state.read().enabled,
            padding_block_size: self.obfuscation_state.read().padding_block_size,
        }
    }

    pub fn state(&self) -> ObfuscationState {
        self.obfuscation_state.read().clone()
    }
}

impl Default for SNIEncryptionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SNIEncryptionManager {
    fn clone(&self) -> Self {
        Self {
            obfuscation_state: Arc::clone(&self.obfuscation_state),
            sni_encryption_key: Arc::clone(&self.sni_encryption_key),
            fingerprint_nonce: Arc::clone(&self.fingerprint_nonce),
            last_nonce_rotation: Arc::clone(&self.last_nonce_rotation),
            total_sni_encryptions: Arc::clone(&self.total_sni_encryptions),
            total_sni_decryptions: Arc::clone(&self.total_sni_decryptions),
            total_fingerprint_masks: Arc::clone(&self.total_fingerprint_masks),
            metadata_bytes_obfuscated: Arc::clone(&self.metadata_bytes_obfuscated),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SNIEncryptionStats {
    pub total_sni_encryptions: u64,
    pub total_sni_decryptions: u64,
    pub total_fingerprint_masks: u64,
    pub metadata_bytes_obfuscated: u64,
    pub obfuscation_enabled: bool,
    pub padding_block_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_encryption_manager_creation() {
        let mgr = SNIEncryptionManager::new();
        assert!(mgr.state().enabled);
    }

    #[test]
    fn test_sni_encrypt_decrypt() {
        let mgr = SNIEncryptionManager::new();
        let hostname = "example.com";

        let encrypted = mgr.encrypt_sni(hostname).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.nonce.is_empty());

        let decrypted = mgr.decrypt_sni(&encrypted).unwrap();
        assert_eq!(decrypted, hostname);
    }

    #[test]
    fn test_sni_padding_obfuscates_length() {
        let mgr = SNIEncryptionManager::new();
        mgr.set_padding_block_size(256);

        let short = mgr.encrypt_sni("a.com").unwrap();
        let long = mgr.encrypt_sni("verylongdomainname.example.com").unwrap();

        assert_eq!(short.ciphertext.len(), long.ciphertext.len());
    }

    #[test]
    fn test_fingerprint_masking() {
        let mgr = SNIEncryptionManager::new();
        let fingerprint = b"sha256_fingerprint_32_bytes_long!";

        let masked = mgr.mask_fingerprint(fingerprint).unwrap();
        assert_ne!(masked.masked, fingerprint);
        assert!(!masked.nonce.is_empty());

        let unmasked = mgr.unmask_fingerprint(&masked).unwrap();
        assert_eq!(unmasked, fingerprint);
    }

    #[test]
    fn test_obfuscation_disable() {
        let mgr = SNIEncryptionManager::new();
        mgr.set_obfuscation_enabled(false);

        let result = mgr.encrypt_sni("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_sni_encryption_stats() {
        let mgr = SNIEncryptionManager::new();
        let _ = mgr.encrypt_sni("test.com").ok();
        let _ = mgr.encrypt_sni("example.org").ok();
        let encrypted = mgr.encrypt_sni("private.net").ok();
        if let Some(enc) = encrypted {
            let _ = mgr.decrypt_sni(&enc).ok();
        }

        let stats = mgr.stats();
        assert_eq!(stats.total_sni_encryptions, 3);
        assert!(stats.total_sni_decryptions > 0);
    }

    #[test]
    fn test_nonce_rotation() {
        let mgr = SNIEncryptionManager::new();
        mgr.rotate_fingerprint_nonce();
        
        assert!(!mgr.should_rotate_nonce());
    }

    #[test]
    fn test_multiple_fingerprint_masks_different() {
        let mgr = SNIEncryptionManager::new();
        let fingerprint = b"same_fingerprint_content_here!!";

        let mask1 = mgr.mask_fingerprint(fingerprint).unwrap();
        let mask2 = mgr.mask_fingerprint(fingerprint).unwrap();

        assert_ne!(mask1.nonce, mask2.nonce);
        
        let unmask1 = mgr.unmask_fingerprint(&mask1).unwrap();
        let unmask2 = mgr.unmask_fingerprint(&mask2).unwrap();
        assert_eq!(unmask1, fingerprint);
        assert_eq!(unmask2, fingerprint);
    }
}
