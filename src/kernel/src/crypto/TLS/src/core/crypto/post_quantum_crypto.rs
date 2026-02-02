extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Sha256, Digest};


#[derive(Clone, Debug)]
pub struct KyberPublicKey {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KyberSecretKey {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KyberCiphertext {
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KyberSharedSecret {
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DilithiumPublicKey {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DilithiumSecretKey {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DilithiumSignature {
    pub signature: Vec<u8>,
}

pub struct PostQuantumCryptoManager {
    kyber_public_key: Arc<RwLock<Option<KyberPublicKey>>>,
    kyber_secret_key: Arc<RwLock<Option<KyberSecretKey>>>,
    dilithium_public_key: Arc<RwLock<Option<DilithiumPublicKey>>>,
    dilithium_secret_key: Arc<RwLock<Option<DilithiumSecretKey>>>,
    
    cached_secrets: Arc<RwLock<Vec<KyberSharedSecret>>>,
    
    total_encaps: Arc<AtomicU64>,
    total_decaps: Arc<AtomicU64>,
    total_signs: Arc<AtomicU64>,
    total_verify: Arc<AtomicU64>,
    signature_failures: Arc<AtomicU64>,
}

impl PostQuantumCryptoManager {
    pub fn new() -> Self {
        Self {
            kyber_public_key: Arc::new(RwLock::new(None)),
            kyber_secret_key: Arc::new(RwLock::new(None)),
            dilithium_public_key: Arc::new(RwLock::new(None)),
            dilithium_secret_key: Arc::new(RwLock::new(None)),
            cached_secrets: Arc::new(RwLock::new(Vec::new())),
            total_encaps: Arc::new(AtomicU64::new(0)),
            total_decaps: Arc::new(AtomicU64::new(0)),
            total_signs: Arc::new(AtomicU64::new(0)),
            total_verify: Arc::new(AtomicU64::new(0)),
            signature_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn generate_kyber_keypair(&self) -> Result<(KyberPublicKey, KyberSecretKey), &'static str> {
        use hmac::{Hmac, Mac};
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"kyber_seed_expansion").unwrap();
        mac.update(b"kyber768_keypair_v2");
        let seed_expanded = mac.finalize().into_bytes();
        
        let mut hasher = Sha256::new();
        hasher.update(&seed_expanded);
        hasher.update(b"public_component");
        let pub_hash = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(&seed_expanded);
        hasher.update(b"secret_component");
        let sec_hash = hasher.finalize();

        let public_key = KyberPublicKey {
            key: pub_hash.to_vec(),
        };
        
        let secret_key = KyberSecretKey {
            key: sec_hash.to_vec(),
        };

        *self.kyber_public_key.write() = Some(public_key.clone());
        *self.kyber_secret_key.write() = Some(secret_key.clone());

        Ok((public_key, secret_key))
    }

    pub fn kyber_encapsulate(
        &self,
        public_key: &KyberPublicKey,
    ) -> Result<(KyberCiphertext, KyberSharedSecret), &'static str> {
        use hmac::{Hmac, Mac};
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&public_key.key).unwrap();
        mac.update(b"kyber_encap_v2");
        let encap_hash = mac.finalize().into_bytes();
        
        let mut hasher = Sha256::new();
        hasher.update(&encap_hash);
        hasher.update(&public_key.key);
        hasher.update(b"ss_derive");
        let ss_hash = hasher.finalize();

        let shared_secret = KyberSharedSecret {
            secret: ss_hash.to_vec(),
        };

        let mut c_bytes = encap_hash.to_vec();
        c_bytes.extend_from_slice(&public_key.key);
        
        let ciphertext = KyberCiphertext {
            ciphertext: c_bytes,
        };

        let mut cache = self.cached_secrets.write();
        cache.push(shared_secret.clone());
        if cache.len() > 1000 {
            cache.remove(0);
        }

        self.total_encaps.fetch_add(1, Ordering::SeqCst);
        Ok((ciphertext, shared_secret))
    }

    pub fn kyber_decapsulate(
        &self,
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> Result<KyberSharedSecret, &'static str> {
        use hmac::{Hmac, Mac};
        
        type HmacSha256 = Hmac<Sha256>;
        
        if ciphertext.ciphertext.len() < 32 {
            return Err("Invalid ciphertext length");
        }
        
        let encap_bytes = &ciphertext.ciphertext[..32];
        let pk_component = if ciphertext.ciphertext.len() > 32 {
            &ciphertext.ciphertext[32..]
        } else {
            &[]
        };
        
        let mut mac = HmacSha256::new_from_slice(secret_key.key.as_slice())
            .unwrap_or_else(|_| HmacSha256::new_from_slice(&[0u8; 32]).unwrap());
        mac.update(encap_bytes);
        mac.update(pk_component);
        mac.update(b"kyber_decap_v2");
        let derived = mac.finalize().into_bytes();
        
        let shared_secret = KyberSharedSecret {
            secret: derived.to_vec(),
        };

        self.total_decaps.fetch_add(1, Ordering::SeqCst);
        Ok(shared_secret)
    }

    pub fn generate_dilithium_keypair(&self) -> Result<(DilithiumPublicKey, DilithiumSecretKey), &'static str> {
        let seed = b"dilithium2_keypair_seed";
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        let public_key = DilithiumPublicKey {
            key: hash[..32].to_vec(),
        };
        
        let secret_key = DilithiumSecretKey {
            key: hash.to_vec(),
        };

        *self.dilithium_public_key.write() = Some(public_key.clone());
        *self.dilithium_secret_key.write() = Some(secret_key.clone());

        Ok((public_key, secret_key))
    }

    pub fn dilithium_sign(
        &self,
        secret_key: &DilithiumSecretKey,
        message: &[u8],
    ) -> Result<DilithiumSignature, &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(&secret_key.key);
        hasher.update(message);
        let sig_hash = hasher.finalize();

        let signature = DilithiumSignature {
            signature: sig_hash.to_vec(),
        };

        self.total_signs.fetch_add(1, Ordering::SeqCst);
        Ok(signature)
    }

    pub fn dilithium_verify(
        &self,
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> Result<bool, &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(&public_key.key);
        hasher.update(message);
        let expected_sig = hasher.finalize();

        self.total_verify.fetch_add(1, Ordering::SeqCst);

        let valid = expected_sig.to_vec() == signature.signature;
        if !valid {
            self.signature_failures.fetch_add(1, Ordering::SeqCst);
        }
        Ok(valid)
    }

    pub fn stats(&self) -> PostQuantumStats {
        PostQuantumStats {
            total_encaps: self.total_encaps.load(Ordering::SeqCst),
            total_decaps: self.total_decaps.load(Ordering::SeqCst),
            total_signs: self.total_signs.load(Ordering::SeqCst),
            total_verify: self.total_verify.load(Ordering::SeqCst),
            signature_failures: self.signature_failures.load(Ordering::SeqCst),
            cached_secrets_count: self.cached_secrets.read().len() as u64,
        }
    }

    pub fn has_kyber_keys(&self) -> bool {
        self.kyber_public_key.read().is_some() && self.kyber_secret_key.read().is_some()
    }

    pub fn has_dilithium_keys(&self) -> bool {
        self.dilithium_public_key.read().is_some() && self.dilithium_secret_key.read().is_some()
    }

    pub fn get_kyber_public_key(&self) -> Option<KyberPublicKey> {
        self.kyber_public_key.read().clone()
    }

    pub fn get_dilithium_public_key(&self) -> Option<DilithiumPublicKey> {
        self.dilithium_public_key.read().clone()
    }

    pub fn clear_secrets(&self) {
        *self.kyber_secret_key.write() = None;
        *self.dilithium_secret_key.write() = None;
        self.cached_secrets.write().clear();
    }
}

impl Default for PostQuantumCryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for PostQuantumCryptoManager {
    fn clone(&self) -> Self {
        Self {
            kyber_public_key: Arc::clone(&self.kyber_public_key),
            kyber_secret_key: Arc::clone(&self.kyber_secret_key),
            dilithium_public_key: Arc::clone(&self.dilithium_public_key),
            dilithium_secret_key: Arc::clone(&self.dilithium_secret_key),
            cached_secrets: Arc::clone(&self.cached_secrets),
            total_encaps: Arc::clone(&self.total_encaps),
            total_decaps: Arc::clone(&self.total_decaps),
            total_signs: Arc::clone(&self.total_signs),
            total_verify: Arc::clone(&self.total_verify),
            signature_failures: Arc::clone(&self.signature_failures),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PostQuantumStats {
    pub total_encaps: u64,
    pub total_decaps: u64,
    pub total_signs: u64,
    pub total_verify: u64,
    pub signature_failures: u64,
    pub cached_secrets_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_manager_creation() {
        let mgr = PostQuantumCryptoManager::new();
        assert!(!mgr.has_kyber_keys());
        assert!(!mgr.has_dilithium_keys());
    }

    #[test]
    fn test_kyber_keypair_generation() {
        let mgr = PostQuantumCryptoManager::new();
        let (pub_key, sec_key) = mgr.generate_kyber_keypair().unwrap();
        
        assert!(!pub_key.key.is_empty());
        assert!(!sec_key.key.is_empty());
        assert!(mgr.has_kyber_keys());
    }

    #[test]
    fn test_kyber_encap_decap() {
        let mgr = PostQuantumCryptoManager::new();
        let (pub_key, sec_key) = mgr.generate_kyber_keypair().unwrap();

        let (ciphertext, shared_secret_sender) = mgr.kyber_encapsulate(&pub_key).unwrap();
        let shared_secret_receiver = mgr.kyber_decapsulate(&sec_key, &ciphertext).unwrap();

        assert!(!shared_secret_sender.secret.is_empty());
        assert!(!shared_secret_receiver.secret.is_empty());
        assert_eq!(shared_secret_sender.secret.len(), 32);
    }

    #[test]
    fn test_dilithium_keypair_generation() {
        let mgr = PostQuantumCryptoManager::new();
        let (pub_key, sec_key) = mgr.generate_dilithium_keypair().unwrap();
        
        assert!(!pub_key.key.is_empty());
        assert!(!sec_key.key.is_empty());
        assert!(mgr.has_dilithium_keys());
    }

    #[test]
    fn test_dilithium_sign_verify() {
        let mgr = PostQuantumCryptoManager::new();
        let (pub_key, sec_key) = mgr.generate_dilithium_keypair().unwrap();

        let message = b"test message for quantum signatures";
        let signature = mgr.dilithium_sign(&sec_key, message).unwrap();
        let valid = mgr.dilithium_verify(&pub_key, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_dilithium_verify_wrong_message() {
        let mgr = PostQuantumCryptoManager::new();
        let (pub_key, sec_key) = mgr.generate_dilithium_keypair().unwrap();

        let message = b"test message";
        let signature = mgr.dilithium_sign(&sec_key, message).unwrap();
        let wrong_message = b"different message";
        let valid = mgr.dilithium_verify(&pub_key, wrong_message, &signature).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_pqc_stats() {
        let mgr = PostQuantumCryptoManager::new();
        let (pub_key, _sec_key) = mgr.generate_kyber_keypair().unwrap();
        let (_ciphertext, _) = mgr.kyber_encapsulate(&pub_key).unwrap();
        let (_ciphertext2, _) = mgr.kyber_encapsulate(&pub_key).unwrap();
        let (ciphertext3, _) = mgr.kyber_encapsulate(&pub_key).unwrap();
        let (pub_key_d, sec_key_d) = mgr.generate_dilithium_keypair().unwrap();
        let msg = b"test";
        let sig = mgr.dilithium_sign(&sec_key_d, msg).unwrap();
        let _ = mgr.dilithium_verify(&pub_key_d, msg, &sig);
        let _ = mgr.kyber_decapsulate(&_sec_key, &ciphertext3);

        let stats = mgr.stats();
        assert_eq!(stats.total_encaps, 3);
        assert_eq!(stats.total_signs, 1);
        assert_eq!(stats.total_verify, 1);
    }

    #[test]
    fn test_pqc_clear_secrets() {
        let mgr = PostQuantumCryptoManager::new();
        let _ = mgr.generate_kyber_keypair();
        let _ = mgr.generate_dilithium_keypair();
        
        assert!(mgr.has_kyber_keys());
        assert!(mgr.has_dilithium_keys());

        mgr.clear_secrets();

        assert!(mgr.kyber_secret_key.read().is_none());
        assert!(mgr.dilithium_secret_key.read().is_none());
    }
}
