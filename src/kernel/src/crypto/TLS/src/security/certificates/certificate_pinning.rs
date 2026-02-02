extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use parking_lot::RwLock;
use alloc::sync::Arc;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificatePin {
    PublicKeyHash(Vec<u8>),
    CertificateHash(Vec<u8>),
    CertificateDer(Vec<u8>),
}

impl CertificatePin {
    pub fn from_public_key(key_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key_der);
        Self::PublicKeyHash(hasher.finalize().to_vec())
    }

    pub fn from_certificate(cert_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        Self::CertificateHash(hasher.finalize().to_vec())
    }

    pub fn from_der(cert_der: Vec<u8>) -> Self {
        Self::CertificateDer(cert_der)
    }

    pub fn hash(&self) -> Vec<u8> {
        match self {
            Self::PublicKeyHash(h) => h.clone(),
            Self::CertificateHash(h) => h.clone(),
            Self::CertificateDer(der) => {
                let mut hasher = Sha256::new();
                hasher.update(der);
                hasher.finalize().to_vec()
            }
        }
    }
}

pub struct CertificatePinner {
    pins: Arc<RwLock<BTreeMap<String, (CertificatePin, u64)>>>,
    validation_cache: Arc<RwLock<BTreeMap<Vec<u8>, bool>>>,
    pin_expiry_secs: u64,
    max_cache_entries: usize,
}

impl CertificatePinner {
    pub fn new() -> Self {
        Self::with_expiry(7 * 24 * 60 * 60)
    }

    pub fn with_expiry(pin_expiry_secs: u64) -> Self {
        Self {
            pins: Arc::new(RwLock::new(BTreeMap::new())),
            validation_cache: Arc::new(RwLock::new(BTreeMap::new())),
            pin_expiry_secs,
            max_cache_entries: 10000,
        }
    }

    pub fn pin_certificate(&self, hostname: &str, pin: CertificatePin) {
        let mut pins = self.pins.write();
        pins.insert(hostname.to_string(), (pin, Self::current_time()));
    }

    pub fn validate(&self, hostname: &str, cert_der: &[u8]) -> bool {
        let cert_hash = {
            let mut hasher = Sha256::new();
            hasher.update(cert_der);
            hasher.finalize().to_vec()
        };

        {
            let cache = self.validation_cache.read();
            if let Some(&result) = cache.get(&cert_hash) {
                return result;
            }
        }

        let pins = self.pins.read();
        let valid = if let Some((pin, created_at)) = pins.get(hostname) {
            if self.pin_expiry_secs > 0 {
                let now = Self::current_time();
                if now.saturating_sub(*created_at) > self.pin_expiry_secs {
                    return false;
                }
            }

            match pin {
                CertificatePin::PublicKeyHash(hash) => cert_hash.starts_with(&hash),
                CertificatePin::CertificateHash(hash) => cert_hash == *hash,
                CertificatePin::CertificateDer(der) => cert_der == der,
            }
        } else {
            true
        };

        let mut cache = self.validation_cache.write();
        if cache.len() >= self.max_cache_entries {
            if let Some(first_key) = cache.keys().next().cloned() {
                cache.remove(&first_key);
            }
        }
        cache.insert(cert_hash, valid);

        valid
    }

    pub fn remove_pin(&self, hostname: &str) -> bool {
        let mut pins = self.pins.write();
        pins.remove(hostname).is_some()
    }

    pub fn pin_count(&self) -> usize {
        let pins = self.pins.read();
        pins.len()
    }

    pub fn clear_all(&self) {
        let mut pins = self.pins.write();
        let mut cache = self.validation_cache.write();
        pins.clear();
        cache.clear();
    }

    pub fn cleanup_expired(&self) {
        if self.pin_expiry_secs == 0 {
            return;
        }

        let mut pins = self.pins.write();
        let now = Self::current_time();
        pins.retain(|_, (_, created_at)| {
            now.saturating_sub(*created_at) <= self.pin_expiry_secs
        });
    }

    fn current_time() -> u64 {
        crate::time_abstraction::kernel_time_secs()
    }
}

impl Default for CertificatePinner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_certificate() {
        let pinner = CertificatePinner::new();
        let cert = b"test_certificate_der";
        let pin = CertificatePin::from_certificate(cert);

        pinner.pin_certificate("example.com", pin);
        assert_eq!(pinner.pin_count(), 1);
    }

    #[test]
    fn test_validate_certificate() {
        let pinner = CertificatePinner::new();
        let cert = b"test_certificate_der";
        let pin = CertificatePin::from_certificate(cert);

        pinner.pin_certificate("example.com", pin);
        assert!(pinner.validate("example.com", cert));
    }

    #[test]
    fn test_invalid_certificate() {
        let pinner = CertificatePinner::new();
        let cert1 = b"test_certificate_1";
        let cert2 = b"test_certificate_2";
        let pin = CertificatePin::from_certificate(cert1);

        pinner.pin_certificate("example.com", pin);
        assert!(!pinner.validate("example.com", cert2));
    }

    #[test]
    fn test_remove_pin() {
        let pinner = CertificatePinner::new();
        let cert = b"test_certificate_der";
        let pin = CertificatePin::from_certificate(cert);

        pinner.pin_certificate("example.com", pin);
        assert!(pinner.remove_pin("example.com"));
        assert_eq!(pinner.pin_count(), 0);
    }

    #[test]
    fn test_cache_validation_result() {
        let pinner = CertificatePinner::new();
        let cert = b"test_certificate_der";
        let pin = CertificatePin::from_certificate(cert);

        pinner.pin_certificate("example.com", pin);
        
        assert!(pinner.validate("example.com", cert));
        
        assert!(pinner.validate("example.com", cert));
    }

    #[test]
    fn test_clear_all() {
        let pinner = CertificatePinner::new();
        let cert = b"test_certificate_der";
        let pin = CertificatePin::from_certificate(cert);

        pinner.pin_certificate("example.com", pin);
        pinner.clear_all();
        assert_eq!(pinner.pin_count(), 0);
    }
}
