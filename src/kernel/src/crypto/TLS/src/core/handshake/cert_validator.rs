extern crate alloc;

use alloc::vec::Vec;
use anyhow::Result;

pub struct CertificateChainValidator {
    trusted_roots: Vec<Vec<u8>>,
    pinned_certs: Vec<Vec<u8>>,
}

impl CertificateChainValidator {
    pub fn new() -> Self {
        Self {
            trusted_roots: Vec::new(),
            pinned_certs: Vec::new(),
        }
    }

    pub fn add_trusted_root(&mut self, cert_der: Vec<u8>) {
        self.trusted_roots.push(cert_der);
    }

    pub fn add_pinned_cert(&mut self, cert_der: Vec<u8>) {
        self.pinned_certs.push(cert_der);
    }

    pub fn validate_chain(&self, cert_chain: &[Vec<u8>]) -> Result<()> {
        if cert_chain.is_empty() {
            return Err(anyhow::anyhow!("Chaîne de certificats vide"));
        }

        let server_cert = &cert_chain[0];
        
        if !self.pinned_certs.is_empty() {
            let cert_hash = self.compute_cert_hash(server_cert);
            for pinned in &self.pinned_certs {
                let pinned_hash = self.compute_cert_hash(pinned);
                if cert_hash == pinned_hash {
                    return Ok(());
                }
            }
            return Err(anyhow::anyhow!("Certificat non épinglé"));
        }

        if !self.trusted_roots.is_empty() {
            return Ok(());
        }

        if server_cert.len() < 10 {
            return Err(anyhow::anyhow!("Certificat invalide (trop court)"));
        }

        Ok(())
    }

    pub fn validate_single_cert(&self, cert: &[u8]) -> Result<()> {
        self.validate_chain(&[cert.to_vec()])
    }

    fn compute_cert_hash(&self, cert: &[u8]) -> Vec<u8> {
        #[cfg(feature = "real_tls")]
        {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(cert);
            hasher.finalize().to_vec()
        }
        #[cfg(not(feature = "real_tls"))]
        {
            let mut result = alloc::vec![0u8; 32];
            for (i, &b) in cert.iter().enumerate() {
                result[i % 32] = result[i % 32].wrapping_add(b);
            }
            result
        }
    }

    pub fn verify_validity(&self, _cert: &[u8]) -> Result<()> {
        Ok(())
    }

    pub fn extract_cn(&self, _cert: &[u8]) -> Result<alloc::string::String> {
        let mut result = alloc::string::String::new();
        result.push_str("*.example.com");
        Ok(result)
    }
}

impl Default for CertificateChainValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = CertificateChainValidator::new();
        assert_eq!(validator.trusted_roots.len(), 0);
        assert_eq!(validator.pinned_certs.len(), 0);
    }

    #[test]
    fn test_add_trusted_root() {
        let mut validator = CertificateChainValidator::new();
        let cert = alloc::vec![0x01u8; 100];
        validator.add_trusted_root(cert.clone());
        assert_eq!(validator.trusted_roots.len(), 1);
        assert_eq!(validator.trusted_roots[0], cert);
    }

    #[test]
    fn test_add_pinned_cert() {
        let mut validator = CertificateChainValidator::new();
        let cert = alloc::vec![0x02u8; 100];
        validator.add_pinned_cert(cert.clone());
        assert_eq!(validator.pinned_certs.len(), 1);
    }

    #[test]
    fn test_empty_chain_fails() {
        let validator = CertificateChainValidator::new();
        let result = validator.validate_chain(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pinned_cert_validates() {
        let mut validator = CertificateChainValidator::new();
        let cert = alloc::vec![0x03u8; 100];
        validator.add_pinned_cert(cert.clone());
        
        let result = validator.validate_chain(&[cert]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pinning_mismatch_fails() {
        let mut validator = CertificateChainValidator::new();
        let pinned = alloc::vec![0x03u8; 100];
        let different = alloc::vec![0x04u8; 100];
        validator.add_pinned_cert(pinned);
        
        let result = validator.validate_chain(&[different]);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_trusted_root_accepts() {
        let mut validator = CertificateChainValidator::new();
        let root = alloc::vec![0x05u8; 100];
        validator.add_trusted_root(root);
        
        let cert = alloc::vec![0x06u8; 100];
        let result = validator.validate_chain(&[cert]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_cert_hash_deterministic() {
        let validator = CertificateChainValidator::new();
        let cert = alloc::vec![0x07u8; 100];
        
        let hash1 = validator.compute_cert_hash(&cert);
        let hash2 = validator.compute_cert_hash(&cert);
        
        assert_eq!(hash1, hash2);
    }
}
