extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use parking_lot::RwLock;
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientCertificate {
    pub cert_der: Vec<u8>,
    pub public_key: Vec<u8>,
    pub subject_cn: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub fingerprint: Vec<u8>,
}

impl ClientCertificate {
    pub fn is_valid(&self, now: u64) -> bool {
        now >= self.valid_from && now <= self.valid_until
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthPolicy {
    Optional,
    Required,
    RequiredAndTrusted,
}

pub struct ClientAuthenticator {
    trusted_certs: Arc<RwLock<BTreeMap<Vec<u8>, ClientCertificate>>>,
    revoked_certs: Arc<RwLock<Vec<Vec<u8>>>>,
    policy: ClientAuthPolicy,
}

impl ClientAuthenticator {
    pub fn new(policy: ClientAuthPolicy) -> Self {
        Self {
            trusted_certs: Arc::new(RwLock::new(BTreeMap::new())),
            revoked_certs: Arc::new(RwLock::new(Vec::new())),
            policy,
        }
    }

    pub fn add_trusted_cert(&self, cert: ClientCertificate) {
        let mut certs = self.trusted_certs.write();
        certs.insert(cert.fingerprint.clone(), cert);
    }

    pub fn revoke_cert(&self, fingerprint: Vec<u8>) {
        let mut revoked = self.revoked_certs.write();
        if !revoked.contains(&fingerprint) {
            revoked.push(fingerprint);
        }
    }

    pub fn is_revoked(&self, fingerprint: &[u8]) -> bool {
        let revoked = self.revoked_certs.read();
        revoked.contains(&fingerprint.to_vec())
    }

    pub fn authenticate(&self, cert: &ClientCertificate) -> Result<bool, ClientAuthError> {
        if self.policy == ClientAuthPolicy::Optional && cert.cert_der.is_empty() {
            return Ok(false);
        }

        let now = Self::current_time();
        if !cert.is_valid(now) {
            return Err(ClientAuthError::CertificateExpired);
        }

        if self.is_revoked(&cert.fingerprint) {
            return Err(ClientAuthError::CertificateRevoked);
        }

        if self.policy == ClientAuthPolicy::RequiredAndTrusted {
            let certs = self.trusted_certs.read();
            if !certs.contains_key(&cert.fingerprint) {
                return Err(ClientAuthError::UntrustedCertificate);
            }
        }

        Ok(true)
    }

    pub fn get_cert(&self, fingerprint: &[u8]) -> Option<ClientCertificate> {
        let certs = self.trusted_certs.read();
        certs.get(fingerprint).cloned()
    }

    pub fn list_trusted_subjects(&self) -> Vec<String> {
        let certs = self.trusted_certs.read();
        certs.values().map(|c| c.subject_cn.clone()).collect()
    }

    pub fn stats(&self) -> ClientAuthStats {
        let certs = self.trusted_certs.read();
        let revoked = self.revoked_certs.read();

        ClientAuthStats {
            trusted_certs: certs.len(),
            revoked_certs: revoked.len(),
            policy: self.policy,
        }
    }

    pub fn clear_trusted(&self) {
        let mut certs = self.trusted_certs.write();
        certs.clear();
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthError {
    CertificateExpired,
    CertificateRevoked,
    UntrustedCertificate,
    MissingCertificate,
}

#[derive(Clone, Debug)]
pub struct ClientAuthStats {
    pub trusted_certs: usize,
    pub revoked_certs: usize,
    pub policy: ClientAuthPolicy,
}

impl Default for ClientAuthenticator {
    fn default() -> Self {
        Self::new(ClientAuthPolicy::Optional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::ToString;

    fn create_test_cert() -> ClientCertificate {
        ClientCertificate {
            cert_der: b"test_cert".to_vec(),
            public_key: b"test_key".to_vec(),
            subject_cn: "client.example.com".to_string(),
            valid_from: 0,
            valid_until: 1000000000,
            fingerprint: b"test_fingerprint".to_vec(),
        }
    }

    #[test]
    fn test_add_trusted_cert() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Optional);
        let cert = create_test_cert();

        auth.add_trusted_cert(cert);
        assert_eq!(auth.stats().trusted_certs, 1);
    }

    #[test]
    fn test_authenticate_valid_cert() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Required);
        let cert = create_test_cert();

        let result = auth.authenticate(&cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_revoke_cert() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Required);
        let cert = create_test_cert();

        auth.revoke_cert(cert.fingerprint.clone());
        let result = auth.authenticate(&cert);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ClientAuthError::CertificateRevoked);
    }

    #[test]
    fn test_is_revoked() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Optional);
        let fingerprint = b"test_fingerprint".to_vec();

        auth.revoke_cert(fingerprint.clone());
        assert!(auth.is_revoked(&fingerprint));
    }

    #[test]
    fn test_get_cert() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Optional);
        let cert = create_test_cert();
        let fingerprint = cert.fingerprint.clone();

        auth.add_trusted_cert(cert);
        let retrieved = auth.get_cert(&fingerprint);

        assert!(retrieved.is_some());
    }

    #[test]
    fn test_list_trusted_subjects() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Optional);
        let cert = create_test_cert();

        auth.add_trusted_cert(cert);
        let subjects = auth.list_trusted_subjects();

        assert!(subjects.contains(&"client.example.com".to_string()));
    }

    #[test]
    fn test_clear_trusted() {
        let auth = ClientAuthenticator::new(ClientAuthPolicy::Optional);
        let cert = create_test_cert();

        auth.add_trusted_cert(cert);
        auth.clear_trusted();

        assert_eq!(auth.stats().trusted_certs, 0);
    }
}
