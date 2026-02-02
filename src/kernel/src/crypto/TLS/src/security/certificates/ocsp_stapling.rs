extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use parking_lot::RwLock;
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OCSPStatus {
    Good,
    Revoked,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct OCSPResponse {
    pub cert_id: Vec<u8>,
    pub status: OCSPStatus,
    pub response_time: u64,
    pub validity_secs: u64,
    pub responder_url: String,
}

impl OCSPResponse {
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.response_time) <= self.validity_secs
    }
}

pub struct OCSPStapling {
    responses: Arc<RwLock<BTreeMap<Vec<u8>, OCSPResponse>>>,
    default_ttl: u64,
    max_responses: usize,
}

impl OCSPStapling {
    pub fn new() -> Self {
        Self::with_ttl(24 * 60 * 60)
    }

    pub fn with_ttl(default_ttl: u64) -> Self {
        Self {
            responses: Arc::new(RwLock::new(BTreeMap::new())),
            default_ttl,
            max_responses: 10000,
        }
    }

    pub fn staple_response(
        &self,
        cert_hash: Vec<u8>,
        status: OCSPStatus,
        responder_url: String,
    ) {
        let response = OCSPResponse {
            cert_id: cert_hash.clone(),
            status,
            response_time: Self::current_time(),
            validity_secs: self.default_ttl,
            responder_url,
        };

        let mut responses = self.responses.write();

        if responses.len() >= self.max_responses {
            if let Some(first_key) = responses.keys().next().cloned() {
                responses.remove(&first_key);
            }
        }

        responses.insert(cert_hash, response);
    }

    pub fn get_response(&self, cert_hash: &[u8]) -> Option<OCSPResponse> {
        let responses = self.responses.read();
        if let Some(response) = responses.get(cert_hash) {
            let now = Self::current_time();
            if response.is_valid(now) {
                return Some(response.clone());
            }
        }
        None
    }

    pub fn validate_cert_status(&self, cert_hash: &[u8]) -> Option<bool> {
        self.get_response(cert_hash)
            .map(|response| response.status == OCSPStatus::Good)
    }

    pub fn is_revoked(&self, cert_hash: &[u8]) -> bool {
        if let Some(response) = self.get_response(cert_hash) {
            response.status == OCSPStatus::Revoked
        } else {
            false
        }
    }

    pub fn update_response(&self, cert_hash: Vec<u8>, status: OCSPStatus) -> bool {
        let mut responses = self.responses.write();
        if let Some(response) = responses.get_mut(&cert_hash) {
            response.status = status;
            response.response_time = Self::current_time();
            true
        } else {
            false
        }
    }

    pub fn remove_response(&self, cert_hash: &[u8]) -> bool {
        let mut responses = self.responses.write();
        responses.remove(cert_hash).is_some()
    }

    pub fn cleanup_expired(&self) {
        let now = Self::current_time();
        let mut responses = self.responses.write();
        responses.retain(|_, response| response.is_valid(now));
    }

    pub fn stats(&self) -> OCSPStats {
        let responses = self.responses.read();
        let now = Self::current_time();

        let mut valid_count = 0;
        let mut revoked_count = 0;
        let mut good_count = 0;

        for response in responses.values() {
            if response.is_valid(now) {
                valid_count += 1;
                match response.status {
                    OCSPStatus::Good => good_count += 1,
                    OCSPStatus::Revoked => revoked_count += 1,
                    OCSPStatus::Unknown => {}
                }
            }
        }

        OCSPStats {
            total_cached: responses.len(),
            valid_responses: valid_count,
            good_certs: good_count,
            revoked_certs: revoked_count,
        }
    }

    pub fn clear_all(&self) {
        let mut responses = self.responses.write();
        responses.clear();
    }

    fn current_time() -> u64 {
        crate::time_abstraction::kernel_time_secs()
    }
}

#[derive(Clone, Debug)]
pub struct OCSPStats {
    pub total_cached: usize,
    pub valid_responses: usize,
    pub good_certs: usize,
    pub revoked_certs: usize,
}

impl Default for OCSPStapling {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::ToString;

    #[test]
    fn test_staple_response() {
        let ocsp = OCSPStapling::new();
        let cert_hash = b"test_cert_hash".to_vec();

        ocsp.staple_response(cert_hash, OCSPStatus::Good, "http://example.com".to_string());
        assert_eq!(ocsp.stats().total_cached, 1);
    }

    #[test]
    fn test_get_response() {
        let ocsp = OCSPStapling::new();
        let cert_hash = b"test_cert_hash".to_vec();

        ocsp.staple_response(cert_hash.clone(), OCSPStatus::Good, "http://example.com".to_string());
        let response = ocsp.get_response(&cert_hash);

        assert!(response.is_some());
        assert_eq!(response.unwrap().status, OCSPStatus::Good);
    }

    #[test]
    fn test_validate_cert_status() {
        let ocsp = OCSPStapling::new();
        let cert_hash = b"test_cert_hash".to_vec();

        ocsp.staple_response(cert_hash.clone(), OCSPStatus::Good, "http://example.com".to_string());
        let valid = ocsp.validate_cert_status(&cert_hash);

        assert_eq!(valid, Some(true));
    }

    #[test]
    fn test_is_revoked() {
        let ocsp = OCSPStapling::new();
        let cert_hash = b"test_cert_hash".to_vec();

        ocsp.staple_response(cert_hash.clone(), OCSPStatus::Revoked, "http://example.com".to_string());
        assert!(ocsp.is_revoked(&cert_hash));
    }

    #[test]
    fn test_remove_response() {
        let ocsp = OCSPStapling::new();
        let cert_hash = b"test_cert_hash".to_vec();

        ocsp.staple_response(cert_hash.clone(), OCSPStatus::Good, "http://example.com".to_string());
        assert!(ocsp.remove_response(&cert_hash));
        assert_eq!(ocsp.stats().total_cached, 0);
    }

    #[test]
    fn test_clear_all() {
        let ocsp = OCSPStapling::new();
        let cert_hash1 = b"cert_hash_1".to_vec();
        let cert_hash2 = b"cert_hash_2".to_vec();

        ocsp.staple_response(cert_hash1, OCSPStatus::Good, "http://example.com".to_string());
        ocsp.staple_response(cert_hash2, OCSPStatus::Revoked, "http://example.com".to_string());

        ocsp.clear_all();
        assert_eq!(ocsp.stats().total_cached, 0);
    }
}
