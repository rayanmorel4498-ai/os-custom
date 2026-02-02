extern crate alloc;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacValidator {
    secret_key: Vec<u8>,
}

impl HmacValidator {
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self { secret_key }
    }

    pub fn compute(&self, data: &[u8]) -> alloc::vec::Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .expect("HMAC-SHA256 key length is valid");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .expect("HMAC-SHA256 key length is valid");
        mac.update(data);

        mac.verify_slice(signature).is_ok()
    }

    pub fn rotate_key(&mut self, new_key: Vec<u8>) {
        self.secret_key = new_key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_hmac_compute_verify() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let validator = HmacValidator::new(key);

        let data = b"test_token_data";
        let signature = validator.compute(data);

        assert!(validator.verify(data, &signature));
    }

    #[test]
    fn test_hmac_invalid_signature() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let validator = HmacValidator::new(key);

        let data = b"test_token_data";
        let mut invalid_signature = validator.compute(data);
        invalid_signature[0] ^= 0xFF;

        assert!(!validator.verify(data, &invalid_signature));
    }

    #[test]
    fn test_key_rotation() {
        let key1 = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut validator = HmacValidator::new(key1);

        let data = b"test_token_data";
        let sig_with_key1 = validator.compute(data);

        let key2 = vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        validator.rotate_key(key2);

        assert!(!validator.verify(data, &sig_with_key1));

        let sig_with_key2 = validator.compute(data);
        assert!(validator.verify(data, &sig_with_key2));
    }
}
