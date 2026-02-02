
use alloc::vec::Vec;
use alloc::string::String;
use core::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct SecureKey {
    data: Zeroizing<Vec<u8>>,
}

impl SecureKey {
    pub fn new(key_bytes: Vec<u8>) -> Self {
        SecureKey {
            data: Zeroizing::new(key_bytes),
        }
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        match hex::decode(hex_str) {
            Ok(bytes) => Ok(Self::new(bytes)),
            Err(_) => Err("invalid_hex"),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.deref()
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.data.deref_mut()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn zeroize_now(&mut self) {
        self.data.zeroize();
    }
}

impl Deref for SecureKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

pub struct SecureString {
    data: Zeroizing<String>,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        SecureString {
            data: Zeroizing::new(s),
        }
    }

    pub fn as_str(&self) -> &str {
        self.data.deref()
    }

    pub fn zeroize_now(&mut self) {
        self.data.zeroize();
    }
}

impl Deref for SecureString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_creation() {
        let key_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let secure_key = SecureKey::new(key_data);
        assert_eq!(secure_key.len(), 5);
        assert_eq!(secure_key.as_bytes()[0], 0x01);
    }

    #[test]
    fn test_secure_key_from_hex() {
        match SecureKey::from_hex("0102030405") {
            Ok(secure_key) => {
                assert_eq!(secure_key.len(), 5);
                assert_eq!(secure_key.as_bytes()[0], 0x01);
            }
            Err(e) => panic!("Failed to create secure key from hex: {}", e),
        }
    }

    #[test]
    fn test_secure_key_empty() {
        let secure_key = SecureKey::new(vec![]);
        assert!(secure_key.is_empty());
    }

    #[test]
    fn test_secure_key_zeroize() {
        let mut secure_key = SecureKey::new(vec![0xFF; 32]);
        secure_key.zeroize_now();
        assert!(secure_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_string_creation() {
        let secure_str = SecureString::new("secret_password".to_string());
        assert_eq!(secure_str.as_str(), "secret_password");
    }

    #[test]
    fn test_secure_string_zeroize() {
        let mut secure_str = SecureString::new("secret".to_string());
        secure_str.zeroize_now();
        assert_eq!(secure_str.as_str().len(), 0);
    }
}
