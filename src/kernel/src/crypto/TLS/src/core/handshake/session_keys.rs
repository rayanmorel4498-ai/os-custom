extern crate alloc;

use alloc::vec::Vec;
use anyhow::Result;

#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
}

impl SessionKeys {
    pub fn derive(
        master_key: &str,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<Self> {
        let mut context_bytes = alloc::vec![0u8; 64];
        context_bytes[0..32].copy_from_slice(client_random);
        context_bytes[32..64].copy_from_slice(server_random);
        
        let crypto_key = crate::core::crypto::crypto::CryptoKey::new(master_key, "tls12-key-expansion")?;
        
        let key_material = crypto_key.encrypt(&context_bytes)?;
        let key_bytes = key_material.as_bytes();
        
        let padded = if key_bytes.len() < 64 {
            let mut v = alloc::vec![0u8; 64];
            v[0..key_bytes.len()].copy_from_slice(key_bytes);
            v
        } else {
            key_bytes[..64].to_vec()
        };
        
        Ok(Self {
            client_write_key: padded[0..16].to_vec(),
            server_write_key: padded[16..32].to_vec(),
            client_mac_key: padded[32..52].to_vec(),
            server_mac_key: padded[52..64].to_vec().to_vec(),
            client_write_iv: [0u8; 16].to_vec(),
            server_write_iv: [0u8; 16].to_vec(),
        })
    }

    #[cfg(test)]
    pub fn test_keys() -> Self {
        Self {
            client_write_key: alloc::vec![0x01; 16],
            server_write_key: alloc::vec![0x02; 16],
            client_write_iv: alloc::vec![0x03; 16],
            server_write_iv: alloc::vec![0x04; 16],
            client_mac_key: alloc::vec![0x05; 20],
            server_mac_key: alloc::vec![0x06; 20],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_keys_derivation() {
        let master_key = "test_master_key_32_bytes_long__";
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        
        let result = SessionKeys::derive(master_key, &client_random, &server_random);
        assert!(result.is_ok());
        
        let keys = result.unwrap();
        assert_eq!(keys.client_write_key.len(), 16);
        assert_eq!(keys.server_write_key.len(), 16);
        assert!(keys.client_mac_key.len() > 0);
        assert!(keys.server_mac_key.len() > 0);
    }

    #[test]
    fn test_session_keys_different_randoms() {
        let master_key = "test_master_key_32_bytes_long__";
        let client_random1 = [0x01u8; 32];
        let client_random2 = [0x02u8; 32];
        let server_random = [0x03u8; 32];
        
        let keys1 = SessionKeys::derive(master_key, &client_random1, &server_random).unwrap();
        let keys2 = SessionKeys::derive(master_key, &client_random2, &server_random).unwrap();
        
        assert_ne!(keys1.client_write_key, keys2.client_write_key);
    }
}
