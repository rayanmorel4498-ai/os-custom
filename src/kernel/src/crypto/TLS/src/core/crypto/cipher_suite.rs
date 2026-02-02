use alloc::vec;
use alloc::vec::Vec;
use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    RSA_WITH_AES_128_CBC_SHA,
    RSA_WITH_AES_256_CBC_SHA,
    ECDHE_RSA_WITH_AES_128_CBC_SHA,
    ECDHE_RSA_WITH_AES_256_CBC_SHA,
    RSA_WITH_AES_128_CBC_SHA256,
    RSA_WITH_AES_256_CBC_SHA256,
}

impl CipherSuite {
    pub fn to_wire(&self) -> u16 {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA => 0x002F,
            Self::RSA_WITH_AES_256_CBC_SHA => 0x0035,
            Self::ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xC009,
            Self::ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xC00A,
            Self::RSA_WITH_AES_128_CBC_SHA256 => 0x003C,
            Self::RSA_WITH_AES_256_CBC_SHA256 => 0x003D,
        }
    }

    pub fn from_wire(code: u16) -> Option<Self> {
        match code {
            0x002F => Some(Self::RSA_WITH_AES_128_CBC_SHA),
            0x0035 => Some(Self::RSA_WITH_AES_256_CBC_SHA),
            0xC009 => Some(Self::ECDHE_RSA_WITH_AES_128_CBC_SHA),
            0xC00A => Some(Self::ECDHE_RSA_WITH_AES_256_CBC_SHA),
            0x003C => Some(Self::RSA_WITH_AES_128_CBC_SHA256),
            0x003D => Some(Self::RSA_WITH_AES_256_CBC_SHA256),
            _ => None,
        }
    }

    pub fn key_exchange(&self) -> KeyExchangeAlgorithm {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA
            | Self::RSA_WITH_AES_256_CBC_SHA
            | Self::RSA_WITH_AES_128_CBC_SHA256
            | Self::RSA_WITH_AES_256_CBC_SHA256 => KeyExchangeAlgorithm::RSA,
            Self::ECDHE_RSA_WITH_AES_128_CBC_SHA | Self::ECDHE_RSA_WITH_AES_256_CBC_SHA => {
                KeyExchangeAlgorithm::ECDHE_RSA
            }
        }
    }

    pub fn cipher(&self) -> SymmetricCipher {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::RSA_WITH_AES_128_CBC_SHA256 => SymmetricCipher::AES128CBC,
            Self::RSA_WITH_AES_256_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_256_CBC_SHA
            | Self::RSA_WITH_AES_256_CBC_SHA256 => SymmetricCipher::AES256CBC,
        }
    }

    pub fn prf_hash(&self) -> PRFHashAlgorithm {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA
            | Self::RSA_WITH_AES_256_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_256_CBC_SHA => PRFHashAlgorithm::SHA1_SHA256,
            Self::RSA_WITH_AES_128_CBC_SHA256 | Self::RSA_WITH_AES_256_CBC_SHA256 => {
                PRFHashAlgorithm::SHA256
            }
        }
    }

    pub fn hmac_hash(&self) -> HMACAlgorithm {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA
            | Self::RSA_WITH_AES_256_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_256_CBC_SHA => HMACAlgorithm::SHA1,
            Self::RSA_WITH_AES_128_CBC_SHA256 | Self::RSA_WITH_AES_256_CBC_SHA256 => {
                HMACAlgorithm::SHA256
            }
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::RSA_WITH_AES_128_CBC_SHA256 => 16,
            Self::RSA_WITH_AES_256_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_256_CBC_SHA
            | Self::RSA_WITH_AES_256_CBC_SHA256 => 32,
        }
    }

    pub fn iv_size(&self) -> usize {
        16
    }

    pub fn mac_size(&self) -> usize {
        match self {
            Self::RSA_WITH_AES_128_CBC_SHA
            | Self::RSA_WITH_AES_256_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::ECDHE_RSA_WITH_AES_256_CBC_SHA => 20,
            Self::RSA_WITH_AES_128_CBC_SHA256 | Self::RSA_WITH_AES_256_CBC_SHA256 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum KeyExchangeAlgorithm {
    RSA,
    ECDHE_RSA,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SymmetricCipher {
    AES128CBC,
    AES256CBC,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum PRFHashAlgorithm {
    SHA1_SHA256,
    SHA256,
    SHA384,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HMACAlgorithm {
    SHA1,
    SHA256,
}

pub struct CipherSuiteNegotiator;

impl CipherSuiteNegotiator {
    pub fn negotiate(
        client_suites: &[CipherSuite],
        server_suites: &[CipherSuite],
    ) -> Option<CipherSuite> {
        for &suite in server_suites {
            if client_suites.contains(&suite) {
                return Some(suite);
            }
        }
        None
    }

    pub fn default_server_preference() -> Vec<CipherSuite> {
        vec![
            CipherSuite::RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite::RSA_WITH_AES_128_CBC_SHA256,

            CipherSuite::RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::RSA_WITH_AES_128_CBC_SHA,
        ]
    }
}

pub struct SecretDerivationPerSuite;

impl SecretDerivationPerSuite {
    pub fn derive_key_material(
        suite: CipherSuite,
        master_secret: &[u8; 48],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<KeyMaterial> {
        let mac_size = suite.mac_size();
        let key_size = suite.key_size();
        let iv_size = suite.iv_size();

        let total_size = 2 * (mac_size + key_size + iv_size);

        let mut seed = Vec::new();
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);

        let key_block = Self::p_hash(master_secret, b"key expansion", &seed, total_size)?;

        let mut offset = 0;

        let client_write_mac = key_block[offset..offset + mac_size].to_vec();
        offset += mac_size;

        let server_write_mac = key_block[offset..offset + mac_size].to_vec();
        offset += mac_size;

        let client_write_key = key_block[offset..offset + key_size].to_vec();
        offset += key_size;

        let server_write_key = key_block[offset..offset + key_size].to_vec();
        offset += key_size;

        let client_write_iv = key_block[offset..offset + iv_size].to_vec();
        offset += iv_size;

        let server_write_iv = key_block[offset..offset + iv_size].to_vec();

        Ok(KeyMaterial {
            client_write_mac,
            server_write_mac,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        })
    }

    fn p_hash(
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut result = Vec::new();
        let mut a = {
            let mut tmp = Vec::new();
            tmp.extend_from_slice(label);
            tmp.extend_from_slice(seed);
            tmp
        };

        while result.len() < output_size {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| anyhow::anyhow!("Invalid HMAC key size"))?;
            mac.update(&a);
            let a_i = mac.finalize().into_bytes().to_vec();

            let mut hmac_input = a_i.clone();
            hmac_input.extend_from_slice(label);
            hmac_input.extend_from_slice(seed);

            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| anyhow::anyhow!("Invalid HMAC key size"))?;
            mac.update(&hmac_input);
            result.extend_from_slice(&mac.finalize().into_bytes());

            a = a_i;
        }

        result.truncate(output_size);
        Ok(result)
    }
}

pub struct KeyMaterial {
    pub client_write_mac: Vec<u8>,
    pub server_write_mac: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_wire_format() {
        let suite = CipherSuite::RSA_WITH_AES_128_CBC_SHA;
        assert_eq!(suite.to_wire(), 0x002F);
        assert_eq!(CipherSuite::from_wire(0x002F), Some(suite));
    }

    #[test]
    fn test_cipher_suite_properties() {
        let suite = CipherSuite::RSA_WITH_AES_256_CBC_SHA256;
        assert_eq!(suite.key_size(), 32);
        assert_eq!(suite.mac_size(), 32);
        assert_eq!(suite.iv_size(), 16);
    }

    #[test]
    fn test_cipher_suite_negotiation() {
        let client = vec![
            CipherSuite::RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::RSA_WITH_AES_256_CBC_SHA,
        ];
        let server = CipherSuiteNegotiator::default_server_preference();

        let selected = CipherSuiteNegotiator::negotiate(&client, &server);
        assert!(selected.is_some());
    }

    #[test]
    fn test_key_material_derivation() {
        let master_secret = [0x42u8; 48];
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];

        let key_material = SecretDerivationPerSuite::derive_key_material(
            CipherSuite::RSA_WITH_AES_128_CBC_SHA256,
            &master_secret,
            &client_random,
            &server_random,
        ).expect("Key material derivation failed");

        assert_eq!(key_material.client_write_key.len(), 16);
        assert_eq!(key_material.server_write_key.len(), 16);
        assert_eq!(key_material.client_write_mac.len(), 32);
    }
}
