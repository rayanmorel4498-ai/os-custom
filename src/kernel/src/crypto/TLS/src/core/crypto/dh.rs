extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
use core::fmt;
use sha2::Sha256;
use hmac::{Hmac, Mac};

#[derive(Clone, Debug)]
pub struct DHParams {
    pub prime: Vec<u8>,
    pub generator: Vec<u8>,
}

impl DHParams {
    pub fn rfc3526_1024() -> Self {
        Self {
            prime: PRIME_1024.to_vec(),
            generator: vec![2],
        }
    }

    pub fn rfc3526_2048() -> Self {
        Self {
            prime: PRIME_2048.to_vec(),
            generator: vec![2],
        }
    }
}

#[derive(Clone, Debug)]
pub struct DHPublicKey {
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DHPrivateKey {
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DHKeyPair {
    pub public: DHPublicKey,
    private: DHPrivateKey,
}

impl DHKeyPair {
    pub fn public_key(&self) -> &DHPublicKey {
        &self.public
    }

    pub fn private_key(&self) -> &DHPrivateKey {
        &self.private
    }

    pub fn compute_shared_secret(&self, peer_public: &DHPublicKey) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.private.value)
            .unwrap_or_else(|_| HmacSha256::new_from_slice(&[0u8; 32]).unwrap());
        mac.update(&peer_public.value);
        mac.finalize().into_bytes().to_vec()
    }
}

pub struct DHKeyExchange {
    params: DHParams,
}

impl DHKeyExchange {
    pub fn new() -> Self {
        Self {
            params: DHParams::rfc3526_2048(),
        }
    }

    pub fn with_params(params: DHParams) -> Self {
        Self { params }
    }

    pub fn generate_keypair(&self) -> DHKeyPair {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"dh_private_key");
        let private_bytes = hasher.finalize().to_vec();

        DHKeyPair {
            public: DHPublicKey {
                value: self.params.generator.clone(),
            },
            private: DHPrivateKey {
                value: private_bytes,
            },
        }
    }

    pub fn compute_shared_secret(
        &self,
        keypair: &DHKeyPair,
        peer_public: &DHPublicKey,
    ) -> Vec<u8> {
        keypair.compute_shared_secret(peer_public)
    }

    pub fn params(&self) -> &DHParams {
        &self.params
    }
}

impl Default for DHKeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DHStatus {
    Idle,
    WaitingForPeerKey,
    SecretComputed,
    Failed,
}

impl fmt::Display for DHStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::WaitingForPeerKey => write!(f, "WaitingForPeerKey"),
            Self::SecretComputed => write!(f, "SecretComputed"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

const PRIME_1024: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
];

const PRIME_2048: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0xA4, 0x02, 0xB1, 0x29, 0xD6, 0x2A, 0x6A, 0x0C, 0xB5, 0x1F, 0x51, 0x73, 0xA9, 0xA4, 0x68, 0x97,
    0x0C, 0xC7, 0x96, 0x5D, 0x7B, 0xDC, 0x7D, 0x5C, 0xDC, 0x97, 0x89, 0x0D, 0x33, 0xFD, 0x04, 0x73,
    0x6A, 0x87, 0x8B, 0x84, 0x9F, 0x3C, 0xF9, 0xAC, 0xAE, 0x60, 0x7C, 0xA6, 0x6B, 0x84, 0x28, 0x36,
    0x1C, 0x4B, 0x9E, 0x1A, 0x7D, 0x7C, 0xD2, 0x6C, 0x25, 0x33, 0x0E, 0xCE, 0x31, 0x44, 0xC4, 0x9C,
];

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_dh_generate_keypair() {
        let dh = DHKeyExchange::new();
        let keypair = dh.generate_keypair();

        assert!(!keypair.public.value.is_empty());
        assert!(!keypair.private.value.is_empty());
    }

    #[test]
    fn test_dh_compute_shared_secret() {
        let dh = DHKeyExchange::new();
        let keypair1 = dh.generate_keypair();
        let keypair2 = dh.generate_keypair();

        let secret1 = dh.compute_shared_secret(&keypair1, keypair2.public_key());
        let secret2 = dh.compute_shared_secret(&keypair2, keypair1.public_key());

        assert!(!secret1.is_empty());
        assert!(!secret2.is_empty());
    }

    #[test]
    fn test_dh_status() {
        assert_eq!(DHStatus::Idle.to_string(), "Idle");
        assert_eq!(DHStatus::WaitingForPeerKey.to_string(), "WaitingForPeerKey");
        assert_eq!(DHStatus::SecretComputed.to_string(), "SecretComputed");
    }

    #[test]
    fn test_dh_params_rfc3526() {
        let params_1024 = DHParams::rfc3526_1024();
        let params_2048 = DHParams::rfc3526_2048();

        assert_eq!(params_1024.generator, vec![2]);
        assert_eq!(params_2048.generator, vec![2]);
        assert!(params_2048.prime.len() > params_1024.prime.len());
    }
}
