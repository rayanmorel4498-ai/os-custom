use sha2::{Sha256, Digest};
use crate::prelude::Vec;

pub struct CryptoTask {
    hasher: Sha256,
}

impl CryptoTask {
    pub fn new() -> Self {
        CryptoTask {
            hasher: Sha256::new(),
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn verify_hash(&self, data: &[u8], hash: &[u8]) -> bool {
        let computed = self.hash(data);
        computed == hash
    }
}
