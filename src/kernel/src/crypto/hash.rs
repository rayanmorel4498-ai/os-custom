extern crate alloc;
use sha2::{Sha256, Digest};

pub struct Hash;

impl Hash {
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    pub fn verify(hash1: &[u8; 32], hash2: &[u8; 32]) -> bool {
        let mut result = 0u8;
        for i in 0..32 {
            result |= hash1[i] ^ hash2[i];
        }
        result == 0
    }

    pub fn hash_multiple(buffers: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for buf in buffers.iter() {
            hasher.update(buf);
        }
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }
}