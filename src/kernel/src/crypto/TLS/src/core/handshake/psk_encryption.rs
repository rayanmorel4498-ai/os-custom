extern crate alloc;

use anyhow::Result;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::ToString;
use parking_lot::RwLock;
use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct PSKEncryption {
	master_key: Arc<RwLock<[u8; 32]>>,
	encrypted_psks: Arc<RwLock<BTreeMap<alloc::string::String, EncryptedPSK>>>,
	stats: Arc<RwLock<PSKEncryptionStats>>,
	key_rotation_interval: Arc<RwLock<u64>>,
}

#[derive(Clone, Debug)]
struct EncryptedPSK {
	ciphertext: Vec<u8>,
	nonce: [u8; 16],
	salt: [u8; 16],
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PSKEncryptionStats {
	pub psk_stored: u64,
	pub psk_encrypted: u64,
	pub psk_decrypted: u64,
	pub encryption_errors: u64,
	pub key_rotations: u64,
}

impl PSKEncryption {
	pub fn new(master_key: [u8; 32]) -> Self {
		Self {
			master_key: Arc::new(RwLock::new(master_key)),
			encrypted_psks: Arc::new(RwLock::new(BTreeMap::new())),
			stats: Arc::new(RwLock::new(PSKEncryptionStats {
				psk_stored: 0,
				psk_encrypted: 0,
				psk_decrypted: 0,
				encryption_errors: 0,
				key_rotations: 0,
			})),
			key_rotation_interval: Arc::new(RwLock::new(3600)),
		}
	}

	pub fn store_psk_encrypted(&self, psk_id: &str, psk_data: &[u8]) -> Result<()> {
		let mut stats = self.stats.write();
		let mut psks = self.encrypted_psks.write();
		
		let nonce = Self::generate_random_bytes::<16>();
		let salt = Self::generate_random_bytes::<16>();

		let master = self.master_key.read();
		let mut ciphertext = psk_data.to_vec();
		
		for (i, byte) in ciphertext.iter_mut().enumerate() {
			*byte ^= master[i % 32];
			*byte ^= nonce[i % 16];
			*byte ^= salt[i % 16];
		}

		psks.insert(
			psk_id.to_string(),
			EncryptedPSK {
				ciphertext,
				nonce,
				salt,
			},
		);

		stats.psk_stored = stats.psk_stored.saturating_add(1);
		stats.psk_encrypted = stats.psk_encrypted.saturating_add(1);

		Ok(())
	}

	pub fn retrieve_psk_decrypted(&self, psk_id: &str) -> Result<Vec<u8>> {
		let psks = self.encrypted_psks.read();
		let mut stats = self.stats.write();

		let encrypted = psks.get(psk_id)
			.ok_or_else(|| anyhow::anyhow!("PSK not found: {}", psk_id))?;

		let master = self.master_key.read();
		let mut plaintext = encrypted.ciphertext.clone();

		for (i, byte) in plaintext.iter_mut().enumerate() {
			*byte ^= master[i % 32];
			*byte ^= encrypted.nonce[i % 16];
			*byte ^= encrypted.salt[i % 16];
		}

		stats.psk_decrypted = stats.psk_decrypted.saturating_add(1);

		Ok(plaintext)
	}

	pub fn delete_psk(&self, psk_id: &str) -> Result<()> {
		let mut psks = self.encrypted_psks.write();
		psks.remove(psk_id)
			.ok_or_else(|| anyhow::anyhow!("PSK not found: {}", psk_id))?;
		Ok(())
	}

	pub fn verify_psk_integrity(&self, psk_id: &str, expected_hash: &[u8; 32]) -> Result<bool> {
		let plaintext = self.retrieve_psk_decrypted(psk_id)?;
		let hash = Self::hash_psk(&plaintext);
		Ok(hash == *expected_hash)
	}

	fn hash_psk(psk_data: &[u8]) -> [u8; 32] {
		let mut hasher = Sha256::new();
		hasher.update(psk_data);
		let result = hasher.finalize();
		let mut hash = [0u8; 32];
		hash.copy_from_slice(&result);
		hash
	}

	pub fn get_rotation_interval(&self) -> u64 {
		*self.key_rotation_interval.read()
	}

	pub fn set_rotation_interval(&self, interval: u64) {
		*self.key_rotation_interval.write() = interval;
	}

	pub fn rotate_master_key(&self, new_master_key: [u8; 32]) -> Result<()> {
		let psks = self.encrypted_psks.read();
		let mut stats = self.stats.write();

		let old_master = self.master_key.read().clone();
		let mut plaintext_psks = BTreeMap::new();

		for (psk_id, encrypted) in psks.iter() {
			let mut plaintext = encrypted.ciphertext.clone();
			for (i, byte) in plaintext.iter_mut().enumerate() {
				*byte ^= old_master[i % 32];
				*byte ^= encrypted.nonce[i % 16];
				*byte ^= encrypted.salt[i % 16];
			}
			plaintext_psks.insert(psk_id.clone(), plaintext);
		}

		drop(psks);
let _ = old_master;

		let mut psks = self.encrypted_psks.write();
		*self.master_key.write() = new_master_key;

		let interval = self.get_rotation_interval();
		let _ = interval;

		for (psk_id, plaintext) in plaintext_psks {
			let nonce = Self::generate_random_bytes::<16>();
			let salt = Self::generate_random_bytes::<16>();
			let mut ciphertext = plaintext;

			for (i, byte) in ciphertext.iter_mut().enumerate() {
				*byte ^= new_master_key[i % 32];
				*byte ^= nonce[i % 16];
				*byte ^= salt[i % 16];
			}

			psks.insert(
				psk_id,
				EncryptedPSK {
					ciphertext,
					nonce,
					salt,
				},
			);
		}

		stats.key_rotations = stats.key_rotations.saturating_add(1);
		Ok(())
	}

	fn generate_random_bytes<const N: usize>() -> [u8; N] {
		let mut bytes = [0u8; N];
		for (i, b) in bytes.iter_mut().enumerate() {
			let mut hasher = Sha256::new();
			hasher.update((i as u64).to_le_bytes());
			let result = hasher.finalize();
			*b = result[i % 32];
		}
		bytes
	}

	pub fn get_stats(&self) -> PSKEncryptionStats {
		self.stats.read().clone()
	}

	pub fn psk_count(&self) -> usize {
		self.encrypted_psks.read().len()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_psk_encryption_storage() {
		let master_key = [42u8; 32];
		let encryptor = PSKEncryption::new(master_key);

		let psk_data = b"secret_psk_value_12345";
		encryptor.store_psk_encrypted("session_1", psk_data).unwrap();

		assert_eq!(encryptor.psk_count(), 1);

		let stats = encryptor.get_stats();
		assert_eq!(stats.psk_stored, 1);
		assert_eq!(stats.psk_encrypted, 1);
	}

	#[test]
	fn test_psk_decryption() {
		let master_key = [42u8; 32];
		let encryptor = PSKEncryption::new(master_key);

		let psk_data = b"my_secret_psk";
		encryptor.store_psk_encrypted("sess_1", psk_data).unwrap();

		let retrieved = encryptor.retrieve_psk_decrypted("sess_1").unwrap();
		assert_eq!(retrieved, psk_data);
	}

	#[test]
	fn test_psk_deletion() {
		let master_key = [42u8; 32];
		let encryptor = PSKEncryption::new(master_key);

		encryptor.store_psk_encrypted("sess_1", b"secret").unwrap();
		assert_eq!(encryptor.psk_count(), 1);

		encryptor.delete_psk("sess_1").unwrap();
		assert_eq!(encryptor.psk_count(), 0);
	}

	#[test]
	fn test_psk_integrity_verification() {
		let master_key = [42u8; 32];
		let encryptor = PSKEncryption::new(master_key);

		let psk_data = b"integrity_test_psk";
		let hash = PSKEncryption::hash_psk(psk_data);

		encryptor.store_psk_encrypted("sess_1", psk_data).unwrap();
		let verified = encryptor.verify_psk_integrity("sess_1", &hash).unwrap();
		assert!(verified);
	}

	#[test]
	fn test_key_rotation() {
		let old_key = [42u8; 32];
		let new_key = [99u8; 32];
		let encryptor = PSKEncryption::new(old_key);

		let psk_data = b"rotation_test_psk";
		encryptor.store_psk_encrypted("sess_1", psk_data).unwrap();

		encryptor.rotate_master_key(new_key).unwrap();

		let retrieved = encryptor.retrieve_psk_decrypted("sess_1").unwrap();
		assert_eq!(retrieved, psk_data);

		let stats = encryptor.get_stats();
		assert_eq!(stats.key_rotations, 1);
	}
}
