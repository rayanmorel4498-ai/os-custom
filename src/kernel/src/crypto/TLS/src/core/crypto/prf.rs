use alloc::vec::Vec;
use anyhow::Result;
use hmac::Mac;
use sha2::{Sha256, Sha384};

#[derive(Clone, Copy, Debug)]
pub enum PRFHashAlgorithm {
    SHA256,
    SHA384,
}

pub struct PRF;

impl PRF {
    pub fn generate(
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        output_size: usize,
        hash_algo: PRFHashAlgorithm,
    ) -> Result<Vec<u8>> {
        match hash_algo {
            PRFHashAlgorithm::SHA256 => Self::p_hash_sha256(secret, label, seed, output_size),
            PRFHashAlgorithm::SHA384 => Self::p_hash_sha384(secret, label, seed, output_size),
        }
    }

    fn p_hash_sha256(
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>> {
        use hmac::Hmac;
        type HmacSha256 = Hmac<Sha256>;

        let mut result = Vec::new();
        let mut label_seed = Vec::new();
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);

        let mut a = label_seed.clone();

        while result.len() < output_size {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| anyhow::anyhow!("Invalid HMAC key size"))?;
            mac.update(&a);
            let a_i = mac.finalize().into_bytes().to_vec();

            let mut hmac_input = a_i.clone();
            hmac_input.extend_from_slice(&label_seed);

            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|_| anyhow::anyhow!("Invalid HMAC key size"))?;
            mac.update(&hmac_input);
            result.extend_from_slice(&mac.finalize().into_bytes());

            a = a_i;
        }

        result.truncate(output_size);
        Ok(result)
    }

    fn p_hash_sha384(
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>> {
        use hmac::Hmac;
        type HmacSha384 = Hmac<Sha384>;

        let mut result = Vec::new();
        let mut label_seed = Vec::new();
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);

        let mut a = label_seed.clone();

        while result.len() < output_size {
            let mut mac = HmacSha384::new_from_slice(secret)
                .map_err(|_| anyhow::anyhow!("Invalid HMAC key size"))?;
            mac.update(&a);
            let a_i = mac.finalize().into_bytes().to_vec();

            let mut hmac_input = a_i.clone();
            hmac_input.extend_from_slice(&label_seed);

            let mut mac = HmacSha384::new_from_slice(secret)
                .map_err(|_| anyhow::anyhow!("Invalid HMAC key size"))?;
            mac.update(&hmac_input);
            result.extend_from_slice(&mac.finalize().into_bytes());

            a = a_i;
        }

        result.truncate(output_size);
        Ok(result)
    }
}

pub struct MasterSecretDerivation;

impl MasterSecretDerivation {
    pub fn derive_master_secret(
        pre_master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        hash_algo: PRFHashAlgorithm,
    ) -> Result<[u8; 48]> {
        let mut seed = Vec::new();
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);

        let master = PRF::generate(
            pre_master_secret,
            b"master secret",
            &seed,
            48,
            hash_algo,
        )?;

        let mut result = [0u8; 48];
        result.copy_from_slice(&master[..48]);
        Ok(result)
    }
}

pub struct KeyMaterialDerivation;

impl KeyMaterialDerivation {
    pub fn derive_key_material(
        master_secret: &[u8; 48],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        key_material_size: usize,
        hash_algo: PRFHashAlgorithm,
    ) -> Result<Vec<u8>> {
        let mut seed = Vec::new();
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);

        PRF::generate(
            master_secret,
            b"key expansion",
            &seed,
            key_material_size,
            hash_algo,
        )
    }
}

pub struct FinishedMessageDerivation;

impl FinishedMessageDerivation {
    pub fn derive_verify_data(
        master_secret: &[u8; 48],
        handshake_messages_hash: &[u8; 32],
        label: &[u8],
        verify_data_size: usize,
        hash_algo: PRFHashAlgorithm,
    ) -> Result<Vec<u8>> {
        PRF::generate(
            master_secret,
            label,
            handshake_messages_hash,
            verify_data_size,
            hash_algo,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_deterministic() {
        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        let result1 = PRF::generate(secret, label, seed, 32, PRFHashAlgorithm::SHA256)
            .expect("PRF generation failed");
        let result2 = PRF::generate(secret, label, seed, 32, PRFHashAlgorithm::SHA256)
            .expect("PRF generation failed");

        assert_eq!(result1, result2, "PRF should be deterministic");
    }

    #[test]
    fn test_prf_sensitivity() {
        let secret1 = b"secret";
        let secret2 = b"secrek";

        let result1 = PRF::generate(secret1, b"label", b"seed", 32, PRFHashAlgorithm::SHA256)
            .expect("PRF generation failed");
        let result2 = PRF::generate(secret2, b"label", b"seed", 32, PRFHashAlgorithm::SHA256)
            .expect("PRF generation failed");

        assert_ne!(result1, result2, "Different secrets should yield different outputs");
    }

    #[test]
    fn test_prf_output_size() {
        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        for size in [16, 32, 48, 64, 100] {
            let result = PRF::generate(secret, label, seed, size, PRFHashAlgorithm::SHA256)
                .expect("PRF generation failed");
            assert_eq!(result.len(), size, "Output should match requested size");
        }
    }

    #[test]
    fn test_master_secret_derivation() {
        let pre_master = [0x42u8; 48];
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];

        let master = MasterSecretDerivation::derive_master_secret(
            &pre_master,
            &client_random,
            &server_random,
            PRFHashAlgorithm::SHA256,
        ).expect("Master secret derivation failed");

        assert_eq!(master.len(), 48);
        assert!(master.iter().any(|&b| b != master[0]));
    }

    #[test]
    fn test_key_material_derivation() {
        let master_secret = [0x55u8; 48];
        let client_random = [0xCCu8; 32];
        let server_random = [0xDDu8; 32];

        let key_material = KeyMaterialDerivation::derive_key_material(
            &master_secret,
            &client_random,
            &server_random,
            64,
            PRFHashAlgorithm::SHA256,
        ).expect("Key material derivation failed");

        assert_eq!(key_material.len(), 64);
    }

    #[test]
    fn test_finished_message_derivation() {
        let master_secret = [0x77u8; 48];
        let handshake_hash = [0x99u8; 32];

        let verify_data = FinishedMessageDerivation::derive_verify_data(
            &master_secret,
            &handshake_hash,
            b"client finished",
            12,
            PRFHashAlgorithm::SHA256,
        ).expect("Verify data derivation failed");

        assert_eq!(verify_data.len(), 12);
    }
}
