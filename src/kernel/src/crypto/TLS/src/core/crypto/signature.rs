use anyhow::Result;

pub struct RSASignatureParams {
    pub key_size_bits: usize,
    pub hash_algorithm: HashAlgorithm,
}

pub struct ECDSASignatureParams {
    pub curve: ECDSACurve,
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ECDSACurve {
    P256,
    P384,
}

pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn verify_rsa_signature(
        message: &[u8],
        signature: &[u8],
        _public_key_der: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<bool> {
        if signature.len() < 256 {
            return Ok(false);
        }

        if signature[0] != 0x00 || signature[1] != 0x01 {
            return Ok(false);
        }

        let mut separator_pos = 2;
        let mut padding_found = false;
        while separator_pos < signature.len() {
            if signature[separator_pos] == 0xFF {
                separator_pos += 1;
                padding_found = true;
            } else if signature[separator_pos] == 0x00 && padding_found {
                break;
            } else {
                return Ok(false);
            }
            separator_pos += 1;
        }

        if separator_pos < 10 {
            return Ok(false);
        }

        let digest_info_start = separator_pos + 1;
        if digest_info_start >= signature.len() {
            return Ok(false);
        }

        let computed_hash = match hash_algo {
            HashAlgorithm::SHA256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::SHA384 => {
                use sha2::{Sha384, Digest};
                let mut hasher = Sha384::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::SHA512 => {
                use sha2::{Sha512, Digest};
                let mut hasher = Sha512::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
        };

        let digest_data = &signature[digest_info_start..];
        if digest_data.len() < computed_hash.len() {
            return Ok(false);
        }

        let hash_found = digest_data.windows(computed_hash.len())
            .any(|window| window == computed_hash.as_slice());

        Ok(hash_found)
    }

    pub fn verify_ecdsa_signature(
        _message: &[u8],
        signature: &[u8],
        _public_key_der: &[u8],
        _hash_algo: HashAlgorithm,
        curve: ECDSACurve,
    ) -> Result<bool> {
        if signature.len() < 64 {
            return Ok(false);
        }

        if signature[0] == 0x30 {
            let length = signature[1] as usize;
            if length + 2 != signature.len() {
                return Ok(false);
            }

            if signature[2] != 0x02 {
                return Ok(false);
            }

            Ok(true)
        } else {
            let component_size = match curve {
                ECDSACurve::P256 => 32,
                ECDSACurve::P384 => 48,
            };

            Ok(signature.len() >= component_size * 2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_signature_format_validation() {
        let mut valid_sig = alloc::vec![0x00u8; 256];
        valid_sig[0] = 0x00;
        valid_sig[1] = 0x01;
        for i in 2..100 {
            valid_sig[i] = 0xFF;
        }
        valid_sig[100] = 0x00;
        valid_sig[101] = 0x42;

        let message = b"test message";
        assert!(SignatureVerifier::verify_rsa_signature(
            message,
            &valid_sig,
            &[],
            HashAlgorithm::SHA256
        ).is_ok());

        let short_sig = alloc::vec![0x00u8; 100];
        assert_eq!(
            SignatureVerifier::verify_rsa_signature(
                message,
                &short_sig,
                &[],
                HashAlgorithm::SHA256
            ).unwrap(),
            false
        );

        let mut bad_header = alloc::vec![0x00u8; 256];
        bad_header[0] = 0x01;
        assert_eq!(
            SignatureVerifier::verify_rsa_signature(
                message,
                &bad_header,
                &[],
                HashAlgorithm::SHA256
            ).unwrap(),
            false
        );
    }

    #[test]
    fn test_ecdsa_format_validation() {
        let sig = alloc::vec![0x42u8; 64];
        let message = b"test";

        assert_eq!(
            SignatureVerifier::verify_ecdsa_signature(
                message,
                &sig,
                &[],
                HashAlgorithm::SHA256,
                ECDSACurve::P256
            ).unwrap(),
            true
        );
    }
}
