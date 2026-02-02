extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{Salt, HKDF_SHA256};
use zeroize::Zeroize;
use core::convert::TryInto;
use alloc::format;
use sha2::{Sha256, Digest};

pub(crate) const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HKDF_INFO_PREFIX: &str = "tls-maison/v1:";

pub struct CryptoKey([u8; KEY_LEN]);

impl CryptoKey {
    pub fn new(master_key: &str, context: &str) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(context.as_bytes());
        hasher.update(b"hkdf_salt_v1");
        let salt_bytes = hasher.finalize();
        let salt = Salt::new(HKDF_SHA256, &salt_bytes[..16]);
        let prk = salt.extract(master_key.as_bytes());
        let info = format!("{}{}", HKDF_INFO_PREFIX, context);

        let info_bytes = info.as_bytes();
        let info_array = [info_bytes]; 
        let okm = prk
            .expand(&info_array, HkdfOutput(KEY_LEN))
            .map_err(|_| anyhow!("HKDF expand failed"))?;

        let mut out = [0u8; KEY_LEN];
        okm.fill(&mut out).map_err(|_| anyhow!("HKDF fill failed"))?;
        Ok(Self(out))
    }

    fn to_less_safe(&self) -> Result<LessSafeKey> {
        let unbound = UnboundKey::new(&aead::AES_256_GCM, &self.0)
            .map_err(|_| anyhow!("Failed to create UnboundKey"))?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String> {
        let aead_key = self.to_less_safe()?;
        let mut nonce = [0u8; NONCE_LEN];
        let _ = crate::rng::kernel_rng_fill(&mut nonce);
        let nonce_obj = Nonce::assume_unique_for_key(nonce);

        let mut buf = plaintext.to_vec();
        aead_key
            .seal_in_place_append_tag(nonce_obj, Aad::empty(), &mut buf)
            .map_err(|_| anyhow!("AEAD seal failed"))?;

        let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }

    pub fn decrypt(&self, token: &str) -> Option<Vec<u8>> {
        let aead_key = self.to_less_safe().ok()?;
        let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
        if decoded.len() < NONCE_LEN + aead::AES_256_GCM.tag_len() {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = decoded[0..NONCE_LEN].try_into().ok()?;
        let mut buf = decoded[NONCE_LEN..].to_vec();
        let nonce_obj = Nonce::assume_unique_for_key(nonce);
        let plain = aead_key.open_in_place(nonce_obj, Aad::empty(), &mut buf).ok()?;
        Some(plain.to_vec())
    }

    #[allow(dead_code)]
    pub fn export_as_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl Drop for CryptoKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct HkdfOutput(usize);
impl ring::hkdf::KeyType for HkdfOutput {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let key = CryptoKey::new("m", "c").unwrap();
        let t = key.encrypt(b"hi").unwrap();
        let o = key.decrypt(&t).unwrap();
        assert_eq!(o, b"hi");
    }

    #[test]
    fn roundtrip_long_nonascii() {
        let key = CryptoKey::new("master_secret_123", "context_test").unwrap();
        let plaintext = "𠜎 Rust TLS 🛡️ ".repeat(10).into_bytes();
        let token = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&token).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn decrypt_invalid_returns_none() {
        let key = CryptoKey::new("m", "c").unwrap();
        assert!(key.decrypt("invalidtoken").is_none());
    }

    #[test]
    fn export_base64_works() {
        let key = CryptoKey::new("m", "c").unwrap();
        let b64 = key.export_as_base64();
        assert!(!b64.is_empty());
    }
}

