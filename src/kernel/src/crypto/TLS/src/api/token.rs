extern crate alloc;

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::hmac;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use secrecy::{SecretString, ExposeSecret};
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use parking_lot::Mutex;
use alloc::collections::BTreeMap;
use serde::{Serialize, Deserialize};
use crate::utils::hex_encode;
use crate::validation;
use alloc::vec::Vec;
use alloc::format;

const NONCE_LEN: usize = 12;
const HMAC_LEN: usize = 32;
const EXPIRY_LEN: usize = 8;

fn current_unix_timestamp() -> u64 {
    crate::time_abstraction::kernel_time_secs()
}

pub(crate) fn encrypt_with_master(master_key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let hkey = hmac::Key::new(hmac::HMAC_SHA256, master_key.as_bytes());
    let hk = hmac::sign(&hkey, b"redmi-tls-aead-v1");
    let key_bytes = hk.as_ref();

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| anyhow::anyhow!("aead key init failed"))?;
    let less = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    let _ = crate::rng::kernel_rng_fill(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    in_out.extend_from_slice(&[0u8; 16]);

    less.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("aead seal failed"))?;

    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

pub(crate) fn decrypt_with_master(master_key: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + aead::AES_256_GCM.tag_len() {
        return Err(anyhow::anyhow!("aead input too short"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);

    let hkey = hmac::Key::new(hmac::HMAC_SHA256, master_key.as_bytes());
    let hk = hmac::sign(&hkey, b"redmi-tls-aead-v1");
    let key_bytes = hk.as_ref();

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| anyhow::anyhow!("aead key init failed"))?;
    let less = LessSafeKey::new(unbound);

    let mut in_out = ciphertext.to_vec();
    let nonce = Nonce::assume_unique_for_key({
        let mut nb = [0u8; 12]; nb.copy_from_slice(&nonce_bytes[0..12]); nb
    });

    let res = less.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("aead open failed"))?;

    Ok(res.to_vec())
}

pub fn generate_token(master_key: &str, context: &str, valid_for_secs: u64) -> Result<String> {
    validation::validate_master_key(master_key)?;
    validation::validate_context(context)?;
    let mut nonce = [0u8; NONCE_LEN];
    let _ = crate::rng::kernel_rng_fill(&mut nonce);

    let now = current_unix_timestamp();
    let expiry = now.saturating_add(valid_for_secs);
    let expiry_bytes = expiry.to_be_bytes();

    let key = hmac::Key::new(hmac::HMAC_SHA256, master_key.as_bytes());
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(context.as_bytes());
    ctx.update(&nonce);
    ctx.update(&expiry_bytes);
    let tag = ctx.sign();

    let mut out = Vec::with_capacity(NONCE_LEN + EXPIRY_LEN + HMAC_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&expiry_bytes);
    out.extend_from_slice(tag.as_ref());

    Ok(URL_SAFE_NO_PAD.encode(&out))
}

pub fn validate_token(master_key: &str, context: &str, token_b64: &str) -> bool {
    if validation::validate_master_key(master_key).is_err() 
        || validation::validate_context(context).is_err() 
        || validation::validate_token_value(token_b64).is_err() {
        return false;
    }
    let decoded = match URL_SAFE_NO_PAD.decode(token_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if decoded.len() != NONCE_LEN + EXPIRY_LEN + HMAC_LEN {
        return false;
    }

    let expiry_bytes = &decoded[NONCE_LEN..NONCE_LEN + EXPIRY_LEN];
    let tag = &decoded[NONCE_LEN + EXPIRY_LEN..];

    let mut e = [0u8; 8];
    e.copy_from_slice(expiry_bytes);
    let expiry = u64::from_be_bytes(e);

    let now = current_unix_timestamp();
    if now > expiry {
        return false;
    }

    let nonce = &decoded[..NONCE_LEN];
    let key = hmac::Key::new(hmac::HMAC_SHA256, master_key.as_bytes());
    let msg = [context.as_bytes(), nonce, expiry_bytes].concat();

    hmac::verify(&key, &msg, tag).is_ok()
}

fn format_dt(ts: i64) -> String {
    format!("ts:{}", ts)
}

fn hmac_hex64(key: &[u8], msg: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, msg);
    hex_encode(tag.as_ref())
}

pub(crate) fn generate_acces_from_other(other_token: &str, count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(count);
    let now_ts = crate::time_abstraction::kernel_time_secs_i64();

    for i in 0..count {
        let ts = now_ts + (i as i64);
        let msg = format!("{}|{}", format_dt(ts), other_token);
        let tok = hmac_hex64(other_token.as_bytes(), msg.as_bytes());
        out.push(tok);
    }

    out
}

#[derive(Clone)]
pub struct TokenManager {
    master_key: SecretString,
    other_token: SecretString,
    _tokens: Arc<Mutex<BTreeMap<String, TokenEntry>>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenEntry {
    token: String,
    expiry: u64,
}

impl TokenManager {
    pub fn new(master_key: &str, other_token: &str) -> Self {
        let map: BTreeMap<String, TokenEntry> = BTreeMap::new();

        Self {
            master_key: SecretString::new(master_key.to_string().into()),
            other_token: SecretString::new(other_token.to_string().into()),
            _tokens: Arc::new(Mutex::new(map)),
        }
    }

    pub(crate) fn master_key(&self) -> &str {
        self.master_key.expose_secret()
    }

    pub(crate) fn other_token(&self) -> &str {
        self.other_token.expose_secret()
    }

    pub fn generate(&self, context: &str, valid_for_secs: u64) -> Option<String> {
        match generate_token(self.master_key(), context, valid_for_secs) {
            Ok(tok) => {
                let mut map = self._tokens.lock();
                let now = current_unix_timestamp();
                let expiry = now.saturating_add(valid_for_secs);
                map.insert(context.to_string(), TokenEntry { token: tok.clone(), expiry });
                Some(tok)
            }
            Err(_) => None,
        }
    }

    pub fn validate(&self, token: &str) -> bool {
        if validate_token(self.master_key(), "", token) {
            return true;
        }

        let map = self._tokens.lock();
        let now = current_unix_timestamp();
        map.values().any(|entry| entry.token == token && entry.expiry > now)
    }

    pub fn validate_with_context(&self, token: &str, context: &str) -> bool {
        validate_token(self.master_key(), context, token)
    }

    #[allow(dead_code)]
    pub fn list_tokens(&self) -> Vec<(String, u64)> {
        let map = self._tokens.lock();
        map.iter().map(|(k, v)| (k.clone(), v.expiry)).collect()
    }

    #[allow(dead_code)]
    pub fn purge_expired(&self) -> usize {
        let mut map = self._tokens.lock();
        let now = current_unix_timestamp();
        let before = map.len();
        map.retain(|_, v| v.expiry > now);
        let purged = before.saturating_sub(map.len());
        purged
    }

    pub(crate) fn generate_acces(&self, count: usize) -> Vec<String> {
        generate_acces_from_other(self.other_token(), count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let master = "test-master-key";
        let plaintext = b"hello aead world";
        let enc = encrypt_with_master(master, plaintext).expect("encrypt");
        let dec = decrypt_with_master(master, &enc).expect("decrypt");
        assert_eq!(&dec[..plaintext.len()], plaintext);
    }

    #[test]
    fn token_generation_and_validation() {
        let master = "another-master";
        let ctx = "ctx";
        let tok = generate_token(master, ctx, 60).expect("generate");
        assert!(validate_token(master, ctx, &tok));
        assert!(!validate_token(master, ctx, "badtoken"));
    }
}

