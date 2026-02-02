#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::ToString;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Verifier};
use ring::hmac;
use secrecy::{SecretString, ExposeSecret};
use serde::{Deserialize, Serialize};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::format;
use parking_lot::Mutex;
use crate::utils::constant_time_eq;
use crate::validation;


#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentType {
    Kernel,
    CPU,
    GPU,
    RAM,
    Thermal,
    DeviceInterfaces,
    SecurityDriver,
    StorageDriver,
    
    OS,
    IA,
    Identity,
    Permissions,
    
    Network,
    Firewall,
    Mesh,
    P2P,
    Messaging,
    Calling,
    Location,
    AntiTheft,
    
    FrontCamera,
    RearCamera,
    GPS,
    NFC,
    Modem,
    Display,
    Audio,
    Haptics,
    Biometric,
    Power,
    
    Custom(u32),
}

impl ComponentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::CPU => "cpu",
            Self::GPU => "gpu",
            Self::RAM => "ram",
            Self::Thermal => "thermal",
            Self::DeviceInterfaces => "device_interfaces",
            Self::SecurityDriver => "security_driver",
            Self::StorageDriver => "storage_driver",
            Self::OS => "os",
            Self::IA => "ia",
            Self::Identity => "identity",
            Self::Permissions => "permissions",
            Self::Network => "network",
            Self::Firewall => "firewall",
            Self::Mesh => "mesh",
            Self::P2P => "p2p",
            Self::Messaging => "messaging",
            Self::Calling => "calling",
            Self::Location => "location",
            Self::AntiTheft => "anti_theft",
            Self::FrontCamera => "front_camera",
            Self::RearCamera => "rear_camera",
            Self::GPS => "gps",
            Self::NFC => "nfc",
            Self::Modem => "modem",
            Self::Display => "display",
            Self::Audio => "audio",
            Self::Haptics => "haptics",
            Self::Biometric => "biometric",
            Self::Power => "power",
            Self::Custom(_) => "custom",
        }
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ComponentToken {
    pub token_id: String,
    pub component: ComponentType,
    pub instance_id: u32,
    pub token_value: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub public_key: String,
    pub algorithm: SignatureAlg,
}

#[derive(Clone, Serialize, Deserialize)]
struct ComponentTokenEntry {
    token: ComponentToken,
    signing_key: String,
    algorithm: SignatureAlg,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SignatureAlg {
    Ed25519,
    HmacSha256,
    HmacSha512,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ComponentSignature {
    pub token_id: String,
    pub message: String,
    pub signature: String,
    pub signed_at: u64,
    pub nonce: String,
}


pub struct ComponentTokenManager {
    master_key: SecretString,
    tokens: Arc<Mutex<BTreeMap<String, ComponentTokenEntry>>>,
    revoked: Arc<Mutex<Vec<String>>>,
}

impl ComponentTokenManager {
    pub fn new(master_key: &str) -> Self {
        let _ = validation::validate_master_key(master_key);
        Self {
            master_key: SecretString::new(master_key.to_string()),
            tokens: Arc::new(Mutex::new(BTreeMap::new())),
            revoked: Arc::new(Mutex::new(Vec::new())),
        }
    }


    pub fn issue_session_token(
        &self,
        component: ComponentType,
        instance_id: u32,
        valid_for_secs: u64,
    ) -> Result<ComponentToken> {
        let alg = match component {
            ComponentType::Kernel => SignatureAlg::Ed25519,
            ComponentType::OS | ComponentType::IA => SignatureAlg::HmacSha256,
            ComponentType::DeviceInterfaces | ComponentType::Display | ComponentType::Audio => SignatureAlg::HmacSha512,
            ComponentType::Power => SignatureAlg::HmacSha256,
            ComponentType::Network | ComponentType::Messaging | ComponentType::Calling => SignatureAlg::HmacSha256,
            _ => SignatureAlg::Ed25519,
        };

        let token_id = self.gen_token_id(&component, instance_id);
        let token_value = self.gen_hmac_token(&token_id)?;

        let signing_key_b64 = match alg {
            SignatureAlg::Ed25519 => {
                let mut seed = [0u8; 32];
                let _ = crate::rng::kernel_rng_fill(&mut seed);
                let signing_key = SigningKey::from_bytes(&seed);
                URL_SAFE_NO_PAD.encode(signing_key.to_bytes())
            }
            SignatureAlg::HmacSha256 | SignatureAlg::HmacSha512 => {
                let mut key = [0u8; 32];
                let _ = crate::rng::kernel_rng_fill(&mut key);
                URL_SAFE_NO_PAD.encode(&key)
            }
        };

        let public_key_b64 = match alg {
            SignatureAlg::Ed25519 => {
                let seed_bytes = URL_SAFE_NO_PAD.decode(&signing_key_b64).map_err(|_| anyhow!("decode signing key failed"))?;
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let signing_key = SigningKey::from_bytes(&seed);
                let verifying_key = signing_key.verifying_key();
                URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
            }
            _ => String::new(),
        };

        let now = self.now_secs();
        let expires_at = now.saturating_add(valid_for_secs);

        let token = ComponentToken {
            token_id: token_id.clone(),
            component,
            instance_id,
            token_value,
            created_at: now,
            expires_at,
            public_key: public_key_b64,
            algorithm: alg.clone(),
        };

        let entry = ComponentTokenEntry {
            token: token.clone(),
            signing_key: signing_key_b64,
            algorithm: alg.clone(),
        };

        let mut tokens = self.tokens.lock();
        tokens.insert(token_id, entry);

        Ok(token)
    }


    pub fn validate_token(&self, token_id: &str, token_value: &str) -> Result<bool> {
        validation::validate_token_id(token_id)?;
        validation::validate_token_value(token_value)?;
        let revoked = self.revoked.lock();
        if revoked.contains(&token_id.to_string()) {
            return Err(anyhow!("Token révoqué"));
        }
        drop(revoked);

        let tokens = self.tokens.lock();
        let entry = tokens
            .get(token_id)
            .ok_or_else(|| anyhow!("Token non trouvé"))?;

        let now = self.now_secs();
        if now > entry.token.expires_at {
            return Err(anyhow!("Token expiré"));
        }

        let expected = self.gen_hmac_token(token_id)?;
        Ok(expected == token_value)
    }


    pub fn sign_action(
        &self,
        token_id: &str,
        message: &str,
        nonce: &str,
    ) -> Result<ComponentSignature> {
        validation::validate_token_id(token_id)?;
        validation::validate_context(message)?;
        validation::validate_context(nonce)?;
        let tokens = self.tokens.lock();
        let entry = tokens
            .get(token_id)
            .ok_or_else(|| anyhow!("Token non trouvé pour signature"))?;

        let now = self.now_secs();
        if now > entry.token.expires_at {
            return Err(anyhow!("Token expiré, impossible de signer"));
        }

        let signing_key_bytes = URL_SAFE_NO_PAD
            .decode(&entry.signing_key)
            .map_err(|_| anyhow!("Décoding signing_key failed"))?;

        let to_sign = format!("{}|{}|{}", message, nonce, token_id);

        match entry.algorithm {
            SignatureAlg::Ed25519 => {
                if signing_key_bytes.len() != 32 {
                    return Err(anyhow!("Invalid signing_key length"));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&signing_key_bytes);
                let signing_key = SigningKey::from_bytes(&seed);
                let signature = signing_key.sign(to_sign.as_bytes());
                Ok(ComponentSignature {
                    token_id: token_id.to_string(),
                    message: message.to_string(),
                    signature: URL_SAFE_NO_PAD.encode(&signature.to_bytes()),
                    signed_at: now,
                    nonce: nonce.to_string(),
                })
            }
            SignatureAlg::HmacSha256 => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, &signing_key_bytes);
                let tag = hmac::sign(&key, to_sign.as_bytes());
                Ok(ComponentSignature {
                    token_id: token_id.to_string(),
                    message: message.to_string(),
                    signature: URL_SAFE_NO_PAD.encode(tag.as_ref()),
                    signed_at: now,
                    nonce: nonce.to_string(),
                })
            }
            SignatureAlg::HmacSha512 => {
                let key = hmac::Key::new(hmac::HMAC_SHA512, &signing_key_bytes);
                let tag = hmac::sign(&key, to_sign.as_bytes());
                Ok(ComponentSignature {
                    token_id: token_id.to_string(),
                    message: message.to_string(),
                    signature: URL_SAFE_NO_PAD.encode(tag.as_ref()),
                    signed_at: now,
                    nonce: nonce.to_string(),
                })
            }
        }
    }


    pub fn verify_signature(&self, sig: &ComponentSignature) -> Result<bool> {
        validation::validate_token_id(&sig.token_id)?;
        validation::validate_signature(&sig.signature)?;
        let tokens = self.tokens.lock();
        let entry = tokens
            .get(&sig.token_id)
            .ok_or_else(|| anyhow!("Token pour signature non trouvé"))?;

        match entry.algorithm {
            SignatureAlg::Ed25519 => {
                let pk_bytes = URL_SAFE_NO_PAD
                    .decode(&entry.token.public_key)
                    .map_err(|_| anyhow!("Decoding public_key failed"))?;

                if pk_bytes.len() != 32 {
                    return Err(anyhow!("Invalid public_key length"));
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&pk_bytes);
                let verifying_key = VerifyingKey::from_bytes(&key_bytes)
                    .map_err(|_| anyhow!("Invalid verifying key"))?;

                let to_verify = format!("{}|{}|{}", sig.message, sig.nonce, sig.token_id);
                let sig_bytes = URL_SAFE_NO_PAD
                    .decode(&sig.signature)
                    .map_err(|_| anyhow!("Decoding signature failed"))?;

                let sig_obj = ed25519_dalek::Signature::from_slice(&sig_bytes)
                    .map_err(|_| anyhow!("Invalid signature format"))?;

                verifying_key.verify(to_verify.as_bytes(), &sig_obj)
                    .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

                Ok(true)
            }
            SignatureAlg::HmacSha256 => {
                let key_bytes = URL_SAFE_NO_PAD
                    .decode(&entry.signing_key)
                    .map_err(|_| anyhow!("Decoding signing key failed"))?;
                let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
                let expected = hmac::sign(&key, format!("{}|{}|{}", sig.message, sig.nonce, sig.token_id).as_bytes());
                let provided = URL_SAFE_NO_PAD.decode(&sig.signature).map_err(|_| anyhow!("decoding provided sig failed"))?;
                if constant_time_eq(expected.as_ref(), &provided) {
                    Ok(true)
                } else {
                    Err(anyhow!("HMAC signature mismatch"))
                }
            }
            SignatureAlg::HmacSha512 => {
                let key_bytes = URL_SAFE_NO_PAD
                    .decode(&entry.signing_key)
                    .map_err(|_| anyhow!("Decoding signing key failed"))?;
                let key = hmac::Key::new(hmac::HMAC_SHA512, &key_bytes);
                let expected = hmac::sign(&key, format!("{}|{}|{}", sig.message, sig.nonce, sig.token_id).as_bytes());
                let provided = URL_SAFE_NO_PAD.decode(&sig.signature).map_err(|_| anyhow!("decoding provided sig failed"))?;
                if constant_time_eq(expected.as_ref(), &provided) {
                    Ok(true)
                } else {
                    Err(anyhow!("HMAC signature mismatch"))
                }
            }
		}
	}


    pub fn revoke_token(&self, token_id: &str) -> Result<()> {
        validation::validate_token_id(token_id)?;
        let mut revoked = self.revoked.lock();
        revoked.push(token_id.to_string());

        let mut tokens = self.tokens.lock();
        tokens.remove(token_id);

        Ok(())
    }


    pub fn rotate_token(
        &self,
        token_id: &str,
        valid_for_secs: u64,
    ) -> Result<ComponentToken> {
        let tokens = self.tokens.lock();
        let old_entry = tokens
            .get(token_id)
            .ok_or_else(|| anyhow!("Token non trouvé pour rotation"))?;

        let component = old_entry.token.component;
        let instance_id = old_entry.token.instance_id;
        drop(tokens);

        self.revoke_token(token_id)?;

        self.issue_session_token(component, instance_id, valid_for_secs)
    }

    #[cfg(feature = "real_tls")]
    pub fn save_tokens_to_file(&self, path: &str) -> Result<()> {
        validation::validate_path(path)?;
        let _ = path;
        Err(anyhow!("File I/O not available in no_std mode"))
    }

    #[cfg(feature = "real_tls")]
    pub fn load_tokens_from_file(&self, path: &str) -> Result<()> {
        validation::validate_path(path)?;
        let _ = path;
        Err(anyhow!("File I/O not available in no_std mode"))
    }


    fn gen_token_id(&self, component: &ComponentType, instance_id: u32) -> String {
        
        let nanos = crate::time_abstraction::kernel_time_secs() as i64 * 1_000_000_000;
        let mut buf = [0u8; 8];
        let _ = crate::rng::kernel_rng_fill(&mut buf);
        let rnd = u64::from_le_bytes(buf);
        let component_str = component.as_str();
        format!("{}:{}:{}:{:016x}", component_str, instance_id, nanos, rnd)
    }

    fn gen_hmac_token(&self, token_id: &str) -> Result<String> {
        let master = self.master_key.expose_secret();
        let key = hmac::Key::new(hmac::HMAC_SHA256, master.as_bytes());
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(token_id.as_bytes());
        let tag = ctx.sign();

        Ok(URL_SAFE_NO_PAD.encode(tag.as_ref()))
    }

    fn now_secs(&self) -> u64 {
        crate::time_abstraction::kernel_time_secs() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_token() {
        let mgr = ComponentTokenManager::new("test_master_key");
        let token = mgr
            .issue_session_token(ComponentType::CPU, 0, 3600)
            .unwrap();

        assert_eq!(token.component, ComponentType::CPU);
        assert!(!token.token_value.is_empty());
    }

    #[test]
    fn test_validate_token() {
        let mgr = ComponentTokenManager::new("test_master_key");
        let token = mgr
            .issue_session_token(ComponentType::GPU, 0, 3600)
            .unwrap();

        let is_valid = mgr
            .validate_token(&token.token_id, &token.token_value)
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_verify() {
        let mgr = ComponentTokenManager::new("test_master_key");
        let token = mgr
            .issue_session_token(ComponentType::IA, 0, 3600)
            .unwrap();

        let sig = mgr
            .sign_action(&token.token_id, "approve_camera_access", "nonce123")
            .unwrap();

        let verified = mgr.verify_signature(&sig).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_revoke_token() {
        let mgr = ComponentTokenManager::new("test_master_key");
        let token = mgr
            .issue_session_token(ComponentType::Thermal, 0, 3600)
            .unwrap();

        mgr.revoke_token(&token.token_id).unwrap();

        let result = mgr.validate_token(&token.token_id, &token.token_value);
        assert!(result.is_err());
    }
}
