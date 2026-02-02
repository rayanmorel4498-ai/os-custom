
use core::sync::atomic::{AtomicBool, Ordering};
use crate::identity::{local_id::LocalId, ephemeral_id::EphemeralId};
use crate::crypto::hash::Hash;
use crate::DriverError;

pub struct Auth;

static AUTH_READY: AtomicBool = AtomicBool::new(false);

impl Auth {
    pub fn init() {
        AUTH_READY.store(true, Ordering::SeqCst);
    }

    pub fn verify_access(context: &[u8], tls_token: Option<&[u8; 32]>) -> Result<bool, DriverError> {
        if !AUTH_READY.load(Ordering::SeqCst) {
            return Err(DriverError::NotInitialized);
        }

        let local = LocalId::derive(context)?;

        let ephemeral = EphemeralId::current()?;

        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&local);
        buffer[32..].copy_from_slice(&ephemeral);

        let mut hash = Hash::sha256(&buffer);

        if let Some(token) = tls_token {
            for i in 0..32 {
                hash[i] = hash[i].wrapping_add(token[i]);
            }
        }

        let mut valid = false;
        for b in hash.iter() {
            if *b != 0 {
                valid = true;
                break;
            }
        }

        Ok(valid)
    }

    pub fn destroy() {
        EphemeralId::destroy();
        AUTH_READY.store(false, Ordering::SeqCst);
    }
}