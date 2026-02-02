#![allow(static_mut_refs)]
extern crate alloc;
use rand_core::{RngCore, OsRng};
use core::sync::atomic::{AtomicBool, Ordering};
use crate::identity::local_id::LocalId;
use crate::DriverError;
use crate::sync::Mutex;

static EPHEMERAL_READY: AtomicBool = AtomicBool::new(false);

static CURRENT_EPHEMERAL: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);

pub struct EphemeralId;

impl EphemeralId {
    pub fn generate(context: &[u8]) -> Result<[u8; 32], DriverError> {
        let local = LocalId::derive(context)?;

        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);

        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&local);
        buffer[32..].copy_from_slice(&random);

        let eph = crate::crypto::hash::Hash::sha256(&buffer);

        {
            let mut cur = CURRENT_EPHEMERAL.lock();
            cur.copy_from_slice(&eph);
        }
        EPHEMERAL_READY.store(true, Ordering::SeqCst);

        Ok(eph)
    }

    pub fn current() -> Result<[u8; 32], DriverError> {
        if !EPHEMERAL_READY.load(Ordering::SeqCst) {
            return Err(DriverError::NotInitialized);
        }
        let cur = CURRENT_EPHEMERAL.lock();
        Ok(*cur)
    }

    pub fn rotate(context: &[u8]) -> Result<[u8; 32], DriverError> {
        Self::destroy();
        Self::generate(context)
    }

    pub fn destroy() {
        {
            let mut cur = CURRENT_EPHEMERAL.lock();
            crate::crypto::storage_crypto::StorageCrypto::zeroize(&mut *cur);
        }
        EPHEMERAL_READY.store(false, Ordering::SeqCst);
    }

    pub fn is_active() -> bool {
        EPHEMERAL_READY.load(Ordering::SeqCst)
    }
}