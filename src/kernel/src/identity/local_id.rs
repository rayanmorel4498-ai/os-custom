
use core::sync::atomic::{AtomicBool, Ordering};
use crate::crypto::{storage_crypto::StorageCrypto, hash::Hash};
use crate::DriverError;
use crate::sync::Mutex;


static LOCAL_ID_READY: AtomicBool = AtomicBool::new(false);

static LOCAL_ID: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);


pub struct LocalId;

impl LocalId {
    pub fn init_from_boot(seed: &[u8]) -> Result<(), DriverError> {
        if LOCAL_ID_READY.load(Ordering::SeqCst) {
            return Err(DriverError::AlreadyInitialized);
        }

        let derived = Hash::sha256(seed);

        {
            let mut local = LOCAL_ID.lock();
            local.copy_from_slice(&derived);
            StorageCrypto::seal(&mut *local)?;
        }

        LOCAL_ID_READY.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn with<F, R>(f: F) -> Result<R, DriverError>
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        if !LOCAL_ID_READY.load(Ordering::SeqCst) {
            return Err(DriverError::NotInitialized);
        }

        {
            let mut local = LOCAL_ID.lock();
            StorageCrypto::unseal(&mut *local)?;
            let result = f(&*local);
            StorageCrypto::seal(&mut *local)?;
            Ok(result)
        }
    }

    pub fn derive(context: &[u8]) -> Result<[u8; 32], DriverError> {
        Self::with(|id| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(id);
            buf[32..32 + context.len().min(32)].copy_from_slice(&context[..context.len().min(32)]);
            Hash::sha256(&buf)
        })
    }

    pub fn destroy() {
        {
            let mut local = LOCAL_ID.lock();
            StorageCrypto::zeroize(&mut *local);
        }
        LOCAL_ID_READY.store(false, Ordering::SeqCst);
    }

    pub fn is_ready() -> bool {
        LOCAL_ID_READY.load(Ordering::SeqCst)
    }
}