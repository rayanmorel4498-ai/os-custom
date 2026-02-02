
extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::secure_element::SecureElement;
use crate::memory::{MemoryRegion, MEMORY_DRIVER};
use crate::threads::{ThreadId, ThreadManager};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

static ENCLAVE_ACTIVE: AtomicBool = AtomicBool::new(false);

pub type TrustedFn = fn(&[u8]);

pub struct TrustedExecution;

impl TrustedExecution {
    pub fn execute_periodic(
        token: &str,
        thread: ThreadId,
        secure_element: &SecureElement,
        thread_manager: &ThreadManager,
        code: TrustedFn,
        mem_size: usize,
        frequency_hz: u32,
        encryption_key: &[u8; 32],
    ) -> Result<(), &'static str> {

        if !Self::thread_allowed(thread) {
            return Err("Thread not authorized");
        }

        if !secure_element.verify_trusted_token(token) {
            return Err("Invalid token");
        }

        if ENCLAVE_ACTIVE.swap(true, Ordering::SeqCst) {
            return Err("Enclave already active");
        }

        let mut region = MEMORY_DRIVER.alloc(mem_size, true)
            .map_err(|_| "Memory allocation failed")?;

        let key = Key::from_slice(encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_bytes = [0u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);

        for _ in 0..frequency_hz {
            let mut mem_buf: Vec<u8> = vec![0u8; mem_size];
            cipher.encrypt(nonce, mem_buf.as_ref())
                .map_err(|_| "Encryption failed")?;

            code(&mem_buf);

            cipher.decrypt(nonce, mem_buf.as_ref())
                .map_err(|_| "Decryption failed")?;
            for byte in mem_buf.iter_mut() { *byte = 0; }
        }

        MEMORY_DRIVER.unprotect(&mut region);
        MEMORY_DRIVER.free(&region);

        ENCLAVE_ACTIVE.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn thread_allowed(thread: ThreadId) -> bool {
        matches!(thread, ThreadId::Kernel | ThreadId::System)
    }
}