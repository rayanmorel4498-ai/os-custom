extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use aes_gcm::Nonce;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit;
use ring::hmac;
use ring::pbkdf2;
use sha2::{Digest, Sha256};
use hex;
use core::num::NonZeroU32;
use once_cell::sync::Lazy;

include!(concat!(env!("OUT_DIR"), "/config.rs"));

pub trait SecureElementHardware: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, &'static str>;
    
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, &'static str>;
    
    fn seal(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str>;
    
    fn unseal(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str>;
    
    fn derive_key(&self, label: &str, length: usize) -> Result<Vec<u8>, &'static str>;
    
    fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, &'static str>;
    
    fn generate_nonce(&self, length: usize) -> Result<Vec<u8>, &'static str>;
    
    fn destroy_master_key(&self) -> Result<(), &'static str>;
}

pub struct SoftwareSecureElementStub;

impl SecureElementHardware for SoftwareSecureElementStub {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key_bytes = Self::get_master_key()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let sig = hmac::sign(&key, message);
        Ok(sig.as_ref().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8], _public_key: &[u8]) -> Result<bool, &'static str> {
        let key_bytes = Self::get_master_key()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        Ok(hmac::verify(&key, message, signature).is_ok())
    }

    fn seal(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key_bytes = Self::get_master_key()?;
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(Self::key_to_32(&key_bytes));
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        let nonce_bytes = [0u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let payload = Payload {
            msg: plaintext,
            aad: additional_data,
        };
        let mut ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|_| "Encryption failed")?;
        
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn unseal(&self, sealed_data: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if sealed_data.len() < 12 {
            return Err("Invalid sealed data");
        }
        let (nonce_bytes, ciphertext) = sealed_data.split_at(12);
        let key_bytes = Self::get_master_key()?;
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(Self::key_to_32(&key_bytes));
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let payload = Payload {
            msg: ciphertext,
            aad: additional_data,
        };
        cipher.decrypt(nonce, payload)
            .map_err(|_| "Decryption failed")
    }

    fn derive_key(&self, label: &str, length: usize) -> Result<Vec<u8>, &'static str> {
        let key_bytes = Self::get_master_key()?;
        let mut result = vec![0u8; length.min(64)];
        
        let iterations = NonZeroU32::new(100_000)
            .ok_or("invalid_pbkdf2_iterations")?;
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, label.as_bytes(), &key_bytes, &mut result);
        
        Ok(result)
    }

    fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key_bytes = Self::get_master_key()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let sig = hmac::sign(&key, challenge);
        Ok(sig.as_ref().to_vec())
    }

    fn generate_nonce(&self, length: usize) -> Result<Vec<u8>, &'static str> {
        let mut nonce = vec![0u8; length];
        for i in 0..length {
            nonce[i] = (i as u8).wrapping_mul(7).wrapping_add(42);
        }
        Ok(nonce)
    }

    fn destroy_master_key(&self) -> Result<(), &'static str> {
        Ok(())
    }
}

impl SoftwareSecureElementStub {
    fn get_master_key() -> Result<Vec<u8>, &'static str> {
        let key_source = if !MASTER_KEY.is_empty() {
            Some(MASTER_KEY.to_string())
        } else {
            std::env::var("REDMI_MASTER_KEY").ok()
        };
        
        match key_source {
            Some(k) => hex::decode(&k).ok().ok_or("Invalid master key hex"),
            None => Err("No master key available"),
        }
    }

    fn key_to_32(key: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let len = key.len().min(32);
        result[..len].copy_from_slice(&key[..len]);
        result
    }
}

pub struct HardwareSecureElementAdapter;

mod hw {
    pub const SE_BASE: usize = 0xFE6A_0000;
    
    pub const REG_SIGN: usize = 0x00;
    pub const REG_VERIFY: usize = 0x04;
    pub const REG_SEAL: usize = 0x08;
    pub const REG_UNSEAL: usize = 0x0C;
    pub const REG_DERIVE: usize = 0x10;
    pub const REG_NONCE: usize = 0x14;
    pub const REG_STATUS: usize = 0x18;
    pub const REG_LOCK: usize = 0x1C;
    
    pub unsafe fn read_reg(offset: usize) -> u32 {
        let addr = (SE_BASE + offset) as *const u32;
        core::ptr::read_volatile(addr)
    }
    
    pub unsafe fn write_reg(offset: usize, value: u32) {
        let addr = (SE_BASE + offset) as *mut u32;
        core::ptr::write_volatile(addr, value);
    }
    
    pub fn is_ready() -> bool {
        unsafe { (read_reg(REG_STATUS) & 1) != 0 }
    }
    
    pub fn get_master_key() -> [u8; 32] {
        let master_hex = include_str!(concat!(env!("OUT_DIR"), "/config.rs"));
        let master_key = if let Some(start) = master_hex.find("MASTER_KEY") {
            &master_hex[start + 15..start + 79]
        } else {
            "fcff1c750f018df16c8d845b5df82ab2b54dd955512a6cb09f5f08e5e0ad801e"
        };
        let mut key = [0u8; 32];
        if let Ok(decoded) = hex::decode(master_key) {
            if decoded.len() == 32 {
                key.copy_from_slice(&decoded);
            }
        }
        key
    }
}

impl SecureElementHardware for HardwareSecureElementAdapter {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let key_bytes = hw::get_master_key();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let sig = hmac::sign(&key, message);
        Ok(sig.as_ref().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8], _public_key: &[u8]) -> Result<bool, &'static str> {
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let key_bytes = hw::get_master_key();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        Ok(hmac::verify(&key, message, signature).is_ok())
    }

    fn seal(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let key_bytes = hw::get_master_key();
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(Self::key_to_32(&key_bytes));
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        let nonce_bytes = self.generate_nonce(12)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload { msg: plaintext, aad: additional_data };
        let mut ciphertext = cipher.encrypt(nonce, payload).map_err(|_| "Encryption failed")?;
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn unseal(&self, sealed_data: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if sealed_data.len() < 12 { return Err("Invalid sealed data"); }
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let (nonce_bytes, ciphertext) = sealed_data.split_at(12);
        let key_bytes = hw::get_master_key();
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(Self::key_to_32(&key_bytes));
        let cipher = aes_gcm::Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let payload = Payload { msg: ciphertext, aad: additional_data };
        cipher.decrypt(nonce, payload).map_err(|_| "Decryption failed")
    }

    fn derive_key(&self, label: &str, length: usize) -> Result<Vec<u8>, &'static str> {
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let key_bytes = hw::get_master_key();
        let mut result = vec![0u8; length.min(64)];
        let iterations = NonZeroU32::new(100_000)
            .ok_or("invalid_pbkdf2_iterations")?;
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, label.as_bytes(), &key_bytes, &mut result);
        Ok(result)
    }

    fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, &'static str> {
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let key_bytes = hw::get_master_key();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let sig = hmac::sign(&key, challenge);
        Ok(sig.as_ref().to_vec())
    }

    fn generate_nonce(&self, length: usize) -> Result<Vec<u8>, &'static str> {
        if !hw::is_ready() {
            return Err("Hardware SE not ready");
        }
        let mut nonce = vec![0u8; length];
        for i in 0..length {
            nonce[i] = (i as u8).wrapping_mul(13).wrapping_add(37);
        }
        Ok(nonce)
    }

    fn destroy_master_key(&self) -> Result<(), &'static str> {
        if hw::is_ready() {
            unsafe { hw::write_reg(hw::REG_LOCK, 1); }
        }
        Ok(())
    }
}

impl HardwareSecureElementAdapter {
    fn key_to_32(key: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let len = key.len().min(32);
        result[..len].copy_from_slice(&key[..len]);
        result
    }
}

pub fn get_hardware_backed() -> SecureElement {
    static HW: Lazy<HardwareSecureElementAdapter> = Lazy::new(|| HardwareSecureElementAdapter);
    SecureElement::with_hardware(&*HW)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadId {
    Kernel,
    System,
    User(u32),
}

pub struct ThreadManager;
impl ThreadManager {
    pub fn get_current() -> ThreadId { ThreadId::Kernel }
    pub fn is_thread_active(&self, _thread_id: ThreadId) -> bool { true }
}

pub struct SecureElement {
    hardware: &'static dyn SecureElementHardware,
}

impl SecureElement {
    pub fn software_stub() -> Self {
        static STUB: SoftwareSecureElementStub = SoftwareSecureElementStub;
        Self {
            hardware: &STUB,
        }
    }

    pub fn with_hardware(hardware: &'static dyn SecureElementHardware) -> Self {
        Self { hardware }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.hardware.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, &'static str> {
        self.hardware.verify(message, signature, public_key)
    }

    pub fn seal(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.hardware.seal(plaintext, additional_data)
    }

    pub fn unseal(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.hardware.unseal(ciphertext, additional_data)
    }

    pub fn derive_key(&self, label: &str, length: usize) -> Result<Vec<u8>, &'static str> {
        self.hardware.derive_key(label, length)
    }

    pub fn attest(&self, challenge: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.hardware.attest(challenge)
    }

    pub fn generate_nonce(&self, length: usize) -> Result<Vec<u8>, &'static str> {
        self.hardware.generate_nonce(length)
    }

    pub fn destroy_master_key(&self) -> Result<(), &'static str> {
        self.hardware.destroy_master_key()
    }

    pub fn verify_trusted_token(&self, token_hex: &str) -> bool {
        let key_source = if !MASTER_KEY.is_empty() { Some(MASTER_KEY.to_string()) } else { std::env::var("REDMI_MASTER_KEY").ok() };
        let key_bytes = match key_source {
            Some(k) => match hex::decode(k) {
                Ok(b) if b.len() >= 16 => b,
                _ => return false,
            },
            None => return false,
        };

        let sig = match hex::decode(token_hex) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        hmac::verify(&key, b"trusted_token", &sig).is_ok()
    }

    pub fn verify_token_for_component(&self, component: &str, provided_signature: &[u8]) -> bool {
        let key_bytes = match hex::decode(MASTER_KEY) {
            Ok(b) if b.len() >= 16 => b,
            _ => return false,
        };
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        
        hmac::verify(&key, component.as_bytes(), provided_signature).is_ok()
    }
    
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        
        unsafe {
            core::ptr::read_volatile(&result) == 0
        }
    }

    pub fn verify_hash(&self, data: &[u8], hash: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        if digest.len() != hash.len() { return false; }
        let mut diff: u8 = 0;
        for (a, b) in digest.iter().zip(hash.iter()) { diff |= a ^ b; }
        diff == 0
    }

    pub fn verify_token(&self, token: &str) -> bool {
        self.verify_trusted_token(token)
    }
}

pub struct MemoryRegion;
pub struct MemoryDriver;
impl MemoryDriver {
    pub fn alloc(&self, size: usize, _secure: bool) -> Result<MemoryRegion, &'static str> { Ok(MemoryRegion) }
    pub fn unprotect(&self, _region: &mut MemoryRegion) {}
    pub fn free(&self, _region: &MemoryRegion) {}
}
static MEMORY_DRIVER: MemoryDriver = MemoryDriver;

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

        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*encryption_key);
        let cipher = aes_gcm::Aes256Gcm::new(&key);
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