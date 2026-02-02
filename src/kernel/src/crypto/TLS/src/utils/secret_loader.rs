

extern crate alloc;

use anyhow::Result;
use alloc::vec::Vec;
use alloc::string::String;

pub trait SecretLoader: Send + Sync {
    fn load(&self, path: &str) -> Result<Vec<u8>>;
}

pub struct NoOpSecretLoader;

impl SecretLoader for NoOpSecretLoader {
    fn load(&self, _path: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("SecretLoader not available in no_std mode"))
    }
}

pub struct HsmSecretLoader {
    pub module: Option<String>,
    pub pin: Option<String>,
}

impl HsmSecretLoader {
    pub fn new(module: Option<String>, pin: Option<String>) -> Self { Self { module, pin } }
}

impl SecretLoader for HsmSecretLoader {
    fn load(&self, _path: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("HSM loading not available in no_std mode"))
    }
}

