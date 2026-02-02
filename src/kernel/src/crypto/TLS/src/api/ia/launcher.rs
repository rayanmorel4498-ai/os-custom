extern crate alloc;

use alloc::sync::Arc;
use anyhow::Result;
use crate::runtime::loops::primary_loop::PrimaryLoop;
use crate::runtime::loops::secondary_loop::SecondaryLoop;
use crate::api::token::TokenManager;

pub struct IALaunchConfig {

    pub ia_tls_port: u16,

    pub is_phone_boot_mode: bool,
}

impl Default for IALaunchConfig {
    fn default() -> Self {
        Self {
            ia_tls_port: 9001,
            is_phone_boot_mode: false,
        }
    }
}
pub struct IALauncher {
    config: IALaunchConfig,
    primary_loop: Option<Arc<PrimaryLoop>>,
    secondary_loop: Option<Arc<SecondaryLoop>>,
    token_manager: Option<Arc<TokenManager>>,
    launched: core::sync::atomic::AtomicBool,
}

impl IALauncher {
    pub fn new(config: IALaunchConfig) -> Self {
        Self {
            config,
            primary_loop: None,
            secondary_loop: None,
            token_manager: None,
            launched: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn with_primary_loop(mut self, loop_: Arc<PrimaryLoop>) -> Self {
        self.primary_loop = Some(loop_);
        self
    }

    pub fn with_secondary_loop(mut self, loop_: Arc<SecondaryLoop>) -> Self {
        self.secondary_loop = Some(loop_);
        self
    }

    pub fn with_token_manager(mut self, tm: Arc<TokenManager>) -> Self {
        self.token_manager = Some(tm);
        self
    }

    pub fn launch(&self) -> Result<()> {
        if self
            .launched
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            return Err(anyhow::anyhow!("IA déjà lancée"));
        }

        match self.config.is_phone_boot_mode {
            true => self.launch_phone_boot_sequence(),
            false => self.launch_dev_mode(),
        }
    }

    fn launch_phone_boot_sequence(&self) -> Result<()> {
        if let Some(secondary_loop) = &self.secondary_loop {
            let ia_port = secondary_loop.get_ia_tls_port();
            if ia_port != self.config.ia_tls_port {
                return Err(anyhow::anyhow!(
                    "Port TLS IA invalide: {} != {}",
                    ia_port,
                    self.config.ia_tls_port
                ));
            }

        } else {
            return Err(anyhow::anyhow!("Secondary loop non configurée"));
        }
        Ok(())
    }

    fn launch_dev_mode(&self) -> Result<()> {
        if let Some(_primary_loop) = &self.primary_loop {
            if self.token_manager.is_some() {
                return Ok(());
            } else {
                return Err(anyhow::anyhow!("TokenManager requis"));
            }
        } else {
            return Err(anyhow::anyhow!("Primary loop non configurée"));
        }
    }

    pub fn ia_tls_port(&self) -> u16 {
        self.config.ia_tls_port
    }

    pub fn is_launched(&self) -> bool {
        self.launched.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn pump_ia_events(&self) -> Result<()> {
        if !self.is_launched() {
            return Err(anyhow::anyhow!("IA non lancée"));
        }

        if let Some(secondary_loop) = &self.secondary_loop {
            secondary_loop.pump_ia_tls()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ia_launcher_creation() {
        let launcher = IALauncher::new(IALaunchConfig::default());
        assert!(!launcher.is_launched());
        assert_eq!(launcher.ia_tls_port(), 9001);
    }

    #[test]
    fn test_ia_launcher_phone_boot_mode() {
        let config = IALaunchConfig {
            ia_tls_port: 9001,
            is_phone_boot_mode: true,
        };
        let launcher = IALauncher::new(config);
        assert!(launcher.config.is_phone_boot_mode);
    }

    #[test]
    fn test_ia_launcher_dev_mode() {
        let config = IALaunchConfig {
            ia_tls_port: 9001,
            is_phone_boot_mode: false,
        };
        let launcher = IALauncher::new(config);
        assert!(!launcher.config.is_phone_boot_mode);
    }

    #[test]
    fn test_ia_launcher_double_launch_prevented() {
        let launcher = IALauncher::new(IALaunchConfig::default());
        launcher
            .launched
            .store(true, core::sync::atomic::Ordering::SeqCst);
        let result = launcher.launch();
        assert!(result.is_err());
    }
}
