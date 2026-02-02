extern crate alloc;

use alloc::sync::Arc;
use anyhow::Result;
use crate::api::ia::launcher::{IALauncher, IALaunchConfig};
use crate::runtime::loops::primary_loop::PrimaryLoop;
use crate::runtime::loops::secondary_loop::SecondaryLoop;
use crate::api::token::TokenManager;

static GLOBAL_IA_LAUNCHER: parking_lot::Mutex<Option<Arc<IALauncher>>> = 
    parking_lot::Mutex::new(None);

pub fn init_ia_launcher_phone_mode(
    primary_loop: Arc<PrimaryLoop>,
    secondary_loop: Arc<SecondaryLoop>,
    token_manager: Arc<TokenManager>,
) -> Result<()> {
    let config = IALaunchConfig {
        ia_tls_port: 9001,
        is_phone_boot_mode: true,
    };

    let launcher = Arc::new(
        IALauncher::new(config)
            .with_primary_loop(primary_loop)
            .with_secondary_loop(secondary_loop)
            .with_token_manager(token_manager),
    );

    launcher.launch()?;
    *GLOBAL_IA_LAUNCHER.lock() = Some(launcher);
    Ok(())
}

pub fn init_ia_launcher_dev_mode(
    primary_loop: Arc<PrimaryLoop>,
    token_manager: Arc<TokenManager>,
) -> Result<()> {
    let config = IALaunchConfig {
        ia_tls_port: 9001,
        is_phone_boot_mode: false,
    };

    let launcher = Arc::new(
        IALauncher::new(config)
            .with_primary_loop(primary_loop)
            .with_token_manager(token_manager),
    );

    launcher.launch()?;
    *GLOBAL_IA_LAUNCHER.lock() = Some(launcher);
    Ok(())
}

pub fn pump_ia_tls_events() -> Result<()> {
    if let Some(launcher) = GLOBAL_IA_LAUNCHER.lock().as_ref() {
        launcher.pump_ia_events()
    } else {
        Ok(())
    }
}

pub fn is_ia_launcher_active() -> bool {
    GLOBAL_IA_LAUNCHER
        .lock()
        .as_ref()
        .map(|l| l.is_launched())
        .unwrap_or(false)
}

pub fn get_ia_tls_port() -> u16 {
    GLOBAL_IA_LAUNCHER
        .lock()
        .as_ref()
        .map(|l| l.ia_tls_port())
        .unwrap_or(9001)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_launcher_state() {
        assert!(!is_ia_launcher_active());
        assert_eq!(get_ia_tls_port(), 9001);
    }

    #[test]
    fn test_pump_without_launcher() {
        let result = pump_ia_tls_events();
        assert!(result.is_ok());
    }
}
