#![allow(dead_code)]

use alloc::format;
use alloc::vec;
use crate::api::component_token::ComponentType;
use crate::services::session_manager::SessionManager;
use crate::security::detection::honeypot::HoneypotSystem;
use crate::core::crypto::crypto::CryptoKey;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use parking_lot::Mutex;
use crossbeam_queue::SegQueue;
use crate::runtime::loops::sandbox::{is_loop_sandbox_active, is_tls_sandbox_active, set_loop_sandbox_active, LoopKind, SandboxHandle, SandboxLimits, SandboxManager, SandboxPolicy};

#[derive(Debug, Clone)]
pub struct PrimaryMessage {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) payload: Vec<u8>,
}

pub struct PrimaryLoop {
    channels: Arc<Mutex<BTreeMap<String, Arc<SegQueue<PrimaryMessage>>>>>,
    session_mgr: Arc<SessionManager>,
    honeypot_system: Arc<HoneypotSystem>,
    master_key: String,
    crypto_key: Arc<CryptoKey>,
    last_health_poll_ms: Arc<Mutex<u64>>,
    health_poll_interval_ms: u64,
    sandbox_manager: SandboxManager,
    sandbox: SandboxHandle,
}

impl PrimaryLoop {
    pub fn new(
        session_mgr: Arc<SessionManager>,
        crypto_key: Arc<CryptoKey>,
        honeypot_system: Arc<HoneypotSystem>,
        master_key: String,
    ) -> Self {
        let sandbox_manager = SandboxManager::new();
        let sandbox = sandbox_manager.create_sandbox(
            ComponentType::Kernel,
            SandboxPolicy::for_os(),
            SandboxLimits::new_moderate(),
        );
        sandbox.deactivate();
        Self {
            channels: Arc::new(Mutex::new(BTreeMap::new())),
            session_mgr,
            honeypot_system,
            master_key,
            crypto_key,
            last_health_poll_ms: Arc::new(Mutex::new(0)),
            health_poll_interval_ms: 100,
            sandbox_manager,
            sandbox,
        }
    }

    pub fn sync_sandbox_state(&self) {
        let kernel_ready = self.session_mgr.get_session(ComponentType::Kernel, 0).is_ok();
        let hardware_ready = [ComponentType::CPU, ComponentType::GPU, ComponentType::RAM, ComponentType::Thermal]
            .iter()
            .all(|component| self.session_mgr.get_session(*component, 0).is_ok());

        if kernel_ready && hardware_ready {
            if !self.sandbox.is_active() {
                self.sandbox.activate();
                crate::api::kernel::callbacks::kernel_sandbox_created(self.sandbox.sandbox_id);
            }
            set_loop_sandbox_active(LoopKind::Primary, true);
        } else if self.sandbox.is_active() {
            self.sandbox.deactivate();
            set_loop_sandbox_active(LoopKind::Primary, false);
        }
    }

    pub fn authorize_start(&self) -> Result<(), &'static str> {
        let kernel_ready = self.session_mgr.get_session(ComponentType::Kernel, 0).is_ok();
        let hardware_ready = [ComponentType::CPU, ComponentType::GPU, ComponentType::RAM, ComponentType::Thermal]
            .iter()
            .all(|component| self.session_mgr.get_session(*component, 0).is_ok());

        if kernel_ready && hardware_ready {
            self.sync_sandbox_state();
            Ok(())
        } else {
            Err("kernel or hardware sessions not ready")
        }
    }

    fn ensure_sandbox_active(&self) -> Result<(), &'static str> {
        if self.sandbox.is_active() {
            Ok(())
        } else {
            Err("sandbox inactive")
        }
    }

    fn ensure_tls_sandbox_active(&self) -> Result<(), &'static str> {
        if is_tls_sandbox_active() {
            Ok(())
        } else {
            Err("tls sandbox inactive")
        }
    }

    fn ensure_loop_flag_active(&self) -> Result<(), &'static str> {
        if is_loop_sandbox_active(LoopKind::Primary) {
            Ok(())
        } else {
            Err("loop sandbox inactive")
        }
    }

    pub fn sign_module_authorization(&self, component: ComponentType) -> Result<Vec<u8>, &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        let _session = self.session_mgr.get_session(ComponentType::Kernel, 0)
            .map_err(|_| "kernel session not found")?;
        let component_str = format!("{:?}", component);
        self.crypto_key.encrypt(component_str.as_bytes())
            .map(|sig| sig.into_bytes())
            .map_err(|_| "failed to sign module authorization")
    }

    pub fn verify_module_authorization(&self, component: ComponentType, signature: &[u8]) -> Result<bool, &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        let _session = self.session_mgr.get_session(ComponentType::Kernel, 0)
            .map_err(|_| "kernel session not found")?;
        let component_str = format!("{:?}", component);
        
        if let Some(decrypted) = self.crypto_key.decrypt(core::str::from_utf8(signature).unwrap_or("")) {
            Ok(decrypted == component_str.as_bytes())
        } else {
            Ok(false)
        }
    }

    pub fn init_kernel_and_hardware(&self) -> Result<(), &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.session_mgr.get_session(ComponentType::Kernel, 0)
            .map_err(|_| "kernel session not found")?;
        
        let hardware_components = vec![
            ComponentType::CPU,
            ComponentType::GPU,
            ComponentType::RAM,
        ];
        
        for component in hardware_components {
            let _ = self.session_mgr.get_session(component, 0);
        }
        
        Ok(())
    }

    pub fn get_kernel_session(&self) -> Result<crate::services::session_manager::ComponentSession, &'static str> {
        self.session_mgr.get_session(ComponentType::Kernel, 0)
            .map_err(|_| "kernel session not found")
    }

    pub fn get_hardware_sessions(&self) -> Vec<(ComponentType, crate::services::session_manager::ComponentSession)> {
        let hardware_components = vec![
            ComponentType::CPU,
            ComponentType::GPU,
            ComponentType::RAM,
        ];
        
        hardware_components.into_iter()
            .filter_map(|comp| {
                self.session_mgr.get_session(comp, 0).ok().map(|token| (comp, token))
            })
            .collect()
    }

    pub fn register_node(&self, node_id: &str, sender: Arc<SegQueue<PrimaryMessage>>) -> Result<(), &'static str> {
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        let mut chans = self.channels.lock();
        chans.insert(String::from(node_id), sender);
        Ok(())
    }

    pub fn list_nodes(&self) -> Vec<String> {
        let chans = self.channels.lock();
        chans.keys().cloned().collect()
    }

    fn validate_kernel_or_hardware_token(&self, token: &str) -> bool {
        let kernel_valid = self.session_mgr
            .validate_token_value(ComponentType::Kernel, 0, token)
            .unwrap_or(false);
        
        if kernel_valid {
            return true;
        }

        let hardware_components = vec![ComponentType::CPU, ComponentType::GPU, ComponentType::RAM, ComponentType::Thermal];
        for component in hardware_components {
            if self.session_mgr
                .validate_token_value(component, 0, token)
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
    }

    pub fn receive_external_token(&self, to: &str, token_bytes: Vec<u8>) -> Result<(), &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        let token_str = String::from_utf8(token_bytes).map_err(|_| {
            let hp = self.honeypot_system.clone();
            hp.signal_attempt();
            "invalid token encoding"
        })?;

        if !self.validate_kernel_or_hardware_token(&token_str) {
            let hp = self.honeypot_system.clone();
            hp.signal_attempt();
            return Err("token validation failed");
        }

        let chans = self.channels.lock();
        if !chans.contains_key(to) {
            let hp = self.honeypot_system.clone();
            hp.signal_attempt();
            return Err("unknown destination");
        }

        Ok(())
    }

    pub fn send_message(&self, from: &str, to: &str, payload: Vec<u8>, token: &str) -> Result<(), &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        if !self.validate_kernel_or_hardware_token(token) {
            let hp = self.honeypot_system.clone();
            hp.signal_attempt();
            return Err("invalid token");
        }

        let chans = self.channels.lock();
        let sender = match chans.get(to) {
            Some(s) => s.clone(),
            None => {
                let hp = self.honeypot_system.clone();
                hp.signal_attempt();
                return Err("destination not found");
            }
        };

        let encrypted = self.crypto_key.encrypt(&payload).map_err(|_| "encryption failed")?;

        let msg = PrimaryMessage {
            from: String::from(from),
            to: String::from(to),
            payload: encrypted.into_bytes(),
        };

        sender.push(msg);
        Ok(())
    }

    pub fn decrypt_message(&self, encrypted: Vec<u8>) -> Option<Vec<u8>> {
        let s = core::str::from_utf8(&encrypted).ok()?;
        self.crypto_key.decrypt(s)
    }

    pub fn is_kernel_or_hardware_token(&self, token: &str) -> bool {
        self.validate_kernel_or_hardware_token(token)
    }

    pub fn trigger_health_poll(&self, timestamp_ms: u64) -> Result<bool, &'static str> {
        let mut last_poll = self.last_health_poll_ms.lock();

        if timestamp_ms.saturating_sub(*last_poll) < self.health_poll_interval_ms {
            return Ok(false);
        }

        *last_poll = timestamp_ms;

        Ok(true)
    }

    pub fn execute_hardware_command(&self, command: &str, params: Vec<u8>, token: &str) -> Result<(), &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        if !self.validate_kernel_or_hardware_token(token) {
            let hp = self.honeypot_system.clone();
            hp.signal_attempt();
            return Err("invalid token for hardware command");
        }

        match command {
            "SetCpuFreq" | "SetGpuFreq" | "SetThermalThrottle" | "SetDisplayBrightness" | "RecoverComponent" => {
                let encrypted = self.crypto_key.encrypt(&params).map_err(|_| "encryption failed")?;
                
                let msg = PrimaryMessage {
                    from: String::from("tls-primary"),
                    to: String::from("hardware-driver"),
                    payload: encrypted.into_bytes(),
                };
                
                let chans = self.channels.lock();
                if let Some(sender) = chans.get("hardware-driver") {
                    sender.push(msg);
                    Ok(())
                } else {
                    Err("hardware-driver not registered")
                }
            },
            _ => Err("unknown hardware command")
        }
    }
}

#[derive(Clone)]
pub struct PrimaryChannel {
    node_id: String,
    primary_loop: Arc<PrimaryLoop>,
    receiver: Arc<SegQueue<PrimaryMessage>>,
}

impl PrimaryChannel {
    pub fn new(node_id: String, primary_loop: Arc<PrimaryLoop>, receiver: Arc<SegQueue<PrimaryMessage>>) -> Self {
        Self {
            node_id,
            primary_loop,
            receiver,
        }
    }

    pub fn send(&self, to: &str, payload: Vec<u8>, token: &str) -> bool {
        self.primary_loop.send_message(&self.node_id, to, payload, token).is_ok()
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        if let Some(msg) = self.receiver.pop() {
            self.primary_loop.decrypt_message(msg.payload)
        } else {
            None
        }
    }

    pub fn validate(&self, token: String) -> bool {
        self.primary_loop.is_kernel_or_hardware_token(&token)
    }
}
