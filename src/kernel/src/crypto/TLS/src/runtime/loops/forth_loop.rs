#![allow(dead_code)]

extern crate alloc;
use alloc::string::ToString;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use parking_lot::Mutex;
use crossbeam_queue::SegQueue;

use crate::services::session_manager::SessionManager;
use crate::api::component_token::ComponentType;
use crate::security::detection::honeypot::HoneypotSystem;
use crate::core::crypto::crypto::CryptoKey;
use crate::runtime::loops::sandbox::{is_loop_sandbox_active, is_tls_sandbox_active, set_loop_sandbox_active, LoopKind, SandboxHandle, SandboxLimits, SandboxManager, SandboxPolicy};

#[derive(Debug, Clone)]
pub struct ForthMessage {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) payload: Vec<u8>,
}

pub struct ForthLoop {
    channels: Arc<Mutex<BTreeMap<String, Arc<SegQueue<ForthMessage>>>>>,
    session_mgr: Arc<SessionManager>,
    honeypot_system: Arc<HoneypotSystem>,
    crypto_key: Arc<CryptoKey>,
    sandbox_manager: SandboxManager,
    sandbox: SandboxHandle,
}

impl ForthLoop {
    pub fn new(
        session_mgr: Arc<SessionManager>,
        crypto_key: Arc<CryptoKey>,
        honeypot_system: Arc<HoneypotSystem>,
    ) -> Self {
        let sandbox_manager = SandboxManager::new();
        let sandbox = sandbox_manager.create_sandbox(
            ComponentType::Power,
            SandboxPolicy::for_device_driver(),
            SandboxLimits::new_restricted(),
        );
        Self {
            channels: Arc::new(Mutex::new(BTreeMap::new())),
            session_mgr,
            honeypot_system,
            crypto_key,
            sandbox_manager,
            sandbox,
        }
    }

    pub fn sync_sandbox_state(&self) {
        let active = self.session_mgr.get_session(ComponentType::Power, 0).is_ok();

        if active {
            if !self.sandbox.is_active() {
                self.sandbox.activate();
            }
            set_loop_sandbox_active(LoopKind::Forth, true);
        } else if self.sandbox.is_active() {
            self.sandbox.deactivate();
            set_loop_sandbox_active(LoopKind::Forth, false);
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
        if is_loop_sandbox_active(LoopKind::Forth) {
            Ok(())
        } else {
            Err("loop sandbox inactive")
        }
    }

    pub fn register_node(&self, node_id: &str, sender: Arc<SegQueue<ForthMessage>>) {
        let mut chans = self.channels.lock();
        chans.insert(node_id.to_string(), sender);
    }

    pub fn list_nodes(&self) -> Vec<String> {
        let chans = self.channels.lock();
        chans.keys().cloned().collect()
    }

    fn validate_power_token(&self, token: &str) -> bool {
        self.session_mgr
            .validate_token_value(ComponentType::Power, 0, token)
            .unwrap_or(false)
    }

    pub(crate) fn receive_external_token(&self, to: &str, token_bytes: Vec<u8>) -> Result<(), &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        let token_str = String::from_utf8(token_bytes).map_err(|_| {
            let hp = self.honeypot_system.clone();
            hp.signal_attempt();
            "invalid token encoding"
        })?;

        if !self.validate_power_token(&token_str) {
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

    pub(crate) fn send_message(&self, from: &str, to: &str, payload: Vec<u8>, token: &str) -> Result<(), &'static str> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active()?;
        self.ensure_loop_flag_active()?;
        self.ensure_sandbox_active()?;
        if !self.validate_power_token(token) {
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
        let msg = ForthMessage {
            from: from.to_string(),
            to: to.to_string(),
            payload: encrypted.into_bytes(),
        };

        sender.push(msg);
        Ok(())
    }

    pub(crate) fn decrypt_message(&self, encrypted: Vec<u8>) -> Option<Vec<u8>> {
        let s = core::str::from_utf8(&encrypted).ok()?;
        self.crypto_key.decrypt(s)
    }

    pub(crate) fn is_power_token(&self, token: &str) -> bool {
        self.validate_power_token(token)
    }
}

#[derive(Clone)]
pub struct ForthChannel {
    node_id: String,
    forth_loop: Arc<ForthLoop>,
    receiver: Arc<SegQueue<ForthMessage>>,
}

impl ForthChannel {
    pub fn new(node_id: String, forth_loop: Arc<ForthLoop>, receiver: Arc<SegQueue<ForthMessage>>) -> Self {
        Self {
            node_id,
            forth_loop,
            receiver,
        }
    }

    pub fn send(&self, to: &str, payload: Vec<u8>, token: &str) -> bool {
        self.forth_loop.send_message(&self.node_id, to, payload, token).is_ok()
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        if let Some(msg) = self.receiver.pop() {
            self.forth_loop.decrypt_message(msg.payload)
        } else {
            None
        }
    }

    pub fn validate(&self, token: String) -> bool {
        self.forth_loop.is_power_token(&token)
    }
}
