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
use crate::api::component_token::ComponentType as ApiComponentType;
use crate::security::detection::honeypot::HoneypotSystem;
use crate::core::crypto::crypto::CryptoKey;
use crate::runtime::{TimeoutManager, TimeoutType, RateLimiter, ComponentType, MetricsCollector};
use crate::runtime::loops::sandbox::{is_loop_sandbox_active, is_tls_sandbox_active, set_loop_sandbox_active, LoopKind, SandboxHandle, SandboxLimits, SandboxManager, SandboxPolicy};

#[derive(Debug, Clone)]
pub struct SecondaryMessage {
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) payload: Vec<u8>,
}

pub struct SecondaryLoop {
    channels: Arc<Mutex<BTreeMap<String, Arc<SegQueue<SecondaryMessage>>>>>,
    session_mgr: Arc<SessionManager>,
    honeypot_system: Arc<HoneypotSystem>,
    crypto_key: Arc<CryptoKey>,
    ia_tls_port: u16,
    timeout_manager: Arc<TimeoutManager>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<MetricsCollector>,
    sandbox_manager: SandboxManager,
    sandbox: SandboxHandle,
}

impl SecondaryLoop {
    pub fn new(
        session_mgr: Arc<SessionManager>,
        crypto_key: Arc<CryptoKey>,
        honeypot_system: Arc<HoneypotSystem>,
    ) -> Self {
        let sandbox_manager = SandboxManager::new();
        let sandbox = sandbox_manager.create_sandbox(
            ApiComponentType::IA,
            SandboxPolicy::for_os(),
            SandboxLimits::new_moderate(),
        );
        sandbox.deactivate();
        Self {
            channels: Arc::new(Mutex::new(BTreeMap::new())),
            session_mgr,
            honeypot_system,
            crypto_key,
            ia_tls_port: 9001,
            timeout_manager: Arc::new(TimeoutManager::new()),
            rate_limiter: Arc::new(RateLimiter::new()),
            metrics: Arc::new(MetricsCollector::new()),
            sandbox_manager,
            sandbox,
        }
    }

    pub fn sync_sandbox_state(&self) {
        let ia_ready = self.session_mgr.get_session(ApiComponentType::IA, 0).is_ok();

        if ia_ready {
            if !self.sandbox.is_active() {
                self.sandbox.activate();
            }
            set_loop_sandbox_active(LoopKind::Secondary, true);
        } else if self.sandbox.is_active() {
            self.sandbox.deactivate();
            set_loop_sandbox_active(LoopKind::Secondary, false);
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
        if is_loop_sandbox_active(LoopKind::Secondary) {
            Ok(())
        } else {
            Err("loop sandbox inactive")
        }
    }

    pub fn register_node(&self, node_id: &str, sender: Arc<SegQueue<SecondaryMessage>>) {
        let mut chans = self.channels.lock();
        chans.insert(node_id.to_string(), sender);
    }

    pub fn list_nodes(&self) -> Vec<String> {
        let chans = self.channels.lock();
        chans.keys().cloned().collect()
    }

    fn validate_os_ia_token(&self, token: &str) -> bool {
        self.session_mgr
            .validate_token_value(ApiComponentType::OS, 0, token)
            .unwrap_or(false)
            || self
                .session_mgr
                .validate_token_value(ApiComponentType::IA, 0, token)
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

        if !self.validate_os_ia_token(&token_str) {
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
        if !self.validate_os_ia_token(token) {
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
        let msg = SecondaryMessage {
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

    pub(crate) fn is_os_or_ia_token(&self, token: &str) -> bool {
        self.validate_os_ia_token(token)
    }

    pub fn get_ia_tls_port(&self) -> u16 {
        self.ia_tls_port
    }

    pub fn pump_ia_tls(&self) -> anyhow::Result<()> {
        self.sync_sandbox_state();
        self.ensure_tls_sandbox_active().map_err(|e| anyhow::anyhow!(e))?;
        self.ensure_loop_flag_active().map_err(|e| anyhow::anyhow!(e))?;
        self.ensure_sandbox_active().map_err(|e| anyhow::anyhow!(e))?;
        let expired = self.timeout_manager.cleanup_expired();
        for _expired_node in expired {
            self.metrics.record_failed_handshake();
        }

        if !self.rate_limiter.is_allowed(ComponentType::IA, 1) {
            self.metrics.record_timeout();
            return Ok(());
        }

        let chans = self.channels.lock();
        let mut _processed_count = 0u64;

        for (node_id, queue) in chans.iter() {
            self.timeout_manager.register_timeout(
                node_id.clone(),
                TimeoutType::MessagePending,
            );

            while let Some(msg) = queue.pop() {
                if self.timeout_manager.has_timeout(node_id) {
                    self.metrics.record_timeout();
                    break;
                }

                _processed_count += 1;
                self.metrics.record_message(msg.payload.len() as u64);
                self.metrics.record_decryption();

                if !self.rate_limiter.is_allowed(ComponentType::IA, 1) {
                    self.metrics.record_timeout();
                    queue.push(msg);
                    break;
                }

                if self.decrypt_message(msg.payload).is_none() {
                    self.metrics.record_failed_handshake();
                    self.honeypot_system.signal_attempt();
                }
            }
        }

        self.metrics.record_latency(5);

        let retry_candidates = self.timeout_manager.get_retry_candidates();
        for candidate in retry_candidates {
            self.timeout_manager.increment_retry(&candidate);
        }

        self.metrics.update_active_sessions(chans.len() as u64);

        Ok(())
    }
}

#[derive(Clone)]
pub struct SecondaryChannel {
    node_id: String,
    secondary_loop: Arc<SecondaryLoop>,
    receiver: Arc<SegQueue<SecondaryMessage>>,
}

impl SecondaryChannel {
    pub fn new(node_id: String, secondary_loop: Arc<SecondaryLoop>, receiver: Arc<SegQueue<SecondaryMessage>>) -> Self {
        Self {
            node_id,
            secondary_loop,
            receiver,
        }
    }

    pub fn send(&self, to: &str, payload: Vec<u8>, token: &str) -> bool {
        self.secondary_loop.send_message(&self.node_id, to, payload, token).is_ok()
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        if let Some(msg) = self.receiver.pop() {
            self.secondary_loop.decrypt_message(msg.payload)
        } else {
            None
        }
    }

    pub fn validate(&self, token: String) -> bool {
        self.secondary_loop.is_os_or_ia_token(&token)
    }

    pub fn get_ia_tls_port(&self) -> u16 {
        self.secondary_loop.ia_tls_port
    }

    pub fn pump_ia_tls(&self) -> anyhow::Result<()> {
        self.secondary_loop.pump_ia_tls()
    }
}
