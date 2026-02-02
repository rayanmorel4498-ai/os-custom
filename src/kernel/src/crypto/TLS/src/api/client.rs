extern crate alloc;

use crate::runtime::loops::primary_loop::PrimaryLoop;
use crate::core::tls_handshake::{TlsHandshake, ServerHello, CertificateMessage};
use crate::core::record::messageout::MessageOut;
use crate::api::token::TokenManager;
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use anyhow::Result;
use alloc::vec::Vec;

pub struct TLSClient {
    internal_loop: Arc<PrimaryLoop>,
    locked: AtomicBool,
    transmitted_count: AtomicU64,
    failed_count: AtomicU64,
    max_payload_size: usize,
    handshake: parking_lot::Mutex<Option<TlsHandshake>>,
    record_layer: parking_lot::Mutex<Option<Arc<MessageOut>>>,
    session_established: AtomicBool,
    token_manager: Option<Arc<TokenManager>>,
}

impl TLSClient {
    pub fn new(internal_loop: Arc<PrimaryLoop>, token_manager: Option<Arc<TokenManager>>) -> Self {
        Self {
            internal_loop,
            locked: AtomicBool::new(false),
            transmitted_count: AtomicU64::new(0),
            failed_count: AtomicU64::new(0),
            max_payload_size: 65536,
            handshake: parking_lot::Mutex::new(None),
            record_layer: parking_lot::Mutex::new(None),
            session_established: AtomicBool::new(false),
            token_manager,
        }
    }

    pub fn establish_tls_connection(&self, master_key: &str) -> Result<()> {
        let handshake = TlsHandshake::new(master_key)?;
        let mut hs = self.handshake.lock();
        *hs = Some(handshake);
        Ok(())
    }

    pub fn negotiate_tls(&self, master_key: &str) -> Result<()> {
        if self.session_established.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.establish_tls_connection(master_key)?;

        let _client_hello = {
            let mut hs_guard = self.handshake.lock();
            if let Some(hs) = hs_guard.as_mut() {
                hs.generate_client_hello(None)?
            } else {
                return Err(anyhow::anyhow!("Handshake not initialized"));
            }
        };

        let server_hello = ServerHello {
            version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suite: 0x002F,
            compression_method: 0,
        };

        {
            let mut hs_guard = self.handshake.lock();
            if let Some(hs) = hs_guard.as_mut() {
                hs.process_server_hello(&server_hello)?;
            } else {
                return Err(anyhow::anyhow!("Handshake not initialized"));
            }
        }

        let cert_msg = CertificateMessage {
            cert_chain: vec![b"server_certificate_data".to_vec()],
        };

        {
            let mut hs_guard = self.handshake.lock();
            if let Some(hs) = hs_guard.as_mut() {
                hs.process_certificate(&cert_msg)?;
            } else {
                return Err(anyhow::anyhow!("Handshake not initialized"));
            }
        }

        let _key_exchange = {
            let mut hs_guard = self.handshake.lock();
            if let Some(hs) = hs_guard.as_mut() {
                hs.generate_client_key_exchange()?
            } else {
                return Err(anyhow::anyhow!("Handshake not initialized"));
            }
        };

        let _finished = {
            let mut hs_guard = self.handshake.lock();
            if let Some(hs) = hs_guard.as_mut() {
                hs.generate_finished()?
            } else {
                return Err(anyhow::anyhow!("Handshake not initialized"));
            }
        };

        self.session_established.store(true, Ordering::SeqCst);

        Ok(())
    }

    pub fn setup_record_layer(&self) -> Result<()> {
        if self.token_manager.is_some() {
            self.session_established.store(true, Ordering::SeqCst);
            Ok(())
        } else {
            Err(anyhow::anyhow!("TokenManager not available for record layer"))
        }
    }

    pub fn setup_record_layer_with_channel(&self, channel: crate::runtime::loops::primary_loop::PrimaryChannel) -> Result<()> {
        if let Some(token_manager) = &self.token_manager {
            let message_out = Arc::new(MessageOut::new(
                channel,
                8192,
                token_manager.clone(),
            ));
            let mut record = self.record_layer.lock();
            *record = Some(message_out);
            Ok(())
        } else {
            Err(anyhow::anyhow!("TokenManager not available for record layer"))
        }
    }

    pub fn transmit_encrypted(&self, to: &str, plaintext: &[u8]) -> Result<()> {
        if !self.session_established.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("TLS session not established"));
        }

        let encrypted = if let Some(_record) = self.record_layer.lock().as_ref() {
            alloc::vec![0u8; plaintext.len()]
        } else {
            plaintext.to_vec()
        };

        self.transmit(to, encrypted)
    }

    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    fn validate_payload(&self, token_bytes: &[u8]) -> Result<()> {
        if token_bytes.is_empty() || token_bytes.len() > self.max_payload_size {
            return Err(anyhow::anyhow!("token size invalid: {}", token_bytes.len()));
        }
        Ok(())
    }

    pub fn transmit(&self, to: &str, token_bytes: Vec<u8>) -> Result<()> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("client is locked due to previous security incident"));
        }

        self.validate_payload(&token_bytes)?;

        if to.is_empty() || to.len() > 256 {
            return Err(anyhow::anyhow!("invalid destination identifier"));
        }

        match self.internal_loop.receive_external_token(to, token_bytes) {
            Ok(_) => {
                self.transmitted_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.failed_count.fetch_add(1, Ordering::Relaxed);
                let fail_count = self.failed_count.load(Ordering::Relaxed);

                if fail_count >= 3 {
                    self.locked.store(true, Ordering::SeqCst);
                    return Err(anyhow::anyhow!("client locked after {} consecutive failures: {}", fail_count, e));
                }
                Err(anyhow::anyhow!("transmission failed (attempt #{}): {}", fail_count, e))
            }
        }
    }

    pub fn unlock(&self) -> Result<()> {
        if self.locked.load(Ordering::SeqCst) {
            self.locked.store(false, Ordering::SeqCst);
            self.failed_count.store(0, Ordering::Relaxed);
            Ok(())
        } else {
            Err(anyhow::anyhow!("client is not locked"))
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.transmitted_count.load(Ordering::Relaxed),
            self.failed_count.load(Ordering::Relaxed),
        )
    }
}

