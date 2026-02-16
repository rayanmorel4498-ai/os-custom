use alloc::sync::Arc;
use crate::utils::error::ErrorCode;
use crate::security::tls::bundle;
use crate::core::tls_integration::TLSIntegrationManager;
use crate::prelude::{String, Vec};

/// Client TLS IA (token signé) — implémentation TLS authentique.
pub struct TLSClient {
    tls: Arc<TLSIntegrationManager>,
}

impl TLSClient {
    pub fn new(tls: Arc<TLSIntegrationManager>) -> Self {
        TLSClient { tls }
    }

    pub fn authenticate_with_secret_vec(&self, token: String, secret: Vec<u8>, nonce: u64) -> bool {
        self.tls.authenticate_with_secret_vec(token, secret, nonce)
    }

    pub fn is_authenticated(&self) -> bool {
        self.tls.is_authenticated()
    }

    pub fn secret_for_component(&self, component: &str) -> Option<Vec<u8>> {
        self.tls.secret_for_component(component)
    }

    pub fn set_pool_id(&self, pool_id: u32) {
        self.tls.set_pool_id(pool_id)
    }

    pub fn set_ia_id(&self, ia_id: u64) {
        self.tls.set_ia_id(ia_id)
    }

    pub fn pool_id(&self) -> Option<u32> {
        self.tls.pool_id()
    }

    pub fn ia_id(&self) -> Option<u64> {
        self.tls.ia_id()
    }

    pub fn send_tls_payload(&self, payload: Vec<u8>, priority: u8) -> Result<u64, String> {
        if !self.is_authenticated() {
            return Err("TLS client not authenticated".into());
        }
        // canal TLS IA: on mappe vers une tâche interne
        Ok(self.tls.submit_task_to_ai(0, payload, priority))
    }

    pub fn send_tls_request(&self, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        if !self.is_authenticated() {
            return Err("TLS client not authenticated".into());
        }
        self.tls.handle_tls_request(&payload)
            .map_err(|_| "TLS request failed".into())
    }

    pub fn session_token(&self) -> Option<String> {
        self.tls.get_context().get_token().cloned()
    }

    pub fn on_tls_bundle_payload(&self, payload: &[u8]) -> Result<(), ErrorCode> {
        bundle::handle_bundle_payload(payload)
    }

    pub fn handle_tls_payload(&self, payload: &[u8]) -> Result<(), ErrorCode> {
        self.on_tls_bundle_payload(payload)
    }
}

impl Clone for TLSClient {
    fn clone(&self) -> Self {
        TLSClient { tls: Arc::clone(&self.tls) }
    }
}
