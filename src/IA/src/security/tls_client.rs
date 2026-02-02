use alloc::sync::Arc;
use crate::core::tls_integration::TLSIntegrationManager;
use crate::prelude::{String, Vec};

/// Client TLS IA (token signé) - placeholder strict, pas un vrai TLS.
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

    pub fn send_tls_payload(&self, payload: Vec<u8>, priority: u8) -> Result<u64, String> {
        if !self.is_authenticated() {
            return Err("TLS client not authenticated".into());
        }
        // canal TLS IA: on mappe vers une tâche interne
        Ok(self.tls.submit_task_to_ai(0, payload, priority))
    }
}

impl Clone for TLSClient {
    fn clone(&self) -> Self {
        TLSClient { tls: Arc::clone(&self.tls) }
    }
}
