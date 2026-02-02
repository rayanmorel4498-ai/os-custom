extern crate alloc;
use alloc::sync::Arc;
use alloc::format;
use parking_lot::RwLock;

#[derive(Clone, Debug)]
pub struct TlsMetrics {
    pub tokens_issued: u64,
    pub tokens_revoked: u64,
    pub tokens_validated: u64,
    pub tokens_validation_failed: u64,
    pub sessions_opened: u64,
    pub sessions_closed: u64,
    pub sessions_expired: u64,
    pub signatures_created: u64,
    pub signatures_verified: u64,
    pub signatures_failed: u64,
    pub privilege_violations: u64,
}

impl Default for TlsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsMetrics {
    pub fn new() -> Self {
        TlsMetrics {
            tokens_issued: 0,
            tokens_revoked: 0,
            tokens_validated: 0,
            tokens_validation_failed: 0,
            sessions_opened: 0,
            sessions_closed: 0,
            sessions_expired: 0,
            signatures_created: 0,
            signatures_verified: 0,
            signatures_failed: 0,
            privilege_violations: 0,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn summary(&self) -> alloc::string::String {
        format!(
            "TlsMetrics {{ tokens_issued: {}, tokens_revoked: {}, tokens_validated: {}, \
             tokens_validation_failed: {}, sessions_opened: {}, sessions_closed: {}, \
             sessions_expired: {}, signatures_created: {}, signatures_verified: {}, \
             signatures_failed: {}, privilege_violations: {} }}",
            self.tokens_issued,
            self.tokens_revoked,
            self.tokens_validated,
            self.tokens_validation_failed,
            self.sessions_opened,
            self.sessions_closed,
            self.sessions_expired,
            self.signatures_created,
            self.signatures_verified,
            self.signatures_failed,
            self.privilege_violations,
        )
    }
}

pub struct MetricsCollector {
    metrics: Arc<RwLock<TlsMetrics>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            metrics: Arc::new(RwLock::new(TlsMetrics::new())),
        }
    }

    pub fn record_token_issued(&self) {
        let mut m = self.metrics.write();
        m.tokens_issued = m.tokens_issued.saturating_add(1);
    }

    pub fn record_token_revoked(&self) {
        let mut m = self.metrics.write();
        m.tokens_revoked = m.tokens_revoked.saturating_add(1);
    }

    pub fn record_token_validated(&self, success: bool) {
        let mut m = self.metrics.write();
        if success {
            m.tokens_validated = m.tokens_validated.saturating_add(1);
        } else {
            m.tokens_validation_failed = m.tokens_validation_failed.saturating_add(1);
        }
    }

    pub fn record_session_opened(&self) {
        let mut m = self.metrics.write();
        m.sessions_opened = m.sessions_opened.saturating_add(1);
    }

    pub fn record_session_closed(&self) {
        let mut m = self.metrics.write();
        m.sessions_closed = m.sessions_closed.saturating_add(1);
    }

    pub fn record_session_expired(&self) {
        let mut m = self.metrics.write();
        m.sessions_expired = m.sessions_expired.saturating_add(1);
    }

    pub fn record_signature_created(&self) {
        let mut m = self.metrics.write();
        m.signatures_created = m.signatures_created.saturating_add(1);
    }

    pub fn record_signature_verified(&self, success: bool) {
        let mut m = self.metrics.write();
        if success {
            m.signatures_verified = m.signatures_verified.saturating_add(1);
        } else {
            m.signatures_failed = m.signatures_failed.saturating_add(1);
        }
    }

    pub fn record_privilege_violation(&self) {
        let mut m = self.metrics.write();
        m.privilege_violations = m.privilege_violations.saturating_add(1);
    }

    pub fn get_metrics(&self) -> TlsMetrics {
        self.metrics.read().clone()
    }

    pub fn summary(&self) -> alloc::string::String {
        self.metrics.read().summary()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        MetricsCollector {
            metrics: Arc::clone(&self.metrics),
        }
    }
}
