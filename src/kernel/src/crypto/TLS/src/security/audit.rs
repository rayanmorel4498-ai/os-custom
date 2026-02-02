use alloc::format;
use core::fmt;
use parking_lot::Mutex;

#[derive(Clone, Debug)]
pub struct AuditLogEntry {
    pub timestamp: u64,
    pub component_id: u64,
    pub operation: AuditOperation,
    pub success: bool,
    pub details: alloc::string::String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditOperation {
    TokenIssued,
    SessionOpened,
    PrivilegeCheck,
    SignatureVerified,
    HmacValidated,
    RateLimitViolation,
    AuthenticationFailed,
    CryptoOperation,
    KeyExchange,
    SessionClosed,
}

impl fmt::Display for AuditOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenIssued => write!(f, "TokenIssued"),
            Self::SessionOpened => write!(f, "SessionOpened"),
            Self::PrivilegeCheck => write!(f, "PrivilegeCheck"),
            Self::SignatureVerified => write!(f, "SignatureVerified"),
            Self::HmacValidated => write!(f, "HmacValidated"),
            Self::RateLimitViolation => write!(f, "RateLimitViolation"),
            Self::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Self::CryptoOperation => write!(f, "CryptoOperation"),
            Self::KeyExchange => write!(f, "KeyExchange"),
            Self::SessionClosed => write!(f, "SessionClosed"),
        }
    }
}

pub struct AuditLogger {
    entries: alloc::sync::Arc<Mutex<alloc::vec::Vec<AuditLogEntry>>>,
    max_entries: usize,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: alloc::sync::Arc::new(Mutex::new(alloc::vec::Vec::new())),
            max_entries,
        }
    }

    pub fn log(&self, entry: AuditLogEntry) {
        let mut entries = self.entries.lock();

        if entries.len() >= self.max_entries {
            entries.remove(0);
        }

        entries.push(entry);
    }

    pub fn log_token_issued(&self, component_id: u64, token_id: u64) {
        self.log(AuditLogEntry {
            timestamp: Self::current_time(),
            component_id,
            operation: AuditOperation::TokenIssued,
            success: true,
            details: format!("token_id={}", token_id),
        });
    }

    pub fn log_session_opened(&self, component_id: u64, session_id: u64) {
        self.log(AuditLogEntry {
            timestamp: Self::current_time(),
            component_id,
            operation: AuditOperation::SessionOpened,
            success: true,
            details: format!("session_id={}", session_id),
        });
    }

    pub fn log_privilege_check(&self, component_id: u64, requested: u8, granted: bool) {
        self.log(AuditLogEntry {
            timestamp: Self::current_time(),
            component_id,
            operation: AuditOperation::PrivilegeCheck,
            success: granted,
            details: format!("requested_level={}, granted={}", requested, granted),
        });
    }

    pub fn log_signature_verified(&self, component_id: u64, verified: bool) {
        self.log(AuditLogEntry {
            timestamp: Self::current_time(),
            component_id,
            operation: AuditOperation::SignatureVerified,
            success: verified,
            details: format!("verified={}", verified),
        });
    }

    pub fn log_hmac_validated(&self, component_id: u64, valid: bool) {
        self.log(AuditLogEntry {
            timestamp: Self::current_time(),
            component_id,
            operation: AuditOperation::HmacValidated,
            success: valid,
            details: format!("valid={}", valid),
        });
    }

    pub fn log_rate_limit_violation(&self, component_id: u64) {
        self.log(AuditLogEntry {
            timestamp: Self::current_time(),
            component_id,
            operation: AuditOperation::RateLimitViolation,
            success: false,
            details: alloc::string::String::from("exceeded_limit"),
        });
    }

    pub fn entries(&self) -> alloc::vec::Vec<AuditLogEntry> {
        let entries = self.entries.lock();
        entries.clone()
    }

    pub fn entries_for_component(&self, component_id: u64) -> alloc::vec::Vec<AuditLogEntry> {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter(|e| e.component_id == component_id)
            .cloned()
            .collect()
    }

    pub fn entries_for_operation(
        &self,
        operation: AuditOperation,
    ) -> alloc::vec::Vec<AuditLogEntry> {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter(|e| e.operation == operation)
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        let mut entries = self.entries.lock();
        entries.clear();
    }

    pub fn entry_count(&self) -> usize {
        let entries = self.entries.lock();
        entries.len()
    }

    fn current_time() -> u64 {
        crate::time_abstraction::kernel_time_secs()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_entry() {
        let logger = AuditLogger::new();
        logger.log_token_issued(100, 1000);

        assert_eq!(logger.entry_count(), 1);
    }

    #[test]
    fn test_audit_entries_for_component() {
        let logger = AuditLogger::new();
        logger.log_token_issued(100, 1000);
        logger.log_token_issued(200, 2000);
        logger.log_session_opened(100, 5000);

        let entries_100 = logger.entries_for_component(100);
        assert_eq!(entries_100.len(), 2);
    }

    #[test]
    fn test_audit_entries_for_operation() {
        let logger = AuditLogger::new();
        logger.log_token_issued(100, 1000);
        logger.log_token_issued(200, 2000);
        logger.log_session_opened(300, 5000);

        let token_entries = logger.entries_for_operation(AuditOperation::TokenIssued);
        assert_eq!(token_entries.len(), 2);
    }

    #[test]
    fn test_audit_circular_buffer() {
        let logger = AuditLogger::with_capacity(3);
        logger.log_token_issued(100, 1000);
        logger.log_token_issued(100, 2000);
        logger.log_token_issued(100, 3000);
        logger.log_token_issued(100, 4000);

        assert_eq!(logger.entry_count(), 3);
    }

    #[test]
    fn test_audit_clear() {
        let logger = AuditLogger::new();
        logger.log_token_issued(100, 1000);
        logger.log_token_issued(200, 2000);
        assert_eq!(logger.entry_count(), 2);

        logger.clear();
        assert_eq!(logger.entry_count(), 0);
    }
}
