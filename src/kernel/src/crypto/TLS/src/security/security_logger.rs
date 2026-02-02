extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use parking_lot::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub enum SecurityEvent {
    ClientHandshakeStart,
    ClientHandshakeSuccess,
    ClientHandshakeFailed,
    CertificateValidationSuccess,
    CertificateValidationFailed,
    RecordLayerActivated,
    SessionKeysDerived,
    KeyRotation,
    SensitiveBufferZeroed,
    AuthenticationFailed,
}

impl SecurityEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientHandshakeStart => "CLIENT_HANDSHAKE_START",
            Self::ClientHandshakeSuccess => "CLIENT_HANDSHAKE_SUCCESS",
            Self::ClientHandshakeFailed => "CLIENT_HANDSHAKE_FAILED",
            Self::CertificateValidationSuccess => "CERT_VALIDATION_SUCCESS",
            Self::CertificateValidationFailed => "CERT_VALIDATION_FAILED",
            Self::RecordLayerActivated => "RECORD_LAYER_ACTIVATED",
            Self::SessionKeysDerived => "SESSION_KEYS_DERIVED",
            Self::KeyRotation => "KEY_ROTATION",
            Self::SensitiveBufferZeroed => "SENSITIVE_BUFFER_ZEROED",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SecurityLogEntry {
    pub event: SecurityEvent,
    pub timestamp: u64,
    pub details: String,
}

pub struct SecurityLogger {
    entries: Mutex<Vec<SecurityLogEntry>>,
    max_entries: usize,
}

impl SecurityLogger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            max_entries,
        }
    }

    pub fn log(&self, event: SecurityEvent, details: &str) {
        let mut entries = self.entries.lock();
        
        let mut details_str = String::new();
        details_str.push_str(details);
        
        let entry = SecurityLogEntry {
            event,
            timestamp: self.current_timestamp(),
            details: details_str,
        };
        
        entries.push(entry);
        
        if entries.len() > self.max_entries {
            entries.remove(0);
        }
    }

    pub fn log_auth_failure(&self, reason: &str) {
        self.log(SecurityEvent::AuthenticationFailed, reason);
    }

    pub fn log_key_rotation(&self, key_type: &str) {
        let details = alloc::format!("Key rotation for {}", key_type);
        self.log(SecurityEvent::KeyRotation, &details);
    }

    pub fn log_client_handshake_success(&self, peer: &str) {
        let details = alloc::format!("Handshake with {}", peer);
        self.log(SecurityEvent::ClientHandshakeSuccess, &details);
    }

    pub fn get_auth_failures(&self) -> Vec<SecurityLogEntry> {
        self.entries.lock()
            .iter()
            .filter(|e| e.event == SecurityEvent::AuthenticationFailed)
            .cloned()
            .collect()
    }

    pub fn get_key_rotations(&self) -> Vec<SecurityLogEntry> {
        self.entries.lock()
            .iter()
            .filter(|e| e.event == SecurityEvent::KeyRotation)
            .cloned()
            .collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    fn current_timestamp(&self) -> u64 {
        static TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        TICK.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for SecurityLogger {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_creation() {
        let logger = SecurityLogger::new(10);
        assert_eq!(logger.entry_count(), 0);
    }

    #[test]
    fn test_log_event() {
        let logger = SecurityLogger::new(10);
        logger.log(SecurityEvent::ClientHandshakeStart, "test");
        assert_eq!(logger.entry_count(), 1);
    }

    #[test]
    fn test_log_auth_failure() {
        let logger = SecurityLogger::new(10);
        logger.log_auth_failure("invalid token");
        let failures = logger.get_auth_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].event, SecurityEvent::AuthenticationFailed);
    }

    #[test]
    fn test_log_key_rotation() {
        let logger = SecurityLogger::new(10);
        logger.log_key_rotation("session_key");
        let rotations = logger.get_key_rotations();
        assert_eq!(rotations.len(), 1);
        assert_eq!(rotations[0].event, SecurityEvent::KeyRotation);
    }

    #[test]
    fn test_max_entries_limit() {
        let logger = SecurityLogger::new(5);
        for i in 0..10 {
            logger.log(SecurityEvent::ClientHandshakeStart, &alloc::format!("event {}", i));
        }
        assert_eq!(logger.entry_count(), 5);
    }

    #[test]
    fn test_clear_log() {
        let logger = SecurityLogger::new(10);
        logger.log(SecurityEvent::ClientHandshakeStart, "test");
        assert_eq!(logger.entry_count(), 1);
        logger.clear();
        assert_eq!(logger.entry_count(), 0);
    }
}
