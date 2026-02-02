extern crate alloc;
use alloc::sync::Arc;
use parking_lot::RwLock;

#[derive(Clone, Debug)]
pub struct DynamicConfig {
    inner: Arc<RwLock<ConfigData>>,
}

#[derive(Clone, Debug)]
struct ConfigData {
    pub max_sessions: usize,
    pub max_pinned_certs: usize,
    pub max_audit_entries: usize,
    pub max_early_data_size: u32,
    pub session_ttl_secs: u64,
    pub key_rotation_interval_secs: u64,
    pub handshake_timeout_ms: u64,
    pub enable_adaptive_resizing: bool,
    pub enable_circuit_breaker: bool,
    pub connection_pool_max: usize,
    pub record_batch_timeout_ms: u64,
    pub rate_limit_per_sec: u32,
}

impl Default for ConfigData {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            max_pinned_certs: 10000,
            max_audit_entries: 10000,
            max_early_data_size: 16384,
            session_ttl_secs: 3600,
            key_rotation_interval_secs: 86400,
            handshake_timeout_ms: 30000,
            enable_adaptive_resizing: true,
            enable_circuit_breaker: true,
            connection_pool_max: 1000,
            record_batch_timeout_ms: 100,
            rate_limit_per_sec: 10000,
        }
    }
}

impl DynamicConfig {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConfigData::default())),
        }
    }

    pub fn with_values(
        max_sessions: usize,
        max_pinned_certs: usize,
        session_ttl_secs: u64,
    ) -> Self {
        let mut config = ConfigData::default();
        config.max_sessions = max_sessions;
        config.max_pinned_certs = max_pinned_certs;
        config.session_ttl_secs = session_ttl_secs;
        
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    pub fn max_sessions(&self) -> usize {
        self.inner.read().max_sessions
    }

    pub fn max_pinned_certs(&self) -> usize {
        self.inner.read().max_pinned_certs
    }

    pub fn max_audit_entries(&self) -> usize {
        self.inner.read().max_audit_entries
    }

    pub fn max_early_data_size(&self) -> u32 {
        self.inner.read().max_early_data_size
    }

    pub fn session_ttl_secs(&self) -> u64 {
        self.inner.read().session_ttl_secs
    }

    pub fn key_rotation_interval_secs(&self) -> u64 {
        self.inner.read().key_rotation_interval_secs
    }

    pub fn handshake_timeout_ms(&self) -> u64 {
        self.inner.read().handshake_timeout_ms
    }

    pub fn enable_adaptive_resizing(&self) -> bool {
        self.inner.read().enable_adaptive_resizing
    }

    pub fn enable_circuit_breaker(&self) -> bool {
        self.inner.read().enable_circuit_breaker
    }

    pub fn connection_pool_max(&self) -> usize {
        self.inner.read().connection_pool_max
    }

    pub fn record_batch_timeout_ms(&self) -> u64 {
        self.inner.read().record_batch_timeout_ms
    }

    pub fn rate_limit_per_sec(&self) -> u32 {
        self.inner.read().rate_limit_per_sec
    }

    pub fn set_max_sessions(&self, value: usize) -> Result<(), &'static str> {
        if value < 100 || value > 1_000_000 {
            return Err("max_sessions must be between 100 and 1M");
        }
        self.inner.write().max_sessions = value;
        Ok(())
    }

    pub fn set_max_pinned_certs(&self, value: usize) -> Result<(), &'static str> {
        if value < 100 || value > 1_000_000 {
            return Err("max_pinned_certs must be between 100 and 1M");
        }
        self.inner.write().max_pinned_certs = value;
        Ok(())
    }

    pub fn set_session_ttl_secs(&self, value: u64) -> Result<(), &'static str> {
        if value < 60 || value > 86400 * 365 {
            return Err("session_ttl must be between 60 seconds and 1 year");
        }
        self.inner.write().session_ttl_secs = value;
        Ok(())
    }

    pub fn set_handshake_timeout_ms(&self, value: u64) -> Result<(), &'static str> {
        if value < 1000 || value > 300_000 {
            return Err("handshake_timeout must be between 1s and 5m");
        }
        self.inner.write().handshake_timeout_ms = value;
        Ok(())
    }

    pub fn set_max_early_data_size(&self, value: u32) -> Result<(), &'static str> {
        if value < 512 || value > 65536 {
            return Err("max_early_data_size must be between 512 and 64KB");
        }
        self.inner.write().max_early_data_size = value;
        Ok(())
    }

    pub fn set_enable_adaptive_resizing(&self, value: bool) {
        self.inner.write().enable_adaptive_resizing = value;
    }

    pub fn set_enable_circuit_breaker(&self, value: bool) {
        self.inner.write().enable_circuit_breaker = value;
    }

    pub fn set_connection_pool_max(&self, value: usize) -> Result<(), &'static str> {
        if value < 10 || value > 100_000 {
            return Err("connection_pool_max must be between 10 and 100K");
        }
        self.inner.write().connection_pool_max = value;
        Ok(())
    }

    pub fn set_rate_limit_per_sec(&self, value: u32) -> Result<(), &'static str> {
        if value < 1 || value > 1_000_000 {
            return Err("rate_limit must be between 1 and 1M req/sec");
        }
        self.inner.write().rate_limit_per_sec = value;
        Ok(())
    }

    pub fn snapshot(&self) -> ConfigSnapshot {
        let data = self.inner.read();
        ConfigSnapshot {
            max_sessions: data.max_sessions,
            max_pinned_certs: data.max_pinned_certs,
            max_audit_entries: data.max_audit_entries,
            max_early_data_size: data.max_early_data_size,
            session_ttl_secs: data.session_ttl_secs,
            key_rotation_interval_secs: data.key_rotation_interval_secs,
            handshake_timeout_ms: data.handshake_timeout_ms,
            enable_adaptive_resizing: data.enable_adaptive_resizing,
            enable_circuit_breaker: data.enable_circuit_breaker,
            connection_pool_max: data.connection_pool_max,
            record_batch_timeout_ms: data.record_batch_timeout_ms,
            rate_limit_per_sec: data.rate_limit_per_sec,
        }
    }

    pub fn reset_to_defaults(&self) {
        *self.inner.write() = ConfigData::default();
    }
}

impl Default for DynamicConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub max_sessions: usize,
    pub max_pinned_certs: usize,
    pub max_audit_entries: usize,
    pub max_early_data_size: u32,
    pub session_ttl_secs: u64,
    pub key_rotation_interval_secs: u64,
    pub handshake_timeout_ms: u64,
    pub enable_adaptive_resizing: bool,
    pub enable_circuit_breaker: bool,
    pub connection_pool_max: usize,
    pub record_batch_timeout_ms: u64,
    pub rate_limit_per_sec: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_config_creation() {
        let config = DynamicConfig::new();
        assert_eq!(config.max_sessions(), 1000);
        assert!(config.enable_adaptive_resizing());
    }

    #[test]
    fn test_dynamic_config_set_valid() {
        let config = DynamicConfig::new();
        assert!(config.set_max_sessions(2000).is_ok());
        assert_eq!(config.max_sessions(), 2000);
    }

    #[test]
    fn test_dynamic_config_set_invalid() {
        let config = DynamicConfig::new();
        assert!(config.set_max_sessions(10).is_err());
        assert!(config.set_max_sessions(2_000_000).is_err());
    }

    #[test]
    fn test_dynamic_config_snapshot() {
        let config = DynamicConfig::new();
        let snapshot = config.snapshot();
        assert_eq!(snapshot.max_sessions, 1000);
        assert!(snapshot.enable_circuit_breaker);
    }

    #[test]
    fn test_dynamic_config_toggle() {
        let config = DynamicConfig::new();
        config.set_enable_adaptive_resizing(false);
        assert!(!config.enable_adaptive_resizing());
    }
}
