
extern crate alloc;
#[cfg(test)]
extern crate std;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::ToString;
use alloc::format;

use crate::api::component_token::{ComponentTokenManager, ComponentType, ComponentToken};
use crate::services::metrics::MetricsCollector;
use crate::security::audit::AuditLogger;
use crate::security::rate_control::RateLimiter;
use crate::security::rate_control::circuit_breaker::CircuitBreaker;
use crate::core::crypto::hmac_validator::HmacValidator;
use crate::core::crypto::dh::DHKeyExchange;
use crate::security::certificates::certificate_pinning::CertificatePinner;
use crate::core::session::session_cache::SessionCache;
use crate::core::crypto::pfs::PerfectForwardSecrecy;
use crate::core::record::compression::TLSCompression;
use crate::security::certificates::ocsp_stapling::OCSPStapling;
use crate::core::handshake::client_auth::ClientAuthenticator;
use crate::security::keys::key_rotation::{KeyRotationManager, KeyRotationPolicy};
use crate::core::handshake::client_auth::ClientAuthPolicy;
use crate::core::handshake::early_data::EarlyDataManager;
use crate::core::session::session_tickets::SessionTicketManager;
use crate::runtime::resources::connection_pool::ConnectionPool;
use crate::core::handshake::handshake_optimizer::HandshakeOptimizer;
use crate::core::record::record_batcher::RecordBatcher;
use crate::runtime::resources::memory_pool::{MemoryPool, PoolConfig};
use crate::runtime::resources::AdaptiveResourceManager;
use crate::core::dynamic_config::DynamicConfig;
use crate::telemetry::TelemetryCollector;
use crate::core::session::psk_manager::PSKManager;
use crate::security::keys::key_update::KeyUpdateManager;
use crate::core::crypto::post_quantum_crypto::PostQuantumCryptoManager;
use crate::core::crypto::sni_encryption::SNIEncryptionManager;
use crate::core::record::compression_detector::CompressionDetector;
use crate::core::handshake::psk_encryption::PSKEncryption;
use crate::security::keys::automatic_rekeying::AutomaticRekeying;
use crate::core::session::session_binding::SessionBinding;
use crate::security::detection::anomaly_detection::AnomalyDetection;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::string::String;
use parking_lot::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    User = 0,
    System = 50,
    Kernel = 100,
}

impl PrivilegeLevel {
    pub fn level(&self) -> u8 {
        *self as u8
    }

    pub fn can_access(&self, required: PrivilegeLevel) -> bool {
        self.level() >= required.level()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ComponentSession {
	pub token: ComponentToken,
	pub last_heartbeat: u64,
	pub valid_requests: u64,
	pub failed_requests: u64,
	pub metadata: BTreeMap<alloc::string::String, alloc::string::String>,
	pub privilege_level: PrivilegeLevel,
}

pub struct SessionManager {
	token_mgr: Arc<ComponentTokenManager>,
    sessions: Arc<RwLock<BTreeMap<String, ComponentSession>>>,
	session_timeout: u64,
	token_lifetime: u64,
	metrics: MetricsCollector,
	audit_logger: Arc<AuditLogger>,
	rate_limiter: Arc<RateLimiter>,
	hmac_validator: Arc<HmacValidator>,
	dh_exchange: Arc<DHKeyExchange>,
	cert_pinner: Arc<CertificatePinner>,
	session_cache: Arc<SessionCache>,
	pfs: Arc<PerfectForwardSecrecy>,
	compression: Arc<parking_lot::Mutex<TLSCompression>>,
	ocsp_stapling: Arc<OCSPStapling>,
	client_authenticator: Arc<ClientAuthenticator>,
	key_rotation_manager: Arc<KeyRotationManager>,
	early_data_manager: Arc<EarlyDataManager>,
	session_ticket_manager: Arc<SessionTicketManager>,
	connection_pool: Arc<ConnectionPool>,
	handshake_optimizer: Arc<HandshakeOptimizer>,
	record_batcher: Arc<parking_lot::Mutex<RecordBatcher>>,
	memory_pool: Arc<MemoryPool>,
    telemetry: TelemetryCollector,
    adaptive_resource_manager: Arc<AdaptiveResourceManager>,
    circuit_breaker: Arc<CircuitBreaker>,
    dynamic_config: Arc<DynamicConfig>,
    psk_manager: Arc<PSKManager>,
    key_update_manager: Arc<KeyUpdateManager>,
	post_quantum_manager: Arc<PostQuantumCryptoManager>,
	sni_encryption_manager: Arc<SNIEncryptionManager>,
	compression_detector: Arc<CompressionDetector>,
	psk_encryption: Arc<PSKEncryption>,
	automatic_rekeying: Arc<AutomaticRekeying>,
	rate_limiter_enhanced: Arc<RateLimiter>,
	session_binding: Arc<SessionBinding>,
	anomaly_detection: Arc<AnomalyDetection>,
}

#[derive(Serialize, Debug)]
pub struct SessionStats {
    pub key: String,
    pub component: String,
    pub token_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_heartbeat: u64,
    pub valid_requests: u64,
    pub failed_requests: u64,
    pub uptime_secs: u64,
    pub privilege_level: u8,
}

impl SessionManager {
    pub fn new(
        master_key: &str,
        session_timeout: u64,
        token_lifetime: u64,
    ) -> Self {
        let hmac_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pool_config = PoolConfig {
            block_size: 4096,
            block_count: 10,
        };
        
        Self {
            token_mgr: Arc::new(ComponentTokenManager::new(master_key)),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            session_timeout,
            token_lifetime,
            metrics: MetricsCollector::new(),
            telemetry: TelemetryCollector::new(),
            audit_logger: Arc::new(AuditLogger::new()),
            rate_limiter: Arc::new(RateLimiter::new()),
            hmac_validator: Arc::new(HmacValidator::new(hmac_key)),
            dh_exchange: Arc::new(DHKeyExchange::new()),
            cert_pinner: Arc::new(CertificatePinner::new()),
            session_cache: Arc::new(SessionCache::new()),
            pfs: Arc::new(PerfectForwardSecrecy::new()),
            compression: Arc::new(parking_lot::Mutex::new(TLSCompression::new())),
            ocsp_stapling: Arc::new(OCSPStapling::new()),
            client_authenticator: Arc::new(ClientAuthenticator::new(ClientAuthPolicy::Optional)),
            key_rotation_manager: Arc::new(KeyRotationManager::new(vec![1, 2, 3], KeyRotationPolicy::TimeBasedRotation(86400))),
            early_data_manager: Arc::new(EarlyDataManager::new(16384, 3600)),
            session_ticket_manager: Arc::new(SessionTicketManager::new(3600, 100)),
            connection_pool: Arc::new(ConnectionPool::new(100, 3600)),
            handshake_optimizer: Arc::new(HandshakeOptimizer::new(3600, 1000)),
            record_batcher: Arc::new(parking_lot::Mutex::new(RecordBatcher::new(16384, 100))),
            memory_pool: Arc::new(MemoryPool::new(pool_config)),
            adaptive_resource_manager: Arc::new(AdaptiveResourceManager::new(100, 50, 500)),
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            dynamic_config: Arc::new(DynamicConfig::new()),
            psk_manager: Arc::new(PSKManager::new(1000, 3600)),
            key_update_manager: Arc::new(KeyUpdateManager::new(vec![0u8; 16])),
            post_quantum_manager: Arc::new(PostQuantumCryptoManager::new()),
            sni_encryption_manager: Arc::new(SNIEncryptionManager::new()),
            compression_detector: Arc::new(CompressionDetector::new()),
            psk_encryption: Arc::new(PSKEncryption::new([0u8; 32])),
            automatic_rekeying: Arc::new(AutomaticRekeying::new(86400, 1048576)),
            rate_limiter_enhanced: Arc::new(RateLimiter::new()),
            session_binding: Arc::new(SessionBinding::new()),
            anomaly_detection: Arc::new(AnomalyDetection::new()),
        }
    }

    pub fn with_token_mgr(
        token_mgr: Arc<ComponentTokenManager>,
        session_timeout: u64,
        token_lifetime: u64,
    ) -> Self {
        let hmac_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pool_config = PoolConfig {
            block_size: 4096,
            block_count: 10,
        };
        
        Self {
            token_mgr,
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            session_timeout,
            token_lifetime,
            metrics: MetricsCollector::new(),
            telemetry: TelemetryCollector::new(),
            audit_logger: Arc::new(AuditLogger::new()),
            rate_limiter: Arc::new(RateLimiter::new()),
            hmac_validator: Arc::new(HmacValidator::new(hmac_key)),
            dh_exchange: Arc::new(DHKeyExchange::new()),
            cert_pinner: Arc::new(CertificatePinner::new()),
            session_cache: Arc::new(SessionCache::new()),
            pfs: Arc::new(PerfectForwardSecrecy::new()),
            compression: Arc::new(parking_lot::Mutex::new(TLSCompression::new())),
            ocsp_stapling: Arc::new(OCSPStapling::new()),
            client_authenticator: Arc::new(ClientAuthenticator::new(ClientAuthPolicy::Optional)),
            key_rotation_manager: Arc::new(KeyRotationManager::new(vec![1, 2, 3], KeyRotationPolicy::TimeBasedRotation(86400))),
            early_data_manager: Arc::new(EarlyDataManager::new(16384, 3600)),
            session_ticket_manager: Arc::new(SessionTicketManager::new(3600, 100)),
            connection_pool: Arc::new(ConnectionPool::new(100, 3600)),
            handshake_optimizer: Arc::new(HandshakeOptimizer::new(3600, 1000)),
            record_batcher: Arc::new(parking_lot::Mutex::new(RecordBatcher::new(16384, 100))),
            memory_pool: Arc::new(MemoryPool::new(pool_config)),
            adaptive_resource_manager: Arc::new(AdaptiveResourceManager::new(100, 50, 500)),
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            dynamic_config: Arc::new(DynamicConfig::new()),
            psk_manager: Arc::new(PSKManager::new(1000, 3600)),
            key_update_manager: Arc::new(KeyUpdateManager::new(vec![0u8; 16])),
            post_quantum_manager: Arc::new(PostQuantumCryptoManager::new()),
            sni_encryption_manager: Arc::new(SNIEncryptionManager::new()),
            compression_detector: Arc::new(CompressionDetector::new()),
            psk_encryption: Arc::new(PSKEncryption::new([0u8; 32])),
            automatic_rekeying: Arc::new(AutomaticRekeying::new(86400, 1048576)),
            rate_limiter_enhanced: Arc::new(RateLimiter::new()),
            session_binding: Arc::new(SessionBinding::new()),
            anomaly_detection: Arc::new(AnomalyDetection::new()),
        }
    }


    pub fn open_session(
        &self,
        component: ComponentType,
        instance_id: u32,
        metadata: Option<BTreeMap<alloc::string::String, alloc::string::String>>,
    ) -> Result<ComponentSession> {
        let component_id = instance_id as u64;
        
        if !self.rate_limiter.check_rate_limit(component_id) {
            self.audit_logger.log_rate_limit_violation(component_id);
            return Err(anyhow!("Rate limit exceeded for component"));
        }

        let key = self.session_key(&component, instance_id);

        {
            let mut sessions = self.sessions.write();
            if let Some(old) = sessions.remove(&key) {
                let _ = self.token_mgr.revoke_token(&old.token.token_id);
            }
        }

        let token = self
            .token_mgr
            .issue_session_token(component, instance_id, self.token_lifetime)?;

        let privilege_level = Self::privilege_for_component(&component);
        let now = self.now_secs();
        let session = ComponentSession {
            token: token.clone(),
            last_heartbeat: now,
            valid_requests: 0,
            failed_requests: 0,
            metadata: metadata.unwrap_or_else(BTreeMap::new),
            privilege_level,
        };

        let mut sessions = self.sessions.write();
        sessions.insert(key, session.clone());
        
        self.metrics.record_session_opened();
        self.telemetry.record_connection_created();
        self.audit_logger.log_session_opened(component_id, self.now_secs());

        Ok(session)
    }


    pub fn issue_token(
        &self,
        component: ComponentType,
        instance_id: u32,
        valid_for_secs: u64,
    ) -> Result<ComponentToken> {
        let component_id = instance_id as u64;

        if !self.rate_limiter.check_rate_limit(component_id) {
            self.audit_logger.log_rate_limit_violation(component_id);
            return Err(anyhow!("Rate limit exceeded for component"));
        }

        let key = self.session_key(&component, instance_id);
        let now = self.now_secs();

        let mut sessions = self.sessions.write();
        let (metadata, valid_requests, failed_requests, privilege_level) = if let Some(old) = sessions.remove(&key) {
            let _ = self.token_mgr.revoke_token(&old.token.token_id);
            (old.metadata, old.valid_requests, old.failed_requests, old.privilege_level)
        } else {
            (
                BTreeMap::new(),
                0,
                0,
                Self::privilege_for_component(&component),
            )
        };

        let token = self
            .token_mgr
            .issue_session_token(component, instance_id, valid_for_secs)?;

        let session = ComponentSession {
            token: token.clone(),
            last_heartbeat: now,
            valid_requests,
            failed_requests,
            metadata,
            privilege_level,
        };

        sessions.insert(key, session);

        self.metrics.record_token_issued();
        self.audit_logger.log(crate::security::audit::AuditLogEntry {
            timestamp: now,
            component_id,
            operation: crate::security::audit::AuditOperation::TokenIssued,
            success: true,
            details: alloc::format!("token_id={}", token.token_id),
        });

        Ok(token)
    }


    pub fn close_session(&self, component: ComponentType, instance_id: u32) -> Result<()> {
        let key = self.session_key(&component, instance_id);
        let mut sessions = self.sessions.write();

        if let Some(session) = sessions.remove(&key) {
            self.token_mgr.revoke_token(&session.token.token_id)?;
            self.audit_logger.log(crate::security::audit::AuditLogEntry {
                timestamp: self.now_secs(),
                component_id: instance_id as u64,
                operation: crate::security::audit::AuditOperation::SessionClosed,
                success: true,
                details: alloc::format!("session_closed"),
            });
            self.telemetry.record_connection_closed();
        }

        Ok(())
    }


    pub fn get_session(&self, component: ComponentType, instance_id: u32) -> Result<ComponentSession> {
        let key = self.session_key(&component, instance_id);
        let sessions = self.sessions.read();

        sessions
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow!("Session non trouvée: {}", key))
    }


    pub fn validate_token_value(
        &self,
        component: ComponentType,
        instance_id: u32,
        token_value: &str,
    ) -> Result<bool> {
        let key = self.session_key(&component, instance_id);
        let mut sessions = self.sessions.write();

        let session = sessions
            .get_mut(&key)
            .ok_or_else(|| anyhow!("Session non trouvée"))?;

        let now = self.now_secs();
        let valid = now <= session.token.expires_at && session.token.token_value == token_value;

        if valid {
            session.valid_requests = session.valid_requests.saturating_add(1);
        } else {
            session.failed_requests = session.failed_requests.saturating_add(1);
        }

        self.metrics.record_token_validated(valid);
        self.audit_logger.log_hmac_validated(instance_id as u64, valid);

        Ok(valid)
    }


    pub fn heartbeat(&self, component: ComponentType, instance_id: u32) -> Result<()> {
        let key = self.session_key(&component, instance_id);
        let mut sessions = self.sessions.write();

        let session = sessions
            .get_mut(&key)
            .ok_or_else(|| anyhow!("Session non trouvée"))?;

        let now = self.now_secs();
        if now > session.token.expires_at {
            return Err(anyhow!("Token session expiré"));
        }

        session.last_heartbeat = now;
        Ok(())
    }


    pub fn record_request(
        &self,
        component: ComponentType,
        instance_id: u32,
        success: bool,
    ) -> Result<()> {
        let key = self.session_key(&component, instance_id);
        let mut sessions = self.sessions.write();

        let session = sessions
            .get_mut(&key)
            .ok_or_else(|| anyhow!("Session non trouvée"))?;

        if success {
            session.valid_requests = session.valid_requests.saturating_add(1);
        } else {
            session.failed_requests = session.failed_requests.saturating_add(1);
        }

        Ok(())
    }


    pub fn cleanup_expired(&self) -> usize {
        let now = self.now_secs();
        let mut sessions = self.sessions.write();

        let to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| {
                now > session.token.expires_at
                    || (now - session.last_heartbeat) > self.session_timeout
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in &to_remove {
            if let Some(session) = sessions.remove(key) {
                let _ = self.token_mgr.revoke_token(&session.token.token_id);
            }
        }

        to_remove.len()
    }


    pub fn list_sessions(&self) -> Vec<(String, ComponentSession)> {
        let sessions = self.sessions.read();
        sessions
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }


    pub fn rotate_token(
        &self,
        component: ComponentType,
        instance_id: u32,
    ) -> Result<ComponentToken> {
        let key = self.session_key(&component, instance_id);
        let mut sessions = self.sessions.write();

        let session = sessions
            .get_mut(&key)
            .ok_or_else(|| anyhow!("Session non trouvée"))?;

        let old_token_id = session.token.token_id.clone();

        let new_token = self
            .token_mgr
            .issue_session_token(component, instance_id, self.token_lifetime)?;

        self.token_mgr.revoke_token(&old_token_id)?;

        session.token = new_token.clone();

        Ok(new_token)
    }


    pub fn renew_session(
        &self,
        component: ComponentType,
        instance_id: u32,
    ) -> Result<ComponentToken> {
        let session = self.get_session(component, instance_id)?;
        let now = self.now_secs();

        let time_remaining = session.token.expires_at.saturating_sub(now);
        let renewal_threshold = self.token_lifetime / 10;

        if time_remaining > renewal_threshold {
            return Ok(session.token);
        }

        self.rotate_token(component, instance_id)
    }


    pub fn session_stats(&self, component: ComponentType, instance_id: u32) -> Result<SessionStats> {
        let session = self.get_session(component, instance_id)?;
        let now = self.now_secs();

        Ok(SessionStats {
            key: self.session_key(&component, instance_id),
            component: component.as_str().to_string(),
            token_id: session.token.token_id,
            created_at: session.token.created_at,
            expires_at: session.token.expires_at,
            last_heartbeat: session.last_heartbeat,
            valid_requests: session.valid_requests,
            failed_requests: session.failed_requests,
            uptime_secs: now.saturating_sub(session.token.created_at),
            privilege_level: session.privilege_level.level(),
        })
    }


    fn session_key(&self, component: &ComponentType, instance_id: u32) -> String {
        format!("{}:{}", component.as_str(), instance_id)
    }

    fn now_secs(&self) -> u64 {
        crate::time_abstraction::kernel_time_secs() as u64
    }

    pub fn get_token_mgr(&self) -> Arc<ComponentTokenManager> {
        Arc::clone(&self.token_mgr)
    }

    fn privilege_for_component(component: &ComponentType) -> PrivilegeLevel {
        match component {
            ComponentType::Kernel => PrivilegeLevel::Kernel,
            ComponentType::OS | ComponentType::IA | ComponentType::SecurityDriver => {
                PrivilegeLevel::System
            }
            _ => PrivilegeLevel::User,
        }
    }

    pub fn check_privilege(
        &self,
        component: ComponentType,
        instance_id: u32,
        required_privilege: PrivilegeLevel,
    ) -> Result<()> {
        let session = self.get_session(component, instance_id)?;
        if !session.privilege_level.can_access(required_privilege) {
            self.metrics.record_privilege_violation();
            return Err(anyhow!(
                "Insufficient privileges: {} < {}",
                session.privilege_level.level(),
                required_privilege.level()
            ));
        }
        Ok(())
    }

    pub fn metrics(&self) -> crate::services::metrics::TlsMetrics {
        self.metrics.get_metrics()
    }

    pub fn metrics_summary(&self) -> alloc::string::String {
        self.metrics.summary()
    }

    pub fn apply_enhanced_security(&self, component: ComponentType, instance_id: u32) -> Result<()> {
        self.compression_detector.check_compression(None)?;

        let _ = self.psk_encryption.get_rotation_interval();

        let _ = self.automatic_rekeying.set_time_interval(86400);

        let _ = self.rate_limiter_enhanced.check_rate_limit(instance_id as u64);

        let _ = self.session_binding.detect_session_migration(
            &format!("{}:{}", component.as_str(), instance_id),
            "192.168.1.1",
        )?;

        self.anomaly_detection.check_metrics(0.1, 0.9, 100, 10, 0.85)?;

        Ok(())
    }

    pub fn audit_logger(&self) -> Arc<AuditLogger> {
        Arc::clone(&self.audit_logger)
    }

    pub fn rate_limiter(&self) -> Arc<RateLimiter> {
        Arc::clone(&self.rate_limiter)
    }

    pub fn hmac_validator(&self) -> Arc<HmacValidator> {
        Arc::clone(&self.hmac_validator)
    }

    pub fn dh_exchange(&self) -> Arc<DHKeyExchange> {
        Arc::clone(&self.dh_exchange)
    }

    pub fn cert_pinner(&self) -> Arc<CertificatePinner> {
        Arc::clone(&self.cert_pinner)
    }

    pub fn session_cache(&self) -> Arc<SessionCache> {
        Arc::clone(&self.session_cache)
    }

    pub fn pfs(&self) -> Arc<PerfectForwardSecrecy> {
        Arc::clone(&self.pfs)
    }

    pub fn compression(&self) -> Arc<parking_lot::Mutex<TLSCompression>> {
        Arc::clone(&self.compression)
    }

    pub fn ocsp_stapling(&self) -> Arc<OCSPStapling> {
        Arc::clone(&self.ocsp_stapling)
    }

    pub fn client_authenticator(&self) -> Arc<ClientAuthenticator> {
        Arc::clone(&self.client_authenticator)
    }

    pub fn key_rotation_manager(&self) -> Arc<KeyRotationManager> {
        Arc::clone(&self.key_rotation_manager)
    }

    pub fn early_data_manager(&self) -> Arc<EarlyDataManager> {
        Arc::clone(&self.early_data_manager)
    }

    pub fn session_ticket_manager(&self) -> Arc<SessionTicketManager> {
        Arc::clone(&self.session_ticket_manager)
    }

    pub fn connection_pool(&self) -> Arc<ConnectionPool> {
        Arc::clone(&self.connection_pool)
    }

    pub fn handshake_optimizer(&self) -> Arc<HandshakeOptimizer> {
        Arc::clone(&self.handshake_optimizer)
    }

    pub fn telemetry(&self) -> crate::telemetry::TelemetryStats {
        self.telemetry.stats()
    }

    pub fn telemetry_collector(&self) -> TelemetryCollector {
        self.telemetry.clone()
    }

    pub fn adaptive_resource_manager(&self) -> Arc<AdaptiveResourceManager> {
        Arc::clone(&self.adaptive_resource_manager)
    }

    pub fn circuit_breaker(&self) -> Arc<CircuitBreaker> {
        Arc::clone(&self.circuit_breaker)
    }

    pub fn dynamic_config(&self) -> Arc<DynamicConfig> {
        Arc::clone(&self.dynamic_config)
    }

    pub fn psk_manager(&self) -> Arc<PSKManager> {
        Arc::clone(&self.psk_manager)
    }

    pub fn key_update_manager(&self) -> Arc<KeyUpdateManager> {
        Arc::clone(&self.key_update_manager)
    }

    pub fn post_quantum_manager(&self) -> Arc<PostQuantumCryptoManager> {
        Arc::clone(&self.post_quantum_manager)
    }

    pub fn sni_encryption_manager(&self) -> Arc<SNIEncryptionManager> {
        Arc::clone(&self.sni_encryption_manager)
    }

    pub fn record_batcher(&self) -> Arc<parking_lot::Mutex<RecordBatcher>> {
        Arc::clone(&self.record_batcher)
    }

    pub fn memory_pool(&self) -> Arc<MemoryPool> {
        Arc::clone(&self.memory_pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_close_session() {
        let mgr = SessionManager::new("test_key", 300, 600);
        let session = mgr
            .open_session(ComponentType::CPU, 0, None)
            .unwrap();

        assert_eq!(session.token.component, ComponentType::CPU);

        mgr.close_session(ComponentType::CPU, 0).unwrap();

        let result = mgr.get_session(ComponentType::CPU, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_heartbeat() {
        let mgr = SessionManager::new("test_key", 300, 600);
        mgr.open_session(ComponentType::GPU, 0, None).unwrap();

        let _ = mgr.heartbeat(ComponentType::GPU, 0);
        let session = mgr.get_session(ComponentType::GPU, 0).unwrap();
        let before = session.last_heartbeat;

        crate::callbacks::kernel_sleep_ms(10);

        let _ = mgr.heartbeat(ComponentType::GPU, 0);
        let session = mgr.get_session(ComponentType::GPU, 0).unwrap();
        assert!(session.last_heartbeat >= before);
    }

    #[test]
    fn test_renew_session() {
        let mgr = SessionManager::new("test_key", 300, 60);
        let session1 = mgr
            .open_session(ComponentType::RAM, 0, None)
            .unwrap();

        let _token1_id = session1.token.token_id.clone();

        let _renewed_token = mgr.renew_session(ComponentType::RAM, 0).unwrap();
        
        let session2 = mgr.get_session(ComponentType::RAM, 0).unwrap();
        
        assert!(!session2.token.token_id.is_empty());
        assert!(session2.token.expires_at > 0);
    }

    #[test]
    fn test_rotate_token() {
        let mgr = SessionManager::new("test_key", 300, 600);
        let session1 = mgr
            .open_session(ComponentType::CPU, 0, None)
            .unwrap();

        let _token1_id = session1.token.token_id.clone();
        let token1_value = session1.token.token_value.clone();

        crate::callbacks::kernel_sleep_ms(1100);

        let new_token = mgr.rotate_token(ComponentType::CPU, 0).unwrap();
        
        assert_ne!(new_token.token_value, token1_value);
        
        let session2 = mgr.get_session(ComponentType::CPU, 0).unwrap();
        assert_eq!(session2.token.token_id, new_token.token_id);
    }

    #[test]
    fn test_session_manager_managers_present_and_telemetry() {
        let mgr = SessionManager::new("test_key", 300, 600);

        let _ = mgr.adaptive_resource_manager();
        let _ = mgr.circuit_breaker();
        let _ = mgr.dynamic_config();
        let _ = mgr.psk_manager();
        let _ = mgr.key_update_manager();
        let _ = mgr.post_quantum_manager();
        let _ = mgr.sni_encryption_manager();

        let before = mgr.telemetry().total_connections_created;
        mgr.open_session(ComponentType::CPU, 1, None).unwrap();
        let after = mgr.telemetry().total_connections_created;
        assert!(after >= before + 1);

        mgr.close_session(ComponentType::CPU, 1).unwrap();
        let stats = mgr.telemetry();
        assert!(stats.current_connections <= stats.total_connections_created);
    }

    #[test]
    fn test_post_quantum_integration() {
        let mgr = SessionManager::new("test_key", 300, 600);
        let pq_mgr = mgr.post_quantum_manager();

        let (pub_key, _sec_key) = pq_mgr.generate_kyber_keypair().unwrap();
        assert!(!pub_key.key.is_empty());
        
        let (dil_pub_key, dil_sec_key) = pq_mgr.generate_dilithium_keypair().unwrap();
        let msg = b"hybrid tls message";
        let sig = pq_mgr.dilithium_sign(&dil_sec_key, msg).unwrap();
        let valid = pq_mgr.dilithium_verify(&dil_pub_key, msg, &sig).unwrap();
        assert!(valid);

        let stats = pq_mgr.stats();
        assert!(stats.total_signs > 0);
        assert!(stats.total_verify > 0);
    }

    #[test]
    fn test_sni_encryption_integration() {
        let mgr = SessionManager::new("test_key", 300, 600);
        let sni_mgr = mgr.sni_encryption_manager();

        let hostname = "secret.example.com";
        let encrypted_sni = sni_mgr.encrypt_sni(hostname).unwrap();
        assert_ne!(encrypted_sni.ciphertext, hostname.as_bytes());

        let decrypted = sni_mgr.decrypt_sni(&encrypted_sni).unwrap();
        assert_eq!(decrypted, hostname);

        let fingerprint = b"sha256_fingerprint_hash_here_32!!";
        let masked = sni_mgr.mask_fingerprint(fingerprint).unwrap();
        assert_ne!(masked.masked, fingerprint);

        let stats = sni_mgr.stats();
        assert!(stats.total_sni_encryptions > 0);
        assert!(stats.total_fingerprint_masks > 0);
        assert!(stats.obfuscation_enabled);
    }
}
