#![allow(dead_code)]

extern crate alloc;
use alloc::string::String;

use crate::services::session_manager::SessionManager;
use alloc::sync::Arc;

pub struct HeartbeatMonitor {
    session_mgr: Arc<SessionManager>,
    cleanup_interval_secs: u64,
    renew_interval_secs: u64,
}

impl HeartbeatMonitor {
    pub fn new(
        session_mgr: Arc<SessionManager>,
        cleanup_interval_secs: u64,
        renew_interval_secs: u64,
    ) -> Self {
        Self {
            session_mgr,
            cleanup_interval_secs,
            renew_interval_secs,
        }
    }

    pub fn do_cleanup(&self) {
        let purged = self.session_mgr.cleanup_expired();
        if purged > 0 {
        }
    }

    pub fn do_renew(&self) {
        let sessions = self.session_mgr.list_sessions();
        
        for (_, session) in sessions {
            let component = session.token.component;
            let instance_id = session.token.instance_id;
            
            let _ = self.session_mgr.renew_session(component, instance_id);
        }
    }

    pub fn health_check(&self) -> HealthStatus {
        let sessions = self.session_mgr.list_sessions();
        
        let total_sessions = sessions.len();
        let total_requests: u64 = sessions.iter().map(|(_, s)| s.valid_requests).sum();
        let total_failures: u64 = sessions.iter().map(|(_, s)| s.failed_requests).sum();
        let success_rate = if total_requests + total_failures > 0 {
            (total_requests as f64) / ((total_requests + total_failures) as f64) * 100.0
        } else {
            100.0
        };

        HealthStatus {
            total_sessions,
            total_valid_requests: total_requests,
            total_failed_requests: total_failures,
            success_rate,
            is_healthy: total_sessions > 0 && success_rate > 50.0,
        }
    }

    pub fn session_summary(&self) -> alloc::vec::Vec<SessionSummary> {
        let sessions = self.session_mgr.list_sessions();
        let now = crate::time_abstraction::kernel_time_secs();
        
        sessions
            .iter()
            .map(|(key, session)| {
                let time_to_expiry = session.token.expires_at.saturating_sub(now);
                let time_since_heartbeat = now.saturating_sub(session.last_heartbeat);

                SessionSummary {
                    key: key.clone(),
                    token_id: session.token.token_id.clone(),
                    time_to_expiry_secs: time_to_expiry,
                    time_since_heartbeat_secs: time_since_heartbeat,
                    valid_requests: session.valid_requests,
                    failed_requests: session.failed_requests,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub total_sessions: usize,
    pub total_valid_requests: u64,
    pub total_failed_requests: u64,
    pub success_rate: f64,
    pub is_healthy: bool,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub key: String,
    pub token_id: String,
    pub time_to_expiry_secs: u64,
    pub time_since_heartbeat_secs: u64,
    pub valid_requests: u64,
    pub failed_requests: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::component_token::ComponentType;

    #[test]
    fn test_health_check() {
        let sm = Arc::new(SessionManager::new("test_key", 300, 600));
        let _ = sm.open_session(ComponentType::CPU, 0, None);
        let _ = sm.open_session(ComponentType::GPU, 0, None);

        let monitor = HeartbeatMonitor::new(sm, 5, 10);
        let health = monitor.health_check();

        assert_eq!(health.total_sessions, 2);
        assert!(health.is_healthy);
    }

    #[test]
    fn test_session_summary() {
        let sm = Arc::new(SessionManager::new("test_key", 300, 600));
        let _ = sm.open_session(ComponentType::CPU, 0, None);

        let monitor = HeartbeatMonitor::new(sm, 5, 10);
        let summary = monitor.session_summary();

        assert_eq!(summary.len(), 1);
        assert!(summary[0].time_to_expiry_secs > 0);
    }

}

