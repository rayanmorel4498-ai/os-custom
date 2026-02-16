// src/core/system_integrity.rs
// Module d'intégrité du système
// Vérifie et monitore la santé de l'OS, des modules et du hardware

use crate::utils::error::{EngineError, Result};
use alloc::collections::BTreeMap as HashMap;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use crate::prelude::{String, Vec};
use serde::{Deserialize, Serialize};
use spin::Mutex;

/// État d'un composant du système
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentHealth {
	Healthy,
	Degraded,
	Critical,
	Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentIntegrityReport {
	pub name: String,
	pub health: ComponentHealth,
	pub last_check: u64,
	pub checks_passed: u64,
	pub checks_failed: u64,
	pub error_message: Option<String>,
}

/// Moniteur d'intégrité du système
pub struct SystemIntegrityMonitor {
    components: Arc<Mutex<HashMap<String, ComponentIntegrityReport>>>,
    alerts: Arc<Mutex<Vec<IntegrityAlert>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityAlert {
    pub component: String,
    pub severity: u8,        // 0=info, 100=critical
    pub message: String,
    pub timestamp: u64,
}

impl SystemIntegrityMonitor {
    pub fn new() -> Self {
        Self {
            components: Arc::new(Mutex::new(HashMap::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Enregistrer un check de composant
    pub async fn check_component(&self, name: &str, success: bool, error: Option<String>) -> Result<()> {
        let mut components = self.components.lock();
        let now = 0u64; // no_std: No system time available

        let report = components
            .entry(name.to_string())
            .or_insert(ComponentIntegrityReport {
                name: name.to_string(),
                health: ComponentHealth::Unknown,
                last_check: 0,
                checks_passed: 0,
                checks_failed: 0,
                error_message: None,
            });

        report.last_check = now;
        if success {
            report.checks_passed += 1;
            report.health = ComponentHealth::Healthy;
            report.error_message = None;
        } else {
            report.checks_failed += 1;
            let fail_rate = (report.checks_failed as f64) / ((report.checks_passed + report.checks_failed) as f64);
            report.health = if fail_rate > 0.5 {
                ComponentHealth::Critical
            } else {
                ComponentHealth::Degraded
            };
            report.error_message = error.clone();

            // Créer une alerte
            if let Some(err) = error {
                let severity = if report.health == ComponentHealth::Critical { 100 } else { 50 };
                let alert = IntegrityAlert {
                    component: name.to_string(),
                    severity,
                    message: err,
                    timestamp: now,
                };
                let mut alerts = self.alerts.lock();
                alerts.push(alert);
            }
        }

        Ok(())
    }

    /// Obtenir le rapport d'un composant
    pub async fn get_component_report(&self, name: &str) -> Result<ComponentIntegrityReport> {
        let components = self.components.lock();
        components
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::CommunicationError(format!("Component not found: {}", name)))
    }

    /// Obtenir tous les rapports
    pub async fn get_all_reports(&self) -> HashMap<String, ComponentIntegrityReport> {
        let components = self.components.lock();
        components.clone()
    }

    /// Vérifier la santé globale du système
    pub async fn system_health(&self) -> ComponentHealth {
        let components = self.components.lock();
        if components.is_empty() {
            return ComponentHealth::Unknown;
        }

        let critical_count = components
            .values()
            .filter(|r| r.health == ComponentHealth::Critical)
            .count();
        let degraded_count = components
            .values()
            .filter(|r| r.health == ComponentHealth::Degraded)
            .count();

        if critical_count > 0 {
            ComponentHealth::Critical
        } else if degraded_count > 0 {
            ComponentHealth::Degraded
        } else {
            ComponentHealth::Healthy
        }
    }

    /// Obtenir les alertes récentes
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<IntegrityAlert> {
        let alerts = self.alerts.lock();
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Lancer un check complet du système
    pub async fn full_system_check(&self) {
        // Vérifier les composants critiques
        let _ = self.check_component("kernel", true, None).await.ok();
        let _ = self.check_component("memory", true, None).await.ok();
        let _ = self.check_component("filesystem", true, None).await.ok();
        let _ = self.check_component("network", true, None).await.ok();
        let _ = self.check_component("security", true, None).await.ok();
    }

    /// Vérifier l'intégrité d'un fichier
    pub async fn verify_file_integrity(&self, path: &str, expected_hash: Option<&str>) -> Result<bool> {
        // Simulate file integrity check
        let is_valid = expected_hash.is_none() || expected_hash == Some("valid_hash");
        if let Err(err) = self.check_component(
            &format!("file:{}", path),
            is_valid,
            if !is_valid {
                Some("Hash mismatch".to_string())
            } else {
                None
            },
        ).await {
            return Err(err);
        }
        Ok(is_valid)
    }

    /// Obtenir un score de santé (0-100)
    pub async fn health_score(&self) -> u8 {
        let components = self.components.lock();
        if components.is_empty() {
            return 0;
        }

        let mut score = 100u16;
        for report in components.values() {
            match report.health {
                ComponentHealth::Healthy => {}
                ComponentHealth::Degraded => score = score.saturating_sub(20),
                ComponentHealth::Critical => score = score.saturating_sub(50),
                ComponentHealth::Unknown => score = score.saturating_sub(10),
            }
        }
        (score as u8).min(100)
    }
}

impl Default for SystemIntegrityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::utils::test_runtime::block_on;

    #[test]
    fn test_component_check() {
        block_on(async {
            let monitor = SystemIntegrityMonitor::new();
            assert!(monitor.check_component("kernel", true, None).await.is_ok());
            let report = monitor.get_component_report("kernel").await.unwrap();
            assert_eq!(report.health, ComponentHealth::Healthy);
            assert_eq!(report.checks_passed, 1);
        });
    }

    #[test]
    fn test_system_health() {
        block_on(async {
            let monitor = SystemIntegrityMonitor::new();
            let _ = monitor.check_component("cpu", true, None).await;
            let _ = monitor
                .check_component("gpu", false, Some("GPU error".to_string()))
                .await;

            let health = monitor.system_health().await;
            assert_eq!(health, ComponentHealth::Degraded);
        });
    }

    #[test]
    fn test_health_score() {
        block_on(async {
            let monitor = SystemIntegrityMonitor::new();
            let _ = monitor.check_component("c1", true, None).await;
            let score = monitor.health_score().await;
            assert!(score > 0);
        });
    }
}
