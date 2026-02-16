/// Module de monitoring temps-réel et alertes
/// Détecte anomalies, dégradations performance, violations SLA

use alloc::sync::Arc;
use spin::Mutex;
use alloc::collections::VecDeque;
use crate::prelude::{Vec, String, ToString};
use alloc::collections::BTreeMap as HashMap;

#[derive(Debug, Clone)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub timestamp: u64,
    pub level: AlertLevel,
    pub metric: String,
    pub current_value: f64,
    pub threshold: f64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct HealthMetric {
    pub name: String,
    pub value: f64,
    pub threshold_warning: f64,
    pub threshold_critical: f64,
    pub timestamp: u64,
}

fn now_ms() -> u64 {
    0
}

/// Moniteur de santé système
pub struct HealthMonitor {
    metrics: Arc<Mutex<VecDeque<HealthMetric>>>,
    alerts: Arc<Mutex<Vec<Alert>>>,
    max_history: usize,
}

impl HealthMonitor {
    pub fn new() -> Self {
        let _monitor_name = "HealthMonitor";
        HealthMonitor {
            metrics: Arc::new(Mutex::new(VecDeque::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
            max_history: 1000,
        }
    }

    /// Enregistrer une métrique
    pub async fn record_metric(
        &self,
        name: &str,
        value: f64,
        threshold_warning: f64,
        threshold_critical: f64,
    ) {
        let metric = HealthMetric {
            name: name.into(),
            value,
            threshold_warning,
            threshold_critical,
            timestamp: now_ms(),
        };

        let mut metrics = self.metrics.lock();
        metrics.push_back(metric.clone());
        while metrics.len() > self.max_history {
            metrics.pop_front();
        }
    }

    /// Ajouter une alerte
    async fn add_alert(
        &self,
        level: AlertLevel,
        metric: &str,
        current_value: f64,
        threshold: f64,
    ) {
        let alert = Alert {
            timestamp: now_ms(),
            level: level.clone(),
            metric: metric.into(),
            current_value,
            threshold,
            message: format!(
                "{:?}: {} = {} (threshold: {})",
                level, metric, current_value, threshold
            ),
        };

        let mut alerts = self.alerts.lock();
        alerts.push(alert);

        // Garder seulement les 500 dernières alertes
        if alerts.len() > 500 {
            alerts.remove(0);
        }
    }

    /// Récupérer les alertes critiques
    pub async fn get_critical_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.lock();
        alerts
            .iter()
            .filter(|a| matches!(a.level, AlertLevel::Critical))
            .cloned()
            .collect()
    }

    /// Récupérer les alertes récentes
    pub async fn get_recent_alerts(&self, count: usize) -> Vec<Alert> {
        let alerts = self.alerts.lock();
        alerts.iter().rev().take(count).cloned().collect::<Vec<_>>().into_iter().rev().collect()
    }

    /// Moyenne d'une métrique sur les N dernières valeurs
    pub async fn get_metric_average(&self, metric_name: &str, last_n: usize) -> Option<f64> {
        let metrics = self.metrics.lock();
        let values: Vec<f64> = metrics
            .iter()
            .rev()
            .take(last_n)
            .filter(|m| m.name == metric_name)
            .map(|m| m.value)
            .collect();

        if values.is_empty() {
            None
        } else {
            Some(values.iter().sum::<f64>() / values.len() as f64)
        }
    }

    /// Trend d'une métrique (increasing, decreasing, stable)
    pub async fn get_metric_trend(&self, metric_name: &str, last_n: usize) -> Option<String> {
        let metrics = self.metrics.lock();
        let values: Vec<f64> = metrics
            .iter()
            .rev()
            .take(last_n)
            .filter(|m| m.name == metric_name)
            .map(|m| m.value)
            .collect();

        if values.len() < 2 {
            return None;
        }

        let first_half_avg = values[..values.len() / 2].iter().sum::<f64>() / (values.len() / 2) as f64;
        let second_half_avg = values[values.len() / 2..].iter().sum::<f64>() / (values.len() / 2) as f64;

        if (second_half_avg - first_half_avg).abs() < 1.0 {
            Some("stable")
        } else if second_half_avg > first_half_avg {
            Some("increasing")
        } else {
            Some("decreasing")
        }
    }
}

/// SLA Monitor - vérifie les SLA
pub struct SLAMonitor {
    sla_targets: Arc<Mutex<HashMap<String, SLATarget>>>,
    violation_history: Arc<Mutex<Vec<SLAViolation>>>,
}

#[derive(Debug, Clone)]
pub struct SLATarget {
    pub name: String,
    pub uptime_percent: f64,          // 99.9%, 99.99%, etc
    pub max_response_time_ms: f64,    // ms
    pub error_rate_percent: f64,      // max %
}

#[derive(Debug, Clone)]
pub struct SLAViolation {
    pub timestamp: u64,
    pub sla_name: String,
    pub metric: String,
    pub target: f64,
    pub actual: f64,
}

impl SLAMonitor {
    pub fn new() -> Self {
        SLAMonitor {
            sla_targets: Arc::new(Mutex::new(HashMap::new())),
            violation_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Ajouter un SLA target
    pub async fn add_target(&self, target: SLATarget) {
        let mut targets = self.sla_targets.lock();
        targets.insert(target.name.clone(), target);
    }

    /// Vérifier un SLA
    pub async fn check_sla(&self, sla_name: &str, metric: &str, value: f64) -> Result<(), SLAViolation> {
        let targets = self.sla_targets.lock();

        if let Some(target) = targets.get(sla_name) {
            let violated = match metric {
                "response_time" => value > target.max_response_time_ms,
                "error_rate" => value > target.error_rate_percent,
                "uptime" => value < target.uptime_percent,
                _ => false,
            };

            if violated {
                let violation = SLAViolation {
                    timestamp: now_ms(),
                    sla_name: sla_name.into(),
                    metric: metric.into(),
                    target: match metric {
                        "response_time" => target.max_response_time_ms,
                        "error_rate" => target.error_rate_percent,
                        "uptime" => target.uptime_percent,
                        _ => 0.0,
                    },
                    actual: value,
                };

                let mut history = self.violation_history.lock();
                history.push(violation.clone());

                return Err(violation);
            }
        }

        Ok(())
    }

    /// Obtenir le SLA compliance (%)
    pub async fn get_compliance_percent(&self, sla_name: &str) -> f64 {
        let history = self.violation_history.lock();
        let violations = history.iter().filter(|v| v.sla_name == sla_name).count();

        if violations == 0 {
            100.0
        } else {
            (history.len() as f64 - violations as f64) / history.len() as f64 * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_runtime::block_on;

    #[test]
    fn test_health_monitor() {
        block_on(async {
        let monitor = HealthMonitor::new();

        monitor.record_metric("cpu_usage", 45.0, 80.0, 95.0);
        monitor.record_metric("cpu_usage", 92.0, 80.0, 95.0);

        let alerts = monitor.get_recent_alerts(10);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warning));
        });
    }

    #[test]
    fn test_sla_monitor() {
        block_on(async {
        let monitor = SLAMonitor::new();

        let target = SLATarget {
            name: "api_service",
            uptime_percent: 99.9,
            max_response_time_ms: 100.0,
            error_rate_percent: 0.1,
        };

        monitor.add_target(target);

        assert!(monitor.check_sla("api_service", "response_time", 50.0).is_ok());

        assert!(monitor.check_sla("api_service", "response_time", 150.0).is_err());
        });
    }
}
