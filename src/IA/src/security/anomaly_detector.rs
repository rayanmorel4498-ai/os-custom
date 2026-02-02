use alloc::collections::BTreeMap;
use crate::prelude::{String, Vec, format};

#[derive(Clone, Copy)]
pub struct AnomalySignal {
    pub battery_level: u8,
    pub temperature_c: f32,
    pub app_cpu: f32,
    pub app_io: f32,
    pub timestamp: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AnomalySeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone)]
pub struct AnomalyAlert {
    pub kind: String,
    pub score: f32,
    pub severity: AnomalySeverity,
    pub message: String,
    pub timestamp: u64,
}

pub struct AnomalyDetector {
    battery_ema: f32,
    temp_ema: f32,
    ema_alpha: f32,
    alerts: Vec<AnomalyAlert>,
    thresholds: BTreeMap<String, f32>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        let mut thresholds = BTreeMap::new();
        thresholds.insert("battery_drop".into(), 15.0);
        thresholds.insert("temp_high".into(), 70.0);
        thresholds.insert("cpu_high".into(), 0.9);
        thresholds.insert("io_high".into(), 0.9);

        AnomalyDetector {
            battery_ema: 100.0,
            temp_ema: 30.0,
            ema_alpha: 0.1,
            alerts: Vec::new(),
            thresholds,
        }
    }

    pub fn update(&mut self, signal: AnomalySignal) -> Vec<AnomalyAlert> {
        self.battery_ema = self.ema_alpha * signal.battery_level as f32
            + (1.0 - self.ema_alpha) * self.battery_ema;
        self.temp_ema = self.ema_alpha * signal.temperature_c
            + (1.0 - self.ema_alpha) * self.temp_ema;

        let mut new_alerts = Vec::new();
        let battery_drop = self.battery_ema - signal.battery_level as f32;
        if battery_drop > *self.thresholds.get("battery_drop").unwrap_or(&15.0) {
            new_alerts.push(self.push_alert(
                "battery_drift",
                battery_drop / 100.0,
                signal.timestamp,
                "Battery drop anomaly",
            ));
        }

        if signal.temperature_c > *self.thresholds.get("temp_high").unwrap_or(&70.0) {
            new_alerts.push(self.push_alert(
                "thermal_hot",
                signal.temperature_c / 100.0,
                signal.timestamp,
                "Device temperature high",
            ));
        }

        if signal.app_cpu > *self.thresholds.get("cpu_high").unwrap_or(&0.9) {
            new_alerts.push(self.push_alert(
                "cpu_spike",
                signal.app_cpu,
                signal.timestamp,
                "App CPU anomaly",
            ));
        }

        if signal.app_io > *self.thresholds.get("io_high").unwrap_or(&0.9) {
            new_alerts.push(self.push_alert(
                "io_spike",
                signal.app_io,
                signal.timestamp,
                "App IO anomaly",
            ));
        }

        new_alerts
    }

    pub fn recent_alerts(&self, limit: usize) -> Vec<AnomalyAlert> {
        self.alerts.iter().rev().take(limit).cloned().collect()
    }

    pub fn export(&self) -> String {
        format!(
            "battery_ema={:.2}, temp_ema={:.2}, alerts={}",
            self.battery_ema,
            self.temp_ema,
            self.alerts.len()
        )
    }

    fn push_alert(&mut self, kind: &str, score: f32, timestamp: u64, message: &str) -> AnomalyAlert {
        let severity = if score >= 0.8 {
            AnomalySeverity::Critical
        } else if score >= 0.5 {
            AnomalySeverity::Warning
        } else {
            AnomalySeverity::Info
        };
        let alert = AnomalyAlert {
            kind: kind.into(),
            score,
            severity,
            message: message.into(),
            timestamp,
        };
        self.alerts.push(alert.clone());
        alert
    }

    pub fn max_severity(alerts: &[AnomalyAlert]) -> AnomalySeverity {
        let mut max = AnomalySeverity::Info;
        for alert in alerts {
            if alert.severity == AnomalySeverity::Critical {
                return AnomalySeverity::Critical;
            }
            if alert.severity == AnomalySeverity::Warning {
                max = AnomalySeverity::Warning;
            }
        }
        max
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}
