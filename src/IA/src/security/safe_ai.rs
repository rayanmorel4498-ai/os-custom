use crate::core::ai_watchdog::AIHealth;
use crate::prelude::{String, format};
use crate::core::anomaly_detector::{AnomalyAlert, AnomalySeverity, AnomalyDetector};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SafeAIModeState {
    Normal,
    Guarded,
    Safe,
    Recovery,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SafeAIAction {
    None,
    PurgeCache,
    RollbackConfig,
}

pub struct SafeAIMode {
    state: SafeAIModeState,
    reason: String,
    reduce_factor: f32,
    consecutive_critical: u32,
    last_recovery_tick: u64,
    last_stable_tick: u64,
}

impl SafeAIMode {
    pub fn new() -> Self {
        SafeAIMode {
            state: SafeAIModeState::Normal,
            reason: "ok".into(),
            reduce_factor: 1.0,
            consecutive_critical: 0,
            last_recovery_tick: 0,
            last_stable_tick: 0,
        }
    }

    pub fn update(&mut self, health: AIHealth, anomalies: &[AnomalyAlert]) {
        let _ = self.update_escalation(health, anomalies, 0);
    }

    pub fn update_escalation(&mut self, health: AIHealth, anomalies: &[AnomalyAlert], tick_ms: u64) -> SafeAIAction {
        let severity = AnomalyDetector::max_severity(anomalies);
        let critical = health == AIHealth::Critical || severity == AnomalySeverity::Critical;
        let degraded = health == AIHealth::Degraded || severity == AnomalySeverity::Warning;

        if critical {
            self.consecutive_critical = self.consecutive_critical.saturating_add(1);
            self.state = SafeAIModeState::Safe;
            self.reduce_factor = 0.3;
            self.reason = if health == AIHealth::Critical { "watchdog_critical".into() } else { "anomaly_critical".into() };

            if self.consecutive_critical >= 3 && tick_ms.saturating_sub(self.last_recovery_tick) > 5_000 {
                self.last_recovery_tick = tick_ms;
                return SafeAIAction::PurgeCache;
            }
            if self.consecutive_critical >= 6 && tick_ms.saturating_sub(self.last_recovery_tick) > 10_000 {
                self.last_recovery_tick = tick_ms;
                return SafeAIAction::RollbackConfig;
            }
            return SafeAIAction::None;
        }

        self.consecutive_critical = 0;
        if degraded {
            self.state = SafeAIModeState::Guarded;
            self.reduce_factor = 0.7;
            self.reason = if health == AIHealth::Degraded { "watchdog_degraded".into() } else { "anomaly_warning".into() };
            return SafeAIAction::None;
        }

        if self.state != SafeAIModeState::Normal {
            self.state = SafeAIModeState::Recovery;
            self.reduce_factor = 0.85;
            self.reason = "recovery".into();
            if self.last_stable_tick == 0 {
                self.last_stable_tick = tick_ms;
            }
            if tick_ms.saturating_sub(self.last_stable_tick) > 2_000 {
                self.state = SafeAIModeState::Normal;
                self.reduce_factor = 1.0;
                self.reason = "ok".into();
                self.last_stable_tick = 0;
            }
        } else {
            self.reduce_factor = 1.0;
            self.reason = "ok".into();
        }
        SafeAIAction::None
    }

    pub fn state(&self) -> SafeAIModeState {
        self.state
    }

    pub fn reduce_factor(&self) -> f32 {
        self.reduce_factor
    }

    pub fn export(&self) -> String {
        let mode = match self.state {
            SafeAIModeState::Normal => "normal",
            SafeAIModeState::Guarded => "guarded",
            SafeAIModeState::Safe => "safe",
            SafeAIModeState::Recovery => "recovery",
        };
        format!("mode={}, reason={}, reduce_factor={:.2}", mode, self.reason, self.reduce_factor)
    }
}

impl Default for SafeAIMode {
    fn default() -> Self {
        Self::new()
    }
}
