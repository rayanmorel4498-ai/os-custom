use redmi_ia::core::ai_watchdog::AIHealth;
use redmi_ia::core::anomaly_detector::{AnomalyAlert, AnomalySeverity};
use redmi_ia::core::safe_ai::{SafeAIAction, SafeAIMode, SafeAIModeState};

fn alert(kind: &str, severity: AnomalySeverity) -> AnomalyAlert {
    AnomalyAlert {
        kind: kind.into(),
        score: match severity {
            AnomalySeverity::Info => 0.2,
            AnomalySeverity::Warning => 0.6,
            AnomalySeverity::Critical => 0.9,
        },
        severity,
        message: "x".into(),
        timestamp: 0,
    }
}

#[test]
fn safe_ai_escalates_and_recovers() {
    let mut safe = SafeAIMode::new();
    let action = safe.update_escalation(AIHealth::Degraded, &[alert("warn", AnomalySeverity::Warning)], 1000);
    assert_eq!(action, SafeAIAction::None);
    assert_eq!(safe.state(), SafeAIModeState::Guarded);

    let action = safe.update_escalation(AIHealth::Critical, &[alert("crit", AnomalySeverity::Critical)], 6000);
    assert!(action == SafeAIAction::PurgeCache || action == SafeAIAction::None);
    assert_eq!(safe.state(), SafeAIModeState::Safe);

    let action = safe.update_escalation(AIHealth::Healthy, &[], 9000);
    assert_eq!(action, SafeAIAction::None);
}
