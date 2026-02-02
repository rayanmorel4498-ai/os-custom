use redmi_ia::core::ai_watchdog::AIHealth;
use redmi_ia::core::anomaly_detector::{AnomalyAlert, AnomalySeverity};
use redmi_ia::core::safe_ai::{SafeAIMode, SafeAIModeState};

#[test]
fn safe_ai_enters_recovery_then_normal() {
    let mut safe = SafeAIMode::new();
    let alert = AnomalyAlert {
        kind: "crit".into(),
        score: 0.9,
        severity: AnomalySeverity::Critical,
        message: "x".into(),
        timestamp: 0,
    };
    let _ = safe.update_escalation(AIHealth::Critical, &[alert], 1000);
    assert_eq!(safe.state(), SafeAIModeState::Safe);
    let _ = safe.update_escalation(AIHealth::Healthy, &[], 4000);
    assert!(matches!(safe.state(), SafeAIModeState::Recovery | SafeAIModeState::Normal));
}
