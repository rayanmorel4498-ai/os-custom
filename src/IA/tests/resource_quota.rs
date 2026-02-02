use redmi_ia::core::resource_quota::{AdmissionDecision, PriorityClass, ResourceQuotaManager};

#[test]
fn resource_quota_allows_under_budget() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("module:1", 10, 32, 50);
    quota.record_cpu("module:1", 5, 0);
    quota.record_latency("module:1", 10);
    assert!(!quota.is_over_budget("module:1"));
    assert_eq!(quota.admission_decision("module:1", PriorityClass::BestEffort), AdmissionDecision::Allow);
}

#[test]
fn resource_quota_throttle_realtime_drop_best_effort() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("module:2", 1, 1, 1);
    quota.record_cpu("module:2", 5, 0);
    quota.record_latency("module:2", 5);
    assert!(quota.is_over_budget("module:2"));
    assert_eq!(quota.admission_decision("module:2", PriorityClass::Realtime), AdmissionDecision::Throttle);
    assert_eq!(quota.admission_decision("module:2", PriorityClass::BestEffort), AdmissionDecision::Drop);
}

#[test]
fn resource_quota_window_resets_cpu() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("module:3", 2, 10, 100);
    quota.set_window_ms(10);
    quota.record_cpu("module:3", 3, 0);
    assert!(quota.is_over_budget("module:3"));
    quota.tick(20);
    assert!(!quota.is_over_budget("module:3"));
}
