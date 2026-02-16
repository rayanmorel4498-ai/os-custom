mod test_guard;
use redmi_ia::core::resource_quota::{AdmissionDecision, PriorityClass, ResourceQuotaManager};

#[test]
fn quota_load_throttle_and_drop() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("module:load", 10, 0, 32, 10);

    for i in 0..100 {
        quota.record_cpu("module:load", 2, i);
        quota.record_latency("module:load", 5);
    }

    assert!(quota.is_over_budget("module:load"));
    assert_eq!(
        quota.admission_decision("module:load", PriorityClass::Realtime),
        AdmissionDecision::Throttle
    );
    assert_eq!(
        quota.admission_decision("module:load", PriorityClass::BestEffort),
        AdmissionDecision::Drop
    );
}
