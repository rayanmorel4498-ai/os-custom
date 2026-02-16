mod test_guard;
use redmi_ia::core::resource_quota::{AdmissionDecision, PriorityClass, ResourceQuotaManager};

#[test]
fn resource_quota_priority_behavior() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("module:9", 1, 0, 1, 1);
    quota.record_cpu("module:9", 10, 0);
    quota.record_latency("module:9", 10);
    assert_eq!(
        quota.admission_decision("module:9", PriorityClass::Realtime),
        AdmissionDecision::Throttle
    );
    assert_eq!(
        quota.admission_decision("module:9", PriorityClass::BestEffort),
        AdmissionDecision::Drop
    );
}
