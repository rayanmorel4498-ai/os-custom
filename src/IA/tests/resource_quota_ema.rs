use redmi_ia::core::resource_quota::ResourceQuotaManager;

#[test]
fn resource_quota_latency_ema_triggers() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("module:lat", 100, 100, 1);
    quota.record_latency("module:lat", 10);
    assert!(quota.is_over_budget("module:lat"));
}
