mod test_guard;
use redmi_ia::core::resource_quota::ResourceQuotaManager;

#[test]
fn resource_quota_load_does_not_panic() {
    let mut quota = ResourceQuotaManager::new();
    quota.set_budget("load", 1000, 100, 1024, 1000);
    for i in 0..10_000u64 {
        quota.record_cpu("load", 1, i);
        quota.record_gpu("load", 1, i);
        if i % 100 == 0 {
            quota.tick(i);
        }
    }
    assert!(quota.is_over_budget("load"));
}
