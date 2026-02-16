mod test_guard;
use redmi_ia::modules::context::{ContextPolicy, ContextStore};

#[test]
fn context_store_auto_purge() {
    let policy = ContextPolicy {
        default_ttl_ms: 10,
        max_entries: 8,
        max_value_bytes: 64,
        purge_interval_ms: 5,
    };
    let mut store = ContextStore::new(policy);
    assert!(store.set("k".into(), vec![1, 2, 3], 0, None));
    let _ = store.get("k", 3);
    assert!(store.get("k", 20).is_none());
}
