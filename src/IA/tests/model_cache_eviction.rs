mod test_guard;
use redmi_ia::core::model_cache::{CachedModel, EvictionPolicy, ModelCache, ModelMetadata};
use std::collections::BTreeMap;

fn make_model(
    model_id: u32,
    last_access: u64,
    access_count: u32,
    weight_len: usize,
) -> CachedModel {
    let weights = vec![vec![0.0f32; weight_len]];
    let mut params = BTreeMap::new();
    params.insert("lr".into(), 0.01);
    params.insert("mom".into(), 0.9);
    CachedModel {
        metadata: ModelMetadata {
            model_id,
            version: 1,
            size_bytes: 0,
            accuracy: 0.0,
            last_access,
            access_count,
            warm: false,
        },
        weights,
        params,
    }
}

#[test]
fn model_cache_lru_eviction() {
    let cache = ModelCache::new(1);
    cache.set_eviction_policy(EvictionPolicy::LRU);

    let m1 = make_model(1, 1, 0, 120_000);
    let m2 = make_model(2, 10, 0, 120_000);
    let m3 = make_model(3, 20, 0, 120_000);

    assert!(cache.cache_model(m1));
    assert!(cache.cache_model(m2));
    assert!(cache.cache_model(m3));

    assert!(cache.get_model(1).is_none());
    assert!(cache.get_model(2).is_some());
    assert!(cache.get_model(3).is_some());
}

#[test]
fn model_cache_lfu_eviction() {
    let cache = ModelCache::new(1);
    cache.set_eviction_policy(EvictionPolicy::LFU);

    let m1 = make_model(1, 1, 1, 120_000);
    let m2 = make_model(2, 2, 10, 120_000);
    let m3 = make_model(3, 3, 2, 120_000);

    assert!(cache.cache_model(m1));
    assert!(cache.cache_model(m2));
    assert!(cache.cache_model(m3));

    assert!(cache.get_model(1).is_none());
    assert!(cache.get_model(2).is_some());
    assert!(cache.get_model(3).is_some());
}
