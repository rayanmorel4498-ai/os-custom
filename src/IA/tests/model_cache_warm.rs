mod test_guard;
use redmi_ia::core::model_cache::{CachedModel, ModelCache, ModelMetadata};
use std::collections::BTreeMap;

fn make_model(id: u32) -> CachedModel {
    let weights = vec![vec![0.0f32; 10]];
    let mut params = BTreeMap::new();
    params.insert("lr".into(), 0.01);
    CachedModel {
        metadata: ModelMetadata {
            model_id: id,
            version: 1,
            size_bytes: 0,
            accuracy: 0.0,
            last_access: 0,
            access_count: 0,
            warm: false,
        },
        weights,
        params,
    }
}

#[test]
fn model_cache_warm_threshold() {
    let cache = ModelCache::new(4);
    cache.set_warm_threshold(2);
    assert!(cache.cache_model(make_model(42)));
    assert!(cache.get_model(42).is_some());
    assert!(cache.get_model(42).is_some());
    let warm = cache.list_warm_models();
    assert!(warm.contains(&42));
}
