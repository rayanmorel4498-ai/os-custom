mod test_guard;
use redmi_ia::core::model_cache::ModelCache;
use redmi_ia::core::offline_pretraining::run_offline_pretraining;

#[test]
fn offline_pretraining_accuracy_retention() {
    let cache = ModelCache::new(8);
    let metrics = run_offline_pretraining(&cache);
    assert!(metrics.pre_quant_accuracy >= 0.0 && metrics.pre_quant_accuracy <= 1.0);
    assert!(metrics.post_quant_accuracy >= 0.0 && metrics.post_quant_accuracy <= 1.0);
    assert!(metrics.accuracy_retention >= 0.0);
}
