use redmi_ia::core::model_cache::ModelCache;
use redmi_ia::core::offline_pretraining::run_offline_pretraining;

#[test]
fn offline_pretraining_metrics_are_populated() {
    let cache = ModelCache::new(8);
    let metrics = run_offline_pretraining(&cache);
    assert!(metrics.samples >= 1000);
    assert!(metrics.epochs >= 1);
    assert!(metrics.train_loss >= 0.0);
    assert!(metrics.val_loss >= 0.0);
    assert!(metrics.pre_quant_accuracy >= 0.0);
    assert!(metrics.post_quant_accuracy >= 0.0);
    assert!(metrics.quant_scale > 0.0);
}
