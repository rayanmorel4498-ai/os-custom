use std::sync::Arc;
use tokio::sync::Mutex;
use alloc::collections::BTreeMap as HashMap;
use crate::prelude::{Vec, String, ToString};
use crate::utils::debug_writer::DebugWriter;

#[derive(Clone, Debug)]
pub struct Metrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub inference_time_ms: f64,
    pub memory_used_mb: f64,
}

impl Metrics {
    pub fn new(accuracy: f64, precision: f64, recall: f64, inference_time_ms: f64) -> Self {
        let f1_score = 2.0 * (precision * recall) / (precision + recall).max(0.0001);
        Metrics {
            accuracy,
            precision,
            recall,
            f1_score,
            inference_time_ms,
            memory_used_mb: 0.0,
        }
    }

    pub fn default() -> Self {
        Metrics {
            accuracy: 0.85,
            precision: 0.88,
            recall: 0.82,
            f1_score: 0.85,
            inference_time_ms: 45.0,
            memory_used_mb: 128.0,
        }
    }
}

pub struct MetricsTracker {
    model_metrics: Arc<Mutex<HashMap<String, Metrics>>>,
    history: Arc<Mutex<Vec<(String, Metrics)>>>,
    best_model: Arc<Mutex<Option<(String, Metrics)>>>,
}

impl MetricsTracker {
    pub fn new() -> Self {
        MetricsTracker {
            model_metrics: Arc::new(Mutex::new(HashMap::new())),
            history: Arc::new(Mutex::new(Vec::new())),
            best_model: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn record_metrics(&self, model_name: String, metrics: Metrics) {
        let name_str = model_name;
        let mut models = self.model_metrics.lock();
        models.insert(model_name.clone(), metrics.clone());

        let mut history = self.history.lock();
        history.push((name_str, metrics.clone()));

        let mut best = self.best_model.lock();
        if best.is_none() || metrics.f1_score > best.as_ref().unwrap().1.f1_score {
            *best = Some((model_name.clone(), metrics.clone()));
            DebugWriter::info(&format!("✓ Nouveau meilleur modèle: {} (F1: {:.3})", model_name, metrics.f1_score));
        }
    }

    pub async fn get_metrics(&self, model_name: &str) -> Option<Metrics> {
        self.model_metrics.lock().get(model_name).cloned()
    }

    pub async fn get_best_model(&self) -> Option<(String, Metrics)> {
        self.best_model.lock().clone()
    }

    pub async fn compare_models(&self, model1: &str, model2: &str) -> String {
        let metrics1 = self.model_metrics.lock().get(model1).cloned();
        let metrics2 = self.model_metrics.lock().get(model2).cloned();

        match (metrics1, metrics2) {
            (Some(m1), Some(m2)) => {
                let winner = if m1.f1_score > m2.f1_score { model1 } else { model2 };
                format!(
                    "{} gagne: F1={:.3} vs {:.3}, Accuracy={:.1}% vs {:.1}%",
                    winner, m1.f1_score, m2.f1_score,
                    m1.accuracy * 100.0, m2.accuracy * 100.0
                )
            }
            _ => "Données insuffisantes",
        }
    }

    pub async fn get_global_stats(&self) -> HashMap<String, f64> {
        let metrics = self.model_metrics.lock();
        let mut stats = HashMap::new();

        if metrics.is_empty() {
            return stats;
        }

        let total = metrics.len() as f64;
        let avg_accuracy = metrics.values().map(|m| m.accuracy).sum::<f64>() / total;
        let avg_f1 = metrics.values().map(|m| m.f1_score).sum::<f64>() / total;
        let avg_inference = metrics.values().map(|m| m.inference_time_ms).sum::<f64>() / total;

        stats.insert("average_accuracy", avg_accuracy);
        stats.insert("average_f1", avg_f1);
        stats.insert("average_inference_time_ms", avg_inference);
        stats.insert("total_models", total);

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_recording() {
        let tracker = MetricsTracker::new();
        let metrics = Metrics::new(0.92, 0.90, 0.94, 50.0);
        tracker.record_metrics("model_v1", metrics.clone()).await;

        let retrieved = tracker.get_metrics("model_v1").await;
    }

    #[test]
    fn test_f1_score_calculation() {
        let metrics = Metrics::new(0.95, 0.92, 0.94, 40.0);
        assert!(metrics.f1_score > 0.93 && metrics.f1_score < 0.95);
    }
}
