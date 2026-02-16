// src/utils/metrics.rs

use alloc::sync::Arc;
use spin::Mutex;
use alloc::collections::BTreeMap as HashMap;
use crate::prelude::{String, Vec, ToString};

/// Métrique de performance d'une tâche
#[derive(Clone, Debug)]
pub struct TaskMetric {
    pub task_name: String,
    pub task_type: String,
    pub duration_ms: u128,
    pub success: bool,
    pub timestamp: u64,
    pub cache_hit: bool,
}

/// Métrique d'apprentissage du modèle
#[derive(Clone, Debug)]
pub struct LearningMetric {
    pub model_name: String,
    pub iteration: u64,
    pub loss: f64,
    pub accuracy: f64,
    pub timestamp: u64,
}

/// Système de métriques global
pub struct MetricsCollector {
    task_metrics: Arc<Mutex<Vec<TaskMetric>>>,
    learning_metrics: Arc<Mutex<Vec<LearningMetric>>>,
    aggregates: Arc<Mutex<HashMap<String, AggregateStats>>>,
}

/// Statistiques agrégées
#[derive(Clone, Debug)]
pub struct AggregateStats {
    pub total_tasks: u64,
    pub successful_tasks: u64,
    pub failed_tasks: u64,
    pub avg_duration_ms: f64,
    pub cache_hit_rate: f64,
    pub throughput: f64, // tâches par seconde
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            task_metrics: Arc::new(Mutex::new(Vec::new())),
            learning_metrics: Arc::new(Mutex::new(Vec::new())),
            aggregates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enregistrer une métrique de tâche
    pub fn record_task(&self, metric: TaskMetric) {
        self.task_metrics.lock().push(metric.clone());
    }

    /// Enregistrer une métrique d'apprentissage
    pub fn record_learning(&self, metric: LearningMetric) {
        self.learning_metrics.lock().push(metric);
    }

    /// Recalculer les statistiques pour un type de tâche
    async fn recalculate_stats(&self, task_type: &str) {
        let metrics = self.task_metrics.lock();
        let relevant: Vec<_> = metrics.iter().filter(|m| m.task_type == task_type).collect();

        if relevant.is_empty() {
            return;
        }

        let total = relevant.len() as u64;
        let successful = relevant.iter().filter(|m| m.success).count() as u64;
        let failed = total - successful;
        let avg_duration = relevant.iter().map(|m| m.duration_ms as f64).sum::<f64>() / total as f64;
        let cache_hits = relevant.iter().filter(|m| m.cache_hit).count() as f64;
        let cache_hit_rate = (cache_hits / total as f64) * 100.0;

        // Calculer le throughput (tâches/sec) basé sur l'intervalle de temps
        let throughput = if !relevant.is_empty() && relevant.len() > 1 {
            let first_time = relevant.first().unwrap().timestamp;
            let last_time = relevant.last().unwrap().timestamp;
            let duration_secs = (last_time - first_time).max(1) as f64;
            (total as f64) / duration_secs
        } else {
            0.0
        };

        let stats = AggregateStats {
            total_tasks: total,
            successful_tasks: successful,
            failed_tasks: failed,
            avg_duration_ms: avg_duration,
            cache_hit_rate,
            throughput,
        };

        self.aggregates.lock().insert(task_type, stats);
    }

    /// Obtenir les statistiques pour un type de tâche
    pub async fn get_stats(&self, task_type: &str) -> Option<AggregateStats> {
        self.aggregates.lock().get(task_type).cloned()
    }

    /// Obtenir toutes les métriques de tâche
    pub async fn get_all_task_metrics(&self) -> Vec<TaskMetric> {
        self.task_metrics.lock().clone()
    }

    /// Obtenir toutes les métriques d'apprentissage
    pub async fn get_all_learning_metrics(&self) -> Vec<LearningMetric> {
        self.learning_metrics.lock().clone()
    }

    /// Obtenir un rapport détaillé
    pub async fn get_report(&self) -> String {
        let aggs = self.aggregates.lock();
        let learning = self.learning_metrics.lock();

        let mut report = String::from("=== RAPPORT DE MÉTRIQUES IA ===\n\n");

        // Section tâches
        report.push_str("TÂCHES EXÉCUTÉES:\n");
        for (task_type, stats) in aggs.iter() {
            report.push_str(&format!("  {}: {} tâches, {} succès, {} erreurs\n", 
                task_type, stats.total_tasks, stats.successful_tasks, stats.failed_tasks));
            report.push_str(&format!("    - Durée moyenne: {:.2}ms\n", stats.avg_duration_ms));
            report.push_str(&format!("    - Taux de cache hit: {:.2}%\n", stats.cache_hit_rate));
            report.push_str(&format!("    - Débit: {:.2} tâches/sec\n", stats.throughput));
        }

        // Section apprentissage
        if !learning.is_empty() {
            report.push_str("\nAPPRENTISSAGE:\n");
            for metric in learning.iter().rev().take(5) {
                report.push_str(&format!("  {}: itération {}, loss={:.4}, accuracy={:.2}%\n",
                    metric.model_name, metric.iteration, metric.loss, metric.accuracy * 100.0));
            }
        }

        report
    }
}

/// Utilitaire pour obtenir le timestamp actuel (no_std)
pub fn current_timestamp() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_runtime::block_on;

    #[test]
    fn test_metrics_collection() {
        block_on(async {
        let collector = MetricsCollector::new();
        
        let metric = TaskMetric {
            task_name: "test_task",
            task_type: "analyze",
            duration_ms: 100,
            success: true,
            timestamp: current_timestamp(),
            cache_hit: false,
        };

        collector.record_task(metric);
        let stats = collector.get_stats("analyze");
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_tasks, 1);
        assert_eq!(stats.successful_tasks, 1);
        });
    }
}
