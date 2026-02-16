/// FEW-SHOT / ZERO-SHOT / MULTI-TASK LEARNING
/// Prototypical networks, Siamese networks, Task-aware embeddings
use crate::prelude::{Vec, String};
use alloc::string::ToString;

pub struct PrototypicalNetworks {
    pub embedding_dim: usize,
    pub num_classes: usize,
    pub num_shots: usize,
}

pub struct SiameseNetwork {
    pub embedding_dim: usize,
    pub distance_metric: String, // "euclidean" or "cosine"
}

pub struct MultiTaskLearner {
    pub tasks: Vec<TaskDefinition>,
    pub task_weights: Vec<f64>,
    pub shared_representation_dim: usize,
}

pub struct DomainAdaptationLearner {
    pub source_domain: String,
    pub target_domain: String,
    pub adaptation_strength: f64,
    pub adversarial_loss_weight: f64,
}

pub struct FederatedLearner {
    pub num_clients: usize,
    pub communication_rounds: usize,
    pub local_epochs: usize,
    pub gradient_compression_ratio: f64,
}

#[derive(Clone)]
pub struct TaskDefinition {
    pub name: String,
    pub num_classes: usize,
    pub loss_weight: f64,
}

impl PrototypicalNetworks {
    pub fn new(embedding_dim: usize, num_classes: usize, num_shots: usize) -> Self {
        eprintln!("[PrototypicalNetworks] embedding={}, classes={}, shots={}", embedding_dim, num_classes, num_shots);
        PrototypicalNetworks {
            embedding_dim,
            num_classes,
            num_shots,
        }
    }
    
    /// Compute prototypes for each class
    pub fn compute_prototypes(&self, support_embeddings: &[Vec<f64>], support_labels: &[u32], num_classes: usize) -> Vec<Vec<f64>> {
        let mut prototypes = vec![vec![0.0; self.embedding_dim]; num_classes];
        let mut class_counts = vec![0; num_classes];
        
        for (emb, label) in support_embeddings.iter().zip(support_labels.iter()) {
            let label_idx = *label as usize;
            for (i, val) in emb.iter().enumerate() {
                prototypes[label_idx][i] += val;
            }
            class_counts[label_idx] += 1;
        }
        
        // Average
        for (proto, &count) in prototypes.iter_mut().zip(class_counts.iter()) {
            if count > 0 {
                for val in proto.iter_mut() {
                    *val /= count as f64;
                }
            }
        }
        
        prototypes
    }
    
    /// Distance to prototypes
    pub fn distance_to_prototypes(&self, query_embedding: &[f64], prototypes: &[Vec<f64>]) -> Vec<f64> {
        prototypes.iter().map(|proto| {
            let mut dist = 0.0;
            for (q, p) in query_embedding.iter().zip(proto.iter()) {
                dist += (q - p).powi(2);
            }
            dist.sqrt()
        }).collect()
    }
}

impl SiameseNetwork {
    pub fn new(embedding_dim: usize) -> Self {
        SiameseNetwork {
            embedding_dim,
            distance_metric: "euclidean".to_string(),
        }
    }
    
    /// Siamese loss (contrastive)
    pub fn siamese_loss(&self, embedding1: &[f64], embedding2: &[f64], is_same: bool, margin: f64) -> f64 {
        let distance = self.compute_distance(embedding1, embedding2);
        
        if is_same {
            distance.powi(2)
        } else {
            (margin - distance).max(0.0).powi(2)
        }
    }
    
    fn compute_distance(&self, emb1: &[f64], emb2: &[f64]) -> f64 {
        match self.distance_metric.as_str() {
            "euclidean" => {
                let mut dist = 0.0;
                for (a, b) in emb1.iter().zip(emb2.iter()) {
                    dist += (a - b).powi(2);
                }
                dist.sqrt()
            }
            "cosine" => {
                let mut dot = 0.0;
                let mut norm1 = 0.0;
                let mut norm2 = 0.0;
                for (a, b) in emb1.iter().zip(emb2.iter()) {
                    dot += a * b;
                    norm1 += a * a;
                    norm2 += b * b;
                }
                1.0 - (dot / (norm1.sqrt() * norm2.sqrt()))
            }
            _ => 0.0,
        }
    }
}

impl MultiTaskLearner {
    pub fn new(tasks: Vec<TaskDefinition>) -> Self {
        let num_tasks = tasks.len();
        let task_weights = vec![1.0 / num_tasks as f64; num_tasks];
        
        MultiTaskLearner {
            tasks,
            task_weights,
            shared_representation_dim: 256,
        }
    }
    
    /// Multi-task loss: weighted sum
    pub fn compute_multi_task_loss(&self, task_losses: &[f64]) -> f64 {
        task_losses.iter()
            .zip(self.task_weights.iter())
            .map(|(loss, weight)| loss * weight)
            .sum()
    }
    
    /// Task-aware attention
    pub fn task_attention(&self, shared_repr: &[f64], task_id: usize) -> Vec<f64> {
        let mut attention = vec![0.0; shared_repr.len()];
        
        // Simple learned attention per task
        let task_attention_weight = (task_id as f64 + 1.0) * 0.1;
        
        for (i, val) in shared_repr.iter().enumerate() {
            attention[i] = val * task_attention_weight;
        }
        
        attention
    }
}

impl DomainAdaptationLearner {
    pub fn new(source: &str, target: &str) -> Self {
        DomainAdaptationLearner {
            source_domain: source.to_string(),
            target_domain: target.to_string(),
            adaptation_strength: 0.1,
            adversarial_loss_weight: 0.5,
        }
    }
    
    /// Maximum Mean Discrepancy (MMD) loss
    pub fn mmd_loss(&self, source_features: &[f64], target_features: &[f64]) -> f64 {
        let source_mean = source_features.iter().sum::<f64>() / source_features.len() as f64;
        let target_mean = target_features.iter().sum::<f64>() / target_features.len() as f64;
        
        (source_mean - target_mean).powi(2)
    }
    
    /// Adversarial domain loss
    pub fn adversarial_domain_loss(&self, domain_logits: &[f64], source_or_target: bool) -> f64 {
        let target = if source_or_target { 1.0 } else { 0.0 };
        let pred = domain_logits[0];
        
        (pred - target).powi(2)
    }
}

impl FederatedLearner {
    pub fn new(num_clients: usize) -> Self {
        FederatedLearner {
            num_clients,
            communication_rounds: 100,
            local_epochs: 5,
            gradient_compression_ratio: 0.1, // Only send top 10% gradients
        }
    }
    
    /// Federated averaging (FedAvg)
    pub fn federated_average(&self, client_weights: &[Vec<f64>]) -> Vec<f64> {
        if client_weights.is_empty() {
            return vec![0.0; 100];
        }
        
        let num_params = client_weights[0].len();
        let mut global_weights = vec![0.0; num_params];
        
        for weights in client_weights {
            for (i, &w) in weights.iter().enumerate() {
                global_weights[i] += w / self.num_clients as f64;
            }
        }
        
        global_weights
    }
    
    /// Gradient compression: only send important gradients
    pub fn compress_gradients(&self, gradients: &[f64]) -> Vec<(usize, f64)> {
        let mut indexed_grads: Vec<(usize, f64)> = gradients.iter()
            .enumerate()
            .map(|(i, &g)| (i, g.abs()))
            .collect();
        
        indexed_grads.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        let num_to_send = ((gradients.len() as f64) * self.gradient_compression_ratio) as usize;
        
        indexed_grads.iter()
            .take(num_to_send)
            .map(|(i, _g)| (*i, gradients[*i]))
            .collect()
    }
    
    /// Differential privacy: add noise to gradients
    pub fn add_differential_privacy(&self, gradients: &[f64], epsilon: f64) -> Vec<f64> {
        // Per-client gradient clipping (L2) followed by Gaussian noise addition
        let clip_norm = 1.0;
        let mut clipped = gradients.to_vec();
        let norm = (clipped.iter().map(|v| v * v).sum::<f64>()).sqrt().max(1e-12);
        if norm > clip_norm {
            for v in clipped.iter_mut() {
                *v *= clip_norm / norm;
            }
        }

        let sensitivity = clip_norm;
        let scale = sensitivity / epsilon; // simplistic
        clipped.iter().map(|g| {
            let noise = (rand::random::<f64>() - 0.5) * 2.0 * scale;
            g + noise
        }).collect()
    }

    /// Differential privacy accountant (simple additive composition tracker)
    pub fn dp_accounting_compose(&self, epsilons: &[f64]) -> f64 {
        // naive composition: sum of epsilons
        epsilons.iter().sum()
    }

    /// Simulate federated rounds with simple thread-based clients and server aggregation
    pub fn simulate_federated_rounds(&self, initial_weights: Vec<f64>) -> Vec<f64> {
        let mut collected: Vec<Vec<f64>> = Vec::new();
        for _client_id in 0..self.num_clients {
            let mut local_w = initial_weights.clone();
            for _ in 0..self.local_epochs {
                for w in local_w.iter_mut() {
                    *w += (rand::random::<f64>() - 0.5) * 0.01;
                }
            }
            collected.push(local_w);
        }

        if collected.is_empty() {
            return initial_weights;
        }

        let num_params = collected[0].len();
        let mut global = vec![0.0; num_params];
        for w in &collected {
            for (i, &val) in w.iter().enumerate() {
                global[i] += val / collected.len() as f64;
            }
        }

        global
    }
}
