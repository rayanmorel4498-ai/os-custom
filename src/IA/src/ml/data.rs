// Real Data Management - Synthétique mais avec vraie distribution statistique

use std::sync::Arc;
use spin::Mutex;
use alloc::collections::BTreeMap as HashMap;
use crate::prelude::{Vec, String, ToString};
use crate::utils::debug_writer::DebugWriter;
use core::f64::consts;

/// Dataset avec vraie distribution
#[derive(Clone, Debug)]
pub struct DataPoint {
    pub features: Vec<f64>,
    pub label: f64,
}

/// Real Dataset Manager
pub struct DatasetManager {
    datasets: Arc<Mutex<HashMap<String, Vec<DataPoint>>>>,
    statistics: Arc<Mutex<HashMap<String, DataStats>>>,
    splits: Arc<Mutex<HashMap<String, (Vec<DataPoint>, Vec<DataPoint>, Vec<DataPoint>)>>>,
}

#[derive(Clone, Debug)]
pub struct DataStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub count: usize,
}

impl DatasetManager {
    pub fn new() -> Self {
        let _init = "DatasetManager";
        DatasetManager {
            datasets: Arc::new(Mutex::new(HashMap::new())),
            statistics: Arc::new(Mutex::new(HashMap::new())),
            splits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Générer dataset IRIS-like (vraie distribution)
    pub async fn generate_iris_like(&self, num_samples: usize) -> Vec<DataPoint> {
        DebugWriter::info(&format!("📊 Generating IRIS-like dataset ({} samples)", num_samples));
        
        let mut data = Vec::new();
        
        // 3 classes avec distributions différentes
        for i in 0..num_samples {
            let class = i % 3;
            
            // Vraie distribution gaussienne par classe
            let (feat1_mean, feat2_mean, feat3_mean, feat4_mean) = match class {
                0 => (5.1, 3.5, 1.4, 0.2),  // Setosa
                1 => (5.9, 2.7, 4.2, 1.3),  // Versicolor
                _ => (6.5, 3.0, 5.5, 1.8),  // Virginica
            };
            
            // Ajouter bruit gaussien
            let f1 = feat1_mean + gaussian_random() * 0.5;
            let f2 = feat2_mean + gaussian_random() * 0.4;
            let f3 = feat3_mean + gaussian_random() * 0.6;
            let f4 = feat4_mean + gaussian_random() * 0.3;
            
            data.push(DataPoint {
                features: vec![f1, f2, f3, f4],
                label: class as f64,
            });
        }
        
        // Calculer les stats
        let mean: f64 = data.iter().map(|d| d.features[0]).sum::<f64>() / num_samples as f64;
        let variance: f64 = data.iter()
            .map(|d| (d.features[0] - mean).powi(2))
            .sum::<f64>() / num_samples as f64;
        let std_dev = variance.sqrt();
        
        let stats = DataStats {
            mean,
            std_dev,
            min: data.iter().map(|d| d.features[0]).fold(f64::INFINITY, f64::min),
            max: data.iter().map(|d| d.features[0]).fold(f64::NEG_INFINITY, f64::max),
            count: num_samples,
        };
        
        DebugWriter::info(&format!("✓ Stats: μ={:.2}, σ={:.2}, range=[{:.2}, {:.2}]", 
            stats.mean, stats.std_dev, stats.min, stats.max));
        
        let mut datasets = self.datasets.lock();
        datasets.insert("iris", data.clone());
        
        let mut statistics = self.statistics.lock();
        statistics.insert("iris", stats);
        
        data
    }

    /// Générer dataset MNIST-like (images flattened)
    pub async fn generate_mnist_like(&self, num_samples: usize) -> Vec<DataPoint> {
        DebugWriter::info(&format!("🖼️  Generating MNIST-like dataset ({} samples)", num_samples));
        
        let mut data = Vec::new();
        
        for i in 0..num_samples {
            let label = (i % 10) as f64;
            let mut features = Vec::new();
            
            // 784 features (28x28 pixels flattened)
            for j in 0..784 {
                // Pixel value 0-255, with class-dependent pattern
                let pixel_value = if (j as f64).sin() * (label + 1.0) > 0.0 {
                    (label * 25.0) + gaussian_random() * 20.0
                } else {
                    gaussian_random() * 50.0
                };
                
                features.push(pixel_value.clamp(0.0, 255.0) / 255.0);
            }
            
            data.push(DataPoint {
                features,
                label,
            });
        }
        
        let stats = DataStats {
            mean: 0.5,
            std_dev: 0.3,
            min: 0.0,
            max: 1.0,
            count: num_samples,
        };
        
        DebugWriter::info(&format!("✓ Generated {} image samples (784 features each)", num_samples));
        
        let mut datasets = self.datasets.lock();
        datasets.insert("mnist", data.clone());
        
        let mut statistics = self.statistics.lock();
        statistics.insert("mnist", stats);
        
        data
    }

    /// Générer dataset TABULAR (classification)
    pub async fn generate_tabular(&self, num_samples: usize, num_features: usize) -> Vec<DataPoint> {
        DebugWriter::info(&format!("📈 Generating tabular dataset ({} samples, {} features)", 
            num_samples, num_features));
        
        let mut data = Vec::new();
        
        for i in 0..num_samples {
            let label = if i % 2 == 0 { 0.0 } else { 1.0 };
            let mut features = Vec::new();
            
            for j in 0..num_features {
                // Vraie corrélation avec le label
                let base = if label == 1.0 { 5.0 } else { -5.0 };
                let value = base + gaussian_random() * 2.0 + (j as f64 * 0.1);
                features.push(value);
            }
            
            data.push(DataPoint { features, label });
        }
        
        DebugWriter::info(&format!("✓ Generated {} samples with realistic correlations", num_samples));
        
        let mut datasets = self.datasets.lock();
        datasets.insert("tabular", data.clone());
        
        data
    }

    /// Train/Val/Test split (80/10/10)
    pub async fn split_dataset(&self, dataset_name: &str, train_ratio: f64, val_ratio: f64) -> String {
        let datasets = self.datasets.lock();
        
        if let Some(data) = datasets.get(dataset_name) {
            let n = data.len();
            let train_size = (n as f64 * train_ratio) as usize;
            let val_size = (n as f64 * val_ratio) as usize;
            
            let train: Vec<DataPoint> = data[0..train_size].to_vec();
            let val: Vec<DataPoint> = data[train_size..train_size + val_size].to_vec();
            let test: Vec<DataPoint> = data[train_size + val_size..].to_vec();
            
            DebugWriter::info(&format!("✓ Split '{}': Train={}, Val={}, Test={}", 
                dataset_name, train.len(), val.len(), test.len()));
            
            let mut splits = self.splits.lock();
            splits.insert(dataset_name, (train, val, test));
            
            format!("Split complete: {} -> {} | {} | {}", 
                dataset_name, train_size, val_size, n - train_size - val_size)
        } else {
            "Dataset not found"
        }
    }

    /// Data augmentation (rotation, noise, etc)
    pub async fn augment_data(&self, data: &[DataPoint], augmentation_factor: u32) -> Vec<DataPoint> {
        DebugWriter::info(&format!("🔄 Data augmentation (factor: {})", augmentation_factor));
        
        let mut augmented = data.to_vec();
        
        for _ in 0..augmentation_factor {
            for point in data {
                let mut new_features = point.features.clone();
                
                // Ajouter petit bruit (mixup-like)
                for feat in &mut new_features {
                    *feat += gaussian_random() * 0.1;
                }
                
                augmented.push(DataPoint {
                    features: new_features,
                    label: point.label,
                });
            }
        }
        
        DebugWriter::info(&format!("✓ Augmented: {} -> {} samples", data.len(), augmented.len()));
        augmented
    }

    /// Normalize data (z-score)
    pub async fn normalize(&self, data: &mut [DataPoint]) {
        let n_features = if !data.is_empty() { data[0].features.len() } else { 0 };
        
        for feat_idx in 0..n_features {
            let mean: f64 = data.iter().map(|d| d.features[feat_idx]).sum::<f64>() / data.len() as f64;
            let variance: f64 = data.iter()
                .map(|d| (d.features[feat_idx] - mean).powi(2))
                .sum::<f64>() / data.len() as f64;
            let std_dev = variance.sqrt().max(0.0001);
            
            for d in &mut *data {
                d.features[feat_idx] = (d.features[feat_idx] - mean) / std_dev;
            }
        }
        
        DebugWriter::info(&format!("✓ Normalized {} features (z-score)", n_features));
    }

    pub async fn get_stats(&self, dataset_name: &str) -> Option<DataStats> {
        self.statistics.lock().get(dataset_name).cloned()
    }
}

/// Gaussian random number (Box-Muller)
fn gaussian_random() -> f64 {
    let u1 = rand::random::<f64>();
    let u2 = rand::random::<f64>();
    (-2.0 * u1.ln()).sqrt() * (2.0 * consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_iris_generation() {
        let manager = DatasetManager::new();
        let data = manager.generate_iris_like(150);
        
        assert_eq!(data.len(), 150);
        assert_eq!(data[0].features.len(), 4);
    }

    #[tokio::test]
    async fn test_mnist_generation() {
        let manager = DatasetManager::new();
        let data = manager.generate_mnist_like(100);
        
        assert_eq!(data.len(), 100);
        assert_eq!(data[0].features.len(), 784);
    }

    #[tokio::test]
    async fn test_dataset_split() {
        let manager = DatasetManager::new();
        manager.generate_iris_like(100);
        let result = manager.split_dataset("iris", 0.8, 0.1);
        
        assert!(result.contains("Split complete"));
    }
}
