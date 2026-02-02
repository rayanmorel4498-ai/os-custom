pub mod facial_model;
pub mod voice_model;
pub mod fingerprint_model;

pub use facial_model::FaceModel;
pub use voice_model::VoiceModel;
pub use fingerprint_model::FingerprintModel;

#[cfg(feature = "ml_full")]
pub mod metrics;
#[cfg(feature = "ml_full")]
pub mod models;
#[cfg(feature = "ml_full")]
pub mod advanced;
#[cfg(feature = "ml_full")]
pub mod cache;
#[cfg(feature = "ml_full")]
pub mod transformer;
#[cfg(feature = "ml_full")]
pub mod quantization;
#[cfg(feature = "ml_full")]
pub mod explainability;
#[cfg(feature = "ml_full")]
pub mod continual_learning;
#[cfg(feature = "ml_full")]
pub mod data;
#[cfg(feature = "ml_full")]
pub mod training;
#[cfg(feature = "ml_full")]
pub mod training_advanced;
#[cfg(feature = "ml_full")]
pub mod training_quantum;
#[cfg(feature = "ml_full")]
pub mod training_continual;
#[cfg(feature = "ml_full")]
pub mod validation;
#[cfg(feature = "ml_full")]
pub mod training_nas;
#[cfg(feature = "ml_full")]
pub mod training_fewshot;
#[cfg(feature = "ml_full")]
pub mod training_uncertainty;
#[cfg(feature = "ml_full")]
pub mod training_explainability;
#[cfg(feature = "ml_full")]
pub mod data_loader_stream;
#[cfg(feature = "ml_full")]
pub mod data_loader;
#[cfg(feature = "ml_full")]
pub mod unified_engine;
#[cfg(feature = "ml_full")]
pub mod integration_tests;
#[cfg(feature = "ml_full")]
pub mod lstm;
#[cfg(feature = "ml_full")]
pub mod real_training;
#[cfg(feature = "ml_full")]
pub mod precision;
#[cfg(feature = "ml_full")]
pub mod dp_accountant;
#[cfg(feature = "ml_full")]
pub mod training_imagenet;
#[cfg(feature = "ml_full")]
pub mod adversarial_hardening;
#[cfg(feature = "ml_full")]
pub mod training_neon_simd;
#[cfg(feature = "ml_full")]
pub mod training_checkpointing;
#[cfg(feature = "ml_full")]
pub mod training_mali_gpu;
#[cfg(feature = "ml_full")]
pub mod training_mali_driver;
#[cfg(feature = "ml_full")]
pub mod training_armnn_binding;
#[cfg(feature = "ml_full")]
pub mod dp_privacy_proofs;
#[cfg(feature = "ml_full")]
pub mod distributed_p2p_network;
#[cfg(feature = "ml_full")]
pub mod e2e_benchmark;

#[cfg(feature = "ml_full")]
pub use metrics::{Metrics, MetricsTracker};
#[cfg(feature = "ml_full")]
pub use models::{NeuralNetwork, RandomForest, GradientBoosting};
#[cfg(feature = "ml_full")]
pub use advanced::{AutoML, TransferLearner, ModelEnsemble, AttentionLayer};
#[cfg(feature = "ml_full")]
pub use cache::LRUCache;
#[cfg(feature = "ml_full")]
pub use transformer::{MultiHeadAttention, TransformerEncoderLayer, TransformerDecoder};
#[cfg(feature = "ml_full")]
pub use quantization::{QuantizationStrategy, ModelQuantizer};
#[cfg(feature = "ml_full")]
pub use explainability::{ModelExplainer, FeatureImportance};
#[cfg(feature = "ml_full")]
pub use continual_learning::{ContinualLearningAgent, ExperienceReplay};
#[cfg(feature = "ml_full")]
pub use lstm::{LSTMCell, LSTM};
#[cfg(feature = "ml_full")]
pub use training::{RealDataset, RealTrainer, EpochStats, DataPoint};
#[cfg(feature = "ml_full")]
pub use training_advanced::{AdvancedTrainer, ModelEnsemble as AdvancedEnsemble, DeepNetwork};
#[cfg(feature = "ml_full")]
pub use training_quantum::{QuantizationAwareTrainer, MetaLearner, AdversarialTrainer, AutoMLSearcher};
#[cfg(feature = "ml_full")]
pub use training_fewshot::{PrototypicalNetworks, SiameseNetwork, MultiTaskLearner, DomainAdaptationLearner, FederatedLearner};
#[cfg(feature = "ml_full")]
pub use training_uncertainty::{UncertaintyQuantifier, BayesianNeuralNetwork, CausalInferenceLearner};
#[cfg(feature = "ml_full")]
pub use training_explainability::{SHAPExplainer, LIMEExplainer, FeatureImportanceAnalyzer, AttentionVisualizer};
#[cfg(feature = "ml_full")]
pub use training_nas::NASController;
#[cfg(feature = "ml_full")]
pub use unified_engine::UnifiedMLEngine;
#[cfg(feature = "ml_full")]
pub use training_continual::{ContrastiveLearner, ContinualLearner, ModelPruner};
#[cfg(feature = "ml_full")]
pub use validation::ValidationMetrics;
#[cfg(feature = "ml_full")]
pub use data::{DatasetManager, DataStats};
#[cfg(feature = "ml_full")]
pub use data_loader_stream::StreamLoader;
#[cfg(feature = "ml_full")]
pub use data_loader::{MNISTDataset, MNISTImage, MNISTStats};
#[cfg(feature = "ml_full")]
pub use real_training::RealNeuralNetwork;
#[cfg(feature = "ml_full")]
pub use precision::{to_f32_slice, to_f64_from_f32, simulate_bf16_roundtrip_vec};
#[cfg(feature = "ml_full")]
pub use dp_accountant::{rdp_gaussian, compute_rdp, get_eps_from_rdp};
#[cfg(feature = "ml_full")]
pub use training_imagenet::ImageNetAdapter;
#[cfg(feature = "ml_full")]
pub use adversarial_hardening::{fgsm_perturb, pgd_attack};
#[cfg(feature = "ml_full")]
pub use training_advanced::TrainingMetrics;
#[cfg(feature = "ml_full")]
pub use training_neon_simd::{multiply_simd_f32, dot_product_simd_f32, convert_f32_to_f16_neon};
#[cfg(feature = "ml_full")]
pub use training_checkpointing::{CheckpointedLayer, SegmentedCheckpoint};
#[cfg(feature = "ml_full")]
pub use training_mali_gpu::{MaliGPUContext, MaliGPUBuffer, MaliGPUKernel};
#[cfg(feature = "ml_full")]
pub use training_mali_driver::{MaliGPUDriver, MaliDeviceStatus, MaliDeviceInfo, PrivacyAccountant};
#[cfg(feature = "ml_full")]
pub use dp_accountant::{rdp_gaussian_clipped, compute_rdp_amplified, compose_rdp, get_eps_delta_verified, PrivacyAccountant as DPAccountant};
#[cfg(feature = "ml_full")]
pub use training_armnn_binding::{ARMNNExecutor, GPUOperation, BackendType, GPUTensor};
#[cfg(feature = "ml_full")]
pub use dp_privacy_proofs::{PrivacyProof, prove_gaussian_mechanism, prove_laplace_mechanism, federated_privacy_analysis};
#[cfg(feature = "ml_full")]
pub use distributed_p2p_network::{P2PNetwork, P2PMessage, MessageType, PeerNode, NetworkStats};
#[cfg(feature = "ml_full")]
pub use e2e_benchmark::{EndToEndBenchmark, PipelineResults, EpochMetrics, ImageNetBenchmark};
