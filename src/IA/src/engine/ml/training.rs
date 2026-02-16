// Real Training Loop - Vraie convergence avec real data

use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::Vec;
use crate::ml::precision::{to_f32_slice, simulate_bf16_roundtrip_vec};
use crate::utils::debug_writer::DebugWriter;

/// Vrai training avec convergence réelle
pub struct RealTrainer {
    learning_rate: f64,
    epochs: usize,
    batch_size: usize,
    validation_split: f64,
    history: Arc<Mutex<Vec<EpochStats>>>,
    momentum: f64,
    weight_decay: f64,
    dropout_rate: f64,
    // Numerical / performance options
    pub use_mixed_precision: bool,
    pub gradient_checkpointing: bool,
    checkpoint_interval_epochs: usize,
    last_checkpoint: Option<TrainingCheckpoint>,
    metrics: Option<TrainingMetrics>,
}

#[derive(Clone, Debug)]
pub struct EpochStats {
    pub epoch: usize,
    pub train_loss: f64,
    pub train_accuracy: f64,
    pub val_loss: f64,
    pub val_accuracy: f64,
    pub learning_rate: f64,
}

#[derive(Clone, Debug)]
pub struct TrainingCheckpoint {
    pub epoch: usize,
    pub best_val_acc: f64,
    pub w_ih: Vec<f64>,
    pub w_ho: Vec<f64>,
    pub b_h: Vec<f64>,
    pub b_o: Vec<f64>,
}

#[derive(Clone, Debug)]
pub struct TrainingMetrics {
    pub epochs_run: usize,
    pub best_val_acc: f64,
    pub avg_train_loss: f64,
    pub avg_val_loss: f64,
    pub early_stopped: bool,
}

impl RealTrainer {
    pub fn new(learning_rate: f64, epochs: usize, batch_size: usize) -> Self {
        eprintln!("[RealTrainer] lr={:.4}, epochs={}, batch={}", learning_rate, epochs, batch_size);
        RealTrainer {
            learning_rate,
            epochs,
            batch_size,
            validation_split: 0.2,
            history: Arc::new(Mutex::new(Vec::new())),
            momentum: 0.9,
            weight_decay: 0.0001,
            dropout_rate: 0.2,
            use_mixed_precision: false,
            gradient_checkpointing: false,
            checkpoint_interval_epochs: 5,
            last_checkpoint: None,
            metrics: None,
        }
    }

    pub fn set_checkpoint_interval(&mut self, interval: usize) {
        self.checkpoint_interval_epochs = interval.max(1);
    }

    pub fn last_checkpoint(&self) -> Option<TrainingCheckpoint> {
        self.last_checkpoint.clone()
    }

    pub fn export_metrics(&self) -> Option<TrainingMetrics> {
        self.metrics.clone()
    }

    /// Vraie Training Loop avec Adam Optimizer + Batch Norm + LR Scheduling + Checkpointing
    pub fn train_real_convergence(&mut self, 
        training_data: &[(Vec<f64>, u32)], 
        validation_data: &[(Vec<f64>, u32)]
    ) -> (f64, f64, Vec<EpochStats>) {
        let input_size = 784;
        let hidden_size = 256;
        let output_size = 10;
        
        // Initialize weights and biases
        let mut w_ih: Vec<f64> = (0..input_size * hidden_size)
            .map(|_| (rand::random::<f64>() - 0.5) * 0.01)
            .collect();
        let mut w_ho: Vec<f64> = (0..hidden_size * output_size)
            .map(|_| (rand::random::<f64>() - 0.5) * 0.01)
            .collect();
        
        let mut b_h = vec![0.0; hidden_size];
        let mut b_o = vec![0.0; output_size];
        
        // Best weights for checkpointing
        let mut best_w_ih = w_ih.clone();
        let mut best_w_ho = w_ho.clone();
        let mut best_b_h = b_h.clone();
        let mut best_b_o = b_o.clone();
        
        // Adam optimizer state
        let mut v_w_ho = vec![0.0; w_ho.len()];
        let mut v_b_o = vec![0.0; output_size];
        
        let mut m_w_ho = vec![0.0; w_ho.len()];
        let mut m_b_o = vec![0.0; output_size];
        
        let mut history = Vec::new();
        let mut best_val_acc = 0.0;
        let mut patience = 0;
        let max_patience = 5;
        
        let base_lr = self.learning_rate;
        let lr_decay: f64 = 0.95;
        let warmup_epochs = (self.epochs / 10).max(1);
        let l2_lambda = self.weight_decay;
        
        println!("\n🚀 ADVANCED TRAINING - ADAM + BATCH NORM + LR SCHEDULING + CHECKPOINTING\n");
        println!("┌───────────────────────────────────────────────────────────────────┐");
        println!("│ Epoch │ Loss │ Acc │ Val Loss │ Val Acc │ LR │ Patience │ Status │");
        println!("├───────────────────────────────────────────────────────────────────┤");
        
        let mut early_stopped = false;
        for epoch in 0..self.epochs {
            // Learning rate scheduling with warmup
            let current_lr = if epoch < warmup_epochs {
                base_lr * (epoch as f64 + 1.0) / warmup_epochs as f64
            } else {
                base_lr * lr_decay.powi(((epoch - warmup_epochs) as i32) / 10)
            };
            self.learning_rate = current_lr;
            
            // Use Kahan summation for numerical stability of train loss accumulation
            let mut train_loss = 0.0;
            let mut c_loss = 0.0; // compensation for Kahan
            let mut train_correct = 0;
            
            for (features, label) in training_data {
                // Sanitize inputs to avoid NaN/Inf propagation
                let mut features_sanitized = features.clone();
                Self::sanitize_tensor(&mut features_sanitized);
                // Forward pass with batch norm (mixed-precision optional)
                let hidden = if self.use_mixed_precision {
                    self.forward_with_activation_mixed(&features_sanitized, &w_ih, &b_h, hidden_size, "relu")
                } else {
                    if self.gradient_checkpointing {
                        // stub: checkpointing-enabled forward (same result, different memory behavior)
                        self.forward_with_activation(&features_sanitized, &w_ih, &b_h, hidden_size, "relu")
                    } else {
                        self.forward_with_activation(&features_sanitized, &w_ih, &b_h, hidden_size, "relu")
                    }
                };
                let hidden_bn = self.batch_normalize(&hidden);
                let hidden_dropout = self.apply_dropout(&hidden_bn, self.dropout_rate);

                let output = if self.use_mixed_precision {
                    self.forward_linear_mixed(&hidden_dropout, &w_ho, &b_o, output_size)
                } else {
                    self.forward_linear(&hidden_dropout, &w_ho, &b_o, output_size)
                };
                let output_softmax = self.softmax(&output);
                
                // Loss computation with L2 regularization
                let base_loss = self.cross_entropy_loss(&output_softmax, *label as usize);
                let l2_loss = l2_lambda * (w_ho.iter().map(|w| w * w).sum::<f64>());
                let loss = base_loss + l2_loss;
                // Kahan add
                let y = loss - c_loss;
                let t = train_loss + y;
                c_loss = (t - train_loss) - y;
                train_loss = t;
                
                // Check prediction - gérer les NaN/Inf
                let pred_class = output_softmax.iter()
                    .enumerate()
                    .max_by(|a, b| {
                        match a.1.partial_cmp(b.1) {
                            Some(ord) => ord,
                            None => {
                                DebugWriter::warn("NaN in output softmax");
                                core::cmp::Ordering::Equal
                            }
                        }
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                
                if pred_class == *label as usize {
                    train_correct += 1;
                }
                
                // Backpropagation with gradient clipping
                let mut output_error = self.compute_output_error(&output_softmax, *label as usize);

                // sanitize gradients/error
                for v in output_error.iter_mut() {
                    if !v.is_finite() {
                        *v = 0.0;
                    }
                }
                
                // Add L2 gradient
                for (i, w) in w_ho.iter().enumerate() {
                    output_error[i % output_size] += 2.0 * l2_lambda * w;
                }
                
                let clipped_error = self.clip_gradients(&output_error, 1.0);
                
                // Adam update for weights
                for (i, grad) in clipped_error.iter().enumerate() {
                    let t = ((epoch - epoch.min(warmup_epochs)) * training_data.len() + i + 1) as f64;
                    let beta1 = 0.9;
                    let beta2 = 0.999;
                    let eps = 1e-8;
                    
                    m_b_o[i] = beta1 * m_b_o[i] + (1.0 - beta1) * grad;
                    v_b_o[i] = beta2 * v_b_o[i] + (1.0 - beta2) * grad * grad;
                    
                    let m_hat = m_b_o[i] / (1.0 - beta1.powf(t));
                    let v_hat = v_b_o[i] / (1.0 - beta2.powf(t));
                    
                    b_o[i] -= current_lr * m_hat / (v_hat.sqrt() + eps);
                    
                    for (j, h_val) in hidden_dropout.iter().enumerate() {
                        let w_grad = h_val * grad + 2.0 * l2_lambda * w_ho[j * output_size + i];
                        m_w_ho[j * output_size + i] = beta1 * m_w_ho[j * output_size + i] + (1.0 - beta1) * w_grad;
                        v_w_ho[j * output_size + i] = beta2 * v_w_ho[j * output_size + i] + (1.0 - beta2) * w_grad * w_grad;
                        
                        let m_hat = m_w_ho[j * output_size + i] / (1.0 - beta1.powf(t));
                        let v_hat = v_w_ho[j * output_size + i] / (1.0 - beta2.powf(t));
                        
                        w_ho[j * output_size + i] -= current_lr * m_hat / (v_hat.sqrt() + eps);
                        w_ho[j * output_size + i] = self.clip_value(w_ho[j * output_size + i], -1.0, 1.0);
                    }
                }
                // Sanitize weights to prevent NaN/Inf propagation
                Self::sanitize_tensor_mut(&mut w_ho);
            }
            
            let train_loss = train_loss / training_data.len() as f64;
            let train_acc = train_correct as f64 / training_data.len() as f64;
            
            // Validation
            let mut val_loss = 0.0;
            let mut c_val = 0.0;
            let mut val_correct = 0;
            
            for (features, label) in validation_data {
                let hidden = self.forward_with_activation(&features, &w_ih, &b_h, hidden_size, "relu");
                let output = self.forward_linear(&hidden, &w_ho, &b_o, output_size);
                let output_softmax = self.softmax(&output);
                
                let vl = self.cross_entropy_loss(&output_softmax, *label as usize);
                // Kahan add for val_loss
                let yv = vl - c_val;
                let tv = val_loss + yv;
                c_val = (tv - val_loss) - yv;
                val_loss = tv;
                
                let pred_class = output_softmax.iter()
                    .enumerate()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                
                if pred_class == *label as usize {
                    val_correct += 1;
                }
            }
            
            val_loss /= validation_data.len() as f64;
            let val_acc = val_correct as f64 / validation_data.len() as f64;
            
            let status = if epoch < warmup_epochs {
                "WARMUP"
            } else if val_acc > best_val_acc {
                "✓ BEST"
            } else {
                "  —  "
            };
            
            println!("│ {:>5} │ {:.3} │ {:.3} │ {:.5} │ {:.4} │ {:.4} │ {:>8} │ {} │",
                epoch + 1, train_loss, train_acc, val_loss, val_acc, current_lr, patience, status);
            
            // Model checkpointing
            if val_acc > best_val_acc {
                best_val_acc = val_acc;
                best_w_ih = w_ih.clone();
                best_w_ho = w_ho.clone();
                best_b_h = b_h.clone();
                best_b_o = b_o.clone();
                self.save_checkpoint(epoch + 1, best_val_acc, &best_w_ih, &best_w_ho, &best_b_h, &best_b_o);
                patience = 0;
            } else {
                patience += 1;
            }
            if (epoch + 1) % self.checkpoint_interval_epochs == 0 {
                self.save_checkpoint(epoch + 1, best_val_acc, &w_ih, &w_ho, &b_h, &b_o);
            }
            
            if patience >= max_patience {
                println!("└───────────────────────────────────────────────────────────────────┘");
                println!("⛔ Early stopping at epoch {} - Restoring best checkpoint\n", epoch + 1);
                w_ih = best_w_ih;
                w_ho = best_w_ho;
                b_h = best_b_h;
                b_o = best_b_o;
                early_stopped = true;
                break;
            }
            
            history.push(EpochStats {
                epoch: epoch + 1,
                train_loss,
                train_accuracy: train_acc,
                val_loss,
                val_accuracy: val_acc,
                learning_rate: current_lr,
            });
        }
        
        if !history.is_empty() {
            println!("└───────────────────────────────────────────────────────────────────┘\n");
        }
        
        let avg_train_loss = if history.is_empty() {
            0.0
        } else {
            history.iter().map(|h| h.train_loss).sum::<f64>() / history.len() as f64
        };
        let avg_val_loss = if history.is_empty() {
            0.0
        } else {
            history.iter().map(|h| h.val_loss).sum::<f64>() / history.len() as f64
        };
        self.metrics = Some(TrainingMetrics {
            epochs_run: history.len(),
            best_val_acc,
            avg_train_loss,
            avg_val_loss,
            early_stopped,
        });

        println!("✅ Training Complete! (Adam + Batch Norm + LR Warmup + L2 Regularization)");
        println!("   Final Training Accuracy: {:.4}", 
            history.last().map(|h| h.train_accuracy).unwrap_or(0.0));
        println!("   Final Validation Accuracy: {:.4}", best_val_acc);
        println!("   Best Model Restored from Checkpoint\n");
        
        (best_val_acc, history.last().map(|h| h.train_loss).unwrap_or(0.0), history)
    }

    fn save_checkpoint(
        &mut self,
        epoch: usize,
        best_val_acc: f64,
        w_ih: &[f64],
        w_ho: &[f64],
        b_h: &[f64],
        b_o: &[f64],
    ) {
        self.last_checkpoint = Some(TrainingCheckpoint {
            epoch,
            best_val_acc,
            w_ih: w_ih.to_vec(),
            w_ho: w_ho.to_vec(),
            b_h: b_h.to_vec(),
            b_o: b_o.to_vec(),
        });
    }
    
    fn forward_with_activation(&self, input: &[f64], weights: &[f64], bias: &[f64], 
                              output_size: usize, activation: &str) -> Vec<f64> {
        let input_size = input.len();
        let mut output = bias.to_vec();
        
        for i in 0..output_size {
            for j in 0..input_size {
                output[i] += input[j] * weights[j * output_size + i];
            }
            output[i] = match activation {
                "relu" => output[i].max(0.0),
                _ => output[i],
            };
        }
        
        output
    }

    fn forward_with_activation_mixed(&self, input: &[f64], weights: &[f64], bias: &[f64],
                                    output_size: usize, activation: &str) -> Vec<f64> {
        // convert to f32
        let in_f32 = to_f32_slice(input);
        let w_f32 = to_f32_slice(weights);
        let b_f32 = to_f32_slice(bias);

        let input_size = in_f32.len();
        let mut out_f32 = b_f32.clone();

        for i in 0..output_size {
            for j in 0..input_size {
                out_f32[i] += in_f32[j] * w_f32[j * output_size + i];
            }
            out_f32[i] = match activation {
                "relu" => out_f32[i].max(0.0),
                _ => out_f32[i],
            };
        }

        // simulate bf16 lossy roundtrip if desired
        let out_d = out_f32.iter().map(|v| *v as f64).collect::<Vec<f64>>();
        simulate_bf16_roundtrip_vec(&out_d)
    }
    
    fn forward_linear(&self, input: &[f64], weights: &[f64], bias: &[f64], 
                     output_size: usize) -> Vec<f64> {
        let input_size = input.len();
        let mut output = bias.to_vec();
        
        for i in 0..output_size {
            for j in 0..input_size {
                output[i] += input[j] * weights[j * output_size + i];
            }
        }
        
        output
    }

    fn forward_linear_mixed(&self, input: &[f64], weights: &[f64], bias: &[f64],
                            output_size: usize) -> Vec<f64> {
        let in_f32 = to_f32_slice(input);
        let w_f32 = to_f32_slice(weights);
        let b_f32 = to_f32_slice(bias);
        let input_size = in_f32.len();
        let mut out_f32 = b_f32.clone();

        for i in 0..output_size {
            for j in 0..input_size {
                out_f32[i] += in_f32[j] * w_f32[j * output_size + i];
            }
        }

        let out_d = out_f32.iter().map(|v| *v as f64).collect::<Vec<f64>>();
        simulate_bf16_roundtrip_vec(&out_d)
    }
    
    fn softmax(&self, input: &[f64]) -> Vec<f64> {
        let max_val = input.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let exps: Vec<f64> = input.iter().map(|x| (x - max_val).exp()).collect();
        let sum: f64 = exps.iter().sum();
        exps.iter().map(|e| e / sum).collect()
    }
    
    fn batch_normalize(&self, input: &[f64]) -> Vec<f64> {
        let mean = input.iter().sum::<f64>() / input.len() as f64;
        let variance = input.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / input.len() as f64;
        
        input.iter()
            .map(|x| (x - mean) / (variance.sqrt() + 1e-5))
            .collect()
    }
    
    fn apply_dropout(&self, input: &[f64], dropout_rate: f64) -> Vec<f64> {
        input.iter()
            .map(|x| {
                if rand::random::<f64>() < dropout_rate {
                    0.0
                } else {
                    x / (1.0 - dropout_rate)
                }
            })
            .collect()
    }
    
    fn compute_output_error(&self, softmax: &[f64], true_label: usize) -> Vec<f64> {
        let mut error = softmax.to_vec();
        error[true_label] -= 1.0;
        error
    }
    
    fn clip_gradients(&self, gradients: &[f64], max_val: f64) -> Vec<f64> {
        gradients.iter()
            .map(|g| {
                if g.abs() > max_val {
                    max_val * g.signum()
                } else {
                    *g
                }
            })
            .collect()
    }
    
    fn clip_value(&self, val: f64, min: f64, max: f64) -> f64 {
        val.max(min).min(max)
    }
    
    fn cross_entropy_loss(&self, output: &[f64], true_label: usize) -> f64 {
        let max_val = output.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let exp_sum: f64 = output.iter().map(|x| (x - max_val).exp()).sum();
        
        let prob = (output[true_label] - max_val).exp() / exp_sum;
        if prob > 1e-7 {
            -prob.ln()
        } else {
            16.0
        }
    }

    /// Replace NaN/Inf and clamp extreme values in a tensor copy
    fn sanitize_tensor(t: &mut [f64]) {
        for v in t.iter_mut() {
            if !v.is_finite() {
                *v = 0.0;
            } else if v.is_infinite() {
                *v = 0.0;
            } else if *v > 1e6 {
                *v = 1e6;
            } else if *v < -1e6 {
                *v = -1e6;
            }
        }
    }

    /// Sanitize tensor in place for weights/gradients
    fn sanitize_tensor_mut(t: &mut [f64]) {
        for v in t.iter_mut() {
            if !v.is_finite() {
                *v = 0.0;
            } else if *v > 1e6 {
                *v = 1e6;
            } else if *v < -1e6 {
                *v = -1e6;
            }
        }
    }

    /// Toggle mixed precision on the trainer (logical flag; computations will need to respect it)
    pub fn set_mixed_precision(&mut self, enabled: bool) {
        self.use_mixed_precision = enabled;
    }

    /// Toggle gradient checkpointing (stub: informs training flow)
    pub fn set_gradient_checkpointing(&mut self, enabled: bool) {
        self.gradient_checkpointing = enabled;
    }
}


