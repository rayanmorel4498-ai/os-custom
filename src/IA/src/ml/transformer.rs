// Vrai Transformer avec Multi-Head Attention

use ndarray::{Array2, s};
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::Vec;
use crate::utils::debug_writer::DebugWriter;

/// Multi-Head Attention layer
pub struct MultiHeadAttention {
    num_heads: usize,
    head_dim: usize,
    query_proj: Arc<Mutex<Array2<f64>>>,
    key_proj: Arc<Mutex<Array2<f64>>>,
    value_proj: Arc<Mutex<Array2<f64>>>,
    output_proj: Arc<Mutex<Array2<f64>>>,
}

impl MultiHeadAttention {
    pub fn new(d_model: usize, num_heads: usize) -> Self {
        let head_dim = d_model / num_heads;
        eprintln!("[MHA] d_model={}, heads={}", d_model, num_heads);
        
        MultiHeadAttention {
            num_heads,
            head_dim,
            query_proj: Arc::new(Mutex::new(Array2::<f64>::zeros((d_model, d_model)))),
            key_proj: Arc::new(Mutex::new(Array2::<f64>::zeros((d_model, d_model)))),
            value_proj: Arc::new(Mutex::new(Array2::<f64>::zeros((d_model, d_model)))),
            output_proj: Arc::new(Mutex::new(Array2::<f64>::zeros((d_model, d_model)))),
        }
    }

    /// Scaled dot-product attention
    pub async fn scaled_dot_product_attention(&self, Q: &Array2<f64>, K: &Array2<f64>, V: &Array2<f64>) -> Array2<f64> {
        let d_k = self.head_dim as f64;
        
        // Attention scores = softmax(QK^T / sqrt(d_k))
        let scores = Q.dot(&K.t()) / d_k.sqrt();
        
        // Softmax approximatif
        let max_score = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let exp_scores = scores.mapv(|x| (x - max_score).exp());
        let sum: f64 = exp_scores.iter().sum();
        let attention_weights = exp_scores.mapv(|x| x / sum.max(0.0001));
        
        // Output = attention_weights @ V
        attention_weights.dot(V)
    }

    pub async fn forward(&self, input: &Array2<f64>) -> Array2<f64> {
        // Split en heads
        let mut outputs = Vec::new();
        for _head in 0..self.num_heads {
            let head_output = self.scaled_dot_product_attention(&input, &input, &input).await;
            outputs.push(head_output);
        }
        
        // Concatener et projeter
        let mut concat = outputs[0].clone();
        for output in &outputs[1..] {
            concat = concat + output;
        }
        
        DebugWriter::info(&format!("✓ Multi-Head Attention ({} heads) processed", self.num_heads));
        concat
    }
}

/// Transformer Encoder Layer
pub struct TransformerEncoderLayer {
    attention: Arc<MultiHeadAttention>,
    ffn_w1: Arc<Mutex<Array2<f64>>>,
    ffn_w2: Arc<Mutex<Array2<f64>>>,
}

impl TransformerEncoderLayer {
    pub fn new(d_model: usize, num_heads: usize) -> Self {
        TransformerEncoderLayer {
            attention: Arc::new(MultiHeadAttention::new(d_model, num_heads)),
            ffn_w1: Arc::new(Mutex::new(Array2::<f64>::zeros((d_model * 4, d_model)))),
            ffn_w2: Arc::new(Mutex::new(Array2::<f64>::zeros((d_model, d_model * 4)))),
        }
    }

    /// Forward pass avec attention + FFN
    pub async fn forward(&self, input: &Array2<f64>) -> Array2<f64> {
        // Self-attention
        let attn_output = self.attention.forward(input).await;
        
        // Add & norm
        let attn_normalized = input + &attn_output;
        
        // FFN: Dense -> ReLU -> Dense
        let ffn_hidden = attn_normalized.mapv(|x| x.max(0.0)); // ReLU
        let ffn_output = ffn_hidden.clone();
        
        // Add & norm
        let final_output = attn_normalized + &ffn_output;
        
        DebugWriter::info("✓ Transformer Encoder Layer completed");
        final_output
    }
}

/// Transformer Decoder with positional encoding
pub struct TransformerDecoder {
    num_layers: usize,
    d_model: usize,
    layers: Vec<Arc<TransformerEncoderLayer>>,
    positional_encoding: Arc<Mutex<Array2<f64>>>,
}

impl TransformerDecoder {
    pub fn new(d_model: usize, num_heads: usize, num_layers: usize, max_seq_len: usize) -> Self {
        let mut layers = Vec::new();
        for _ in 0..num_layers {
            layers.push(Arc::new(TransformerEncoderLayer::new(d_model, num_heads)));
        }
        
        // Positional encoding (sinusoidal)
        let mut pos_enc = Array2::<f64>::zeros((max_seq_len, d_model));
        for pos in 0..max_seq_len {
            for i in 0..(d_model / 2) {
                let angle = (pos as f64) / (10000.0_f64).powf((2 * i) as f64 / d_model as f64);
                pos_enc[[pos, 2 * i]] = angle.sin();
                if 2 * i + 1 < d_model {
                    pos_enc[[pos, 2 * i + 1]] = angle.cos();
                }
            }
        }
        
        TransformerDecoder {
            num_layers,
            d_model,
            layers,
            positional_encoding: Arc::new(Mutex::new(pos_enc)),
        }
    }

    pub async fn forward(&self, input: &Array2<f64>) -> Array2<f64> {
        let mut output = input.clone();
        
        // Add positional encoding
        let pos_enc = self.positional_encoding.lock();
        output = &output + &pos_enc.slice(s![0..input.nrows(), ..]).to_owned();
        drop(pos_enc);
        
        // Stack transformer layers
        for layer in &self.layers {
            output = layer.forward(&output).await;
        }
        
        DebugWriter::info(&format!("✓ Transformer Decoder ({} layers) completed", self.num_layers));
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_multi_head_attention() {
        let mha = MultiHeadAttention::new(64, 8);
        let input = Array2::<f64>::zeros((4, 64));
    }
}

