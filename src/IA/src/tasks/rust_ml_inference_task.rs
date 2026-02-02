use crate::prelude::Vec;
use alloc::vec;

pub struct NeuralNetInference {
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

impl NeuralNetInference {
    pub fn new(input_size: usize, output_size: usize) -> Self {
        let mut weights = Vec::new();
        for _ in 0..output_size {
            weights.push(vec![0.1; input_size]);
        }
        NeuralNetInference {
            weights,
            biases: vec![0.0; output_size],
        }
    }

    pub fn infer(&self, input: &[f32]) -> Vec<f32> {
        let mut output = Vec::with_capacity(self.biases.len());
        
        for (idx, bias) in self.biases.iter().enumerate() {
            let mut sum = *bias;
            if let Some(weights_row) = self.weights.get(idx) {
                for (i, w) in weights_row.iter().enumerate() {
                    if let Some(&x) = input.get(i) {
                        sum += w * x;
                    }
                }
            }
            output.push(self.relu(sum));
        }
        output
    }

    fn relu(&self, x: f32) -> f32 {
        if x > 0.0 { x } else { 0.0 }
    }
}
